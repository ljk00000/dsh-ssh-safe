// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe — security-first SSH tools for DeepSeek Harness.
//
// DESIGN CONTRACT (the whole point of this plugin):
//   1. No telemetry. The only connections this package opens are your SSH
//      sessions. Grep for 'fetch(' to verify: there is no HTTP client here.
//   2. No cloud. No endpoint is ever contacted.
//   3. No auto-update. The plugin never rewrites itself or fetches versions.
//   4. No host patching. cordis.patch.yml inserts this plugin only; it does
//      not disable fs-sandbox / bash-sandbox and does not touch app.asar.
//   5. Credentials come from environment variables by default. Passing a
//      password through a tool call requires explicit opt-in
//      (allowSessionPassword: true).
//   6. Nothing secret reaches disk, config, logs, tool results, or prompts.
//
// SSH is a PARALLEL tool set. Local read/write/bash keep working as before.

import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { readFileSync, existsSync } from 'node:fs'
import net from 'node:net'
import { homedir } from 'node:os'
import { SshPool, expandHome, formatHost, hideAddress, pick } from './pool.js'
import { expectedEnv, redact } from './credentials.js'
import {
  credentialFor,
  credentialState,
  credentialsPath,
  credentialsTemplate,
  knownAliases,
  loadCredentialFile,
  machineDefinition,
  readCredentialFile,
} from './machines.js'
import { storePath } from './hostkey.js'
import { DEFAULT_DENY_RULES, checkCommand, describeRule, invalidPatterns } from './guard.js'
import { exitLine, formatListing, plural } from './format.js'
import { AuditLog, summarize } from './audit.js'
import {
  findWorkspace,
  listWorkspaces,
  readMarker,
  remoteDir,
  remoteRoot,
  remoteTitle,
  removeRemoteDir,
  writeRemoteWorkspace,
} from './remote-workspace.js'

export const name = 'dsh-ssh-safe'
export const inject = ['tools']

export const Config = z.object({
  /** Machine alias used when a tool call omits 'machine'. */
  defaultMachine: z.string().default(''),

  /**
   * Machines defined here edit like any other setting: DSH renders this schema
   * as a form, so host, port and user can be changed without touching
   * environment variables or restarting.
   *
   * Passwords belong in the credential file instead (see below). A password
   * typed here is stored in the profile's config file in plain text.
   */
  machines: z.dict(z.object({
    host: z.string().default(''),
    port: z.number().step(1).min(1).max(65535).default(22),
    user: z.string().default(''),
    keyPath: z.string().default(''),
    keyPassphrase: z.string().default(''),
    password: z.string().default(''),
    hostKeyPolicy: z.union(['', 'strict', 'tofu', 'off']).default(''),
    /**
     * Trust store for this machine. Empty uses the plugin's own
     * <DSH_HOME>/dsh-ssh-safe/known_hosts.json.
     *
     * An OpenSSH known_hosts file is accepted too, and verified read-only: plain,
     * wildcard, hashed and [host]:port entries, plus @revoked. It is never
     * written to -- a new host is added with ssh-keyscan, because writing a
     * format this plugin only half-validates is how trust stores rot.
     */
    knownHosts: z.string().default(''),
  })).default({}),

  /**
   * Read <DSH_HOME>/dsh-ssh-safe/credentials.json on each connection.
   *
   * This is the file to edit when a password changes: it is re-read every time,
   * so a new value takes effect on the next command with no restart. Mode 0600.
   */
  useCredentialFile: z.boolean().default(true),

  /**
   * Accept a plaintext password from the settings form or the credential file.
   *
   * OFF by default, and it should stay off: a plaintext password is readable by
   * anything that can read the file, and it travels with the file into backups,
   * sync folders and screenshots. The credential file stores a DPAPI-encrypted
   * value instead, and an environment variable keeps the secret in memory only.
   */
  allowPlaintextPassword: z.boolean().default(false),

  /**
   * Allow a password through a tool argument. OFF by default: with it off,
   * credentials can only come from environment variables, so they never
   * enter the conversation transcript or the config file.
   */
  allowSessionPassword: z.boolean().default(false),

  /**
   * How much of the machine inventory ssh_machines prints.
   *
   *   full  — alias, user@host:port, key path, detected env names (default)
   *   alias — alias and auth kind only; host, port and key path are masked,
   *           so a shared or exported transcript does not leak the network
   *           topology or where private keys live
   */
  machineInventory: z.union(['full', 'alias']).default('full'),

  /**
   * Append an NDJSON record for every operation to
   * <DSH_HOME>/dsh-ssh-safe/audit.ndjson.
   *
   * Records the alias, operation, a one-line command summary, exit code and
   * outcome — never command output, file contents, or credentials.
   * Off by default so the plugin does not write files unasked.
   */
  auditLog: z.boolean().default(false),

  /**
   * Probe a pooled connection that has been idle this long before reusing it.
   * A firewalled connection otherwise accepts writes that go nowhere and only
   * surface as a command timeout.
   *
   * Defaults to 5 minutes: the probe costs a round trip, so a short interval
   * would make every command after a brief pause slower. NAT idle timeouts on
   * the common cloud providers are far longer than this. 0 disables the probe.
   */
  healthCheckIdleMs: z.number().step(1).min(0).default(300000),

  /** How long the liveness probe may take. */
  healthCheckTimeoutMs: z.number().step(1).min(100).default(3000),

  /**
   * allow   — ssh_exec runs immediately (default)
   * confirm — ssh_exec requires confirm: true, so a model cannot run a
   *           command entirely on its own initiative
   */
  execGuard: z.union(['allow', 'confirm']).default('allow'),

  /**
   * strict — only hosts already recorded may connect (default)
   * tofu   — first contact records the fingerprint; a CHANGE is still fatal
   * off    — no verification (MITM-unsafe; reported in every result)
   */
  hostKeyPolicy: z.union(['strict', 'tofu', 'off']).default('strict'),

  commandTimeoutMs: z.number().step(1).min(1000).default(30000),

  /**
   * Deadline for a single SFTP read/write/list. ssh2 can stall without emitting
   * an error, so this is the backstop that keeps a tool call from hanging.
   */
  sftpTimeoutMs: z.number().step(1).min(1000).default(30000),

  /**
   * How long to wait for the peer to confirm a close. A silent peer must not
   * hang shutdown, so this bounds both closeOne and closeAll.
   */
  closeTimeoutMs: z.number().step(1).min(100).default(1500),
  connectTimeoutMs: z.number().step(1).min(1000).default(15000),
  keepaliveIntervalMs: z.number().step(1).min(0).default(20000),
  maxOutputChars: z.number().step(1).min(1024).default(200000),
  maxFileBytes: z.number().step(1).min(1024).default(1048576),
  /**
   * How many directory entries ssh_list renders. A directory of 200k files used
   * to produce a 20 MB tool result; the cap keeps one listing from crowding out
   * the rest of the conversation, and the count of omitted entries is reported.
   * 0 means no limit.
   */
  maxListEntries: z.number().step(1).min(0).default(2000),
  reconnectCooldownMs: z.number().step(1).min(0).default(15000),

  /**
   * Maximum number of SSH connections kept alive at once. Least recently used
   * connections are closed when the limit is exceeded. 0 disables the limit.
   */
  maxConnections: z.number().step(1).min(0).default(8),

  /**
   * Commands matching these regular expressions are refused before exec.
   * A safety rail against catastrophic typos, NOT a security boundary — a
   * shell can always be reached through other commands.
   */
  /**
   * How to treat a pipeline into an interpreter (`curl ... | bash`).
   *
   *   refuse — treat it as blocked (default): pattern matching cannot see what
   *            the left side produced, so it cannot be judged
   *   allow  — let it through; only denyPatterns apply
   */
  pipeToShell: z.union(['refuse', 'allow']).default('refuse'),

  // One definition, in guard.js: the refusal message names the rule that matched,
  // so the pattern and its name must not be able to drift apart.
  denyPatterns: z.array(z.string()).default(DEFAULT_DENY_RULES.map((rule) => rule.pattern)),
})

/** Where the host-key store lives. */
function resolveDshHome() {
  if (process.env.DSH_HOME) return process.env.DSH_HOME
  return homedir() + (process.platform === 'win32' ? '\\' : '/') + '.dsh'
}

export async function apply(ctx, config) {
  // Validate through the schema instead of spreading defaults and overwriting
  // them. The spread form let any value through: execGuard: "yes" stayed at
  // "yes", which is not "confirm", so the confirmation guard was silently OFF
  // while the config displayed something that looked enabled.
  //
  // A bad value now fails the load with a message naming the setting and its
  // allowed values. Refusing to start is correct here: a security plugin that
  // quietly interprets an unknown policy is worse than one that will not boot.
  // Reject a setting whose name is a near-miss for a real one.
  //
  // schemastery passes unknown keys through untouched, so 'execGurad: confirm'
  // parsed cleanly and then governed nothing: the guard stayed on 'allow' while
  // the config displayed a line that looked like confirmation was on. A typo in
  // a security setting is the one kind of typo that must not be quiet.
  //
  // Only a near-miss is refused. A key that is nothing like a real setting is
  // left alone on purpose: the host may add metadata of its own, and refusing to
  // load over an unknown field would be its own outage.
  const knownKeys = Object.keys(Config.dict || {})
  const near = (a, b) => {
    if (Math.abs(a.length - b.length) > 2) return false
    const row = Array.from({ length: b.length + 1 }, (_, i) => i)
    for (let i = 1; i <= a.length; i++) {
      let prev = row[0]
      row[0] = i
      for (let j = 1; j <= b.length; j++) {
        const tmp = row[j]
        row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1))
        prev = tmp
      }
    }
    return row[b.length] <= 2
  }
  const suspicious = Object.keys(config && typeof config === 'object' ? config : {})
    .filter((key) => !key.startsWith('$') && !knownKeys.includes(key))
    .map((key) => [key, knownKeys.find((known) => near(key.toLowerCase(), known.toLowerCase()))])
    .filter(([, suggestion]) => suggestion)
  if (suspicious.length > 0) {
    throw new Error(
      'dsh-ssh-safe: unknown setting "' + suspicious[0][0] + '" — did you mean "' + suspicious[0][1] + '"? ' +
      'Fix the plugin config listed under "dsh-ssh-safe" in cordis.patch.yml. ' +
      'A misspelled security setting would otherwise be ignored while looking enabled.'
    )
  }

  // A rule that does not compile is skipped at match time, so a typo here turns
  // a protection off while leaving it visible in the config. Refuse to load.
  const broken = invalidPatterns(config && typeof config === 'object' ? config.denyPatterns : undefined)
  if (broken.length > 0) {
    const first = broken[0]
    throw new Error(
      'dsh-ssh-safe: invalid configuration — denyPatterns[' + first.index + '] is not a valid regular expression (' +
      first.message + '): ' + first.pattern +
      '. That rule would be skipped silently, so the plugin refuses to load. ' +
      'Fix or remove the entry in the plugin config listed under "dsh-ssh-safe" in cordis.patch.yml.'
    )
  }

  let cfg
  try {
    cfg = Config(config || {})
  } catch (err) {
    const detail = err && err.message ? err.message : String(err)
    throw new Error(
      'dsh-ssh-safe: invalid configuration — ' + detail +
      '. Fix the plugin config listed under "dsh-ssh-safe" in cordis.patch.yml ' +
      '(or run ssh_config after a valid load to see the effective values).'
    )
  }
  const dshHome = resolveDshHome()
  // Everything that reads the credential file goes through this one decision.
  // When the setting is off the file must be invisible to the host, port and
  // user as well as to the password -- and to the connection, not just to the
  // tools that report where credentials come from. It was honoured only by
  // ssh_credentials, while a connection still authenticated from the file.
  const credentialHome = cfg.useCredentialFile === true ? dshHome : ''
  const pool = new SshPool(cfg, { dshHome, credentialHome })
  // Auditing is off by default: writing files someone did not ask for is its
  // own surprise. Turning it on is a one-line config change.
  const audit = new AuditLog(dshHome + (process.platform === 'win32' ? '\\' : '/') + 'dsh-ssh-safe', {
    enabled: cfg.auditLog === true,
  })

  /**
   * Argument validators.
   *
   * `parameters` describes the arguments to the model; nothing enforces it. A
   * model can send null, a number, or a negative timeout, and each tool used to
   * check only one field with its own wording. These run before any network work,
   * so a malformed call fails immediately instead of surfacing as ECONNREFUSED or
   * being swallowed by the reconnect cooldown.
   */
  const requireText = (value, field) => {
    if (typeof value !== 'string') {
      throw new Error(field + ' must be a string (received ' + (value === null ? 'null' : typeof value) + ')')
    }
    const trimmed = value.trim()
    if (trimmed.length === 0) throw new Error(field + ' is required')
    return trimmed
  }

  /**
   * Text for the audit log.
   *
   * machineInventory: 'alias' promises that the host and port stay out of
   * everything this plugin says; the audit log is read back through ssh_audit, so
   * a failure recorded there ('Could not connect to tester@1.2.3.4:2222') leaked
   * exactly what the setting hides.
   *
   * @param {string} alias
   * @param {unknown} text
   * @returns {string}
   */
  const auditText = (alias, text) => {
    const masked = redact(text)
    if (cfg.machineInventory !== 'alias') return masked
    try {
      const m = machineDefinition(alias, { machines: cfg.machines, dshHome: credentialHome })
      return hideAddress(masked, m)
    } catch {
      return masked
    }
  }

  /**
   * Permission bits, written the way chmod writes them.
   *
   * Accepts "600", "0600" and the number 600 -- all read as octal digits, which
   * is what a user typing a mode means. 0o600 (the JS number 384) is rejected
   * with the reason, because guessing between decimal and octal is how a file
   * ends up world-readable.
   *
   * @param {unknown} value
   * @returns {number|undefined} the numeric mode, e.g. 0o600
   */
  const parseMode = (value) => {
    if (value === undefined || value === null || value === '') return undefined
    const text = String(value).trim().replace(/^0o/i, '')
    if (!/^[0-7]{3,4}$/.test(text)) {
      throw new Error(
        'mode must be octal digits like "600" or "0644" (received ' + JSON.stringify(value) + '). ' +
        'Use 0600 for a file only the account should read.'
      )
    }
    return parseInt(text, 8)
  }

  /** Optional string: absent stays undefined, a non-string is rejected. */
  const optionalText = (value, field) => {
    if (value === undefined || value === null || value === '') return undefined
    if (typeof value !== 'string') {
      throw new Error(field + ' must be a string when provided (received ' + typeof value + ')')
    }
    return value
  }

  /**
   * Optional positive integer, used for timeouts and sizes.
   * Returns undefined when absent or 0, so callers fall back to the config.
   */
  const optionalBudget = (value, field) => {
    if (value === undefined || value === null || value === '' || value === 0) return undefined
    const n = Number(value)
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error(field + ' must be a positive number (received ' + JSON.stringify(value) + ')')
    }
    return Math.floor(n)
  }

  /** Boolean that only accepts true/false, not the string "true". */
  const optionalFlag = (value, field) => {
    if (value === undefined || value === null) return false
    if (typeof value !== 'boolean') {
      throw new Error(field + ' must be true or false (received ' + typeof value + ')')
    }
    return value
  }

  const textOut = {
    schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
    render: (_args, value) => [{ type: 'text', text: String(value?.text ?? '') }],
  }

  /**
   * Tool registration, across harness generations.
   *
   * Harness 0.2.1 removed `ctx.tools.defineTool`: the compiler moved to the
   * `@deepseek-ai/dsh-tools` export and the service now takes an
   * already-compiled definition through `ctx.tools.register`. Calling the old
   * method threw "ctx.tools.defineTool is not a function" while the plugin was
   * activating, so every tool vanished from the registry and the whole plugin
   * reported "did not activate" — a security plugin that silently stops
   * existing is the worst failure mode it has.
   *
   * Both entry points are supported: `register` when the service offers it,
   * otherwise the older `defineTool` method, which took the un-compiled
   * definition itself. Detection is per-call-site so a harness upgrade cannot
   * leave half the tools on one protocol.
   */
/**
 * Levenshtein distance, bounded: enough to suggest a near-miss argument name.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function editDistance(a, b) {
  if (a === b) return 0
  const rows = a.length + 1
  const cols = b.length + 1
  let previous = Array.from({ length: cols }, (_, i) => i)
  for (let i = 1; i < rows; i++) {
    const current = [i]
    for (let j = 1; j < cols; j++) {
      current[j] = Math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1))
    }
    previous = current
  }
  return previous[cols - 1]
}

/**
 * The caller's cancellation signal, or undefined.
 *
 * The harness aborts this when the user stops the turn. Tools that pass it down
 * can stop their work instead of finishing it for nobody.
 *
 * @param {{signal?: unknown}} [execution]
 * @returns {AbortSignal|undefined}
 */
/** Fields a machine entry in the settings form may use. */
const MACHINE_FIELDS = ['host', 'port', 'user', 'password', 'keyPath', 'keyPassphrase', 'hostKeyPolicy', 'knownHosts']

/** The credential file additionally takes an encrypted password and 'username'. */
const CREDENTIAL_FIELDS = [...MACHINE_FIELDS, 'passwordDpapi', 'username']

/**
 * Spell-check the machine entries in the settings form.
 *
 * schemastery drops keys it does not know, so `keypath: ~/.ssh/id_ed25519`
 * parsed fine and then reported "no password, key or agent available": the
 * machine looked configured and behaved unconfigured.
 *
 * @param {Record<string, any>} [machines]
 * @returns {string[]} one sentence per unknown field
 */
function unknownMachineFields(machines, only = '', where = 'settings form', allowed = MACHINE_FIELDS) {
  const problems = []
  for (const [alias, entry] of Object.entries(machines || {})) {
    if (!entry || typeof entry !== 'object') continue
    if (only && alias.toLowerCase() !== String(only).toLowerCase()) continue
    for (const key of Object.keys(entry)) {
      if (allowed.includes(key)) continue
      let best = ''
      let bestDistance = Number.POSITIVE_INFINITY
      for (const name of allowed) {
        const distance = editDistance(key.toLowerCase(), name.toLowerCase())
        if (distance < bestDistance) { bestDistance = distance; best = name }
      }
      problems.push(
        'machine "' + alias + '" in the ' + where + ' has an unknown field "' + key + '"' +
        (bestDistance <= 3 ? ' (did you mean "' + best + '"?)' : '') +
        ' — it is ignored'
      )
    }
  }
  return problems
}

/** Unknown fields in both configuration sources, for one machine or all. */
function machineFieldProblems(only = '') {
  const file = loadCredentialFile(credentialHome)
  // Copying the settings-form shape into the credential file is a natural
  // mistake: the file is keyed by alias directly, and 'machines' then becomes a
  // machine whose fields are other machines.
  const nested = file.machines
  const looksNested = nested && typeof nested === 'object' &&
    Object.values(nested).some((entry) => entry && typeof entry === 'object')
  const fileProblems = unknownMachineFields(file, only, 'credential file', CREDENTIAL_FIELDS)
    // The nested message explains this entry; "unknown field prod (did you mean
    // port?)" right above it only adds noise.
    .filter((problem) => !(looksNested && problem.startsWith('machine "machines" in the credential file')))
  const problems = [
    ...unknownMachineFields(cfg.machines, only, 'settings form', MACHINE_FIELDS),
    ...fileProblems,
  ]
  if (looksNested && !only) {
    problems.push(
      'the credential file has a "machines" key: it should be keyed by alias directly ' +
      '({"prod": {...}}), not nested under "machines"'
    )
  }
  return problems
}

function executionSignal(execution) {
  const signal = execution && /** @type {any} */ (execution).signal
  return signal && typeof signal === 'object' && typeof signal.aborted === 'boolean'
    ? /** @type {AbortSignal} */ (signal)
    : undefined
}

/**
 * Reject arguments the tool does not declare.
 *
 * The harness compiles a tool's parameters into an OPEN object schema, so a
 * misspelled argument is accepted and silently ignored: `timeout: 500` ran with
 * the configured 30 seconds and `maxByte: 5` read up to a megabyte. Both looked
 * like they worked. A typo in an argument name is otherwise invisible.
 *
 * @param {Record<string, unknown>} args
 * @param {string[]} known
 * @param {string} toolName
 */
function assertKnownArgs(args, known, toolName) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return
  const allowed = new Set(known)
  const unknown = Object.keys(args).filter((key) => !allowed.has(key))
  if (unknown.length === 0) return
  const describe = (key) => {
    const lower = key.toLowerCase()
    let best = ''
    let bestDistance = Number.POSITIVE_INFINITY
    for (const name of known) {
      const distance = editDistance(lower, name.toLowerCase())
      if (distance < bestDistance) { bestDistance = distance; best = name }
    }
    return '"' + key + '"' + (bestDistance <= 2 ? ' (did you mean "' + best + '"?)' : '')
  }
  // "Accepted: ." is what a zero-argument tool printed: the list was empty.
  const accepted = known.length > 0
    ? '. Accepted: ' + known.join(', ') + '.'
    : '. ' + toolName + ' takes no arguments, so the call was refused.'
  throw new Error(
    'Unknown argument(s) for ' + toolName + ': ' + unknown.map(describe).join(', ') + accepted
  )
}
  // Wrap execute once so every tool rejects undeclared arguments.
  const withArgCheck = (definition) => {
    const known = Object.keys(definition.parameters || {})
    const run = definition.execute
    return {
      ...definition,
      execute: (args, toolContext) => {
        assertKnownArgs(args, known, definition.name)
        return run(args, toolContext)
      },
    }
  }
  const registerTool = typeof ctx.tools.register === 'function'
    ? (definition) => ctx.tools.register(defineTool(withArgCheck(definition)))
    : typeof ctx.tools.defineTool === 'function'
      ? (definition) => ctx.tools.defineTool(withArgCheck(definition))
      : () => {
        throw new Error(
          'dsh-ssh-safe: this harness exposes neither ctx.tools.register (0.2.1+) nor ' +
          'ctx.tools.defineTool (0.1.x), so no tool can be registered. ' +
          'Check which DSH version is running (dsh --version) and report it.'
        )
      }

  // Aliases are case-insensitive: envNames() uppercases them anyway, so
  // 'PROD' and 'prod' name the same machine and must not be listed twice.
  const normalizeAlias = (value) => String(value ?? '').trim().toLowerCase()

  /**
   * How a machine is named in tool output.
   *
   * machineInventory: 'alias' exists so the conversation carries no topology;
   * every tool that prints a target has to ask here, or one of them leaks the
   * host the others hide.
   *
   * @param {{username?: string, host?: string, port?: number}} m
   * @returns {string}
   */
  const endpointOf = (m) => cfg.machineInventory === 'alias'
    ? '<host hidden>'
    // Same IPv6 convention as the pool: user@[::1]:22, never user@::1:22.
    : (m.username || '?') + '@' + formatHost(m.host || '?') + ':' + (m.port || 22)

  const machineFor = (args) => {
    const alias = normalizeAlias(args?.machine || cfg.defaultMachine || '')
    if (!alias) {
      throw new Error(
        'No machine given. Pass machine: "<alias>" or set defaultMachine in the plugin config. ' +
        'An alias maps to environment variables: alias "prod" reads DSH_SSH_PROD_HOST.'
      )
    }
    return alias
  }

  const guard = (command, confirmed, machine) => {
    if (cfg.execGuard === 'confirm' && confirmed !== true) {
      throw new Error('execGuard is "confirm": pass confirm: true to run this command.')
    }
    const verdict = cfg.pipeToShell === 'allow'
      ? checkCommand(command, cfg.denyPatterns, { allowPipeline: true })
      : checkCommand(command, cfg.denyPatterns)
    if (verdict.blocked) {
      audit.write({
        kind: 'refused',
        // Which machine it was aimed at is the first thing an operator asks
        // about a refused command; the record used to leave it out.
        machine,
        command: summarize(command),
        pattern: verdict.pattern,
        reason: verdict.reason,
      })
      const where = verdict.reason === 'matches deny pattern' ? '' : ' (' + verdict.reason + ')'
      // Point at the setting that actually governs this refusal.
      const remedy = String(verdict.reason || '').startsWith('pipes into ')
        ? 'Set pipeToShell: allow in the plugin config to permit pipelines into interpreters.'
        : 'Adjust denyPatterns in the plugin config if this is intentional.'
      // A rule has a name here; a regular expression tells the user nothing.
      const what = verdict.reason === 'matches deny pattern'
        ? describeRule(verdict.pattern)
        : verdict.pattern
      throw new Error('Command refused' + where + ': ' + what + '. ' + remedy)
    }
  }

  /**
   * Gate for remote writes.
   *
   * execGuard previously applied only to ssh_exec, so a file write -- a script,
   * a line in ~/.bashrc, a replacement authorized_keys -- went through without
   * confirmation. Writing is often the more dangerous half of an agent's work,
   * so the guard covers it too.
   */
  const guardWrite = (confirmed, direction = 'write to') => {
    if (cfg.execGuard === 'confirm' && confirmed !== true) {
      // The direction matters: a refused read used to say "pass confirm: true to
      // write to the remote host", which describes the wrong tool entirely.
      const why = direction === 'read from'
        ? 'Reads can copy a private key or a configuration file off the host, so they are gated as well.'
        : 'Writes can install scripts or change access, so they are gated as well.'
      throw new Error('execGuard is "confirm": pass confirm: true to ' + direction + ' the remote host. ' + why)
    }
  }

  /**
   * Warnings from the credential resolver, for the caller that supplied a
   * password. A session password is the last resort, so passing one while a
   * stored credential exists has no effect — and used to say nothing at all,
   * which reads as "my new password worked". Re-resolving here (the resolver
   * caches the decrypted value) keeps the note specific to this call instead of
   * inheriting whatever the pooled connection was opened with.
   */
  const credentialWarnings = (alias, sessionPassword) => {
    if (!sessionPassword) return []
    try {
      const auth = credentialFor(alias, {
        machines: cfg.machines,
        dshHome: credentialHome,
        sessionPassword,
        allowSessionPassword: cfg.allowSessionPassword === true,
        allowPlaintextPassword: cfg.allowPlaintextPassword === true,
      })
      return Array.isArray(auth.warnings) ? auth.warnings : []
    } catch {
      return []
    }
  }

  const trustedLine = (m) => {
    // A per-machine knownHosts override goes through the same ~ expansion the
    // pool uses; without it a "~/.ssh/x.json" value is read as a literal path.
    const file = m.knownHosts ? expandHome(m.knownHosts) : storePath(dshHome)
    let raw
    try {
      raw = JSON.parse(readFileSync(file, 'utf8'))
    } catch (err) {
      // Distinguish "no store yet" from "the store exists but is unreadable".
      // Silently reporting "not trusted" for a permission error would hide a
      // real misconfiguration.
      const code = err && /** @type {{code?: string}} */ (err).code
      if (code === 'ENOENT') return 'not trusted yet (no fingerprint recorded)'
      return 'known-hosts store unreadable (' + (code || 'parse error') + '): ' + file
    }
    const rec = raw?.hosts?.[String(m.host) + ':' + (m.port || 22)]
    if (!rec) return 'not trusted yet (no fingerprint recorded)'
    return 'trusted: ' + rec.fingerprint + (rec.firstSeenAt ? ' (since ' + rec.firstSeenAt + ')' : '')
  }

  // ── ssh_machines ──────────────────────────────────────────────────────
  registerTool({
    name: 'ssh_machines',
    description:
      'List the SSH machines configured through environment variables: alias, host, user, auth ' +
      'kind, host-key trust state. Never returns a password, passphrase, or key material. ' +
      'Call this first when you do not know which aliases exist.',
    parameters: {},
    output: textOut,
    // Every call owns its own SSH channel, so two calls never share one; the
    // pool keys state per alias and connects once per alias. Without this the
    // harness treats the tool as exclusive and runs nested calls one at a
    // time: a three-second command on one machine made an unrelated 200ms
    // command on the same or another machine wait for it.
    isConcurrencySafe: () => true,
    async execute() {
      const aliases = new Set()
      if (cfg.defaultMachine) aliases.add(normalizeAlias(cfg.defaultMachine))
      // Config, credential file and environment: any of the three can define a
      // machine, so the inventory lists all of them.
      for (const alias of knownAliases({ machines: cfg.machines, dshHome: credentialHome })) aliases.add(alias)
      if (aliases.size === 0) {
        return { text:
          'No machines configured. Any one of these works:\n' +
          '\n' +
          ' 1. Settings form (recommended): add an entry under machines, e.g.\n' +
          '      machines.prod = { host: "10.0.0.5", user: "ubuntu", port: 22 }\n' +
          '\n' +
          ' 2. Credential file for passwords that change often — no restart needed:\n' +
          '      ' + credentialsPath(dshHome) + '\n' +
          '    ' + credentialsTemplate().split('\n').join('\n    ') + '\n' +
          '\n' +
          ' 3. Environment variables (restart required):\n' +
          '      DSH_SSH_PROD_HOST=10.0.0.5\n' +
          '      DSH_SSH_PROD_USER=ubuntu\n' +
          '      DSH_SSH_PROD_KEY_PATH=~/.ssh/id_ed25519' }
      }
      const out = []
      const lean = cfg.machineInventory === 'alias'
      for (const alias of aliases) {
        const m = machineDefinition(alias, { machines: cfg.machines, dshHome: credentialHome })
        const need = expectedEnv(alias)
        // machineDefinition() never carries the password itself (it may need
        // decrypting), so test the SOURCE. Testing m.password meant the line
        // said "NONE" for a machine whose password was sitting in the
        // credential file.
        const pwSource = m.sources.password
        const authKind = pwSource && pwSource !== 'none'
          ? 'password (' + pwSource + ')'
          : m.keyPath
            ? (lean
                ? 'private key (' + m.sources.keyPath + ', path hidden)'
                : 'key ' + m.keyPath + ' (' + m.sources.keyPath + ')')
            : 'NONE'
        // A port that cannot be dialled is shown as configured, not as the 22
        // fallback: showing 22 hid the value the user has to fix.
        const shownPort = m.portProblem && m.portRaw !== '' ? m.portRaw : m.port
        const endpoint = lean
          ? '<host hidden>'
          : (m.username || '<no user>') + '@' + (m.host ? formatHost(m.host) : '<no host>') + ':' + shownPort
        out.push(
          '• ' + alias + '  ' + endpoint +
          '\n    auth: ' + authKind +
          '\n    hostKeyPolicy: ' + (m.hostKeyPolicy || cfg.hostKeyPolicy) +
          '\n    ' + trustedLine(m) +
          (lean
            ? ''
            : (() => {
                const used = Object.entries(m.sources || {})
                  .filter(([, source]) => source !== 'none')
                  .map(([field, source]) => field + '=' + source)
                return used.length ? '\n    sources: ' + used.join(', ') : '\n    sources: none'
              })()) +
          (m.host && m.username ? '' : '\n    MISSING: ' + need.required.join(', ')) +
          (m.portProblem ? '\n    BAD PORT: ' + m.portProblem : '')
        )
      }
      if (lean) {
        out.push('', '(machineInventory is "alias": host, port and key paths are hidden. Set machineInventory: full to show them.)')
      }
      // Field typos in the settings form are dropped by the schema, so the
      // machine silently looks unconfigured; the inventory is where a user
      // checks their config, so it is where the misspelling is actionable.
      const typos = machineFieldProblems()
      if (typos.length) out.push('', 'Configuration problems:', ...typos.map((t) => '  ' + t))
      return { text: out.join('\n') }
    },
  })

  // ── ssh_connect ───────────────────────────────────────────────────────
  registerTool({
    name: 'ssh_connect',
    description:
      'Open or reuse the SSH connection for a machine, then report the host-key fingerprint and ' +
      'the remote uname. Refuses an unknown host unless trustHostKey: true is passed once, and ' +
      'always refuses a host whose key changed. Never returns credentials.',
    parameters: {
      machine: { type: 'string', description: 'Machine alias, e.g. "prod". Defaults to defaultMachine.' },
      trustHostKey: { type: 'boolean', description: 'Accept this host key on FIRST contact only. Ignored when the key changed.' },
      force: { type: 'boolean', description: 'Bypass the reconnect cooldown after a recent failure.' },
      password: { type: 'string', description: 'Only honoured when the profile sets allowSessionPassword: true.' },
    },
    output: textOut,
    // Every call owns its own SSH channel, so two calls never share one; the
    // pool keys state per alias and connects once per alias. Without this the
    // harness treats the tool as exclusive and runs nested calls one at a
    // time: a three-second command on one machine made an unrelated 200ms
    // command on the same or another machine wait for it.
    isConcurrencySafe: () => true,
    async execute(args) {
      const alias = machineFor(args)
      const startedAt = Date.now()
      try {
        await pool.connect(alias, {
          sessionPassword: optionalText(args.password, 'password'),
          trustHostKey: optionalFlag(args.trustHostKey, 'trustHostKey'),
          force: optionalFlag(args.force, 'force'),
        })
      } catch (err) {
        audit.write({
          kind: 'connect',
          machine: alias,
          outcome: 'error',
          error: auditText(alias, err && err.message ? err.message : String(err)).slice(0, 200),
          ms: Date.now() - startedAt,
        })
        throw err
      }
      audit.write({ kind: 'connect', machine: alias, outcome: 'ok', ms: Date.now() - startedAt })

      const m = machineDefinition(alias, { machines: cfg.machines, dshHome: credentialHome })
      const entry = pool.entry(alias)
      const stats = pool.connectionStats()
      // Deliberately no remote command here. Verifying the channel is what
      // ssh_doctor is for; running 'uname' as a side effect of connecting put an
      // extra command in the audit trail and an extra entry in the in-flight
      // counter for something the caller never asked for.
      return { text:
        'Connected: ' + endpointOf(m) +
        '\nHost key: ' + (entry.fingerprint || 'NOT VERIFIED (policy: ' + cfg.hostKeyPolicy + ')') +
        '\nPool: ' + stats.live + ' live' + (stats.limit > 0 ? ' / ' + stats.limit + ' max' : ' (no limit)') +
        (cfg.hostKeyPolicy === 'off' ? '\n\nWARNING: hostKeyPolicy is "off" — this connection is not protected against a man-in-the-middle.' : '') +
        credentialWarnings(alias, optionalText(args.password, 'password'))
          .map((warning) => '\n[note] ' + warning)
          .join('') +
        '\n(Tip: ssh_doctor verifies the command channel and authentication end to end.)' }
    },
  })

  // ── ssh_exec ──────────────────────────────────────────────────────────
  registerTool({
    name: 'ssh_exec',
    description:
      'Run a shell command on the remote machine; returns stdout, stderr and the exit code. ' +
      'Honours commandTimeoutMs and maxOutputChars. Requires confirm: true when execGuard is "confirm".',
    parameters: {
      machine: { type: 'string', description: 'Machine alias. Defaults to defaultMachine.' },
      command: { type: 'string', required: true, description: 'Command to run on the remote host.' },
      timeoutMs: { type: 'integer', description: 'Override the per-command timeout. 0 = configured value.' },
      confirm: { type: 'boolean', description: 'Required when execGuard is "confirm".' },
      password: { type: 'string', description: 'Only honoured when the profile sets allowSessionPassword: true.' },
    },
    output: textOut,
    // Every call owns its own SSH channel, so two calls never share one; the
    // pool keys state per alias and connects once per alias. Without this the
    // harness treats the tool as exclusive and runs nested calls one at a
    // time: a three-second command on one machine made an unrelated 200ms
    // command on the same or another machine wait for it.
    isConcurrencySafe: () => true,
    async execute(args, execution) {
      const alias = machineFor(args)
      const command = requireText(args.command, 'command')
      const budget = optionalBudget(args.timeoutMs, 'timeoutMs')
      guard(command, optionalFlag(args.confirm, 'confirm'), alias)
      const startedAt = Date.now()
      let r
      try {
        r = await pool.exec(alias, command, {
          signal: execution && execution.signal ? execution.signal : undefined,
          timeoutMs: budget,
          sessionPassword: optionalText(args.password, 'password'),
        })
      } catch (err) {
        audit.write({
          kind: 'exec',
          machine: alias,
          command: summarize(command),
          outcome: 'error',
          error: auditText(alias, err && err.message ? err.message : String(err)).slice(0, 200),
          ms: Date.now() - startedAt,
        })
        throw err
      }
      audit.write({
        kind: 'exec',
        machine: alias,
        command: summarize(command),
        outcome: r.cancelled ? 'cancel' : (r.timedOut ? 'timeout' : (r.dropped ? 'incomplete' : (r.code === 0 ? 'ok' : 'exit'))),
        exitCode: r.code,
        truncated: r.truncated,
        ms: Date.now() - startedAt,
      })
      // Render the two streams in the order the chunks arrived.
      //
      // Caveat, measured against a real host: ssh2 exposes stdout and stderr as
      // two independent Readables and does NOT preserve their relative order.
      // 'echo one; echo two >&2; echo three' arrives as ["one\nthree\n"] and
      // ["two\n"], so stderr can look like it came last. The timeline is
      // therefore an ordering hint, not a transcript; ordering inside each
      // stream is exact, ordering between them is whatever the library hands
      // over. A PTY would merge them, at the cost of turning the whole thing
      // into one stream with no exit-code boundary, so it is not used.
      const parts = []
      const timeline = Array.isArray(r.timeline) ? r.timeline : []
      if (timeline.length > 0) {
        let buffer = ''
        let bufferStream = null
        const flush = () => {
          if (!buffer) return
          parts.push(bufferStream === 'err' ? '[stderr]\n' + buffer.replace(/\s+$/, '') : buffer.replace(/\s+$/, ''))
          buffer = ''
        }
        for (const entry of timeline) {
          if (bufferStream !== null && entry.stream !== bufferStream) flush()
          bufferStream = entry.stream
          buffer += entry.text
        }
        flush()
      } else {
        if (r.stdout) parts.push(String(r.stdout).replace(/\s+$/, ''))
        if (r.stderr) parts.push('[stderr]\n' + String(r.stderr).replace(/\s+$/, ''))
      }
      if (r.truncated) {
        // "truncated" alone left the caller guessing whether one character or a
        // megabyte was lost, and what to do about it.
        const lost = Number(r.droppedChars) || 0
        parts.push('[output truncated at maxOutputChars' +
          (lost > 0 ? ': ' + lost + ' more character' + (lost === 1 ? '' : 's') + ' were dropped' : '') +
          ' — raise maxOutputChars, or send the output to a file and read it with ssh_read]')
      }
      if (r.timedOut) parts.push('[timed out after ' + (budget || cfg.commandTimeoutMs) + 'ms]')
      if (r.cancelled) {
        parts.push('[cancelled at the caller request — the remote command was sent SIGTERM; the output above is what arrived first]')
      }
      // 'exit unknown' alone is ambiguous; the commonest cause is a connection
      // that died mid-command, and the caller needs to know the output is only
      // what arrived before that.
      if (r.dropped) {
        parts.push('[connection closed before the command reported an exit status — the output above is partial]')
      }
      // A killed process has no exit code; naming the signal is the only
      // honest answer, and '[exit unknown]' reads like the harness lost it.
      // A cancelled command has no exit status at all: the note above already
      // says why, and '[exit unknown]' after it is noise.
      if (!r.cancelled) parts.push(exitLine(r))
      for (const warning of credentialWarnings(alias, optionalText(args.password, 'password'))) {
        parts.push('[note] ' + warning)
      }
      return { text: redact(parts.join('\n')) }  },
  })

  // ── ssh_read ──────────────────────────────────────────────────────────
  registerTool({
    name: 'ssh_read',
    description:
      'Read a file from the remote machine as UTF-8 text, capped at maxFileBytes. ' +
      'Prefer this over ssh_exec "cat": it streams and truncates cleanly. ' +
      'Requires confirm: true when execGuard is "confirm" (a read can copy a key off the host).',
    parameters: {
      machine: { type: 'string', description: 'Machine alias. Defaults to defaultMachine.' },
      path: { type: 'string', required: true, description: 'Absolute path on the remote host.' },
      maxBytes: { type: 'integer', description: '0 = use the configured cap.' },
      raw: { type: 'boolean', description: 'Return the file verbatim, skipping secret redaction. Use only when the redacted form hides what you need.' },
      timeoutMs: { type: 'integer', description: 'Override the per-transfer deadline. 0 = configured value.' },
      password: { type: 'string', description: 'Only honoured when the profile sets allowSessionPassword: true.' },
      confirm: { type: 'boolean', description: 'Required when execGuard is "confirm".' },
    },
    output: textOut,
    // Every call owns its own SSH channel, so two calls never share one; the
    // pool keys state per alias and connects once per alias. Without this the
    // harness treats the tool as exclusive and runs nested calls one at a
    // time: a three-second command on one machine made an unrelated 200ms
    // command on the same or another machine wait for it.
    isConcurrencySafe: () => true,
    async execute(args, execution) {
      const alias = machineFor(args)
      guardWrite(optionalFlag(args.confirm, 'confirm'), 'read from')
      const remotePath = requireText(args.path, 'path')
      const startedAt = Date.now()
      let r
      try {
        r = await pool.readFile(alias, remotePath, {
          // These two went through a bare Number() while the other tools used
          // the shared validators, so "abc" reached the pool as NaN and -5 as a
          // negative budget. Same shape as the password below.
          maxBytes: optionalBudget(args.maxBytes, 'maxBytes'),
          timeoutMs: optionalBudget(args.timeoutMs, 'timeoutMs'),
          signal: executionSignal(execution),
          sessionPassword: optionalText(args.password, 'password'),
        })
      } catch (err) {
        audit.write({
          kind: 'read', machine: alias, path: remotePath, outcome: 'error',
          error: auditText(alias, err && err.message ? err.message : String(err)).slice(0, 200),
          ms: Date.now() - startedAt,
        })
        throw err
      }
      audit.write({
        kind: 'read', machine: alias, path: r.path, outcome: 'ok',
        bytes: r.bytes, truncated: r.truncated, redacted: args.raw !== true,
        ms: Date.now() - startedAt,
      })
      // A file read is the most likely place for an .env or a config with a
      // password in it to reach the conversation transcript, so the default is
      // to redact. raw: true opts out for the cases where the masked value is
      // the thing being investigated.
      const body = args.raw === true ? r.content : redact(r.content)
      // The file is larger than the ceiling; say so and say what raises it.
      // maxBytes can only tighten the limit, so pointing at maxFileBytes is the
      // only advice that works.
      const header = r.truncated
        ? '[truncated: the first ' + plural(r.bytes, 'byte') + ' of a larger file — raise maxFileBytes in the plugin config to read more]\n'
        : ''
      // Only claim to have masked something when the text actually changed: a
      // README read through the default path used to end with a warning that
      // implied secrets had been found and hidden.
      const masked = args.raw !== true && body !== r.content
      const note = masked ? '\n[secrets masked; pass raw: true to see the file verbatim]' : ''
      return { text: header + body + note }
    },
  })

  // ── ssh_write ─────────────────────────────────────────────────────────
  registerTool({
    name: 'ssh_write',
    description:
      'Write UTF-8 text to a file on the remote machine (create or overwrite). ' +
      'Refuses to write more than maxFileBytes. The parent directory must exist unless ' +
      'createDirs: true is passed.',
    parameters: {
      machine: { type: 'string', description: 'Machine alias. Defaults to defaultMachine.' },
      path: { type: 'string', required: true, description: 'Absolute path on the remote host.' },
      content: { type: 'string', required: true, description: 'Full file content.' },
      createDirs: { type: 'boolean', description: 'Create missing parent directories first. Default false, so a mistyped path does not silently build a tree.' },
      mode: { type: 'string', description: 'Permission bits for a NEWLY created file, as octal digits: "600" for a key or .env, "644" for content other users must read. An existing file keeps its permissions. Default: the server umask.' },
      timeoutMs: { type: 'integer', description: 'Override the per-transfer deadline. 0 = configured value.' },
      password: { type: 'string', description: 'Only honoured when the profile sets allowSessionPassword: true.' },
      confirm: { type: 'boolean', description: 'Required when execGuard is "confirm".' },
    },
    output: textOut,
    // Every call owns its own SSH channel, so two calls never share one; the
    // pool keys state per alias and connects once per alias. Without this the
    // harness treats the tool as exclusive and runs nested calls one at a
    // time: a three-second command on one machine made an unrelated 200ms
    // command on the same or another machine wait for it.
    isConcurrencySafe: () => true,
    async execute(args, execution) {
      guardWrite(optionalFlag(args.confirm, 'confirm'))
      const alias = machineFor(args)
      const remotePath = requireText(args.path, 'path')
      // Content is required and must be a string: String(null) silently wrote
      // the four characters "null" into a file.
      if (typeof args.content !== 'string') {
        throw new Error('content must be a string (received ' + (args.content === null ? 'null' : typeof args.content) + ')')
      }
      const content = args.content
      const bytes = Buffer.byteLength(content)
      if (bytes > cfg.maxFileBytes) {
        throw new Error(
          'Refusing to write ' + plural(bytes, 'byte') + ' (maxFileBytes = ' + cfg.maxFileBytes + '). ' +
          'Raise maxFileBytes in the plugin config, or split the content across several writes — ' +
          'a partial write would leave a broken file behind.'
        )
      }
      const startedAt = Date.now()
      let r
      const createDirs = optionalFlag(args.createDirs, 'createDirs')
      const mode = parseMode(args.mode)
      try {
        r = await pool.writeFile(alias, remotePath, content, {
          timeoutMs: optionalBudget(args.timeoutMs, 'timeoutMs'),
          sessionPassword: optionalText(args.password, 'password'),
          createDirs,
          mode,
          signal: executionSignal(execution),
        })
      } catch (err) {
        const message = err && err.message ? err.message : String(err)
        // A missing parent directory is the commonest write failure, and the
        // server's own words ("No such file") do not say which half of the path
        // is absent or how to fix it.
        if (/no such file/i.test(message) || err?.code === 2) {
          err.message = message + (createDirs
            // createDirs was already asked for: it only creates directories that
            // are missing, and cannot replace a path component that is a file.
            ? ' — createDirs could not create the parent path; is part of it a file?'
            : ' — the parent directory does not exist. Pass createDirs: true to create it.')
        }
        audit.write({
          kind: 'write', machine: alias, path: remotePath, outcome: 'error',
          error: auditText(alias, err && err.message ? err.message : String(err)).slice(0, 200),
          ms: Date.now() - startedAt,
        })
        throw err
      }
      audit.write({
        kind: 'write', machine: alias, path: r.path, outcome: 'ok', bytes: r.bytes,
        // The link target is where the bytes actually went; an operator reading
        // the log after 'why did /etc change?' needs it. The mode says who can
        // read the file afterwards.
        ...(r.linkTarget ? { linkTarget: r.linkTarget } : {}),
        ...(typeof r.mode === 'number' ? { mode: r.mode.toString(8).padStart(4, '0') } : {}),
        ms: Date.now() - startedAt,
      })
      // A symlink means the bytes are somewhere the path did not name. Say where;
      // the audit line records the real target too.
      const viaLink = r.linkTarget
        ? '\n[note] that path is a symbolic link to ' + r.linkTarget +
          '; the content was written there, not to the link itself'
        : ''
      // The mode the file ended up with decides who can read what was just
      // written; the server applies its umask, so it is not always the one asked
      // for.
      const modeNote = typeof r.mode === 'number'
        ? ' (mode ' + r.mode.toString(8).padStart(4, '0') + ')'
        : ''
      return { text: 'Wrote ' + plural(r.bytes, 'byte') + ' to ' + r.path + modeNote + viaLink }
    },
  })

  // ── ssh_list ──────────────────────────────────────────────────────────
  registerTool({
    name: 'ssh_list',
    description: 'List a directory on the remote machine (name, size, type, mtime).',
    parameters: {
      machine: { type: 'string', description: 'Machine alias. Defaults to defaultMachine.' },
      path: { type: 'string', description: 'Absolute path on the remote host. Defaults to "."' },
      timeoutMs: { type: 'integer', description: 'Override the listing deadline. 0 = configured value.' },
      password: { type: 'string', description: 'Only honoured when the profile sets allowSessionPassword: true.' },
    },
    output: textOut,
    // Every call owns its own SSH channel, so two calls never share one; the
    // pool keys state per alias and connects once per alias. Without this the
    // harness treats the tool as exclusive and runs nested calls one at a
    // time: a three-second command on one machine made an unrelated 200ms
    // command on the same or another machine wait for it.
    isConcurrencySafe: () => true,
    async execute(args, execution) {
      const alias = machineFor(args)
      const rawPath = args.path === undefined || args.path === null || args.path === '' ? '.' : args.path
      if (typeof rawPath !== 'string') {
        throw new Error('path must be a string (received ' + typeof rawPath + ')')
      }
      const remotePath = rawPath.trim() || '.'
      const startedAt = Date.now()
      let listing
      try {
        listing = await pool.list(alias, remotePath, {
          timeoutMs: optionalBudget(args.timeoutMs, 'timeoutMs'),
          signal: executionSignal(execution),
          sessionPassword: optionalText(args.password, 'password'),
        })
      } catch (err) {
        audit.write({
          kind: 'list', machine: alias, path: remotePath, outcome: 'error',
          error: auditText(alias, err && err.message ? err.message : String(err)).slice(0, 200),
          ms: Date.now() - startedAt,
        })
        throw err
      }
      audit.write({
        kind: 'list', machine: alias, path: listing.path, outcome: 'ok',
        entries: listing.items.length, ms: Date.now() - startedAt,
      })
      return { text: formatListing(listing, cfg.maxListEntries) }
    },
  })

  // ── ssh_workspace ─────────────────────────────────────────────────────
  /**
   * A DSH workspace is a local directory, so a remote host becomes one by
   * creating a placeholder directory that stands for it and registering that
   * directory. The placeholder holds an AGENTS.md that tells the agent this
   * directory is a pointer to a remote machine and that every file or command
   * operation must go through the ssh_* tools -- which the harness already
   * loads as project instructions, so no prompt API is involved.
   */
  registerTool({
    name: 'ssh_workspace',
    description:
      'Create, list or remove a remote workspace: a sidebar workspace whose working directory is bound to ' +
      'one SSH machine. Starting a session inside it loads instructions that route every file and command ' +
      'operation through the ssh_* tools. Holds no credential; only a placeholder directory and AGENTS.md.',
    parameters: {
      action: { type: 'string', description: 'list (default) | create | remove' },
      machine: { type: 'string', description: 'Machine alias. Defaults to defaultMachine for create/remove.' },
      deleteFiles: { type: 'boolean', description: 'remove: also delete the placeholder directory. Files on the remote host are never touched.' },
    },
    output: textOut,
    // Every call owns its own SSH channel, so two calls never share one; the
    // pool keys state per alias and connects once per alias. Without this the
    // harness treats the tool as exclusive and runs nested calls one at a
    // time: a three-second command on one machine made an unrelated 200ms
    // command on the same or another machine wait for it.
    isConcurrencySafe: () => true,
    async execute(args) {
      const action = String(args.action === undefined || args.action === null ? 'list' : args.action).toLowerCase()
      // Reject an unknown action before anything else: it used to fall through
      // to the machine check and answer "action \"nope\" needs machine", which
      // sends the caller looking at the wrong argument.
      if (action !== 'list' && action !== 'create' && action !== 'remove') {
        throw new Error('action 只能是 list、create 或 remove（收到 ' + JSON.stringify(args.action) + '）。')
      }
      // The workspace registry is a host service, not a tool: a profile that
      // does not mount workspaces (headless) must still be able to create the
      // placeholder, so a missing registry is a reported limitation rather than
      // a failure.
      const registry = typeof ctx.get === 'function' ? ctx.get('workspaceRegistry') : undefined

      // Read the registry once, and never let its failure take the answer with
      // it: the aliases and their placeholder directories have nothing to do
      // with whether the workspace service is answering.
      const registryRead = listWorkspaces(registry)
      if (action === 'list') {
        const aliases = [...knownAliases({ machines: cfg.machines, dshHome: credentialHome })].sort()
        if (aliases.length === 0) return { text: '没有配置任何机器。先用设置界面或凭据文件添加一台，再创建远程工作区。' }
        // machineInventory hides the topology from the conversation; this
        // listing is conversation output like any other, and it used to print
        // user@host:port regardless.
        const lean = cfg.machineInventory === 'alias'
        const rows = aliases.map((alias) => {
          const m = machineDefinition(alias, { machines: cfg.machines, dshHome: credentialHome })
          const dir = remoteDir(dshHome, alias)
          const marker = readMarker(dshHome, alias)
          const workspace = findWorkspace({ list: () => registryRead.items }, dir)
          // "create will register it" is only true where a workspace service
          // exists. Without one (headless, tui) the old text sent the user to
          // run a command that cannot do what the line promised.
          const noService = !registry || typeof registry.list !== 'function'
          // 'not created' was also printed for a directory that exists but is not
          // a placeholder (marker deleted, or the user put something there). The
          // row then contradicted itself: "未创建" followed by the directory path.
          const dirExists = existsSync(dir)
          // The instructions are the point of the placeholder: a workspace whose
          // AGENTS.md was deleted still registers, but the session that opens
          // there learns nothing about the remote host.
          const missingInstructions = dirExists && !existsSync(dir + '\\AGENTS.md')
          const state = registryRead.error
            ? '无法读取工作区服务，无法判断是否已注册（' + registryRead.error + '）'
            : workspace
              ? '已注册为工作区「' + workspace.title + '」'
              : marker
                ? (missingInstructions
                  ? '有占位目录，但 AGENTS.md 已被删除（说明文件缺失，会话学不到远端规则）；用 action: "create" 重建'
                  : noService
                    ? '有占位目录（当前 profile 没有 workspace 服务，无法注册到侧栏）'
                    : '有占位目录，但未注册（用 action: "create" 注册）')
                : dirExists
                  ? '目录已存在，但不是占位目录（.dsh-remote-workspace.json 缺失或无法解析）；用 action: "create" 重建'
                  : (noService
                    ? '未创建（当前 profile 没有 workspace 服务，只能生成目录）'
                    : '未创建（用 action: "create" 创建）')
          const endpoint = lean
            ? '<host hidden>'
            : (m.username || '?') + '@' + (m.host || '?') + ':' + (m.port || 22)
          return '• ' + alias + '  ' + endpoint +
            '\n    ' + state +
            (existsSync(dir) ? '\n    ' + dir : '')
        })
        return { text:
          '远程工作区：\n' + rows.join('\n') +
          '\n\n根目录: ' + remoteRoot(dshHome) +
          (registry ? '' : '\n注意：当前 profile 没有 workspace 服务，只能创建目录，无法注册到侧栏。') }
      }

      const alias = normalizeAlias(args.machine || cfg.defaultMachine || '')
      if (!alias) throw new Error('action "' + action + '" 需要 machine: "<alias>"（或先设置 defaultMachine）。')

      const dir = remoteDir(dshHome, alias)

      if (action === 'create') {
        const m = machineDefinition(alias, { machines: cfg.machines, dshHome: credentialHome })
        if (!m.host || !m.username) {
          const need = expectedEnv(alias)
          throw new Error(
            '机器 "' + alias + '" 还没有主机或用户：至少需要 ' + need.required.join(', ') +
            '。先用设置界面或凭据文件补齐，再创建远程工作区。'
          )
        }
        let created
        try {
          ({ created } = writeRemoteWorkspace(dshHome, alias, m))
        } catch (err) {
          // A file sitting where the placeholder directory should be fails as a
          // bare 'EEXIST: file already exists, mkdir …', which does not say which
          // machine, which tool, or what to do about it.
          const code = err && /** @type {{code?: string}} */ (err).code
          const detail = code === 'EEXIST' || code === 'ENOTDIR'
            ? '那个位置已经有一个同名文件，占位目录建不出来'
            : '目录无法创建（' + (code || (err && err.message) || '未知原因') + '）'
          throw new Error(
            '无法创建机器 "' + alias + '" 的远程工作区：' + detail + '。\n' +
            '  目录：' + dir + '\n' +
            '先删除或改名那个文件，再重试。'
          )
        }
        let registered = ''
        if (registry && typeof registry.create === 'function') {
          try {
            const workspace = await registry.create(dir, remoteTitle(alias))
            registered = '已注册到侧栏工作区：「' + (workspace && workspace.title || remoteTitle(alias)) + '」'
          } catch (err) {
            registered = '目录已就绪，但注册失败：' + String(err && err.message ? err.message : err).slice(0, 200)
          }
        } else {
          registered = '当前 profile 没有 workspace 服务：目录已就绪，请在「工作区 → 打开文件夹」里手动选择它。'
        }
        return { text:
          (created ? '已创建远程工作区' : '已刷新远程工作区') + '\n' +
          '  别名   ' + alias + '\n' +
          '  目录   ' + dir + '\n' +
          '  绑定   ' + (cfg.machineInventory === 'alias'
            ? '<host hidden>'
            : m.username + '@' + m.host + ':' + (m.port || 22)) + '\n' +
          '  ' + registered + '\n\n' +
          '下一步：在侧栏的这个工作区里新开会话。该会话会自动读到 AGENTS.md，' +
          '所有文件与命令操作都会走 ssh_* 工具（machine: "' + alias + '"）。\n' +
          '（侧栏若没立刻刷新，按 F5 重载页面。）' }
      }

      if (action === 'remove') {
        // Removing a registration needs a trustworthy read: "no record" and
        // "cannot read the registry" must not look alike, or a stale workspace
        // stays in the sidebar while the tool reports it gone.
        if (registryRead.error) {
          throw new Error('读取工作区服务失败，未做任何改动：' + registryRead.error)
        }
        const workspace = findWorkspace({ list: () => registryRead.items }, dir)
        let removed = '没有注册记录'
        if (workspace && registry && typeof registry.delete === 'function') {
          const ok = await registry.delete(workspace.id)
          removed = ok ? '已从侧栏移除「' + workspace.title + '」' : '注册记录已不存在'
        }
        let files = '占位目录保留：' + dir
        if (args.deleteFiles === true) {
          removeRemoteDir(dshHome, alias)
          files = '占位目录已删除'
        }
        return { text: '远程工作区 ' + alias + '\n  ' + removed + '\n  ' + files +
          '\n  远端主机上的文件没有被动过。' }
      }

      // The three actions above return; anything else is a bug in this file.
      throw new Error('action 已校验却未处理：' + action)
    },
  })

  // ── ssh_audit ─────────────────────────────────────────────────────────
  registerTool({
    name: 'ssh_audit',
    description:
      'Show the most recent SSH operations this plugin performed: alias, operation, a one-line ' +
      'command summary, exit code and outcome. Never includes command output, file contents or ' +
      'credentials. Requires auditLog: true in the plugin config.',
    parameters: {
      limit: { type: 'integer', description: 'How many records to show (default 20, max 200).' },
    },
    output: textOut,
    // Every call owns its own SSH channel, so two calls never share one; the
    // pool keys state per alias and connects once per alias. Without this the
    // harness treats the tool as exclusive and runs nested calls one at a
    // time: a three-second command on one machine made an unrelated 200ms
    // command on the same or another machine wait for it.
    isConcurrencySafe: () => true,
    async execute(args) {
      const requested = args.limit === undefined || args.limit === null ? 20 : Number(args.limit)
      if (!Number.isFinite(requested)) {
        throw new Error('limit must be a number (received ' + JSON.stringify(args.limit) + ')')
      }
      const limit = Math.min(Math.max(Math.floor(requested), 1), 200)

      if (cfg.auditLog !== true) {
        return { text:
          'Audit logging is off. Set auditLog: true in the plugin config to record operations.\n' +
          'Records include the command summary, exit code and outcome — never output or secrets.' }
      }
      const records = audit.recent(limit)
      if (records.length === 0) return { text: 'No operations recorded yet.' }
      const rows = records.map((r) => {
        // The audit module already filters non-objects, but a renderer must not
        // be the place a bad file becomes a crash.
        if (!r || typeof r !== 'object' || r.malformed) {
          return '[unreadable record] ' + String(r && r.line ? r.line : '')
        }
        const when = String(r.at || '').replace('T', ' ').slice(0, 19)
        const machine = r.machine ? ' ' + r.machine : ''
        const parts = [when, machine.trim(), r.kind || '?', r.outcome || '']
        if (r.exitCode !== null && r.exitCode !== undefined) parts.push('exit=' + r.exitCode)
        // Show the subject: a command for exec, a path for transfers.
        const subject = r.command || r.path || r.pattern || ''
        if (subject) parts.push(subject)
        const head = parts.filter(Boolean).join(' ')

        // The detail fields are what make a record actionable; the earlier
        // renderer dropped every one of them.
        const detail = []
        if (r.bytes !== undefined) detail.push(r.bytes + 'B')
        // Where a write actually landed, and who can read it afterwards.
        if (r.mode) detail.push('mode ' + String(r.mode))
        if (r.linkTarget) detail.push('via link ' + String(r.linkTarget))
        if (r.entries !== undefined) detail.push(r.entries + (r.entries === 1 ? ' entry' : ' entries'))
        if (r.truncated) detail.push('truncated')
        if (r.redacted === true) detail.push('redacted')
        if (r.ms !== undefined) detail.push(r.ms + 'ms')
        if (r.reason) detail.push('reason=' + r.reason)
        if (r.error) detail.push('error: ' + r.error)
        return detail.length > 0 ? head + '\n    ' + detail.join('  ') : head
      })
      return { text: rows.join('\n') }
    },
  })

  // ── ssh_credentials ──────────────────────────────────────────────────
  registerTool({
    name: 'ssh_credentials',
    description:
      'Show where each machine`s credentials come from: the settings form, the credential ' +
      'file, or the environment. Reports the source, never the value. Use this after a ' +
      'password rotation to confirm the plugin is reading the new one.',
    parameters: {},
    output: textOut,
    // Every call owns its own SSH channel, so two calls never share one; the
    // pool keys state per alias and connects once per alias. Without this the
    // harness treats the tool as exclusive and runs nested calls one at a
    // time: a three-second command on one machine made an unrelated 200ms
    // command on the same or another machine wait for it.
    isConcurrencySafe: () => true,
    async execute() {
      const aliases = knownAliases({ machines: cfg.machines, dshHome: credentialHome })
      if (cfg.defaultMachine && !aliases.includes(normalizeAlias(cfg.defaultMachine))) {
        aliases.push(normalizeAlias(cfg.defaultMachine))
      }
      const file = credentialsPath(dshHome)
      const head = [
        'Credential sources (values are never shown):',
        '  settings form   machines.<alias> in the plugin config',
        '  credential file ' + file + (cfg.useCredentialFile === true ? '' : '  [DISABLED]'),
        '  environment     DSH_SSH_<ALIAS>_*',
        // Matches credentialFor(): any usable password outranks a key, and a key
        // outranks the agent. Listing only three of the six sources sent users
        // looking in the wrong place, and hid the fact that a password beats a key.
        '  precedence      settings password > encrypted file > plaintext file > environment',
        '                  > key file > session password > SSH agent',
        '                  (a usable password always outranks a key)',
        '  encryption      ' + (cfg.allowPlaintextPassword === true
          ? 'plaintext ACCEPTED (allowPlaintextPassword is on)'
          : 'plaintext refused; passwords stored DPAPI encrypted'),
      ]
      if (cfg.useCredentialFile !== true) {
        head.push('  note            the credential file is disabled, so its entries are not used')
      } else {
        // A file that exists but cannot be understood reads exactly like "no
        // machine has a password"; name it here, where the sources are listed.
        const fileState = readCredentialFile(dshHome)
        if (fileState.problem) head.push('  WARNING         ' + fileState.problem)
      }
      if (aliases.length === 0) {
        head.push('', 'No machines defined yet.')
        return { text: head.join('\n') }
      }
      for (const alias of aliases) {
        const st = credentialState(alias, {
          machines: cfg.machines,
          dshHome: cfg.useCredentialFile === true ? dshHome : '',
        })
        const where = (source) => source === 'none' ? '—' : source
        // machineInventory hides the topology from the conversation. This tool
        // is part of that conversation too, and it used to print user@host:port
        // even with the setting on.
        const lean = cfg.machineInventory === 'alias'
        head.push(
          '',
          '• ' + alias + '  ' + (lean
            ? (st.configured ? '<host hidden>' : 'INCOMPLETE (needs host and user)')
            : (st.configured
              ? (st.username || '?') + '@' + (st.host || '?') + ':' + st.port
              : 'INCOMPLETE (needs host and user)')),
          '    password   ' + where(st.passwordSource),
          '    key        ' + where(st.keyPathSource) +
            (st.keyPath ? '  ' + String(st.keyPath).replace(/^.*[\\/]/, '…/') : ''),
          '    host key   ' + st.hostKeyPolicy +
          (st.passwordSource === 'file-plaintext'
            ? '\n    WARNING    plaintext password in the credential file is ignored;' +
              ' re-run scripts/set-password.mjs to store it encrypted'
            : '') +
          (st.passwordSource === 'config' && cfg.allowPlaintextPassword !== true
            ? '\n    WARNING    the settings-form password is plaintext and is ignored;' +
              ' use the credential file or an environment variable'
            : '')
        )
      }
      return { text: head.join('\n') }
    },
  })

  // ── ssh_config ────────────────────────────────────────────────────────
  registerTool({
    name: 'ssh_config',
    description:
      'Show the plugin configuration actually in effect, plus live pool state. Useful when a ' +
      'setting is not behaving as expected: this reports what the running instance uses, not ' +
      'what a file says. Secrets are never included.',
    parameters: {},
    output: textOut,
    // Every call owns its own SSH channel, so two calls never share one; the
    // pool keys state per alias and connects once per alias. Without this the
    // harness treats the tool as exclusive and runs nested calls one at a
    // time: a three-second command on one machine made an unrelated 200ms
    // command on the same or another machine wait for it.
    isConcurrencySafe: () => true,
    async execute() {
      const stats = pool.connectionStats()
      const rows = [
        ['hostKeyPolicy', cfg.hostKeyPolicy, 'strict | tofu | off'],
        ['execGuard', cfg.execGuard, 'allow | confirm'],
        ['allowSessionPassword', cfg.allowSessionPassword, 'password through a tool argument'],
        ['machineInventory', cfg.machineInventory, 'full | alias'],
        ['auditLog', cfg.auditLog, 'NDJSON record of operations'],
        ['defaultMachine', cfg.defaultMachine || '(none)', ''],
        ['machines', Object.keys(cfg.machines || {}).length + ' defined', 'editable in the settings form'],
        ['useCredentialFile', cfg.useCredentialFile, 'read per connection, no restart needed'],
        ['allowPlaintextPassword', cfg.allowPlaintextPassword, 'off: store DPAPI-encrypted or in memory only'],
        ['commandTimeoutMs', cfg.commandTimeoutMs, 'per ssh_exec command'],
        ['sftpTimeoutMs', cfg.sftpTimeoutMs, 'per transfer'],
        ['connectTimeoutMs', cfg.connectTimeoutMs, ''],
        ['closeTimeoutMs', cfg.closeTimeoutMs, 'wait for the peer to confirm a close'],
        ['keepaliveIntervalMs', cfg.keepaliveIntervalMs, '0 disables'],
        ['maxOutputChars', cfg.maxOutputChars, 'stdout + stderr together'],
        ['maxFileBytes', cfg.maxFileBytes, 'hard ceiling per transfer'],
        ['maxListEntries', cfg.maxListEntries, 'rows per ssh_list; 0 = unlimited'],
        ['maxConnections', cfg.maxConnections, '0 = unlimited'],
        ['reconnectCooldownMs', cfg.reconnectCooldownMs, 'after a failure'],
        ['healthCheckIdleMs', cfg.healthCheckIdleMs, '0 disables the probe'],
        ['healthCheckTimeoutMs', cfg.healthCheckTimeoutMs, 'liveness probe deadline'],
        ['pipeToShell', cfg.pipeToShell, 'refuse | allow a pipe into an interpreter'],
        ['denyPatterns', (cfg.denyPatterns || []).length + ' pattern(s)', 'safety rail, not a boundary'],
      ]
      const lines = ['Configuration in effect:']
      for (const [key, value, note] of rows) {
        lines.push('  ' + String(key).padEnd(24) + JSON.stringify(value) + (note ? '   # ' + note : ''))
      }
      // A setting added to Config but not to this list would be invisible to the
      // operator, which is how pipeToShell and healthCheckTimeoutMs went missing.
      const shown = new Set(rows.map((r) => r[0]))
      const missing = Object.keys(cfg).filter((k) => !shown.has(k))
      if (missing.length > 0) {
        lines.push('', 'Settings not shown above (report this): ' + missing.join(', '))
      }

      if (cfg.useCredentialFile === true) {
        lines.push('', 'Credential file: ' + credentialsPath(dshHome) + '  (mode 0600)')
      }
      const defined = Object.keys(cfg.machines || {})
      if (defined.length > 0) lines.push('Machines in the settings form: ' + defined.join(', '))

      lines.push('', 'Live connections: ' + stats.live +
        (stats.limit > 0 ? ' / ' + stats.limit + ' max' : ' (no limit)') +
        (stats.overLimit ? '  (over the limit: the extra ones are running a command)' : '') +
        (stats.aliases.length ? '  [' + stats.aliases.join(', ') + ']' : ''))
      if (cfg.auditLog === true) {
        lines.push('Audit log: ' + dshHome + (process.platform === 'win32' ? '\\' : '/') + 'dsh-ssh-safe' +
          (process.platform === 'win32' ? '\\' : '/') + 'audit.ndjson')
      }
      return { text: lines.join('\n') }
    },
  })

  // ── ssh_doctor ────────────────────────────────────────────────────────
  registerTool({
    name: 'ssh_doctor',
    description:
      'Diagnose one machine stage by stage: configuration, TCP reachability, host key, then ' +
      'authentication. Each stage reports pass, fail or skip, so a bare ' +
      '"All configured authentication methods failed" becomes actionable. Never prints a ' +
      'password, passphrase or key body.',
    parameters: {
      machine: { type: 'string', description: 'Machine alias. Defaults to defaultMachine.' },
    },
    output: textOut,
    // Every call owns its own SSH channel, so two calls never share one; the
    // pool keys state per alias and connects once per alias. Without this the
    // harness treats the tool as exclusive and runs nested calls one at a
    // time: a three-second command on one machine made an unrelated 200ms
    // command on the same or another machine wait for it.
    isConcurrencySafe: () => true,
    async execute(args) {
      const alias = machineFor(args)
      const m = machineDefinition(alias, { machines: cfg.machines, dshHome: credentialHome })
      const need = expectedEnv(alias)
      const lines = []
      const say = (stage, verdict, detail) => lines.push('[' + verdict + '] ' + stage + (detail ? ': ' + detail : ''))

      // 1. configuration
      const missing = []
      if (!m.host) missing.push(need.required[0])
      if (!m.username) missing.push(need.required[1])
      const auth = credentialFor(alias, {
        machines: cfg.machines,
        dshHome: credentialHome,
        allowSessionPassword: cfg.allowSessionPassword,
        allowPlaintextPassword: cfg.allowPlaintextPassword === true,
      })
      if (missing.length) say('configuration', 'FAIL', 'missing ' + missing.join(', '))
      else if (m.portProblem) say('configuration', 'FAIL', m.portProblem)
      else say('configuration', 'ok', endpointOf(m))
      // A misspelled field in the settings form is silently dropped by the
      // schema -- 'keypath' instead of 'keyPath' turned a key machine into
      // "no credentials" -- so name it here rather than at connect time.
      for (const problem of machineFieldProblems(alias)) {
        say('configuration', 'warn', problem)
      }
      // Cheque the credential's usability, not just its declared kind: an
      // env-key pointing at a missing file reported ok and then failed the
      // connection, which is the opposite of what a diagnostic should do.
      let credentialProblem = ''
      // Any key-based kind: config, credential file or environment, not just the
      // environment: the other sources deserve the same scrutiny.
      if (String(auth.kind).endsWith('-key')) {
        const keyPath = expandHome(auth.keyPath)
        if (!existsSync(keyPath)) {
          credentialProblem = 'key file not found: ' + keyPath
        } else {
          try {
            const body = readFileSync(keyPath)
            if (body.length === 0) credentialProblem = 'key file is empty: ' + keyPath
            else if (!/PRIVATE KEY-----/.test(String(body.subarray(0, 200)))) {
              credentialProblem = 'key file does not look like a private key: ' + keyPath
            }
          } catch (err) {
            const code = err && /** @type {{code?: string}} */ (err).code
            credentialProblem = 'key file unreadable (' + (code || 'error') + '): ' + keyPath
          }
        }
      } else if (auth.kind === 'agent') {
        if (!existsSync(auth.agent)) credentialProblem = 'agent socket not found: ' + auth.agent
      }

      if (auth.kind === 'none') {
        say('credentials', 'FAIL', 'no password, key or agent available — set ' + need.auth[0])
      } else if (credentialProblem) {
        say('credentials', 'FAIL', credentialProblem)
      } else {
        say('credentials', 'ok', auth.kind)
      }

      // Refused or unreadable sources are reported rather than silently skipped:
      // "it did not use my password" is otherwise very hard to diagnose.
      for (const warning of auth.warnings || []) {
        say('credentials', 'warn', warning)
      }

      // A broken credential cannot be fixed by waiting, so diagnose no further.
      if (missing.length || auth.kind === 'none' || credentialProblem) {
        lines.push('', 'Stopped: fix the above before testing the network.')
        return { text: lines.join('\n') }
      }

      // 2. TCP reachability
      // machineInventory: 'alias' hides host AND port (that is what
      // ssh_machines promises), so the probe's detail line must not name it.
      const lean = cfg.machineInventory === 'alias'
      const port = m.port || 22
      const portText = lean ? 'the configured port' : 'port ' + port
      const tcp = await new Promise((resolve) => {
        const socket = net.connect({ host: m.host, port })
        const done = (ok, detail) => { try { socket.destroy() } catch {} ; resolve({ ok, detail }) }
        socket.setTimeout(pick(cfg.connectTimeoutMs, 15000))
        socket.once('connect', () => done(true, portText + ' accepts connections'))
        socket.once('timeout', () => done(false, 'no answer on ' + portText + ' within the timeout'))
        socket.once('error', (err) => {
          const code = err && /** @type {{code?: string}} */ (err).code
          done(false, code || 'connect failed')
        })
      })
      say('tcp', tcp.ok ? 'ok' : 'FAIL', tcp.detail)
      if (!tcp.ok) {
        lines.push('', 'Stopped: the host is unreachable, so authentication cannot be tested.')
        return { text: lines.join('\n') }
      }

      // 3. host key + 4. authentication, via a real connect attempt.
      //
      // Diagnosis must not change what it diagnoses. If this run has to open a
      // connection, it closes it again afterwards and restores the failure state,
      // so calling ssh_doctor never leaves a socket behind or clears a cooldown.
      const wasConnected = Boolean(pool.entries.get(alias)?.client)
      // Doctor authenticates and runs a command, so it has to leave the same trail
      // as any other use of the account; it used to log in silently.
      const doctorStartedAt = Date.now()
      const doctorRecord = (outcome, detail) => audit.write({
        kind: 'doctor', machine: alias, outcome,
        ...(detail ? { reason: auditText(alias, detail).slice(0, 120) } : {}),
        ms: Date.now() - doctorStartedAt,
      })
      try {
        await pool.connect(alias, { force: true })
        const e = pool.entry(alias)
        say('host key', 'ok', e.fingerprint || 'verified')
        const probe = await pool.exec(alias, 'echo doctor-ok', { timeoutMs: 8000 })
        const replied = String(probe.stdout || '').includes('doctor-ok')
        doctorRecord(replied ? 'ok' : 'error', replied ? '' : 'the session opened but produced no stdout')
        say('authentication', replied ? 'ok' : 'FAIL', replied ? 'command channel works' : 'connected but no output')
        if (!replied) say('shell', 'warn', 'the session opened but produced no stdout; the remote shell may be restricted')
      } catch (err) {
        const message = redact(err && err.message ? err.message : String(err))
        // Authentication was attempted (or at least the connection was), so the
        // attempt belongs in the log whether or not it worked.
        doctorRecord('error', message)
        if (/host key|fingerprint|HOST KEY CHANGED|Unknown host/i.test(message)) {
          say('host key', 'FAIL', message)
          say('authentication', 'skip', 'host key was rejected first')
        } else if (/authentication|permission denied|publickey|password/i.test(message)) {
          say('host key', 'ok', 'accepted')
          say('authentication', 'FAIL', message)
          lines.push('', 'The server refused the credential. Check that the public key is in',
            '  ~/.ssh/authorized_keys on the remote host, that the account is allowed to log in,',
            '  and that the key is not passphrase-protected without a passphrase supplied.')
        } else {
          say('connect', 'FAIL', message)
        }
      } finally {
        // Restore the pre-diagnosis state -- but do not force it.
        //
        // Without force, closeOne refuses while an operation is in flight. A
        // command that started while this diagnosis was running now owns that
        // connection; force-closing here severed it, and the caller saw a
        // dropped command with no idea that ssh_doctor was the cause.
        if (!wasConnected) {
          await pool.closeOne(alias)
        }
      }

      return { text: lines.join('\n') }
    },
  })

  // ── ssh_close ─────────────────────────────────────────────────────────
  registerTool({
    name: 'ssh_close',
    description:
      'Close pooled SSH connections. The next call reconnects. A connection with a command still ' +
      'running is left open and reported as busy unless force: true is passed, because severing ' +
      'a running command can corrupt whatever it was doing.',
    parameters: {
      machine: { type: 'string', description: 'Alias to close; empty closes all.' },
      force: { type: 'boolean', description: 'Close even if a command is still running on that connection.' },
    },
    output: textOut,
    // Every call owns its own SSH channel, so two calls never share one; the
    // pool keys state per alias and connects once per alias. Without this the
    // harness treats the tool as exclusive and runs nested calls one at a
    // time: a three-second command on one machine made an unrelated 200ms
    // command on the same or another machine wait for it.
    isConcurrencySafe: () => true,
    async execute(args) {
      const alias = normalizeAlias(args.machine || '')
      const force = optionalFlag(args.force, 'force')
      if (alias) {
        const result = await pool.closeOne(alias, { force })
        if (result.pending) {
          return { text: force
            ? 'A connection to ' + alias + ' is still being established; it will be closed as soon as it completes.'
            : 'A connection to ' + alias + ' is still being established. Pass force: true to have it closed on arrival.' }
        }
        if (result.busy) {
          return { text:
            'Not closing ' + alias + ': a command is still running on it. ' +
            'Wait for it to finish, or pass force: true to cut it off.' }
        }
        if (!result.closed) return { text: 'No live connection for ' + alias }
        return { text: result.confirmed
          ? 'Closed: ' + alias
          : 'Requested close for ' + alias + ' but the peer did not confirm; the entry was reset so the next call reconnects.' }
      }
      const result = await pool.closeAll({ force })
      const parts = []
      if (result.closed.length) parts.push('Closed: ' + result.closed.join(', '))
      if (result.busy.length) {
        parts.push('Left open (command running): ' + result.busy.join(', ') +
          ' — pass force: true to cut them off')
      }
      if (parts.length === 0) parts.push('No live connections')
      return { text: parts.join('\n') }
    },
  })

  // Release sockets when the plugin unloads.
  if (typeof ctx.effect === 'function') {
    // On unload there is no later call to retry, so shutdown must not defer to
    // busy connections: force is correct here, unlike the interactive default.
    ctx.effect(() => () => { pool.closeAll({ force: true }).catch(() => {}) }, 'dsh-ssh-safe.close')
  }
}
