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
import { SshPool, expandHome, pick } from './pool.js'
import { expectedEnv, redact } from './credentials.js'
import {
  credentialFor,
  credentialState,
  credentialsPath,
  credentialsTemplate,
  knownAliases,
  machineDefinition,
} from './machines.js'
import { storePath } from './hostkey.js'
import { checkCommand } from './guard.js'
import { exitLine, formatListing, plural } from './format.js'
import { AuditLog, summarize } from './audit.js'
import {
  findWorkspace,
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

  denyPatterns: z.array(z.string()).default([
    // '/' alone, or '/' followed by a glob: 'rm -rf /' and 'rm -rf /*' both
    // destroy the filesystem, so the target must be '/' and not the start of
    // a longer path.
    '(?:^|[\\s;&|()])rm\\s+-[rf]{1,2}\\s+/+(?:\\*|\\.{1,2})?(?:\\s|$|[)])',
    // The home directory is the other root-shaped target: 'rm -rf ~' is the
    // same accident at a different path.
    '(?:^|[\\s;&|()])rm\\s+-[rf]{1,2}\\s+(?:~|\\$(?:\\{HOME\\}|HOME))/?(?:\\s|$|[)])',
    // 'cd / && rm -rf *' deletes the root one level at a time. The rule above
    // cannot see it: the slash belongs to the cd, not to the rm. Only the
    // root-targeting form is refused, so 'cd /tmp && rm -rf *' still works.
    '\\bcd\\s+(?:/+|~|\\$(?:\\{HOME\\}|HOME))\\s*(?:&&|;|\\|\\|)\\s*(?:(?:sudo|doas|env|nohup)\\s+)?(?:-{1,2}\\S+(?:\\s+\\S+)?\\s+)*(?:[\\w./-]*/)?rm\\s+-[a-z]*r[a-z]*\\s+(?:\\./)?\\*',
    // Only a device is a disk. 'mkfs.ext4 ./disk.img' builds a filesystem in a
    // file, which is ordinary work for loopback mounts and swap images.
    '\\bmkfs(?:\\.\\w+)?\\b[^\n]*\\s/dev/',
    '\\bdd\\s+if=.*\\bof=/dev/[sn]',
    // 'find / -delete' walks the whole tree and deletes every file; the same
    // run through -exec rm is the spelled-out version.
    '\\bfind\\s+/+(?:\\s|$)[^\\n]*-delete\\b',
    '\\bfind\\s+/+(?:\\s|$)[^\\n]*-exec\\s+(?:[\\w./-]*/)?rm\\b',
    ':\\(\\)\\s*\\{\\s*:\\|:\\s*&\\s*\\};:',
    // Only at a command position. The bare word anywhere refused ordinary work:
    // 'grep -c shutdown /etc/hostname' and 'echo reboot' were both blocked.
    '(?:^|[;&|]+\\s*|\\(\\s*)(?:(?:sudo|doas|nohup|nice|setsid|command|exec|env|time)\\s+(?:-{1,2}\\S+(?:\\s+\\S+)?\\s+)*)*(?:timeout\\s+\\S+\\s+)?(?:systemctl\\s+(?:-\\S+\\s+)*)?(?:shutdown|reboot|halt|poweroff)\\b',
  ]),
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
  const pool = new SshPool(cfg, { dshHome })
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
  const registerTool = typeof ctx.tools.register === 'function'
    ? (definition) => ctx.tools.register(defineTool(definition))
    : typeof ctx.tools.defineTool === 'function'
      ? (definition) => ctx.tools.defineTool(definition)
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

  const guard = (command, confirmed) => {
    if (cfg.execGuard === 'confirm' && confirmed !== true) {
      throw new Error('execGuard is "confirm": pass confirm: true to run this command.')
    }
    const verdict = cfg.pipeToShell === 'allow'
      ? checkCommand(command, cfg.denyPatterns, { allowPipeline: true })
      : checkCommand(command, cfg.denyPatterns)
    if (verdict.blocked) {
      audit.write({
        kind: 'refused',
        command: summarize(command),
        pattern: verdict.pattern,
        reason: verdict.reason,
      })
      const where = verdict.reason === 'matches deny pattern' ? '' : ' (' + verdict.reason + ')'
      // Point at the setting that actually governs this refusal.
      const remedy = String(verdict.reason || '').startsWith('pipes into ')
        ? 'Set pipeToShell: allow in the plugin config to permit pipelines into interpreters.'
        : 'Adjust denyPatterns in the plugin config if this is intentional.'
      throw new Error('Command refused' + where + ': ' + verdict.pattern + '. ' + remedy)
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
  const guardWrite = (confirmed) => {
    if (cfg.execGuard === 'confirm' && confirmed !== true) {
      throw new Error(
        'execGuard is "confirm": pass confirm: true to write to the remote host. ' +
        'Writes can install scripts or change access, so they are gated as well.'
      )
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
        dshHome,
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
      for (const alias of knownAliases({ machines: cfg.machines, dshHome })) aliases.add(alias)
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
        const m = machineDefinition(alias, { machines: cfg.machines, dshHome })
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
        const endpoint = lean
          ? '<host hidden>'
          : (m.username || '<no user>') + '@' + (m.host || '<no host>') + ':' + m.port
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
          (m.host && m.username ? '' : '\n    MISSING: ' + need.required.join(', '))
        )
      }
      if (lean) {
        out.push('', '(machineInventory is "alias": host, port and key paths are hidden. Set machineInventory: full to show them.)')
      }
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
          error: redact(err && err.message ? err.message : String(err)).slice(0, 200),
          ms: Date.now() - startedAt,
        })
        throw err
      }
      audit.write({ kind: 'connect', machine: alias, outcome: 'ok', ms: Date.now() - startedAt })

      const m = machineDefinition(alias, { machines: cfg.machines, dshHome })
      const entry = pool.entry(alias)
      const stats = pool.connectionStats()
      // Deliberately no remote command here. Verifying the channel is what
      // ssh_doctor is for; running 'uname' as a side effect of connecting put an
      // extra command in the audit trail and an extra entry in the in-flight
      // counter for something the caller never asked for.
      return { text:
        'Connected: ' + (m.username || '?') + '@' + (m.host || '?') + ':' + (m.port || 22) +
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
    async execute(args) {
      const alias = machineFor(args)
      const command = requireText(args.command, 'command')
      const budget = optionalBudget(args.timeoutMs, 'timeoutMs')
      guard(command, optionalFlag(args.confirm, 'confirm'))
      const startedAt = Date.now()
      let r
      try {
        r = await pool.exec(alias, command, {
          timeoutMs: budget,
          sessionPassword: optionalText(args.password, 'password'),
        })
      } catch (err) {
        audit.write({
          kind: 'exec',
          machine: alias,
          command: summarize(command),
          outcome: 'error',
          error: redact(err && err.message ? err.message : String(err)).slice(0, 200),
          ms: Date.now() - startedAt,
        })
        throw err
      }
      audit.write({
        kind: 'exec',
        machine: alias,
        command: summarize(command),
        outcome: r.timedOut ? 'timeout' : (r.dropped ? 'incomplete' : (r.code === 0 ? 'ok' : 'exit')),
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
      if (r.truncated) parts.push('[output truncated at maxOutputChars]')
      if (r.timedOut) parts.push('[timed out after ' + (budget || cfg.commandTimeoutMs) + 'ms]')
      // 'exit unknown' alone is ambiguous; the commonest cause is a connection
      // that died mid-command, and the caller needs to know the output is only
      // what arrived before that.
      if (r.dropped) {
        parts.push('[connection closed before the command reported an exit status — the output above is partial]')
      }
      // A killed process has no exit code; naming the signal is the only
      // honest answer, and '[exit unknown]' reads like the harness lost it.
      parts.push(exitLine(r))
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
      'Prefer this over ssh_exec "cat": it streams and truncates cleanly.',
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
    async execute(args) {
      const alias = machineFor(args)
      guardWrite(optionalFlag(args.confirm, 'confirm'))
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
          sessionPassword: optionalText(args.password, 'password'),
        })
      } catch (err) {
        audit.write({
          kind: 'read', machine: alias, path: remotePath, outcome: 'error',
          error: redact(err && err.message ? err.message : String(err)).slice(0, 200),
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
      const header = r.truncated ? '[truncated at ' + plural(r.bytes, 'byte') + ']\n' : ''
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
    async execute(args) {
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
        throw new Error('Refusing to write ' + plural(bytes, 'byte') + ' (maxFileBytes = ' + cfg.maxFileBytes + ').')
      }
      const startedAt = Date.now()
      let r
      const createDirs = optionalFlag(args.createDirs, 'createDirs')
      try {
        r = await pool.writeFile(alias, remotePath, content, {
          timeoutMs: optionalBudget(args.timeoutMs, 'timeoutMs'),
          sessionPassword: optionalText(args.password, 'password'),
          createDirs,
        })
      } catch (err) {
        const message = err && err.message ? err.message : String(err)
        // A missing parent directory is the commonest write failure, and the
        // server's own words ("No such file") do not say which half of the path
        // is absent or how to fix it.
        if (!createDirs && (/no such file/i.test(message) || err?.code === 2)) {
          err.message = message + ' — the parent directory does not exist. Pass createDirs: true to create it.'
        }
        audit.write({
          kind: 'write', machine: alias, path: remotePath, outcome: 'error',
          error: redact(err && err.message ? err.message : String(err)).slice(0, 200),
          ms: Date.now() - startedAt,
        })
        throw err
      }
      audit.write({
        kind: 'write', machine: alias, path: r.path, outcome: 'ok', bytes: r.bytes,
        ms: Date.now() - startedAt,
      })
      return { text: 'Wrote ' + plural(r.bytes, 'byte') + ' to ' + r.path }
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
    async execute(args) {
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
          sessionPassword: optionalText(args.password, 'password'),
        })
      } catch (err) {
        audit.write({
          kind: 'list', machine: alias, path: remotePath, outcome: 'error',
          error: redact(err && err.message ? err.message : String(err)).slice(0, 200),
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
      // The workspace registry is a host service, not a tool: a profile that
      // does not mount workspaces (headless) must still be able to create the
      // placeholder, so a missing registry is a reported limitation rather than
      // a failure.
      const registry = typeof ctx.get === 'function' ? ctx.get('workspaceRegistry') : undefined

      if (action === 'list') {
        const aliases = [...knownAliases({ machines: cfg.machines, dshHome })].sort()
        if (aliases.length === 0) return { text: '没有配置任何机器。先用设置界面或凭据文件添加一台，再创建远程工作区。' }
        const rows = aliases.map((alias) => {
          const m = machineDefinition(alias, { machines: cfg.machines, dshHome })
          const dir = remoteDir(dshHome, alias)
          const marker = readMarker(dshHome, alias)
          const workspace = findWorkspace(registry, dir)
          const state = workspace
            ? '已注册为工作区「' + workspace.title + '」'
            : marker
              ? '有占位目录，但未注册（用 action: "create" 注册）'
              : '未创建（用 action: "create" 创建）'
          return '• ' + alias + '  ' + (m.username || '?') + '@' + (m.host || '?') + ':' + (m.port || 22) +
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
        const m = machineDefinition(alias, { machines: cfg.machines, dshHome })
        if (!m.host || !m.username) {
          const need = expectedEnv(alias)
          throw new Error(
            '机器 "' + alias + '" 还没有主机或用户：至少需要 ' + need.required.join(', ') +
            '。先用设置界面或凭据文件补齐，再创建远程工作区。'
          )
        }
        const { created } = writeRemoteWorkspace(dshHome, alias, m)
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
          '  绑定   ' + m.username + '@' + m.host + ':' + (m.port || 22) + '\n' +
          '  ' + registered + '\n\n' +
          '下一步：在侧栏的这个工作区里新开会话。该会话会自动读到 AGENTS.md，' +
          '所有文件与命令操作都会走 ssh_* 工具（machine: "' + alias + '"）。\n' +
          '（侧栏若没立刻刷新，按 F5 重载页面。）' }
      }

      if (action === 'remove') {
        const workspace = findWorkspace(registry, dir)
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

      throw new Error('action 只能是 list、create 或 remove（收到 ' + JSON.stringify(args.action) + '）。')
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
        if (r.malformed) return '[unreadable record] ' + r.line
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
      const aliases = knownAliases({ machines: cfg.machines, dshHome })
      if (cfg.defaultMachine && !aliases.includes(normalizeAlias(cfg.defaultMachine))) {
        aliases.push(normalizeAlias(cfg.defaultMachine))
      }
      const file = credentialsPath(dshHome)
      const head = [
        'Credential sources (values are never shown):',
        '  settings form   machines.<alias> in the plugin config',
        '  credential file ' + file + (cfg.useCredentialFile === true ? '' : '  [DISABLED]'),
        '  environment     DSH_SSH_<ALIAS>_*',
        '  precedence      encrypted file > environment > SSH agent',
        '  encryption      ' + (cfg.allowPlaintextPassword === true
          ? 'plaintext ACCEPTED (allowPlaintextPassword is on)'
          : 'plaintext refused; passwords stored DPAPI encrypted'),
      ]
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
        head.push(
          '',
          '• ' + alias + '  ' + (st.configured
            ? (st.username || '?') + '@' + (st.host || '?') + ':' + st.port
            : 'INCOMPLETE (needs host and user)'),
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
      const m = machineDefinition(alias, { machines: cfg.machines, dshHome })
      const need = expectedEnv(alias)
      const lines = []
      const say = (stage, verdict, detail) => lines.push('[' + verdict + '] ' + stage + (detail ? ': ' + detail : ''))

      // 1. configuration
      const missing = []
      if (!m.host) missing.push(need.required[0])
      if (!m.username) missing.push(need.required[1])
      const auth = credentialFor(alias, {
        machines: cfg.machines,
        dshHome,
        allowSessionPassword: cfg.allowSessionPassword,
        allowPlaintextPassword: cfg.allowPlaintextPassword === true,
      })
      if (missing.length) say('configuration', 'FAIL', 'missing ' + missing.join(', '))
      else say('configuration', 'ok', m.username + '@' + m.host + ':' + m.port)
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
      const port = m.port || 22
      const tcp = await new Promise((resolve) => {
        const socket = net.connect({ host: m.host, port })
        const done = (ok, detail) => { try { socket.destroy() } catch {} ; resolve({ ok, detail }) }
        socket.setTimeout(pick(cfg.connectTimeoutMs, 15000))
        socket.once('connect', () => done(true, 'port ' + port + ' accepts connections'))
        socket.once('timeout', () => done(false, 'no answer on port ' + port + ' within the timeout'))
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
      try {
        await pool.connect(alias, { force: true })
        const e = pool.entry(alias)
        say('host key', 'ok', e.fingerprint || 'verified')
        const probe = await pool.exec(alias, 'echo doctor-ok', { timeoutMs: 8000 })
        const replied = String(probe.stdout || '').includes('doctor-ok')
        say('authentication', replied ? 'ok' : 'FAIL', replied ? 'command channel works' : 'connected but no output')
        if (!replied) say('shell', 'warn', 'the session opened but produced no stdout; the remote shell may be restricted')
      } catch (err) {
        const message = redact(err && err.message ? err.message : String(err))
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
        // Restore the pre-diagnosis state.
        if (!wasConnected) {
          await pool.closeOne(alias, { force: true })
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
