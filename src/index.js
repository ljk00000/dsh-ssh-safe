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
import { readFileSync } from 'node:fs'
import net from 'node:net'
import { homedir } from 'node:os'
import { SshPool, expandHome, pick } from './pool.js'
import { expectedEnv, machineFromEnv, redact, resolveAuth } from './credentials.js'
import { storePath } from './hostkey.js'
import { checkCommand } from './guard.js'
import { AuditLog, summarize } from './audit.js'

export const name = 'dsh-ssh-safe'
export const inject = ['tools']

export const Config = z.object({
  /** Machine alias used when a tool call omits 'machine'. */
  defaultMachine: z.string().default(''),

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
    'rm\\s+-rf\\s+/(?:\\s|$)',
    '\\bmkfs\\.',
    '\\bdd\\s+if=.*\\bof=/dev/[sn]',
    ':\\(\\)\\s*\\{\\s*:\\|:\\s*&\\s*\\};:',
    '\\b(?:shutdown|reboot|halt|poweroff)\\b',
  ]),
})

/** Where the host-key store lives. */
function resolveDshHome() {
  if (process.env.DSH_HOME) return process.env.DSH_HOME
  return homedir() + (process.platform === 'win32' ? '\\' : '/') + '.dsh'
}

export async function apply(ctx, config) {
  const cfg = { ...Config(), ...(config || {}) }
  const dshHome = resolveDshHome()
  const pool = new SshPool(cfg, { dshHome })
  // Auditing is off by default: writing files someone did not ask for is its
  // own surprise. Turning it on is a one-line config change.
  const audit = new AuditLog(dshHome + (process.platform === 'win32' ? '\\' : '/') + 'dsh-ssh-safe', {
    enabled: cfg.auditLog === true,
  })

  const textOut = {
    schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
    render: (_args, value) => [{ type: 'text', text: String(value?.text ?? '') }],
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
      throw new Error(
        'Command refused' + where + ': ' + verdict.pattern +
        '. Adjust denyPatterns in the plugin config if this is intentional.'
      )
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
  ctx.tools.defineTool({
    name: 'ssh_machines',
    description:
      'List the SSH machines configured through environment variables: alias, host, user, auth ' +
      'kind, host-key trust state. Never returns a password, passphrase, or key material. ' +
      'Call this first when you do not know which aliases exist.',
    parameters: {},
    output: textOut,
    async execute() {
      const aliases = new Set()
      if (cfg.defaultMachine) aliases.add(normalizeAlias(cfg.defaultMachine))
      for (const key of Object.keys(process.env)) {
        const m = /^DSH_SSH_(.+)_HOST$/.exec(key)
        if (m && process.env[key]) aliases.add(m[1].toLowerCase())
      }
      if (aliases.size === 0) {
        return { text:
          'No machines configured. Set environment variables, then restart DeepSeek Harness:\n' +
          '  DSH_SSH_PROD_HOST=10.0.0.5\n' +
          '  DSH_SSH_PROD_USER=ubuntu\n' +
          '  DSH_SSH_PROD_KEY_PATH=~/.ssh/id_ed25519\n' +
          '(or DSH_SSH_PROD_PASSWORD). Values are read at call time and never written to config.' }
      }
      const out = []
      const lean = cfg.machineInventory === 'alias'
      for (const alias of aliases) {
        const m = machineFromEnv(alias)
        const need = expectedEnv(alias)
        const authKind = m.password
          ? 'password (env)'
          : m.keyPath
            ? (lean ? 'private key (path hidden)' : 'key ' + m.keyPath)
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
            : (m.present.length ? '\n    detected env: ' + m.present.join(', ') : '\n    detected env: none')) +
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
  ctx.tools.defineTool({
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
    async execute(args) {
      const alias = machineFor(args)
      const startedAt = Date.now()
      try {
        await pool.connect(alias, {
          sessionPassword: args.password,
          trustHostKey: args.trustHostKey === true,
          force: args.force === true,
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

      const m = machineFromEnv(alias)
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
        '\n(Tip: ssh_doctor verifies the command channel and authentication end to end.)' }
    },
  })

  // ── ssh_exec ──────────────────────────────────────────────────────────
  ctx.tools.defineTool({
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
    async execute(args) {
      const alias = machineFor(args)
      const command = String(args.command || '').trim()
      if (!command) throw new Error('command is required')
      guard(command, args.confirm)
      const budget = args.timeoutMs ? Number(args.timeoutMs) : undefined
      const startedAt = Date.now()
      let r
      try {
        r = await pool.exec(alias, command, { timeoutMs: budget, sessionPassword: args.password })
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
        outcome: r.timedOut ? 'timeout' : (r.code === 0 ? 'ok' : 'exit'),
        exitCode: r.code,
        truncated: r.truncated,
        ms: Date.now() - startedAt,
      })
      // Render the two streams in the order they actually arrived. The old
      // all-stdout-then-all-stderr layout made compiler errors and progress
      // output hard to follow, because their position relative to stdout was
      // lost.
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
      parts.push('[exit ' + (r.code === null ? 'unknown' : r.code) + ']')
      return { text: redact(parts.join('\n')) }  },
  })

  // ── ssh_read ──────────────────────────────────────────────────────────
  ctx.tools.defineTool({
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
    },
    output: textOut,
    async execute(args) {
      const alias = machineFor(args)
      const remotePath = String(args.path || '').trim()
      if (!remotePath) throw new Error('path is required')
      const startedAt = Date.now()
      let r
      try {
        r = await pool.readFile(alias, remotePath, {
          maxBytes: args.maxBytes ? Number(args.maxBytes) : undefined,
          timeoutMs: args.timeoutMs ? Number(args.timeoutMs) : undefined,
          sessionPassword: args.password,
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
      const header = r.truncated ? '[truncated at ' + r.bytes + ' bytes]\n' : ''
      const note = args.raw === true ? '' : '\n[secrets masked; pass raw: true to see the file verbatim]'
      return { text: header + body + note }
    },
  })

  // ── ssh_write ─────────────────────────────────────────────────────────
  ctx.tools.defineTool({
    name: 'ssh_write',
    description:
      'Write UTF-8 text to a file on the remote machine (create or overwrite). ' +
      'Refuses to write more than maxFileBytes.',
    parameters: {
      machine: { type: 'string', description: 'Machine alias. Defaults to defaultMachine.' },
      path: { type: 'string', required: true, description: 'Absolute path on the remote host.' },
      content: { type: 'string', required: true, description: 'Full file content.' },
      timeoutMs: { type: 'integer', description: 'Override the per-transfer deadline. 0 = configured value.' },
      password: { type: 'string', description: 'Only honoured when the profile sets allowSessionPassword: true.' },
    },
    output: textOut,
    async execute(args) {
      const alias = machineFor(args)
      const remotePath = String(args.path || '').trim()
      const content = String(args.content ?? '')
      if (!remotePath) throw new Error('path is required')
      const bytes = Buffer.byteLength(content)
      if (bytes > cfg.maxFileBytes) {
        throw new Error('Refusing to write ' + bytes + ' bytes (maxFileBytes = ' + cfg.maxFileBytes + ').')
      }
      const startedAt = Date.now()
      let r
      try {
        r = await pool.writeFile(alias, remotePath, content, {
          timeoutMs: args.timeoutMs ? Number(args.timeoutMs) : undefined,
          sessionPassword: args.password,
        })
      } catch (err) {
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
      return { text: 'Wrote ' + r.bytes + ' bytes to ' + r.path }
    },
  })

  // ── ssh_list ──────────────────────────────────────────────────────────
  ctx.tools.defineTool({
    name: 'ssh_list',
    description: 'List a directory on the remote machine (name, size, type, mtime).',
    parameters: {
      machine: { type: 'string', description: 'Machine alias. Defaults to defaultMachine.' },
      path: { type: 'string', description: 'Absolute path on the remote host. Defaults to "."' },
      timeoutMs: { type: 'integer', description: 'Override the listing deadline. 0 = configured value.' },
      password: { type: 'string', description: 'Only honoured when the profile sets allowSessionPassword: true.' },
    },
    output: textOut,
    async execute(args) {
      const alias = machineFor(args)
      const remotePath = String(args.path || '.').trim() || '.'
      const startedAt = Date.now()
      let listing
      try {
        listing = await pool.list(alias, remotePath, {
          timeoutMs: args.timeoutMs ? Number(args.timeoutMs) : undefined,
          sessionPassword: args.password,
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
      const items = listing.items
      if (!items.length) return { text: '(empty directory: ' + listing.path + ')' }
      const rows = items
        .sort((a, b) => (a.dir === b.dir ? a.name.localeCompare(b.name) : a.dir ? -1 : 1))
        .map((it) => (it.dir ? 'd' : '-') + ' ' + String(it.size).padStart(10) + '  ' + (it.mtime || '') + '  ' + it.name)
      return { text: listing.path + '\n' + rows.join('\n') }
    },
  })


  // ── ssh_audit ─────────────────────────────────────────────────────────
  ctx.tools.defineTool({
    name: 'ssh_audit',
    description:
      'Show the most recent SSH operations this plugin performed: alias, operation, a one-line ' +
      'command summary, exit code and outcome. Never includes command output, file contents or ' +
      'credentials. Requires auditLog: true in the plugin config.',
    parameters: {
      limit: { type: 'integer', description: 'How many records to show (default 20, max 200).' },
    },
    output: textOut,
    async execute(args) {
      if (cfg.auditLog !== true) {
        return { text:
          'Audit logging is off. Set auditLog: true in the plugin config to record operations.\n' +
          'Records include the command summary, exit code and outcome — never output or secrets.' }
      }
      const limit = Math.min(Math.max(Number(args.limit) || 20, 1), 200)
      const records = audit.recent(limit)
      if (records.length === 0) return { text: 'No operations recorded yet.' }
      const rows = records.map((r) => {
        if (r.malformed) return '[unreadable record] ' + r.line
        const when = String(r.at || '').replace('T', ' ').slice(0, 19)
        const code = r.exitCode === null || r.exitCode === undefined ? '' : ' exit=' + r.exitCode
        const machine = r.machine ? ' ' + r.machine : ''
        return when + machine + ' ' + (r.kind || '?') + ' ' + (r.outcome || '') + code +
          '  ' + (r.command || r.pattern || '')
      })
      return { text: rows.join('\n') }
    },
  })

  // ── ssh_config ────────────────────────────────────────────────────────
  ctx.tools.defineTool({
    name: 'ssh_config',
    description:
      'Show the plugin configuration actually in effect, plus live pool state. Useful when a ' +
      'setting is not behaving as expected: this reports what the running instance uses, not ' +
      'what a file says. Secrets are never included.',
    parameters: {},
    output: textOut,
    async execute() {
      const stats = pool.connectionStats()
      const rows = [
        ['hostKeyPolicy', cfg.hostKeyPolicy, 'strict | tofu | off'],
        ['execGuard', cfg.execGuard, 'allow | confirm'],
        ['allowSessionPassword', cfg.allowSessionPassword, 'password through a tool argument'],
        ['machineInventory', cfg.machineInventory, 'full | alias'],
        ['auditLog', cfg.auditLog, 'NDJSON record of operations'],
        ['defaultMachine', cfg.defaultMachine || '(none)', ''],
        ['commandTimeoutMs', cfg.commandTimeoutMs, 'per ssh_exec command'],
        ['sftpTimeoutMs', cfg.sftpTimeoutMs, 'per transfer'],
        ['connectTimeoutMs', cfg.connectTimeoutMs, ''],
        ['closeTimeoutMs', cfg.closeTimeoutMs, 'wait for the peer to confirm a close'],
        ['keepaliveIntervalMs', cfg.keepaliveIntervalMs, '0 disables'],
        ['maxOutputChars', cfg.maxOutputChars, 'stdout + stderr together'],
        ['maxFileBytes', cfg.maxFileBytes, 'hard ceiling per transfer'],
        ['maxConnections', cfg.maxConnections, '0 = unlimited'],
        ['reconnectCooldownMs', cfg.reconnectCooldownMs, 'after a failure'],
        ['healthCheckIdleMs', cfg.healthCheckIdleMs, '0 disables the probe'],
        ['denyPatterns', (cfg.denyPatterns || []).length + ' pattern(s)', 'safety rail, not a boundary'],
      ]
      const lines = ['Configuration in effect:']
      for (const [key, value, note] of rows) {
        lines.push('  ' + String(key).padEnd(24) + JSON.stringify(value) + (note ? '   # ' + note : ''))
      }
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
  ctx.tools.defineTool({
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
    async execute(args) {
      const alias = machineFor(args)
      const m = machineFromEnv(alias)
      const need = expectedEnv(alias)
      const lines = []
      const say = (stage, verdict, detail) => lines.push('[' + verdict + '] ' + stage + (detail ? ': ' + detail : ''))

      // 1. configuration
      const missing = []
      if (!m.host) missing.push(need.required[0])
      if (!m.username) missing.push(need.required[1])
      const auth = resolveAuth(alias, { allowSessionPassword: cfg.allowSessionPassword })
      if (missing.length) say('configuration', 'FAIL', 'missing ' + missing.join(', '))
      else say('configuration', 'ok', m.username + '@' + m.host + ':' + m.port)
      say('credentials', auth.kind === 'none' ? 'FAIL' : 'ok',
        auth.kind === 'none'
          ? 'no password, key or agent available — set ' + need.auth[0]
          : auth.kind)

      if (missing.length || auth.kind === 'none') {
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
  ctx.tools.defineTool({
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
    async execute(args) {
      const alias = normalizeAlias(args.machine || '')
      const force = args.force === true
      if (alias) {
        const result = await pool.closeOne(alias, { force })
        if (result.busy) {
          return { text:
            'Not closing ' + alias + ': a command is still running on it. ' +
            'Wait for it to finish, or pass force: true to cut it off.' }
        }
        if (!result.closed) return { text: 'No live connection for ' + alias }
        return { text: result.confirmed
          ? 'Closed ' + alias
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
