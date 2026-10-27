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
import { homedir } from 'node:os'
import { SshPool, expandHome } from './pool.js'
import { expectedEnv, machineFromEnv, redact } from './credentials.js'
import { storePath } from './hostkey.js'
import { checkCommand } from './guard.js'

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
   * allow   — ssh_exec runs immediately (default)
   * confirm — ssh_exec requires confirm: true, so a model cannot run a
   *           command entirely on its own initiative
   */
  execGuard: z.string().default('allow'),

  /**
   * strict — only hosts already recorded may connect (default)
   * tofu   — first contact records the fingerprint; a CHANGE is still fatal
   * off    — no verification (MITM-unsafe; reported in every result)
   */
  hostKeyPolicy: z.string().default('strict'),

  commandTimeoutMs: z.number().step(1).min(1000).default(30000),

  /**
   * Deadline for a single SFTP read/write/list. ssh2 can stall without emitting
   * an error, so this is the backstop that keeps a tool call from hanging.
   */
  sftpTimeoutMs: z.number().step(1).min(1000).default(30000),
  connectTimeoutMs: z.number().step(1).min(1000).default(15000),
  keepaliveIntervalMs: z.number().step(1).min(0).default(20000),
  maxOutputChars: z.number().step(1).min(1024).default(200000),
  maxFileBytes: z.number().step(1).min(1024).default(1048576),
  reconnectCooldownMs: z.number().step(1).min(0).default(15000),

  /**
   * Commands matching these regular expressions are refused before exec.
   * A safety rail against catastrophic typos, NOT a security boundary — a
   * shell can always be reached through other commands.
   */
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

  const textOut = {
    schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true } } },
    render: (_args, value) => [{ type: 'text', text: String(value?.text ?? '') }],
  }

  const machineFor = (args) => {
    const alias = String(args?.machine || cfg.defaultMachine || '').trim()
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
    const verdict = checkCommand(command, cfg.denyPatterns)
    if (verdict.blocked) {
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
      const code = err && err.code
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
      if (cfg.defaultMachine) aliases.add(String(cfg.defaultMachine))
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
      for (const alias of aliases) {
        const m = machineFromEnv(alias)
        const need = expectedEnv(alias)
        const authKind = m.password ? 'password (env)' : m.keyPath ? 'key ' + m.keyPath : 'NONE'
        out.push(
          '• ' + alias + '  ' + (m.username || '<no user>') + '@' + (m.host || '<no host>') + ':' + m.port +
          '\n    auth: ' + authKind +
          '\n    hostKeyPolicy: ' + (m.hostKeyPolicy || cfg.hostKeyPolicy) +
          '\n    ' + trustedLine(m) +
          (m.present.length ? '\n    detected env: ' + m.present.join(', ') : '\n    detected env: none') +
          (m.host && m.username ? '' : '\n    MISSING: ' + need.required.join(', '))
        )
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
      await pool.connect(alias, {
        sessionPassword: args.password,
        trustHostKey: args.trustHostKey === true,
        force: args.force === true,
      })
      const uname = await pool.exec(alias, 'uname -a 2>/dev/null || ver', { timeoutMs: 8000 })
      const m = machineFromEnv(alias)
      return { text:
        'Connected: ' + (m.username || '?') + '@' + (m.host || '?') + ':' + (m.port || 22) +
        '\nHost key: ' + (pool.entry(alias).fingerprint || 'NOT VERIFIED (policy: ' + cfg.hostKeyPolicy + ')') +
        '\nRemote: ' + (redact(String(uname.stdout || '').trim()) || '(no output)') +
        (cfg.hostKeyPolicy === 'off' ? '\n\nWARNING: hostKeyPolicy is "off" — this connection is not protected against a man-in-the-middle.' : '') }
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
    },
    output: textOut,
    async execute(args) {
      const alias = machineFor(args)
      const command = String(args.command || '').trim()
      if (!command) throw new Error('command is required')
      guard(command, args.confirm)
      const budget = args.timeoutMs ? Number(args.timeoutMs) : undefined
      const r = await pool.exec(alias, command, { timeoutMs: budget })
      const parts = []
      if (r.stdout) parts.push(String(r.stdout).replace(/\s+$/, ''))
      if (r.stderr) parts.push('[stderr]\n' + String(r.stderr).replace(/\s+$/, ''))
      if (r.truncated) parts.push('[output truncated at maxOutputChars]')
      if (r.timedOut) parts.push('[timed out after ' + (budget || cfg.commandTimeoutMs) + 'ms]')
      parts.push('[exit ' + (r.code === null ? 'unknown' : r.code) + ']')
      return { text: redact(parts.join('\n')) }
    },
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
    },
    output: textOut,
    async execute(args) {
      const alias = machineFor(args)
      const remotePath = String(args.path || '').trim()
      if (!remotePath) throw new Error('path is required')
      const r = await pool.readFile(alias, remotePath, { maxBytes: args.maxBytes ? Number(args.maxBytes) : undefined })
      return { text: (r.truncated ? '[truncated at ' + r.bytes + ' bytes]\n' : '') + r.content }
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
      const r = await pool.writeFile(alias, remotePath, content)
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
    },
    output: textOut,
    async execute(args) {
      const alias = machineFor(args)
      const remotePath = String(args.path || '.').trim() || '.'
      const items = await pool.list(alias, remotePath)
      if (!items.length) return { text: '(empty directory: ' + remotePath + ')' }
      const rows = items
        .sort((a, b) => (a.dir === b.dir ? a.name.localeCompare(b.name) : a.dir ? -1 : 1))
        .map((it) => (it.dir ? 'd' : '-') + ' ' + String(it.size).padStart(10) + '  ' + (it.mtime || '') + '  ' + it.name)
      return { text: remotePath + '\n' + rows.join('\n') }
    },
  })

  // ── ssh_close ─────────────────────────────────────────────────────────
  ctx.tools.defineTool({
    name: 'ssh_close',
    description: 'Close pooled SSH connections. The next call reconnects.',
    parameters: { machine: { type: 'string', description: 'Alias to close; empty closes all.' } },
    output: textOut,
    async execute(args) {
      const alias = String(args.machine || '').trim()
      if (alias) {
        const had = await pool.closeOne(alias)
        return { text: had ? 'Closed ' + alias : 'No live connection for ' + alias }
      }
      await pool.closeAll()
      return { text: 'Closed all SSH connections' }
    },
  })

  // Release sockets when the plugin unloads.
  if (typeof ctx.effect === 'function') {
    ctx.effect(() => () => { pool.closeAll().catch(() => {}) }, 'dsh-ssh-safe.close')
  }
}
