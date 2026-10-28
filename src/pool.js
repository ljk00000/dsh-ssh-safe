// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe — SSH connection pool.
//
// One lazily-opened connection per machine alias. Every operation goes through
// this module so that timeouts, output caps and redaction are applied in one
// place instead of once per tool.
//
// Deliberate limits:
//   - no reconnect storms (a failed connect is cached for cooldownMs)
//   - no unbounded output (maxOutputChars truncates, with a visible marker)
//   - no secret ever appears in an error string (see credentials.redact)

// ssh2 is imported lazily: credential and host-key logic must be testable (and
// the plugin must be loadable enough to report a clear error) even when the
// native dependency is missing from a half-installed tree.
let Client = null
async function loadClient() {
  if (Client) return Client
  try {
    const mod = await import('ssh2')
    Client = mod.Client
    return Client
  } catch (err) {
    throw new Error(
      'The ssh2 package is not installed. Reinstall the plugin (dsh plugin add dsh-ssh-safe) ' +
      'so its bundled dependencies are present. ' + (err && err.message ? err.message : '')
    )
  }
}
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { homedir } from 'node:os'
import { redact, envNames } from './credentials.js'
import { credentialFor, machineDefinition } from './machines.js'
import { checkHostKey } from './hostkey.js'
import { Utf8Collector, OutputBudget } from './buffer.js'
import { normalizeRemotePath } from './remote-path.js'
import { closeClient } from './close.js'
import { readRemoteFile, writeRemoteFile, listRemoteDir } from './sftp.js'

/**
 * One pooled machine slot.
 *
 * @typedef {object} PoolEntry
 * @property {any} client        live ssh2 client, or null
 * @property {Promise<any>|null} ready in-progress handshake
 * @property {string} lastError   redacted message from the last failure
 * @property {number} nextAttemptAt epoch ms before which retries are refused
 * @property {number} lastUsedAt  epoch ms of the last use, for LRU ordering
 * @property {string|null} [fingerprint] host key fingerprint, null when unknown
 * @property {string|undefined} [credentialIdentity] digest of the credential used
 */

/**
 * Read a numeric setting, treating 0 as a real value.
 *
 * `cfg.setting || fallback` silently replaces a deliberate 0 with the default,
 * so every setting documented as "0 disables" actually did the opposite and
 * ssh_config reported a number the runtime never used.
 *
 * @param {unknown} value
 * @param {number} fallback
 * @returns {number}
 */
export function pick(value, fallback) {
  if (value === null || value === undefined) return fallback
  const n = Number(value)
  return Number.isFinite(n) ? n : fallback
}

/** Policies the host-key store understands. */
const VALID_POLICIES = new Set(['strict', 'tofu', 'off'])

/**
 * Resolve the host-key policy for one connection.
 *
 * A per-machine setting wins outright. The previous implementation only read
 * the machine value when it happened to be 'tofu', so a machine could never be
 * tightened to 'strict' nor relaxed to 'off' — the setting silently did nothing.
 *
 * An unrecognised machine value is ignored rather than passed through, so a
 * typo cannot silently disable verification.
 *
 * @param {string} globalPolicy from the plugin config
 * @param {string} machinePolicy from DSH_SSH_<ALIAS>_HOST_KEY_POLICY
 * @returns {'strict'|'tofu'|'off'}
 */
export function effectivePolicy(globalPolicy, machinePolicy) {
  const machine = String(machinePolicy ?? '').trim().toLowerCase()
  if (VALID_POLICIES.has(machine)) return /** @type {'strict'|'tofu'|'off'} */ (machine)
  const global = String(globalPolicy ?? '').trim().toLowerCase()
  if (VALID_POLICIES.has(global)) return /** @type {'strict'|'tofu'|'off'} */ (global)
  return 'strict'
}

/** Expand a leading ~ so key paths written by hand work. */
export function expandHome(p) {
  const s = String(p || '')
  if (!s.startsWith('~')) return s
  return s.replace(/^~(?=[/\\]|$)/, homedir())
}

export class SshPool {
  constructor(config, deps) {
    this.config = config
    this.deps = deps
    /**
     * Per-alias count of operations currently using the connection.
     *
     * closeAll() used to end every client unconditionally, so a shutdown -- or
     * a plugin unload -- severed a running command mid-flight. An apt upgrade
     * or a database import cut in half is worse than waiting a few seconds,
     * so shutdown now refuses to close a busy connection until it drains.
     */
    this.inflight = new Map()
    /** @type {Map<string, PoolEntry>} */
    this.entries = new Map()
  }

  /**
   * Get or create the pool slot for an alias.
   *
   * The slot is declared with a JSDoc typedef because checkJs otherwise infers
   * a narrow object literal type and then rejects every field assigned later
   * (fingerprint, credentialIdentity, lastUsedAt).
   *
   * @param {string} alias
   * @returns {PoolEntry}
   */
  entry(alias) {
    let e = this.entries.get(alias)
    if (!e) {
      /** @type {PoolEntry} */
      const fresh = { client: null, ready: null, lastError: '', nextAttemptAt: 0, lastUsedAt: Date.now() }
      e = fresh
      this.entries.set(alias, e)
    }
    e.lastUsedAt = Date.now()
    return e
  }

  /** Mark an operation as using this alias' connection. */
  beginOp(alias) {
    this.inflight.set(alias, (this.inflight.get(alias) || 0) + 1)
  }

  /** Mark an operation as finished. */
  endOp(alias) {
    const n = (this.inflight.get(alias) || 0) - 1
    if (n > 0) this.inflight.set(alias, n)
    else this.inflight.delete(alias)
  }

  /** Is anything running on this alias? */
  isBusy(alias) {
    return (this.inflight.get(alias) || 0) > 0
  }

  /**
   * Close the least recently used connections until at most `keep` live ones
   * remain.
   *
   * Without this a long session that touches many machines holds an SSH
   * socket open per machine for the life of the process; nothing but the
   * explicit ssh_close or a plugin unload ever released them.
   *
   * @param {number} keep how many live connections to retain
   * @param {string} [protect] an alias that must not be evicted (the one just used)
   * @returns {Promise<string[]>} aliases that were closed
   */
  /**
   * Close the least recently used connections until at most `keep` live ones
   * remain.
   *
   * Eviction is a ceiling, not a preference: when the limit is exceeded the
   * oldest connection is closed even if an operation is still using it, because
   * the alternative is an unbounded number of sockets. That is why this passes
   * force to closeOne -- and why it must check what closeOne actually did.
   *
   * The previous version ignored the result: closeOne returned
   * {closed:false, busy:true}, eviction still reported the alias as closed, and
   * the ceiling was silently exceeded.
   *
   * @param {number} keep how many live connections to retain
   * @param {string} [protect] an alias that must not be evicted (the one just used)
   * @returns {Promise<string[]>} aliases that were actually closed
   */
  async evictIdle(keep, protect) {
    const limit = Number(keep)
    if (!Number.isFinite(limit) || limit <= 0) return []

    // Never evict the connection the caller is about to use.
    const candidates = [...this.entries.entries()]
      .filter(([alias, e]) => e.client && alias !== protect)
    if (candidates.length === 0) return []

    const liveTotal = [...this.entries.values()].filter((e) => e.client).length
    const excess = liveTotal - limit
    if (excess <= 0) return []

    // Oldest first, so the most recently used survive.
    candidates.sort((a, b) => (a[1].lastUsedAt || 0) - (b[1].lastUsedAt || 0))

    const closed = []
    for (const [alias] of candidates) {
      if (closed.length >= excess) break
      const result = await this.closeOne(alias, { force: true })
      if (result.closed) closed.push(alias)
    }
    return closed
  }

  /**
   * Connection count and ceiling, for diagnostics.
   * @returns {{live: number, limit: number, aliases: string[]}}
   */
  connectionStats() {
    const aliases = [...this.entries.entries()]
      .filter(([, e]) => e.client)
      .map(([alias]) => alias)
    const limit = Number(this.config.maxConnections)
    return {
      live: aliases.length,
      limit: Number.isFinite(limit) ? limit : 0,
      aliases,
    }
  }

  describe(alias) {
    return machineDefinition(alias, {
      machines: this.config.machines || {},
      dshHome: this.deps.dshHome,
    })
  }

  /**
   * @param {string} alias
   * @param {{sessionPassword?: string, trustHostKey?: boolean, force?: boolean}} [options]
   */
  async connect(alias, { sessionPassword, trustHostKey, force = false } = {}) {
    const e = this.entry(alias)

    // A pooled connection was opened with one specific credential. Reusing it
    // for a call that supplies a different session password would silently
    // authenticate as the earlier user, so the credential identity is part of
    // the cache key.
    // Only a digest is kept. Storing the password itself would leave a usable
    // secret resident in the pool for the life of the process, where a heap
    // dump or a careless error message could expose it.
    const wantCredential = typeof sessionPassword === 'string' && sessionPassword.length > 0
      ? 'session:' + createHash('sha256').update(sessionPassword).digest('hex').slice(0, 16)
      : 'configured'

    if (e.client && e.credentialIdentity !== undefined && e.credentialIdentity !== wantCredential) {
      await this.closeOne(alias)
    }

    if (e.client) {
      // A connection can be dead without anyone noticing: a NAT idle timeout
      // or a firewall drop leaves the socket open locally while the peer is
      // gone. Probing once per idle period avoids writing into a void and
      // waiting for the command timeout to say so.
      const idleMs = Date.now() - (e.lastUsedAt || 0)
      const probeAfter = Number(this.config.healthCheckIdleMs) || 0
      if (probeAfter > 0 && idleMs > probeAfter) {
        const alive = await this.#probe(alias, e.client)
        if (!alive) {
          await this.closeOne(alias, { force: true })
          e.lastError = 'previous connection was dead; reconnecting'
        } else {
          return e.client
        }
      } else {
        return e.client
      }
    }

    if (!force && Date.now() < e.nextAttemptAt) {
      const waitMs = Math.max(0, e.nextAttemptAt - Date.now())
      throw new Error(
        'Refusing to retry ' + alias + ' for another ' + Math.ceil(waitMs / 1000) + 's ' +
        '(last failure: ' + (e.lastError || 'unknown') + '). ' +
        'Pass force: true to try immediately.'
      )
    }
    if (e.ready) return e.ready

    // force skips the cooldown for this attempt only.
    if (force) e.nextAttemptAt = 0

    e.ready = this.#open(alias, e, { sessionPassword, trustHostKey })
      .then(async (client) => {
        e.client = client
        e.lastError = ''
        e.nextAttemptAt = 0
        e.credentialIdentity = wantCredential
        e.lastUsedAt = Date.now()
        // Enforce the ceiling here, not in the tools: ssh_exec / ssh_read /
        // ssh_write / ssh_list all reach the network through this method, so
        // evicting anywhere else leaves those paths unbounded. `alias` is
        // protected because it was just used.
        const limit = Number(this.config.maxConnections)
        if (Number.isFinite(limit) && limit > 0) {
          await this.evictIdle(limit, alias)
        }
        return client
      })
      .catch((err) => {
        e.lastError = redact(err && err.message ? err.message : String(err))
        e.nextAttemptAt = Date.now() + pick(this.config.reconnectCooldownMs, 15000)
        throw err
      })
      .finally(() => { e.ready = null })

    return e.ready
  }

  /**
   * Cheap liveness probe for a pooled connection.
   *
   * ssh2 exposes no ping, so the channel is checked by asking whether it is
   * still writable and by racing a no-op exec against a short deadline. A
   * failure here means 'reconnect', not 'report an error'.
   *
   * @returns {Promise<boolean>}
   */
  async #probe(alias, client) {
    try {
      const deadline = Number(this.config.healthCheckTimeoutMs) || 3000
      const result = await Promise.race([
        new Promise((resolve) => {
          try {
            client.exec('true', (err, stream) => {
              if (err) return resolve(false)
              try { stream.destroy() } catch {}
              resolve(true)
            })
          } catch { resolve(false) }
        }),
        new Promise((resolve) => setTimeout(() => resolve(false), deadline)),
      ])
      return result === true
    } catch {
      return false
    }
  }

  async #open(alias, e, { sessionPassword, trustHostKey }) {
    const auth = credentialFor(alias, {
      machines: this.config.machines || {},
      dshHome: this.deps.dshHome,
      sessionPassword,
      allowSessionPassword: this.config.allowSessionPassword === true,
      allowPlaintextPassword: this.config.allowPlaintextPassword === true,
    })
    const m = auth.machine
    if (!m.host || !m.username) {
      const names = envNames(alias)
      const need = []
      if (!m.host) need.push(names.host)
      if (!m.username) need.push(names.user)
      throw new Error(
        'Machine "' + alias + '" is not configured: missing ' + need.join(', ') +
        '. Set it in the plugin settings (machines.' + alias + '), or as the environment ' +
        'variable(s) ' + need.join(', ') + ', or pass host/username ' +
        'explicitly to ssh_connect. Nothing was read from disk.'
      )
    }
    if (auth.kind === 'none') {
      throw new Error(
        'Machine "' + alias + '" has no credentials. Set ' + envNames(alias).password +
        ' or ' + envNames(alias).keyPath + '. Also checked: SSH_AUTH_SOCK for an agent,' +
        ' which none was found at.' +
        (this.config.allowSessionPassword
          ? ' Or pass password (this profile allows it).'
          : ' Passing a password in conversation is disabled for this profile.')
      )
    }

    const connectConfig = {
      host: m.host,
      port: m.port || 22,
      username: m.username,
      readyTimeout: pick(this.config.connectTimeoutMs, 15000),
      keepaliveInterval: pick(this.config.keepaliveIntervalMs, 20000),
      keepaliveCountMax: 3,
    }

    if (auth.kind === 'session-password' || auth.kind === 'env-password') {
      connectConfig.password = auth.password
    } else if (auth.kind === 'env-key') {
      connectConfig.privateKey = readFileSync(expandHome(auth.keyPath))
      if (auth.passphrase) connectConfig.passphrase = auth.passphrase
    } else if (auth.kind === 'agent') {
      // The agent holds the key; ssh2 asks it to sign and we never see it.
      connectConfig.agent = auth.agent
    }

    const ClientClass = await loadClient()

    return new Promise((resolve, reject) => {
      const client = new ClientClass()
      let settled = false
      const fail = (err) => {
        if (settled) return
        settled = true
        try { client.end() } catch {}
        reject(new Error(redact(err && err.message ? err.message : String(err))))
      }

      client.on('error', fail)
      client.on('ready', () => {
        if (settled) return
        settled = true
        resolve(client)
      })
      client.on('close', () => {
        // Drop from the pool so the next call reconnects instead of using a corpse.
        // Every derived field goes with it: a stale fingerprint would otherwise be
        // reported for a host we have not spoken to yet, and a stale cooldown
        // would keep a healthy server unreachable.
        if (e.client === client) {
          e.client = null
          e.fingerprint = null
          e.credentialIdentity = undefined
          e.nextAttemptAt = 0
        }
        if (!settled) fail(new Error('connection closed before the handshake completed'))
      })

      if (typeof client.connect !== 'function') return fail(new Error('ssh2 Client is unavailable'))
      // hostVerifier must be set before connect().
      connectConfig.hostVerifier = (keyBlob) => {
        // Clear before deciding: if this handshake is rejected, the previous
        // host's fingerprint must not survive into the error report.
        e.fingerprint = null
        const verdict = checkHostKey({
          dshHome: this.deps.dshHome,
          host: m.host,
          port: m.port || 22,
          keyBlob,
          policy: effectivePolicy(this.config.hostKeyPolicy, m.hostKeyPolicy),
          trustHostKey,
          knownHostsFile: m.knownHosts ? expandHome(m.knownHosts) : undefined,
        })
        if (!verdict.ok) {
          fail(new Error(verdict.reason))
          return false
        }
        e.fingerprint = verdict.fp
        return true
      }
      client.connect(connectConfig)
    })
  }

  /**
   * @param {string} alias
   * @param {string} command
   * @param {{timeoutMs?: number, sessionPassword?: string}} [inline]
   */
  async exec(alias, command, { timeoutMs, sessionPassword } = {}) {
    const client = await this.connect(alias, { sessionPassword })
    this.beginOp(alias)
    try {
      return await this.#execOn(alias, client, command, timeoutMs)
    } finally {
      this.endOp(alias)
    }
  }

  async #execOn(alias, client, command, timeoutMs) {
    const limit = pick(timeoutMs || undefined, pick(this.config.commandTimeoutMs, 20000))
    const cap = pick(this.config.maxOutputChars, 200000)

    return await new Promise((resolve, reject) => {
      const out = { text: '', truncated: false }
      const err = { text: '', truncated: false }
      // Ordered transcript of both streams. Concatenating stdout then stderr
      // loses the interleaving, which is exactly what a compiler error or a
      // progress bar needs to be readable.
      const timeline = []
      // One budget for both streams: stdout and stderr together stay within
      // maxOutputChars instead of each getting the full allowance.
      const budget = new OutputBudget(cap)
      let settled = false
      let stream = null
      let timer = null
      let timedOutResult = null

      const settle = (result, error) => {
        if (settled) return
        settled = true
        if (timer) clearTimeout(timer)
        // Detach listeners so a stream that keeps draining after we gave up
        // cannot grow the buffers or fire a second completion.
        if (stream) {
          try { stream.removeAllListeners('data'); stream.removeAllListeners('close'); stream.stderr?.removeAllListeners('data') } catch {}
          try { stream.close() } catch {}
          try { stream.destroy() } catch {}
        }
        if (error) reject(error)
        else resolve(result)
      }

      timer = setTimeout(() => {
        // ssh2 does not expose the remote pid, so sending a signal to the
        // channel is the portable way to stop the command — and it is what ssh
        // itself does on ^C.
        //
        // Signal first, then wait one turn of the event loop before tearing the
        // channel down. signal() only queues an SSH message; close()/destroy()
        // run synchronously inside settle(), so calling settle() immediately
        // destroyed the channel before the TERM message could be written and
        // the remote process kept running.
        try { if (stream) stream.signal('TERM') } catch {}
        timedOutResult = {
          stdout: out.text,
          stderr: err.text,
          code: null,
          timedOut: true,
          truncated: budget.truncated,
          timeline,
        }
        // Let the TERM message flush before the channel is destroyed.
        setImmediate(() => settle(timedOutResult))
      }, limit)

      client.exec(command, (error, s) => {
        if (error) return settle(null, new Error(redact(error.message)))
        stream = s
        s.on('data', (d) => {
          const text = Buffer.isBuffer(d) ? d.toString('utf8') : String(d)
          timeline.push({ stream: 'out', text })
          budget.append(out, text)
        })
        s.stderr.on('data', (d) => {
          const text = Buffer.isBuffer(d) ? d.toString('utf8') : String(d)
          timeline.push({ stream: 'err', text })
          budget.append(err, text)
        })
        s.on('close', (code) => {
          settle({
            stdout: out.text,
            stderr: err.text,
            code: typeof code === 'number' ? code : null,
            timedOut: false,
            truncated: budget.truncated,
            timeline,
          })
        })
        s.on('error', (e) => settle(null, new Error(redact(e.message))))
      })
    })
  }

  /** @param {string} alias @param {string} remotePath @param {{maxBytes?: number, timeoutMs?: number, sessionPassword?: string}} [opts] */
  async readFile(alias, remotePath, opts = {}) {
    this.beginOp(alias)
    try {
      return await this.#readFileOn(alias, remotePath, opts)
    } finally {
      this.endOp(alias)
    }
  }

  /**
   * @param {string} alias
   * @param {string} remotePath
   * @param {{maxBytes?: number, sessionPassword?: string, timeoutMs?: number}} [inline]
   */
  async #readFileOn(alias, remotePath, { maxBytes, sessionPassword, timeoutMs } = {}) {
    // Validate before connecting: an invalid path is the caller's mistake, and
    // surfacing it as ECONNREFUSED (or as a cooldown) sends the user after a
    // server that is perfectly healthy.
    normalizeRemotePath(remotePath)
    // maxBytes can only tighten the configured ceiling: a tool argument must not
    // be able to pull an arbitrary amount of the remote file into memory.
    const configured = pick(this.config.maxFileBytes, 1048576)
    const requested = Number(maxBytes) || 0
    const cap = requested > 0 ? Math.min(requested, configured) : configured
    const client = await this.connect(alias, { sessionPassword })
    return await readRemoteFile(client, remotePath, {
      maxBytes: cap,
      timeoutMs: pick(timeoutMs || undefined, pick(this.config.sftpTimeoutMs, 30000)),
    })
  }

  /** @param {string} alias @param {string} remotePath @param {{timeoutMs?: number, sessionPassword?: string}} [opts] */
  async writeFile(alias, remotePath, content, opts = {}) {
    this.beginOp(alias)
    try {
      return await this.#writeFileOn(alias, remotePath, content, opts)
    } finally {
      this.endOp(alias)
    }
  }

  /**
   * @param {string} alias
   * @param {string} remotePath
   * @param {string|Buffer} content
   * @param {{sessionPassword?: string, timeoutMs?: number}} [inline]
   */
  async #writeFileOn(alias, remotePath, content, { sessionPassword, timeoutMs } = {}) {
    // See readFile: reject a bad path before touching the network.
    normalizeRemotePath(remotePath)
    const client = await this.connect(alias, { sessionPassword })
    return await writeRemoteFile(client, remotePath, content, {
      timeoutMs: pick(timeoutMs || undefined, pick(this.config.sftpTimeoutMs, 30000)),
    })
  }

  /** @param {string} alias @param {string} remotePath @param {{timeoutMs?: number, sessionPassword?: string}} [opts] */
  async list(alias, remotePath, opts = {}) {
    this.beginOp(alias)
    try {
      return await this.#listOn(alias, remotePath, opts)
    } finally {
      this.endOp(alias)
    }
  }

  /**
   * @param {string} alias
   * @param {string} remotePath
   * @param {{sessionPassword?: string, timeoutMs?: number}} [inline]
   */
  async #listOn(alias, remotePath, { sessionPassword, timeoutMs } = {}) {
    // list allows a relative path, so it validates with allowRelative rather
    // than insisting on an absolute one.
    normalizeRemotePath(remotePath || '.', { allowRelative: true })
    const client = await this.connect(alias, { sessionPassword })
    return await listRemoteDir(client, remotePath, {
      timeoutMs: pick(timeoutMs || undefined, pick(this.config.sftpTimeoutMs, 30000)),
    })
  }
  /**
   * @param {string} alias
   * @param {{force?: boolean}} [inline]
   */
  async closeOne(alias, { force = false } = {}) {
    const e = this.entries.get(alias)
    if (!e) return { closed: false, confirmed: false }
    if (!force && this.isBusy(alias)) {
      return { closed: false, confirmed: false, busy: true }
    }
    const client = e.client
    e.client = null
    e.ready = null
    e.fingerprint = null
    e.credentialIdentity = undefined
    e.nextAttemptAt = 0
    if (!client) return { closed: false, confirmed: false }
    const confirmed = await closeClient(client, pick(this.config.closeTimeoutMs, 1500))
    return { closed: true, confirmed }
  }

  /**
   * Close every connection, but do not sever work in progress.
   *
   * Busy aliases are skipped and reported back, so the caller can decide
   * whether to wait or to force. Shutdown that silently kills a running apt
   * upgrade is worse than shutdown that says 'two connections are still busy'.
   *
   * @param {{force?: boolean, drainMs?: number}} [options]
   * @returns {Promise<{closed: string[], busy: string[]}>}
   */
  /** @param {{force?: boolean, drainMs?: number}} [inline] */
  async closeAll({ force = false, drainMs = 0 } = {}) {
    const deadline = drainMs > 0 ? Date.now() + drainMs : 0

    // Give in-flight work a bounded window to finish before deciding.
    if (deadline) {
      while (Date.now() < deadline) {
        const busyNow = [...this.entries.keys()].filter((a) => this.isBusy(a))
        if (busyNow.length === 0) break
        await new Promise((r) => setTimeout(r, 50))
      }
    }

    const closed = []
    const busy = []
    const clients = []

    for (const [alias, e] of this.entries) {
      if (!force && this.isBusy(alias)) {
        busy.push(alias)
        continue
      }
      if (e.client) clients.push(e.client)
      if (e.client) closed.push(alias)
      e.client = null
      e.ready = null
      e.fingerprint = null
      e.credentialIdentity = undefined
      e.nextAttemptAt = 0
    }

    // An entry exists only to hold a connection. Busy aliases keep theirs (the
    // connection is still open); every other entry is dropped so nothing
    // phantom is left behind.
    for (const [alias, e] of [...this.entries]) {
      if (!e.client && !this.isBusy(alias)) this.entries.delete(alias)
    }

    await Promise.all(clients.map((client) => closeClient(client, pick(this.config.closeTimeoutMs, 1500))))
    return { closed, busy }
  }
}
