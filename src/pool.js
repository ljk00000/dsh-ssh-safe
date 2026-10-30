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
import { connectOptions, expandHome } from './connect.js'
import { credentialFor, machineDefinition } from './machines.js'
import { checkHostKey } from './hostkey.js'
import { Utf8Collector, OutputBudget } from './buffer.js'
import { normalizeRemotePath } from './remote-path.js'
import { closeClient } from './close.js'
import { readRemoteFile, writeRemoteFile, listRemoteDir } from './sftp.js'

/** The largest delay setTimeout accepts; anything larger is clamped to 1 ms. */
const MAX_TIMER_MS = 2147483647

/**
 * Clamp a caller-supplied deadline to something setTimeout can represent.
 *
 * A tool call may pass any positive number, and setTimeout silently rewrites a
 * value above 2^31-1 to 1 ms — so 'timeoutMs: 10000000000' returned "timed out"
 * in 12 ms instead of waiting.
 *
 * @param {unknown} value requested deadline
 * @param {number} fallback used when the value is missing or not positive
 * @returns {number}
 */
function timerValue(value, fallback) {
  const n = Number(value)
  if (!Number.isFinite(n) || n <= 0) return fallback
  return Math.min(n, MAX_TIMER_MS)
}

/**
 * Turn a handshake failure into something a caller can act on.
 *
 * ssh2 reports the bare socket/library error -- "read ECONNRESET", "Timed out
 * while waiting for handshake", "All configured authentication methods failed".
 * With several machines configured that names neither the machine nor the
 * likely cause, and the difference between "the password is wrong" and "that
 * port is not sshd" is what decides the next step.
 *
 * @param {unknown} err
 * @param {{host?: string, port?: number, username?: string}} [m]
 * @returns {Error}
 */
export function connectFailure(err, m) {
  const raw = redact(err && /** @type {any} */ (err).message ? /** @type {any} */ (err).message : String(err))
  // Already decorated, or already explains itself: the host key store writes a
  // complete sentence naming the host, the fingerprint and the way out, and the
  // ssh_doctor line above it already carries the target.
  if (/^(Could not connect to |Refusing to retry )/.test(raw)) return new Error(raw)
  if (/^(Unknown host|Host key verification failed|Host key changed|HOST KEY CHANGED)/i.test(raw)) return new Error(raw)
  const target = m && m.host
    ? (m.username ? m.username + '@' : '') + m.host + ':' + (m.port || 22)
    : 'the remote host'
  /** @type {Array<[RegExp, string]>} */
  const hints = [
    [/ECONNREFUSED/i, 'nothing is listening on that port'],
    [/ECONNRESET/i, 'the server closed the connection during the handshake — the port may not be sshd'],
    [/ENOTFOUND|EAI_AGAIN/i, 'the host name did not resolve'],
    [/Timed out while waiting for handshake|ETIMEDOUT/i, 'no SSH banner arrived — the port may not speak SSH, or a firewall is dropping packets'],
    [/All configured authentication methods failed|Permission denied/i, 'the server rejected the credentials — check the user, the key or password, and authorized_keys'],
    [/Host key verification failed|Unknown host/i, 'the host key store does not trust this host; run ssh_connect with trustHostKey once'],
  ]
  const hint = hints.find(([pattern]) => pattern.test(raw))
  return new Error('Could not connect to ' + target + ': ' + raw + (hint ? ' (' + hint[1] + ')' : ''))
}

/**
 * Largest command that fits one SSH exec request.
 *
 * RFC 4253 caps a transport packet at 35000 bytes, and ssh2 refuses the request
 * before sending when the command does not fit: the caller got a bare
 * "Unable to exec" with no hint that the command was 100 KB. Measured boundary
 * is between 34900 (ok) and 35000 (fails); this keeps a margin for framing.
 */
export const MAX_COMMAND_BYTES = 34000

/** Mark an error that must not arm the reconnect cooldown. */
function noCooldown(err) {
  /** @type {any} */ (err).noCooldown = true
  return err
}

/**
 * Name the real cause when ssh2 says the client is not connected.
 *
 * A close or an eviction can land between connect() and the first use, and
 * ssh2 answers with a bare "Not connected" that reads like a plugin bug.
 *
 * @param {unknown} err
 * @param {string} alias
 * @returns {Error}
 */
function explainGone(err, alias) {
  const message = String((err && /** @type {any} */ (err).message) || err || '')
  if (!/Not connected|not connected|Channel open failure/i.test(message)) return err instanceof Error ? err : new Error(message)
  return new Error(
    'The connection to "' + alias + '" is gone: it was closed while the operation was starting ' +
    'or running (ssh_close, an eviction, or a dropped channel). The operation did not complete; ' +
    'call it again to reconnect.'
  )
}

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

// Expand-home lives in connect.js now: the pool and the settings page both
// need it, and sharing it is how they stopped disagreeing about key paths.
export { expandHome }

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
      dshHome: this.#credentialHome,
    })
  }

  /**
   * Where the credential file may be read from.
   *
   * '' when the profile turned it off: useCredentialFile must make the file
   * invisible to the connection, not just to the tools that report sources.
   * The known_hosts store keeps using the real home either way.
   */
  get #credentialHome() {
    return this.deps.credentialHome === undefined ? this.deps.dshHome : this.deps.credentialHome
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
    // A session password the profile does not allow is ignored by
    // credentialFor(), so it must not be part of the identity either: otherwise
    // a caller that types a different (unused) password forces a needless
    // reconnect, and the pool claims to hold a credential it never used.
    const sessionAllowed = this.config.allowSessionPassword === true
    const wantCredential = sessionAllowed && typeof sessionPassword === 'string' && sessionPassword.length > 0
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
        // Configuration errors are marked: they must not start a cooldown, or
        // the message after a quick fix is the cooldown rather than the result.
        if (!(err && /** @type {any} */ (err).noCooldown === true)) {
          e.nextAttemptAt = Date.now() + pick(this.config.reconnectCooldownMs, 15000)
        }
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
      dshHome: this.#credentialHome,
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
      // A configuration error is not a network failure: retrying costs nothing
      // and the user usually fixes the setting and retries at once. Marking it
      // keeps the reconnect cooldown from answering "Refusing to retry for
      // another 15s" when the real answer is "fill in the host".
      throw noCooldown(new Error(
        'Machine "' + alias + '" is not configured: missing ' + need.join(', ') +
        '. Set it in the plugin settings (machines.' + alias + '), or as the environment ' +
        'variable(s) ' + need.join(', ') + ', or pass host/username ' +
        'explicitly to ssh_connect. Nothing was read from disk.'
      ))
    }
    if (auth.kind === 'none') {
      throw noCooldown(new Error(
        'Machine "' + alias + '" has no credentials. Set ' + envNames(alias).password +
        ' or ' + envNames(alias).keyPath + '. Also checked: SSH_AUTH_SOCK for an agent,' +
        ' which none was found at.' +
        (this.config.allowSessionPassword
          ? ' Or pass password (this profile allows it).'
          : ' Passing a password in conversation is disabled for this profile.')
      ))
    }

    // One shared mapping, also used by the settings page's test button. It keys
    // on the resolved credential VALUE rather than on the kind: the previous
    // per-kind chain dropped every source it did not name (notably a password
    // from the credential file), which produced a connect attempt carrying no
    // authentication at all.
    let connectConfig
    try {
      connectConfig = connectOptions(m, auth, {
        readyTimeout: pick(this.config.connectTimeoutMs, 15000),
        keepaliveInterval: pick(this.config.keepaliveIntervalMs, 20000),
      })
    } catch (err) {
      // A key that cannot be read is a configuration problem, not a network
      // one: say which machine and which file, and do not start a cooldown.
      throw noCooldown(new Error(
        'Machine "' + alias + '" cannot use its credential: ' +
        redact(err && /** @type {any} */ (err).message ? /** @type {any} */ (err).message : String(err))
      ))
    }

    // Tests inject a stand-in here: without a seam the auth mapping below was
    // never executed by any test, which is how a password from the credential
    // file went to ssh2 as no authentication at all.
    const ClientClass = this.deps && this.deps.clientClass ? this.deps.clientClass : await loadClient()

    return new Promise((resolve, reject) => {
      const client = new ClientClass()
      let settled = false
      const fail = (err) => {
        if (settled) return
        settled = true
        try { client.end() } catch {}
        reject(connectFailure(err, m))
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
    // Refuse a command that cannot be sent before opening a connection for it.
    const bytes = Buffer.byteLength(String(command ?? ''), 'utf8')
    if (bytes > MAX_COMMAND_BYTES) {
      throw noCooldown(new Error(
        'The command for "' + alias + '" is ' + bytes + ' bytes; a single SSH exec request carries at most ' +
        MAX_COMMAND_BYTES + ' (the transport packet limit is 35000). Write the script with ssh_write and ' +
        'run it from there, or split the command.'
      ))
    }
    const client = await this.connect(alias, { sessionPassword })
    this.beginOp(alias)
    try {
      return await this.#execOn(alias, client, command, timeoutMs)
    } catch (err) {
      throw explainGone(err, alias)
    } finally {
      this.endOp(alias)
    }
  }

  async #execOn(alias, client, command, timeoutMs) {
    const limit = timerValue(pick(timeoutMs || undefined, pick(this.config.commandTimeoutMs, 20000)), 20000)
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
          signal: null,
          timedOut: true,
          dropped: false,
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
          // The timeline is what the caller renders, so it has to draw from the
          // same budget as the accumulators. Pushing every chunk and letting the
          // budget cap only the unused strings bypassed maxOutputChars entirely.
          const kept = budget.append(out, text)
          if (kept) timeline.push({ stream: 'out', text: kept })
        })
        s.stderr.on('data', (d) => {
          const text = Buffer.isBuffer(d) ? d.toString('utf8') : String(d)
          const kept = budget.append(err, text)
          if (kept) timeline.push({ stream: 'err', text: kept })
        })
        // close(code, signal): a process killed by a signal reports no code.
        s.on('close', (code, signal) => {
          const named = typeof signal === 'string' && signal.length > 0
          settle({
            stdout: out.text,
            stderr: err.text,
            code: typeof code === 'number' ? code : null,
            signal: named ? signal : null,
            timedOut: false,
            // A shell always reports something when the command ends: an exit
            // status or a signal. Neither means the channel died under it — a
            // dropped network, or this plugin evicting the connection — and the
            // output is only what arrived before that. Saying so is the
            // difference between "it printed nothing" and "we lost the rest".
            dropped: typeof code !== 'number' && !named,
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
    } catch (err) {
      throw explainGone(err, alias)
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
      timeoutMs: timerValue(pick(timeoutMs || undefined, pick(this.config.sftpTimeoutMs, 30000)), 30000),
    })
  }

  /** @param {string} alias @param {string} remotePath @param {{timeoutMs?: number, sessionPassword?: string, createDirs?: boolean}} [opts] */
  async writeFile(alias, remotePath, content, opts = {}) {
    this.beginOp(alias)
    try {
      return await this.#writeFileOn(alias, remotePath, content, opts)
    } catch (err) {
      throw explainGone(err, alias)
    } finally {
      this.endOp(alias)
    }
  }

  /**
   * @param {string} alias
   * @param {string} remotePath
   * @param {string|Buffer} content
   * @param {{sessionPassword?: string, timeoutMs?: number, createDirs?: boolean}} [inline]
   */
  async #writeFileOn(alias, remotePath, content, { sessionPassword, timeoutMs, createDirs } = {}) {
    // See readFile: reject a bad path before touching the network.
    normalizeRemotePath(remotePath)
    const client = await this.connect(alias, { sessionPassword })
    return await writeRemoteFile(client, remotePath, content, {
      timeoutMs: timerValue(pick(timeoutMs || undefined, pick(this.config.sftpTimeoutMs, 30000)), 30000),
      createDirs: createDirs === true,
    })
  }

  /** @param {string} alias @param {string} remotePath @param {{timeoutMs?: number, sessionPassword?: string}} [opts] */
  async list(alias, remotePath, opts = {}) {
    this.beginOp(alias)
    try {
      return await this.#listOn(alias, remotePath, opts)
    } catch (err) {
      throw explainGone(err, alias)
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
      timeoutMs: timerValue(pick(timeoutMs || undefined, pick(this.config.sftpTimeoutMs, 30000)), 30000),
    })
  }
  /**
   * @param {string} alias
   * @param {{force?: boolean}} [inline]
   */
  async closeOne(alias, { force = false } = {}) {
    const e = this.entries.get(alias)
    if (!e) return { closed: false, confirmed: false }
    // A handshake can be in flight. Closing now finds no client and reports
    // that there was nothing to close, while the connection that lands a
    // moment later stays open -- the opposite of what the caller asked for.
    if (e.ready) {
      if (!force) return { closed: false, confirmed: false, busy: this.isBusy(alias), pending: true }
      const landing = e.ready
      e.ready = null
      landing.then(
        (client) => { closeClient(client, pick(this.config.closeTimeoutMs, 1500)).catch(() => {}) },
        () => { /* the handshake failed; nothing landed */ },
      )
      return { closed: false, confirmed: false, pending: true }
    }
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

    // A handshake that is still running has no client yet; nulling its entry
    // would orphan the connection when it lands, leaving a socket nobody ever
    // closes. Arrange for that arrival to be closed too.
    for (const [, e] of this.entries) {
      if (!e.ready) continue
      const landing = e.ready
      e.ready = null
      landing.then(
        (client) => { closeClient(client, pick(this.config.closeTimeoutMs, 1500)).catch(() => {}) },
        () => { /* the handshake failed; nothing landed */ },
      )
    }

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