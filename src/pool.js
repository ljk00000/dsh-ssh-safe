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
import { resolveAuth, redact, machineFromEnv, envNames } from './credentials.js'
import { checkHostKey } from './hostkey.js'
import { Utf8Collector, OutputBudget } from './buffer.js'
import { normalizeRemotePath } from './remote-path.js'
import { closeClient } from './close.js'

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
  if (VALID_POLICIES.has(machine)) return machine
  const global = String(globalPolicy ?? '').trim().toLowerCase()
  if (VALID_POLICIES.has(global)) return global
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
    /** @type {Map<string, {client: any, ready: Promise<any>, lastError: string, nextAttemptAt: number}>} */
    this.entries = new Map()
  }

  entry(alias) {
    let e = this.entries.get(alias)
    if (!e) {
      e = { client: null, ready: null, lastError: '', nextAttemptAt: 0, lastUsedAt: Date.now() }
      this.entries.set(alias, e)
    }
    e.lastUsedAt = Date.now()
    return e
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
  async evictIdle(keep, protect) {
    const limit = Number(keep)
    if (!Number.isFinite(limit) || limit <= 0) return []

    const live = [...this.entries.entries()].filter(([alias, e]) => e.client && alias !== protect)
    const protectedLive = [...this.entries.entries()].filter(([alias, e]) => e.client && alias === protect)
    // Count the protected connection against the ceiling.
    if (live.length + protectedLive.length <= limit) return []
    const allowedVictims = live.length

    // Oldest first; keep the most recently used.
    live.sort((a, b) => (a[1].lastUsedAt || 0) - (b[1].lastUsedAt || 0))
    const excess = live.length + protectedLive.length - limit
    if (excess <= 0) return []
    const victims = live.slice(0, Math.min(excess, allowedVictims))
    const closed = []
    for (const [alias] of victims) {
      await this.closeOne(alias)
      closed.push(alias)
    }
    return closed
  }

  /** Machine definition merged from env (+ explicit host override for one-offs). */
  describe(alias) {
    return machineFromEnv(alias)
  }

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

    if (e.client) return e.client

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
        e.nextAttemptAt = Date.now() + (this.config.reconnectCooldownMs || 15000)
        throw err
      })
      .finally(() => { e.ready = null })

    return e.ready
  }

  async #open(alias, e, { sessionPassword, trustHostKey }) {
    const auth = resolveAuth(alias, {
      sessionPassword,
      allowSessionPassword: this.config.allowSessionPassword === true,
    })
    const m = auth.machine
    if (!m.host || !m.username) {
      const names = envNames(alias)
      const need = []
      if (!m.host) need.push(names.host)
      if (!m.username) need.push(names.user)
      throw new Error(
        'Machine "' + alias + '" is not configured: missing ' + need.join(', ') +
        '. Set the environment variable(s) and restart DeepSeek Harness, or pass host/username ' +
        'explicitly to ssh_connect. Nothing was read from disk.'
      )
    }
    if (auth.kind === 'none') {
      throw new Error(
        'Machine "' + alias + '" has no credentials. Set ' + envNames(alias).password +
        ' or ' + envNames(alias).keyPath + '.' +
        (this.config.allowSessionPassword
          ? ' Or pass password to ssh_connect (this profile allows it).'
          : ' Passing a password in conversation is disabled for this profile.')
      )
    }

    const connectConfig = {
      host: m.host,
      port: m.port || 22,
      username: m.username,
      readyTimeout: this.config.connectTimeoutMs || 15000,
      keepaliveInterval: this.config.keepaliveIntervalMs || 20000,
      keepaliveCountMax: 3,
    }

    if (auth.kind === 'session-password' || (auth.kind === 'env-password')) {
      connectConfig.password = auth.password
    } else if (auth.kind === 'env-key') {
      connectConfig.privateKey = readFileSync(expandHome(auth.keyPath))
      if (auth.passphrase) connectConfig.passphrase = auth.passphrase
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

  async exec(alias, command, { timeoutMs, sessionPassword } = {}) {
    const client = await this.connect(alias, { sessionPassword })
    const limit = timeoutMs || this.config.commandTimeoutMs || 20000
    const cap = this.config.maxOutputChars || 200000

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

  async readFile(alias, remotePath, { maxBytes, sessionPassword, timeoutMs } = {}) {
    const target = normalizeRemotePath(remotePath)
    // maxBytes can only tighten the configured ceiling, never raise it: a tool
    // argument must not be able to pull an arbitrary amount of the remote file
    // into memory.
    const configured = this.config.maxFileBytes || 1048576
    const requested = Number(maxBytes) || 0
    const cap = requested > 0 ? Math.min(requested, configured) : configured
    const limit = timeoutMs || this.config.sftpTimeoutMs || 30000
    const client = await this.connect(alias, { sessionPassword })
    return await new Promise((resolve, reject) => {
      const collector = new Utf8Collector(cap)
      let settled = false
      let timer = null
      let rs = null
      const settle = (result, error) => {
        if (settled) return
        settled = true
        if (timer) clearTimeout(timer)
        if (rs) {
          try { rs.removeAllListeners('data'); rs.removeAllListeners('error') } catch {}
          try { rs.destroy() } catch {}
        }
        if (error) reject(error)
        else resolve(result)
      }

      timer = setTimeout(() => {
        settle(null, new Error('reading ' + target + ' did not complete within ' + limit + 'ms'))
      }, limit)

      client.sftp((error, sftp) => {
        if (error) return settle(null, new Error(redact(error.message)))
        rs = sftp.createReadStream(target)
        rs.on('data', (chunk) => {
          collector.push(chunk)
          if (collector.truncated) settle({ content: collector.toString(), truncated: true, bytes: collector.bytes })
        })
        rs.on('error', (e) => settle(null, new Error(redact(e.message))))
        rs.on('end', () => settle({ content: collector.toString(), truncated: collector.truncated, bytes: collector.bytes }))
        rs.on('close', () => settle({ content: collector.toString(), truncated: collector.truncated, bytes: collector.bytes }))
      })
    })
  }

  async writeFile(alias, remotePath, content, { sessionPassword, timeoutMs } = {}) {
    const target = normalizeRemotePath(remotePath)
    const client = await this.connect(alias, { sessionPassword })
    const limit = timeoutMs || this.config.sftpTimeoutMs || 30000
    const payload = Buffer.isBuffer(content) ? content : Buffer.from(String(content ?? ''), 'utf8')

    return await new Promise((resolve, reject) => {
      let settled = false
      let timer = null
      let ws = null
      const settle = (result, error) => {
        if (settled) return
        settled = true
        if (timer) clearTimeout(timer)
        if (ws) {
          try { ws.removeAllListeners('error'); ws.removeAllListeners('close'); ws.removeAllListeners('finish') } catch {}
          try { ws.destroy() } catch {}
        }
        if (error) reject(error)
        else resolve(result)
      }

      // ssh2's write stream can fail without emitting 'error' or 'close' (a
      // server that drops the channel mid-transfer is one case), which used to
      // hang the tool forever. A deadline is the only reliable backstop.
      timer = setTimeout(() => {
        settle(null, new Error(
          'writing ' + target + ' did not complete within ' + limit + 'ms' +
          ' — the remote channel may have dropped'
        ))
      }, limit)

      client.sftp((err, sftp) => {
        if (err) return settle(null, new Error(redact(err.message)))
        ws = sftp.createWriteStream(target)
        ws.on('error', (e) => settle(null, new Error(redact(e.message))))
        ws.on('close', () => settle({ bytes: payload.length, path: target }))
        // 'finish' fires when all data was handed to SFTP; 'close' can lag.
        ws.on('finish', () => settle({ bytes: payload.length, path: target }))
        ws.end(payload)
      })
    })
  }

  async list(alias, remotePath, { sessionPassword, timeoutMs } = {}) {
    const target = normalizeRemotePath(remotePath || '.', { allowRelative: true })
    const limit = timeoutMs || this.config.sftpTimeoutMs || 30000
    const client = await this.connect(alias, { sessionPassword })
    return await new Promise((resolve, reject) => {
      let settled = false
      const timer = setTimeout(() => {
        if (settled) return
        settled = true
        reject(new Error('listing ' + target + ' did not complete within ' + limit + 'ms'))
      }, limit)
      const settle = (result, error) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        if (error) reject(error)
        else resolve(result)
      }
      client.sftp((err, sftp) => {
        if (err) return settle(null, new Error(redact(err.message)))
        sftp.readdir(target, (e, items) => {
          if (e) return settle(null, new Error(redact(e.message)))
          settle({ path: target, items: items.map((it) => ({
            name: it.filename,
            size: it.attrs.size,
            dir: (it.attrs.mode & 0o040000) !== 0,
            mtime: it.attrs.mtime ? new Date(it.attrs.mtime * 1000).toISOString() : null,
          })) })
        })
      })
    })
  }

  /**
   * Close every pooled connection.
   *
   * ssh2's end() is asynchronous; the entries are dropped synchronously so the
   * next call reconnects, and the sockets are given a bounded grace period to
   * close rather than leaking when the process keeps running.
   */
  /** Close one alias' connection, keeping the pool entry usable. */
  async closeOne(alias) {
    const e = this.entries.get(alias)
    if (!e) return { closed: false, confirmed: false }
    const client = e.client
    e.client = null
    e.ready = null
    e.fingerprint = null
    e.credentialIdentity = undefined
    e.nextAttemptAt = 0
    if (!client) return { closed: false, confirmed: false }
    const confirmed = await closeClient(client, this.config.closeTimeoutMs || 1500)
    return { closed: true, confirmed }
  }

  async closeAll() {
    const clients = []
    for (const [, e] of this.entries) {
      if (e.client) clients.push(e.client)
      e.client = null
      e.ready = null
      e.fingerprint = null
      e.credentialIdentity = undefined
      e.nextAttemptAt = 0
    }
    this.entries.clear()
    await Promise.all(clients.map((client) => closeClient(client, this.config.closeTimeoutMs || 1500)))
  }
}
