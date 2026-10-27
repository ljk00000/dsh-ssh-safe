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
import { homedir } from 'node:os'
import { resolveAuth, redact, machineFromEnv, envNames } from './credentials.js'
import { checkHostKey } from './hostkey.js'

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
      e = { client: null, ready: null, lastError: '', nextAttemptAt: 0 }
      this.entries.set(alias, e)
    }
    return e
  }

  /** Machine definition merged from env (+ explicit host override for one-offs). */
  describe(alias) {
    return machineFromEnv(alias)
  }

  async connect(alias, { sessionPassword, trustHostKey } = {}) {
    const e = this.entry(alias)
    if (e.client) return e.client
    if (Date.now() < e.nextAttemptAt) {
      throw new Error(
        'Refusing to retry ' + alias + ' yet (last failure: ' + (e.lastError || 'unknown') + ')'
      )
    }
    if (e.ready) return e.ready

    e.ready = this.#open(alias, e, { sessionPassword, trustHostKey })
      .then((client) => {
        e.client = client
        e.lastError = ''
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
        if (e.client === client) e.client = null
        if (!settled) fail(new Error('connection closed before the handshake completed'))
      })

      if (typeof client.connect !== 'function') return fail(new Error('ssh2 Client is unavailable'))
      // hostVerifier must be set before connect().
      connectConfig.hostVerifier = (keyBlob) => {
        const verdict = checkHostKey({
          dshHome: this.deps.dshHome,
          host: m.host,
          port: m.port || 22,
          keyBlob,
          policy: this.config.hostKeyPolicy === 'off' ? 'off' : (m.hostKeyPolicy === 'tofu' ? 'tofu' : this.config.hostKeyPolicy),
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
      let out = ''
      let errOut = ''
      let truncated = false
      let done = false
      const finish = (result) => {
        if (done) return
        done = true
        clearTimeout(timer)
        resolve(result)
      }
      const timer = setTimeout(() => {
        finish({ stdout: out, stderr: errOut, code: null, timedOut: true, truncated })
      }, limit)

      client.exec(command, (err, stream) => {
        if (err) {
          clearTimeout(timer)
          done = true
          return reject(new Error(redact(err.message)))
        }
        const push = (target, chunk) => {
          const text = String(chunk)
          if (target === 'out') {
            if (out.length >= cap) { truncated = true; return }
            out += text.slice(0, cap - out.length)
            if (text.length > cap - (out.length - text.length)) truncated = true
          } else {
            if (errOut.length >= cap) { truncated = true; return }
            errOut += text.slice(0, cap - errOut.length)
          }
        }
        stream.on('data', (d) => push('out', d))
        stream.stderr.on('data', (d) => push('err', d))
        stream.on('close', (code) => {
          finish({ stdout: out, stderr: errOut, code: typeof code === 'number' ? code : null, timedOut: false, truncated })
        })
      })
    })
  }

  async readFile(alias, remotePath, { maxBytes, sessionPassword } = {}) {
    const cap = maxBytes || this.config.maxFileBytes || 1048576
    const client = await this.connect(alias, { sessionPassword })
    return await new Promise((resolve, reject) => {
      client.sftp((err, sftp) => {
        if (err) return reject(new Error(redact(err.message)))
        const chunks = []
        let size = 0
        let truncated = false
        const rs = sftp.createReadStream(remotePath)
        rs.on('data', (c) => {
          if (size >= cap) { truncated = true; return }
          const take = c.subarray(0, cap - size)
          chunks.push(take)
          size += take.length
          if (take.length < c.length) truncated = true
        })
        rs.on('error', (e) => reject(new Error(redact(e.message))))
        rs.on('end', () => resolve({ content: Buffer.concat(chunks).toString('utf8'), truncated, bytes: size }))
      })
    })
  }

  async writeFile(alias, remotePath, content, { sessionPassword } = {}) {
    const client = await this.connect(alias, { sessionPassword })
    return await new Promise((resolve, reject) => {
      client.sftp((err, sftp) => {
        if (err) return reject(new Error(redact(err.message)))
        const ws = sftp.createWriteStream(remotePath)
        ws.on('error', (e) => reject(new Error(redact(e.message))))
        ws.on('close', () => resolve({ bytes: Buffer.byteLength(content) }))
        ws.end(content)
      })
    })
  }

  async list(alias, remotePath, { sessionPassword } = {}) {
    const client = await this.connect(alias, { sessionPassword })
    return await new Promise((resolve, reject) => {
      client.sftp((err, sftp) => {
        if (err) return reject(new Error(redact(err.message)))
        sftp.readdir(remotePath, (e, items) => {
          if (e) return reject(new Error(redact(e.message)))
          resolve(items.map((it) => ({
            name: it.filename,
            size: it.attrs.size,
            dir: (it.attrs.mode & 0o040000) !== 0,
            mtime: it.attrs.mtime ? new Date(it.attrs.mtime * 1000).toISOString() : null,
          })))
        })
      })
    })
  }

  closeAll() {
    for (const [, e] of this.entries) {
      try { e.client?.end() } catch {}
      e.client = null
    }
    this.entries.clear()
  }
}
