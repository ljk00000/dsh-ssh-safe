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
import { StringDecoder } from 'node:string_decoder'
import { homedir } from 'node:os'
import { isIPv6 } from 'node:net'
import { redact, envNames } from './credentials.js'
import { connectOptions, expandHome } from './connect.js'
import { credentialFor, machineDefinition } from './machines.js'
import { checkHostKey } from './hostkey.js'
import { Utf8Collector, OutputBudget, countCodePoints } from './buffer.js'
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
 * Host as it should be printed: an IPv6 literal in brackets, once.
 *
 * 'user@::1:22' reads as host "::1:22"; 'user@[::1]:22' cannot be misread. A
 * host that already carries brackets is left alone rather than doubled.
 *
 * @param {string} host
 * @returns {string}
 */
export function formatHost(host) {
  const text = String(host || '')
  const bare = text.startsWith('[') && text.endsWith(']') ? text.slice(1, -1) : text
  // isIPv6, not "contains a colon": 'example.com:2222' and 'ssh://h' also
  // contain colons, and bracketing them produced 'u@[ssh://h]:22'.
  if (isIPv6(bare)) return '[' + bare + ']'
  // A colon in a value that is not an IPv6 literal is a sign the address was
  // pasted whole; quoting keeps "u@a:b:22" from reading as host "a:b:22".
  return text.includes(':') ? '"' + text + '"' : text
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
 * @param {{host?: string, port?: number, username?: string, alias?: string}} [m]
 * @param {{lean?: boolean}} [options] hide the address when machineInventory is 'alias'
 * @returns {Error}
 */
export function connectFailure(err, m, { lean = false } = {}) {
  const raw = redact(err && /** @type {any} */ (err).message ? /** @type {any} */ (err).message : String(err))
  // The socket error itself carries the address: "connect ECONNREFUSED
  // 127.0.0.1:1". Masking only the prefix left that in the message (and in the
  // audit record) under machineInventory: 'alias'.
  const shown = lean ? hideAddress(raw, m) : raw
  // Already decorated, or already explains itself: the host key store writes a
  // complete sentence naming the host, the fingerprint and the way out, and the
  // ssh_doctor line above it already carries the target.
  if (/^(Could not connect to |Refusing to retry )/.test(raw)) return new Error(raw)
  if (/^(Unknown host|Host key verification failed|Host key changed|HOST KEY CHANGED)/i.test(raw)) return new Error(raw)
  // machineInventory: 'alias' keeps the topology out of the conversation. The
  // success paths honoured it; every failure message still said
  // "root@10.9.8.7:22", which is where a transcript is most likely to be shared.
  const target = m && m.host
    ? lean
      ? 'machine "' + (m.alias || 'unknown') + '" (address hidden)'
      // user@::1:22 reads as host "::1:22"; bracketing is how ssh prints an IPv6
      // literal, and it is the only thing that makes the port unambiguous.
      : (m.username ? m.username + '@' : '') + formatHost(m.host) + ':' + (m.port || 22)
    : 'the remote host'
  /** @type {Array<[RegExp, string]>} */
  const hints = [
    [/ECONNREFUSED/i, 'nothing is listening on that port'],
    // EPIPE and ECONNABORTED are the same situation under a different errno:
    // the peer accepted the socket and closed it before the SSH banner, which is
    // what a non-SSH port does. Linux reports EPIPE where Windows reports
    // ECONNRESET, and the caller should not need to know which.
    [/ECONNRESET|EPIPE|ECONNABORTED/i, 'the server closed the connection during the handshake — the port may not be sshd'],
    [/ENOTFOUND|EAI_AGAIN/i, 'the host name did not resolve'],
    [/Timed out while waiting for handshake|ETIMEDOUT/i, 'no SSH banner arrived — the port may not speak SSH, or a firewall is dropping packets'],
    // ssh2 says only "Connection lost before handshake" when the peer speaks
    // something that is not SSH (an HTTP or proxy service on that port, which is
    // what happens when port 80 or 443 is used by mistake).
    [/Connection lost before handshake/i, 'the port answered but not with SSH — check the port number; an HTTP or proxy service answers like this'],
    [/All configured authentication methods failed|Permission denied/i, 'the server rejected the credentials — check the user, the key or password, and authorized_keys'],
    [/Host key verification failed|Unknown host/i, 'the host key store does not trust this host; run ssh_connect with trustHostKey once'],
  ]
  const hint = hints.find(([pattern]) => pattern.test(raw))
  const extra = /ENOTFOUND|EAI_FAIL|EAI_AGAIN/i.test(raw)
    ? hostShapeHint(m && m.host)
    : /authentication methods failed|Permission denied/i.test(raw) ? userShapeHint(m && m.username) : ''
  const advice = [hint ? hint[1] : '', extra].filter(Boolean).join('; ')
  return new Error('Could not connect to ' + target + ': ' + shown + (advice ? ' (' + advice + ')' : ''))
}

/**
 * Tell the remote command that nothing will ever arrive on its stdin.
 *
 * Nothing in this plugin writes to a channel, so leaving stdin open means every
 * command that reads input waits for a line that never comes: 'sudo apt-get
 * install' sat for the full command timeout with no output and the message
 * blamed the deadline. With EOF the command fails at once and says why
 * ('sudo: a terminal is required', 'Aborted', ...).
 *
 * eof(), not end(): ssh2's Channel is a Duplex and its writable side has no wire
 * effect -- measured, end() left the channel open while eof() moved the outgoing
 * state to 'eof' (CHANNEL_EOF). The plain end() is kept as a fallback for a
 * channel object that has no eof().
 *
 * @param {any} channel
 */
export function sendStdinEof(channel) {
  if (!channel) return
  try {
    if (typeof channel.eof === 'function') channel.eof()
    else if (typeof channel.end === 'function') channel.end()
  } catch { /* the channel may already be gone; the command fails on its own */ }
}

/**
 * Replace a host (and host:port) inside a message with a placeholder.
 *
 * Word-ish boundaries so a one-letter host cannot mangle the sentence around it.
 *
 * @param {string} text
 * @param {{host?: string, port?: number}} [m]
 * @returns {string}
 */
export function hideAddress(text, m) {
  const host = String((m && m.host) || '')
  if (!host) return text
  const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const port = String((m && m.port) || 22)
  let out = String(text)
  out = out.replace(new RegExp('(?<![A-Za-z0-9.-])' + escapeRegExp(host) + ':' + port + '(?![A-Za-z0-9.-])', 'g'), '<host hidden>')
  return out.replace(new RegExp('(?<![A-Za-z0-9.-])' + escapeRegExp(host) + '(?![A-Za-z0-9.-])', 'g'), '<host hidden>')
}

/**
 * Explain a host value that cannot be a host name.
 *
 * A resolve failure is where these surface, and "the host name did not resolve"
 * is true but unhelpful when the value is a URL, a user@host pair or host:port
 * pasted into the wrong field.
 *
 * @param {string} [host]
 * @returns {string} a sentence, or ''
 */
function hostShapeHint(host) {
  const text = String(host || '')
  if (!text) return ''
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    return 'the host looks like a URL — use the bare host name and put the port in the port setting'
  }
  if (text.includes('@')) {
    return 'the host contains "@" — the user name belongs in the user field'
  }
  if (/:\d+$/.test(text)) {
    return 'the host ends with a port — put it in the port setting and use the bare host name'
  }
  if (text !== text.trim()) {
    return 'the host has leading or trailing spaces'
  }
  // '#' first: 'example.com # note' contains both, and the comment is the
  // informative half -- anything after '#' in a config file was meant as a note.
  if (text.includes('#')) {
    return "the host contains '#' — in a config file everything after it is a comment and is not part of the name"
  }
  // A space in the middle survives trim() and then fails at DNS, where the
  // message is "the host name did not resolve" -- true, and nowhere near the
  // actual problem.
  if (/\s/.test(text)) {
    return 'the host contains a space — host names cannot contain spaces'
  }
  if (/[\\/]/.test(text)) {
    return 'the host contains a path separator'
  }
  return ''
}

/**
 * Explain a user name that cannot be an account name.
 *
 * 'tester@host' pasted into the user field fails authentication, and the server's
 * "All configured authentication methods failed" points at the credentials
 * rather than at the field that is wrong.
 *
 * @param {string} [username]
 * @returns {string} a sentence, or ''
 */
function userShapeHint(username) {
  const text = String(username || '')
  if (!text) return ''
  if (text.includes('@')) return 'the user contains "@" — put only the account name, without the host'
  if (/[\u0000-\u001f]/.test(text)) return 'the user contains a control character (a newline from a pasted value?)'
  if (/\s/.test(text)) return 'the user contains whitespace'
  return ''
}

/**
 * A host or user name that can never work, checked before dialling.
 *
 * Both were only caught after a real attempt: a user name with a newline stalled
 * until the handshake timed out, and a host with a space failed at DNS. Neither
 * message pointed at the field, and both cost a timeout.
 *
 * @param {{host?: string, username?: string}} m
 * @returns {string} a message naming the field, or '' when the values are usable
 */
export function identityProblem(m) {
  const host = String((m && m.host) || '')
  const user = String((m && m.username) || '')
  const hostHint = hostShapeHint(host)
  // Only the shapes that cannot be repaired by retrying: a URL or a host:port is
  // a different field's value, and a space or '#' is not a legal character.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(host)) return 'the host field holds a URL: ' + hostHint
  // '#' before whitespace: 'example.com # note' has both, and the comment is the
  // informative one.
  if (host.includes('#')) return 'the host field is unusable: ' + hostHint
  if (/\s/.test(host)) return 'the host field is unusable: ' + hostHint
  if (/[\u0000-\u001f]/.test(user)) return 'the user field is unusable: ' + userShapeHint(user)
  return ''
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
 * @property {string} [hostKeyPolicy] effective policy for this connection
 * @property {boolean} [hostKeyVerified] false when the policy was 'off'
 * @property {boolean} [hostKeyFirstSeen] true when this run recorded the key
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
    /** Writes in flight per remote target, so two never interleave. */
    this.writeQueue = new Map()
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
    // Do NOT touch lastUsedAt here. connect() asks entry() for the slot and then
    // reads lastUsedAt to decide whether to probe; refreshing it on access made
    // the idle time zero on every call, so the health check never ran and a
    // dropped connection was only noticed when a command timed out -- the exact
    // failure the probe exists to avoid. Used at is set when an operation is
    // handed a connection (connect) or one is established (#open).
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

    // Evict what is idle. A connection with a command in flight is left alone:
    // force-closing it aborts real work -- a build, a transfer -- because the
    // agent touched a ninth machine while the eighth was busy. The ceiling is a
    // resource guard, not a reason to kill a running command, and the overflow
    // is bounded by how many operations can be in flight at once. The next
    // acquire evicts again, by which time those connections are idle.
    const closed = []
    let stillOver = false
    for (const [alias] of candidates) {
      if (closed.length >= excess) break
      const result = await this.closeOne(alias, { force: false })
      if (result.closed) closed.push(alias)
      else if (result.busy) stillOver = true
    }
    this.overLimit = stillOver && closed.length < excess
    return closed
  }

  /**
   * Connection count and ceiling, for diagnostics.
   * @returns {{live: number, limit: number, overLimit: boolean, aliases: string[]}}
   */
  connectionStats() {
    const aliases = [...this.entries.entries()]
      .filter(([, e]) => e.client)
      .map(([alias]) => alias)
    const limit = Number(this.config.maxConnections)
    return {
      live: aliases.length,
      limit: Number.isFinite(limit) ? limit : 0,
      // True while the cap is exceeded because the connections that would have
      // been evicted are running something.
      overLimit: aliases.length > (Number.isFinite(limit) ? limit : 0) && Boolean(this.overLimit),
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
   * @param {{sessionPassword?: string, trustHostKey?: boolean, force?: boolean, signal?: AbortSignal}} [options]
   */
  async connect(alias, { sessionPassword, trustHostKey, force = false, signal } = {}) {
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
      // Never probe a connection that is carrying work: a probe that fails for
      // an unrelated reason (the server is at MaxSessions, or slow to open a
      // channel) closes the connection and takes the running command with it --
      // the same mistake the eviction ceiling made. A dead connection announces
      // itself to the operation using it.
      if (probeAfter > 0 && idleMs > probeAfter && !this.isBusy(alias)) {
        const alive = await this.#probe(alias, e.client)
        if (!alive) {
          await this.closeOne(alias, { force: true })
          e.lastError = 'previous connection was dead; reconnecting'
        } else {
          e.lastUsedAt = Date.now()
          // A ceiling exceeded while a command was running must be enforced once
          // that command ends. Only a NEW connection used to evict, so reusing an
          // alias left maxConnections-1 connections open indefinitely (measured:
          // 'maxConnections: 1' kept 2 sockets after both went idle).
          await this.evictIdle(Number(this.config.maxConnections), alias)
          return e.client
        }
      } else {
        e.lastUsedAt = Date.now()
        await this.evictIdle(Number(this.config.maxConnections), alias)
        return e.client
      }
    }

    if (!force && Date.now() < e.nextAttemptAt) {
      const waitMs = Math.max(0, e.nextAttemptAt - Date.now())
      throw new Error(
        'Refusing to retry ' + alias + ' for another ' + Math.ceil(waitMs / 1000) + 's ' +
        '(last failure: ' + (e.lastError || 'unknown') + '). ' +
        // This message is produced for every tool, but only ssh_connect has a
        // force option: ssh_exec told the caller to "pass force: true" and there was
        // no such argument to pass.
        'A successful connect clears this. ssh_connect accepts force: true to try ' +
        'immediately (and trustHostKey: true on ssh_connect to accept a first-contact ' +
        'key in the same call); ssh_exec, ssh_read, ssh_write and ssh_list do not have ' +
        'a force option.'
      )
    }
    if (e.ready) return e.ready

    // force skips the cooldown for this attempt only.
    if (force) e.nextAttemptAt = 0

    // A cancelled call must stop dialling. Without this, aborting ssh_connect
    // during a stalled handshake waited out the full connectTimeoutMs (measured:
    // 8s for an 8s timeout with the abort at 300ms) and the caller who pressed
    // stop was still made to wait.
    let onAbort = null
    const cancelled = new Promise((_resolve, reject) => {
      if (!signal) return
      if (signal.aborted) {
        // noCooldown() rather than a cast on the next line: without a semicolon
        // after 'const error = ...' the '(...)' cast continues that expression and
        // reads the const before it is initialised (a TypeError at abort time).
        reject(noCooldown(new Error('connection to ' + alias + ' was cancelled before it started')))
        return
      }
      onAbort = () => {
        const error = noCooldown(new Error('connection to ' + alias + ' was cancelled while dialling'))
        reject(error)
        const client = e.client
        if (client) { try { client.end() } catch { /* already gone */ } }
      }
      signal.addEventListener('abort', onAbort, { once: true })
    })
    const opened = this.#open(alias, e, { sessionPassword, trustHostKey })
    e.ready = Promise.race([opened, cancelled])
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
      .finally(() => {
        if (onAbort && signal) signal.removeEventListener('abort', onAbort)
        e.ready = null
      })

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
    let timer
    try {
      const deadline = Number(this.config.healthCheckTimeoutMs) || 3000
      const result = await Promise.race([
        new Promise((resolve) => {
          try {
            client.exec('true', (err, stream) => {
              // A stream that arrives after the deadline resolved this promise
              // still has to be released.
              if (err) return resolve(false)
              try { stream.destroy() } catch {}
              resolve(true)
            })
          } catch { resolve(false) }
        }),
        new Promise((resolve) => { timer = setTimeout(() => resolve(false), deadline) }),
      ])
      return result === true
    } catch {
      return false
    } finally {
      // Promise.race leaves the losing timer pending: every probe kept the
      // event loop alive for up to healthCheckTimeoutMs after the answer.
      if (timer) clearTimeout(timer)
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
        '. Set it in the plugin settings (machines.' + alias + ') or in the settings page, ' +
        'or as the environment variable(s) ' + need.join(', ') +
        '. Nothing was read from disk.'
      ))
    }
    // A port that cannot be dialled is a configuration error, not a network
    // one: say which machine, which value and which source, and do not cool down.
    if (m.portProblem) {
      throw noCooldown(new Error(
        'Machine "' + alias + '" cannot be used: ' + m.portProblem + '. ' +
        'Fix the port in that source, then retry.'
      ))
    }
    // A host with a space and a user with a newline both fail much later with a
    // message about DNS or the handshake, so neither names the field that is
    // wrong. Refuse before dialling.
    const identity = identityProblem(m)
    if (identity) {
      throw noCooldown(new Error('Machine "' + alias + '" cannot be used: ' + identity + '.'))
    }
    if (auth.kind === 'none') {
      throw noCooldown(new Error(
        'Machine "' + alias + '" has no credentials. Set ' + envNames(alias).password +
        ' or ' + envNames(alias).keyPath + '. Also checked: SSH_AUTH_SOCK for an agent,' +
        ' which none was found at.' +
        (this.config.allowSessionPassword
          ? ' Or pass password (this profile allows it).'
          : ' Passing a password in conversation is disabled for this profile.') +
        // A credential file that exists but cannot be read is the likeliest
        // reason for "no credentials" right after editing it, and the message
        // above pointed at the environment instead.
        ((auth.warnings || []).length > 0 ? ' ' + auth.warnings.join(' ') : '')
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
        reject(connectFailure(err, m, { lean: this.config.machineInventory === 'alias' }))
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
        // Whether this run is what recorded the key. ssh_doctor says so: "ok"
        // alone let "hostKeyPolicy: off" read like a verified host.
        e.hostKeyPolicy = effectivePolicy(this.config.hostKeyPolicy, m.hostKeyPolicy)
        e.hostKeyFirstSeen = verdict.firstSeen === true
        e.hostKeyVerified = e.hostKeyPolicy !== 'off'
        return true
      }
      client.connect(connectConfig)
    })
  }

  /**
   * @param {string} alias
   * @param {string} command
   * @param {{timeoutMs?: number, sessionPassword?: string, signal?: AbortSignal}} [inline]
   */
  async exec(alias, command, { timeoutMs, sessionPassword, signal } = {}) {
    // Refuse a command that cannot be sent before opening a connection for it.
    const bytes = Buffer.byteLength(String(command ?? ''), 'utf8')
    if (bytes > MAX_COMMAND_BYTES) {
      throw noCooldown(new Error(
        'The command for "' + alias + '" is ' + bytes + ' bytes; a single SSH exec request carries at most ' +
        MAX_COMMAND_BYTES + ' (the transport packet limit is 35000). Write the script with ssh_write and ' +
        'run it from there, or split the command.'
      ))
    }
    const client = await this.connect(alias, { sessionPassword, signal })
    this.beginOp(alias)
    try {
      return await this.#execOn(alias, client, command, timeoutMs, signal)
    } catch (err) {
      throw explainGone(err, alias)
    } finally {
      this.endOp(alias)
    }
  }

  async #execOn(alias, client, command, timeoutMs, signal) {
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

      let abortListener = null
      const settle = (result, error) => {
        if (settled) return
        settled = true
        if (timer) clearTimeout(timer)
        if (abortListener && signal) {
          try { signal.removeEventListener('abort', abortListener) } catch {}
          abortListener = null
        }
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
          droppedChars: budget.dropped,
          timeline,
        }
        // Let the TERM message flush before the channel is destroyed.
        setImmediate(() => settle(timedOutResult))
      }, limit)

      // The caller can cancel: the harness aborts exec.signal when the user
      // stops the turn, and a remote command left running is a side effect the
      // user asked to end. Same treatment as a deadline: TERM the channel, keep
      // what was printed, and let the flush happen before the destroy.
      const cancel = () => {
        if (settled) return
        try { if (stream) stream.signal('TERM') } catch {}
        const cancelledResult = {
          stdout: out.text,
          stderr: err.text,
          code: null,
          signal: null,
          timedOut: false,
          cancelled: true,
          dropped: false,
          truncated: budget.truncated,
          droppedChars: budget.dropped,
          timeline,
        }
        setImmediate(() => settle(cancelledResult))
      }
      if (signal) {
        if (signal.aborted) {
          settle(null, new Error('the command was cancelled before it started'))
          return
        }
        abortListener = cancel
        try { signal.addEventListener('abort', abortListener, { once: true }) } catch {}
      }

      client.exec(command, (error, s) => {
        if (error) return settle(null, new Error(redact(error.message)))
        stream = s
        const outDecoder = new StringDecoder('utf8')
        const errDecoder = new StringDecoder('utf8')
        // Close the stdin side at once. Nothing in this plugin ever writes to a
        // channel, so leaving it open means every command that reads input waits
        // for a line that will never arrive: 'sudo apt-get install' sat for the
        // full command timeout with no output and the message blamed the
        // deadline. With EOF the command fails immediately and says why
        // ('sudo: a terminal is required', 'Aborted', ...).
        sendStdinEof(s)
        // Room the error output may take back from stdout.
        //
        // The budget is shared, so a command that prints a lot before failing
        // ('make' with thousands of lines, then one 'Error 2') spent all of it on
        // stdout and stderr arrived to nothing: the exit code was 2 and the only
        // line that explained it had been thrown away. stderr may now trim the
        // tail of stdout to make room, down to half the budget -- the first half
        // of the output plus the error is what a person reads anyway.
        const stdoutFloor = Math.floor(budget.cap / 2)
        const trimTimelineForStdout = (need) => {
          for (let i = timeline.length - 1; i >= 0 && need > 0; i--) {
            const entry = timeline[i]
            if (entry.stream !== 'out') continue
            if (entry.text.length <= need) {
              need -= entry.text.length
              timeline.splice(i, 1)
            } else {
              entry.text = entry.text.slice(0, entry.text.length - need)
              need = 0
            }
          }
        }
        s.on('data', (d) => {
          // A chunk boundary can fall inside a multi-byte character: decoding each
          // chunk on its own turned one '中' (3 bytes) into three U+FFFD. The
          // decoder holds the partial sequence until the rest arrives.
          const text = Buffer.isBuffer(d) ? outDecoder.write(d) : String(d)
          // The timeline is what the caller renders, so it has to draw from the
          // same budget as the accumulators. Pushing every chunk and letting the
          // budget cap only the unused strings bypassed maxOutputChars entirely.
          const kept = budget.append(out, text)
          if (kept) timeline.push({ stream: 'out', text: kept })
        })
        s.stderr.on('data', (d) => {
          const text = Buffer.isBuffer(d) ? errDecoder.write(d) : String(d)
          if (budget.remaining === 0 && out.text.length > stdoutFloor) {
            let need = Math.min(text.length, out.text.length - stdoutFloor)
            // Do not leave the first half of a surrogate pair behind.
            const lastKept = out.text.charCodeAt(out.text.length - need - 1)
            if (lastKept >= 0xd800 && lastKept <= 0xdbff) need += 1
            const removed = out.text.slice(out.text.length - need)
            out.text = out.text.slice(0, out.text.length - need)
            budget.used -= need
            budget.dropped += countCodePoints(removed)
            budget.truncated = true
            out.truncated = true
            trimTimelineForStdout(need)
          }
          const kept = budget.append(err, text)
          if (kept) timeline.push({ stream: 'err', text: kept })
        })
        // close(code, signal): a process killed by a signal reports no code.
        s.on('close', (code, signal) => {
          // Flush whatever the decoders still hold: without it a stream that ends
          // mid-character loses its tail.
          const tailOut = outDecoder.end()
          if (tailOut) {
            const keptOut = budget.append(out, tailOut)
            if (keptOut) timeline.push({ stream: 'out', text: keptOut })
          }
          const tailErr = errDecoder.end()
          if (tailErr) {
            const keptErr = budget.append(err, tailErr)
            if (keptErr) timeline.push({ stream: 'err', text: keptErr })
          }
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
            droppedChars: budget.dropped,
            timeline,
          })
        })
        s.on('error', (e) => settle(null, new Error(redact(e.message))))
      })
    })
  }

  /** @param {string} alias @param {string} remotePath @param {{maxBytes?: number, timeoutMs?: number, sessionPassword?: string, signal?: AbortSignal}} [opts] */
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
   * @param {{maxBytes?: number, sessionPassword?: string, timeoutMs?: number, signal?: AbortSignal}} [inline]
   */
  async #readFileOn(alias, remotePath, { maxBytes, sessionPassword, timeoutMs, signal } = {}) {
    // Validate before connecting: an invalid path is the caller's mistake, and
    // surfacing it as ECONNREFUSED (or as a cooldown) sends the user after a
    // server that is perfectly healthy.
    normalizeRemotePath(remotePath, { file: true })
    // maxBytes can only tighten the configured ceiling: a tool argument must not
    // be able to pull an arbitrary amount of the remote file into memory.
    const configured = pick(this.config.maxFileBytes, 1048576)
    const requested = Number(maxBytes) || 0
    const cap = requested > 0 ? Math.min(requested, configured) : configured
    const client = await this.connect(alias, { sessionPassword, signal })
    return await readRemoteFile(client, remotePath, {
      maxBytes: cap,
      timeoutMs: timerValue(pick(timeoutMs || undefined, pick(this.config.sftpTimeoutMs, 30000)), 30000),
      signal,
    })
  }

  /**
   * Run `task` after everything already queued for `key`, then let the next one
   * run.
   *
   * Two writes to one remote file used to interleave their SFTP chunks: with
   * 300 kB and 1 kB written at the same time the result was 1 kB of B followed by
   * 299 kB of A -- a file that is neither -- while both calls reported success.
   * The queue makes the second writer wait instead, so the file is one of the
   * two contents.
   *
   * @template T
   * @param {string} key
   * @param {() => Promise<T>} task
   * @returns {Promise<T>}
   */
  #enqueueWrite(key, task) {
    const tail = this.writeQueue.get(key) || Promise.resolve()
    // The previous task's failure must not cancel this one.
    const result = tail.then(task, task)
    const guard = result.then(() => {}, () => {})
    this.writeQueue.set(key, guard)
    guard.then(() => {
      if (this.writeQueue.get(key) === guard) this.writeQueue.delete(key)
    })
    return result
  }

  /** @param {string} alias @param {string} remotePath @param {{timeoutMs?: number, sessionPassword?: string, createDirs?: boolean, signal?: AbortSignal, mode?: number}} [opts] */
  async writeFile(alias, remotePath, content, opts = {}) {
    this.beginOp(alias)
    try {
      // Keyed by target, so writes to different files still run in parallel.
      let key = alias + '\u0000' + remotePath
      try { key = alias + '\u0000' + normalizeRemotePath(remotePath) } catch { /* invalid path: the write reports it */ }
      return await this.#enqueueWrite(key, () => this.#writeFileOn(alias, remotePath, content, opts))
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
   * @param {{sessionPassword?: string, timeoutMs?: number, createDirs?: boolean, signal?: AbortSignal, mode?: number}} [inline]
   */
  async #writeFileOn(alias, remotePath, content, { sessionPassword, timeoutMs, createDirs, signal, mode } = {}) {
    // See readFile: reject a bad path before touching the network.
    normalizeRemotePath(remotePath, { file: true })
    const client = await this.connect(alias, { sessionPassword, signal })
    return await writeRemoteFile(client, remotePath, content, {
      timeoutMs: timerValue(pick(timeoutMs || undefined, pick(this.config.sftpTimeoutMs, 30000)), 30000),
      createDirs: createDirs === true,
      signal,
      mode,
    })
  }

  /** @param {string} alias @param {string} remotePath @param {{timeoutMs?: number, sessionPassword?: string, signal?: AbortSignal}} [opts] */
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
   * @param {{sessionPassword?: string, timeoutMs?: number, signal?: AbortSignal}} [inline]
   */
  async #listOn(alias, remotePath, { sessionPassword, timeoutMs, signal } = {}) {
    // list allows a relative path, so it validates with allowRelative rather
    // than insisting on an absolute one.
    normalizeRemotePath(remotePath || '.', { allowRelative: true })
    const client = await this.connect(alias, { sessionPassword, signal })
    return await listRemoteDir(client, remotePath, {
      timeoutMs: timerValue(pick(timeoutMs || undefined, pick(this.config.sftpTimeoutMs, 30000)), 30000),
      signal,
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