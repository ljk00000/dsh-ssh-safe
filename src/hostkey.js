// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe — host key verification (TOFU store).
//
// Default policy is STRICT: a host must already be trusted, or the caller must
// pass trustHostKey: true exactly once for that fingerprint. There is no
// "accept anything" default, which is the single most common SSH mistake.
//
// The store lives in <DSH_HOME>/dsh-ssh-safe/known_hosts.json with mode 0600
// where the platform supports it. It contains host, port and fingerprint only —
// never a username, password, or key.

import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync, chmodSync, renameSync, existsSync } from 'node:fs'
import path from 'node:path'

const STORE_VERSION = 1

export function storePath(dshHome) {
  return path.join(dshHome, 'dsh-ssh-safe', 'known_hosts.json')
}

/**
 * Read the trust store, and say when it could not be understood.
 *
 * A corrupt store used to be indistinguishable from an empty one. The next
 * connection then looked like "unknown host", the caller was told to verify the
 * fingerprint and connect with trustHostKey, and doing so rewrote the file with
 * ONE entry -- silently discarding every other host that had been trusted.
 *
 * @param {string} file
 * @returns {{store: {version: number, hosts: Record<string, any>}, problem: string}}
 */
function readStore(file) {
  const empty = { version: STORE_VERSION, hosts: /** @type {Record<string, any>} */ ({}) }
  let text
  try {
    text = readFileSync(file, 'utf8')
  } catch (err) {
    // A store that does not exist yet is the normal first run.
    const code = err && /** @type {{code?: string}} */ (err).code
    if (code === 'ENOENT') return { store: empty, problem: '' }
    return {
      store: empty,
      problem: 'the host key store ' + file + ' could not be read (' + (code || (err && err.message) || 'unknown error') + ')',
    }
  }
  try {
    const raw = JSON.parse(text)
    if (raw && raw.version === STORE_VERSION && raw.hosts && typeof raw.hosts === 'object') {
      return { store: raw, problem: '' }
    }
    return {
      store: empty,
      problem: 'the host key store ' + file + ' is not in the expected format (version ' +
        JSON.stringify(raw && raw.version) + ')',
    }
  } catch (err) {
    return {
      store: empty,
      problem: 'the host key store ' + file + ' could not be parsed (' +
        String(err && err.message ? err.message : err).slice(0, 80) + ')',
    }
  }
}

/**
 * Persist the store atomically.
 *
 * Writing straight to the target would leave a truncated file if the process
 * died mid-write, and a reader would then treat every host as unknown. Writing
 * to a sibling and renaming makes the swap atomic on every platform Node
 * supports.
 */
function writeStore(file, store) {
  mkdirSync(path.dirname(file), { recursive: true })
  const tmp = file + '.tmp-' + process.pid + '-' + Date.now()
  writeFileSync(tmp, JSON.stringify(store, null, 2), { encoding: 'utf8', mode: 0o600 })
  try { chmodSync(tmp, 0o600) } catch { /* best effort on Windows */ }
  renameSync(tmp, file)
}

/**
 * Record one host fingerprint without discarding concurrent additions.
 *
 * The previous code did readStore() -> mutate -> writeStore() with nothing in
 * between, so two hosts reached for the first time in the same tick lost one
 * another: the second write overwrote the first entry. Re-reading immediately
 * before the merge narrows that window to a single synchronous block, which Node
 * cannot interleave.
 */
function recordHost(file, id, fingerprintValue) {
  const fresh = readStore(file)
  // Never write over a store that could not be understood: the write would keep
  // only this host and discard the rest of the file's contents.
  if (fresh.problem) throw new Error(fresh.problem + ' — refusing to overwrite it')
  fresh.store.hosts[id] = { fingerprint: fingerprintValue, firstSeenAt: new Date().toISOString() }
  writeStore(file, fresh.store)
}

export function keyId(host, port) {
  // The key this plugin stores a host under. Keep it stable: changing it would
  // orphan every recorded IPv6 fingerprint, and an orphaned record means the
  // next key is silently recorded as a first contact.
  return String(host) + ':' + port
}

/**
 * How a host:port is written in a message a user has to act on.
 *
 * '::1:22' reads as either host '::1' port 22 or host '::' port 1:22, so an
 * IPv6 literal is bracketed the way ssh writes it.
 */
export function hostLabel(host, port) {
  const name = String(host)
  return (name.includes(':') ? '[' + name + ']' : name) + ':' + port
}

/**
 * Recognise an OpenSSH known_hosts file.
 *
 * The setting is called knownHosts, and that name means the OpenSSH file to
 * everybody who has one. Pointing it at '~/.ssh/known_hosts' used to produce a
 * JSON syntax error: true, useless, and it made the setting look broken.
 */
export function looksLikeOpenSshKnownHosts(text) {
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const parts = line.replace(/^@\S+\s+/, '').split(/\s+/)
    if (parts.length < 3) continue
    // host-patterns, key type, base64 blob
    if (/^(ssh-|ecdsa-|sk-|rsa-sha2-|dsa-)/.test(parts[1]) && /^[A-Za-z0-9+/=]+$/.test(parts[2])) return true
    return false
  }
  return false
}

/** Wildcards in a host pattern: '*' and '?', anchored, case-insensitive. */
function globMatch(pattern, value) {
  const escaped = pattern.replace(/[.*+?${}()|[\]\\]/g, '\\$&')
    .replace(/\\\*/g, '.*')
    .replace(/\\\?/g, '.')
  try {
    return new RegExp('^' + escaped + '$', 'i').test(value)
  } catch {
    return false
  }
}

/** '|1|salt|hash' — HMAC-SHA1 of the host name, OpenSSH's hashed form. */
function hashedEntryMatches(field, host) {
  const parts = field.split('|')
  if (parts.length !== 4 || parts[1] !== '1') return false
  let salt
  let want
  try {
    salt = Buffer.from(parts[2], 'base64')
    want = Buffer.from(parts[3], 'base64')
  } catch {
    return false
  }
  if (salt.length === 0 || want.length === 0) return false
  const got = createHmac('sha1', salt).update(host).digest()
  return got.length === want.length && timingSafeEqual(got, want)
}

/**
 * Does an entry's host field cover this host (and port)?
 *
 * Port 22 is spelled 'host'; any other port is '[host]:port', which is hashed
 * and matched the same way OpenSSH does it.
 */
function entryCoversHost(field, host, port) {
  const bracketed = '[' + host + ']:' + port
  const candidates = port === 22 ? [host] : [bracketed, host]
  // A '!pattern' anywhere in the list takes the whole entry out of play, which
  // is what OpenSSH does. Ignoring the negation made '*.example.com,!bad.example.com'
  // cover bad.example.com: a key the user explicitly excluded was accepted.
  for (const rawPattern of String(field).split(',')) {
    const trimmed = rawPattern.trim()
    if (!trimmed.startsWith('!')) continue
    const negated = trimmed.slice(1)
    if (!negated) continue
    if (negated.startsWith('|1|')) {
      for (const candidate of candidates) if (hashedEntryMatches(negated, candidate)) return false
      continue
    }
    for (const candidate of candidates) if (globMatch(negated, candidate)) return false
  }
  for (const rawPattern of String(field).split(',')) {
    const pattern = rawPattern.trim()
    if (!pattern) continue
    if (pattern.startsWith('|1|')) {
      for (const candidate of candidates) if (hashedEntryMatches(pattern, candidate)) return true
      continue
    }
    for (const candidate of candidates) if (globMatch(pattern, candidate)) return true
  }
  return false
}

/**
 * Parse an OpenSSH known_hosts file into entries this plugin can check.
 *
 * '@revoked' lines are collected separately: a key listed there is refused
 * outright. '@cert-authority' is skipped -- verifying certificates needs the CA
 * key and a validity period, and pretending to check one would be worse than
 * ignoring it.
 *
 * @param {string} text
 * @returns {{entries: Array<{hostField: string, keyType: string, blob: Buffer}>,
 *   revoked: Array<{hostField: string, keyType: string, blob: Buffer}>}}
 */
export function parseOpenSshKnownHosts(text) {
  const entries = []
  const revoked = []
  for (const raw of String(text || '').split(/\r?\n/)) {
    let line = raw.trim()
    if (!line || line.startsWith('#')) continue
    let marker = ''
    if (line.startsWith('@')) {
      const match = /^@(\S+)\s+(.*)$/.exec(line)
      if (!match) continue
      marker = match[1]
      line = match[2]
    }
    const parts = line.split(/\s+/)
    if (parts.length < 3) continue
    const hostField = parts[0]
    const keyType = parts[1]
    const encoded = parts[2]
    if (!/^(ssh-|ecdsa-|sk-|rsa-sha2-|dsa-)/.test(keyType)) continue
    if (!/^[A-Za-z0-9+/=]+$/.test(encoded)) continue
    const blob = Buffer.from(encoded, 'base64')
    if (blob.length === 0) continue
    if (marker === 'revoked') revoked.push({ hostField, keyType, blob })
    else if (marker === '') entries.push({ hostField, keyType, blob })
  }
  return { entries, revoked }
}

/**
 * A sentence about the store file itself, for the unknown-host message.
 *
 * 'Unknown host' with a custom knownHosts path is usually a typo, and the advice
 * used to recommend appending to a directory that does not exist — a command that
 * fails exactly where it is offered.
 *
 * @param {string} file
 * @returns {string}
 */
function storeState(file) {
  try {
    if (existsSync(file)) return ''
    const dir = path.dirname(file)
    if (existsSync(dir)) {
      return 'The file does not exist yet, so every connection is a first contact; the append below creates it. '
    }
    return 'The file does not exist, and neither does the directory ' + dir +
      ', so the append below would fail: create the directory first (mkdir -p "' + dir + '"). '
  } catch {
    return ''
  }
}

/**
 * Verify a presented host key against an OpenSSH known_hosts file.
 *
 * Read-only on purpose: writing OpenSSH format back is a different promise, and
 * appending a line our own parser cannot fully validate is how trust stores get
 * corrupted. New hosts are added with ssh-keyscan, or by using the plugin's own
 * store (drop the knownHosts setting).
 */
export function checkOpenSshHostKey({ text, file, host, port, keyBlob, policy, trustHostKey, fp }) {
  const parsedFile = parseOpenSshKnownHosts(text)
  const id = hostLabel(host, port)
  const presented = fingerprint(keyBlob)
  const covers = (entry) => entryCoversHost(entry.hostField, host, port)

  for (const entry of parsedFile.revoked) {
    if (covers(entry) && fingerprintsEqual(fingerprint(entry.blob), presented)) {
      return {
        ok: false,
        reason: 'Host key verification failed: ' + id + ' is marked @revoked in ' + file +
          ' with the fingerprint it presents (' + presented + '). Refusing to connect.',
        fp,
        firstSeen: false,
      }
    }
  }

  const matching = parsedFile.entries.filter(covers)
  if (matching.length > 0) {
    const same = matching.find((entry) => fingerprintsEqual(fingerprint(entry.blob), presented))
    if (same) {
      return { ok: true, reason: 'host key matches the entry in ' + file, fp, firstSeen: false }
    }
    return {
      ok: false,
      reason: 'HOST KEY CHANGED for ' + id + ': ' + file + ' records ' +
        matching.map((entry) => fingerprint(entry.blob)).join(', ') + ', presented ' + presented +
        '. This can mean the server was reinstalled — or that traffic is being intercepted. ' +
        'Refusing to connect. If the server was legitimately rebuilt, update that entry after ' +
        'verifying the new fingerprint out of band.',
      fp,
      firstSeen: false,
    }
  }

  if (trustHostKey === true) {
    return {
      ok: true,
      reason: 'trustHostKey accepted the key for this call; nothing was written to ' + file +
        ' because it is an OpenSSH known_hosts file. Add the host with ssh-keyscan to stop being asked.',
      fp,
      firstSeen: true,
    }
  }
  if (policy === 'tofu') {
    // The advice has to match the file's state: appending to a path whose
    // directory does not exist fails, and a mistyped knownHosts path is the
    // commonest reason to land here.
    const storeNote = storeState(file)
    return {
      ok: false,
      reason: 'Unknown host ' + id + ' with fingerprint ' + presented + '. ' + file +
        ' is an OpenSSH known_hosts file, which this plugin verifies but does not write to. ' +
        storeNote +
        'Add the host with: ssh-keyscan -p ' + port + ' ' + host + ' >> "' + file + '" — after ' +
        'confirming the fingerprint out of band — or call ssh_connect with trustHostKey: true ' +
        'for this one connection.',
      fp,
      firstSeen: true,
    }
  }
  return {
    ok: false,
    reason: 'Unknown host ' + id + ' with fingerprint ' + presented + '. This machine is not in ' +
      file + ' (an OpenSSH known_hosts file, verified but not written by this plugin). Verify the ' +
      'fingerprint out of band, then add it with: ssh-keyscan -p ' + port + ' ' + host + ' >> "' +
      file + '" — or call ssh_connect with trustHostKey: true for this one connection.',
    fp,
    firstSeen: true,
  }
}

/**
 * Compare two fingerprints without leaking their common prefix through timing.
 *
 * A JS string === short-circuits on the first differing byte. The value being
 * compared is a public fingerprint, so the practical risk is negligible -- but
 * a plugin whose selling point is host verification should not be the one place
 * in the codebase that compares security material with ===.
 */
export function fingerprintsEqual(a, b) {
  const left = Buffer.from(String(a ?? ''), 'utf8')
  const right = Buffer.from(String(b ?? ''), 'utf8')
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}

/**
 * Describe why a recorded fingerprint cannot be used.
 *
 * '(undefined)' and '(object)' are developer shorthand for a user whose trust store
 * is broken; the field being missing and the field being empty are different fixes.
 */
function fingerprintState(value) {
  if (value === undefined) return 'the field is missing'
  if (value === null) return 'it is null'
  if (typeof value === 'string') return value === '' ? 'it is empty' : 'it is not a fingerprint'
  return 'it is a ' + typeof value
}

/** SHA256 fingerprint of the server's public key, ssh-style. */
export function fingerprint(keyBlob) {
  const b = Buffer.isBuffer(keyBlob) ? keyBlob : Buffer.from(String(keyBlob))
  return 'SHA256:' + createHash('sha256').update(b).digest('base64').replace(/=+$/, '')
}

/**
 * Decide whether to accept a presented host key.
 * @returns {{ok: boolean, reason: string, fp: string, firstSeen: boolean}}
 */
export function checkHostKey({ dshHome, host, port, keyBlob, policy, trustHostKey, knownHostsFile }) {
  const fp = fingerprint(keyBlob)
  const file = knownHostsFile || storePath(dshHome)
  // Verification is not requested at all here: policy off wins over everything,
  // including a knownHosts file that would otherwise refuse.
  if (policy === 'off') {
    return { ok: true, reason: 'host key verification disabled by policy', fp, firstSeen: false }
  }
  // The setting is called knownHosts, and that is what people point at their
  // OpenSSH file. Read it as one rather than answering with a JSON syntax error.
  if (knownHostsFile) {
    let text = null
    try {
      text = readFileSync(file, 'utf8')
    } catch (err) {
      const code = err && /** @type {{code?: string}} */ (err).code
      if (code !== 'ENOENT') {
        return {
          ok: false,
          reason: 'Host key verification failed: the known_hosts file ' + file + ' could not be read (' +
            (code || (err && err.message) || 'unknown error') + ').',
          fp,
          firstSeen: false,
        }
      }
      text = ''
    }
    // A file that is empty, or holds nothing but comments, is a perfectly valid
    // known_hosts with no entries yet ('touch ~/.ssh/known_hosts'). It used to fall
    // through to the 'not in a format this plugin can verify' branch and quote an
    // empty first entry, which is an alarming answer to a file that is simply new.
    const entryLines = text === null ? [] : text.split(/\r?\n/).filter((line) => {
      const trimmed = line.trim()
      return trimmed !== '' && !trimmed.startsWith('#')
    })
    if (text !== null && (entryLines.length === 0 || looksLikeOpenSshKnownHosts(text))) {
      return checkOpenSshHostKey({
        text, file, host, port, keyBlob, policy, trustHostKey: trustHostKey === true, fp,
      })
    }
    // The file was named as the known_hosts file but reads as neither that nor
    // this plugin's store. Falling through answered with a JSON parse error,
    // which is a strange thing to see for '~/.ssh/known_hosts'.
    // A JSON document is this plugin's own store (a caller may point knownHostsFile
    // at one); readStore below explains whatever is wrong with it.
    let looksJson = false
    try { JSON.parse(text); looksJson = true } catch { looksJson = false }
    if (text !== null && !looksJson) {
      const firstLine = String(text).split(/\r?\n/).find((line) => line.trim() && !line.trim().startsWith('#')) || ''
      return {
        ok: false,
        reason: 'Host key verification failed: the known_hosts file ' + file +
          ' is not in a format this plugin can verify — it is neither an OpenSSH known_hosts file ' +
          'nor the plugin\'s own store (first entry: ' + JSON.stringify(firstLine.trim().slice(0, 60)) + '). ' +
          'Fix the file, or point the knownHosts setting at ~/.ssh/known_hosts.',
        fp,
        firstSeen: false,
      }
    }
  }
  const id = keyId(host, port)
  const label = hostLabel(host, port)
  const read = readStore(file)
  const store = read.store
  const recorded = store.hosts[id]

  if (policy === 'off') {
    return { ok: true, reason: 'host key verification disabled by policy', fp, firstSeen: !recorded }
  }
  // Verification against a store that cannot be read is impossible, and trusting
  // the presented key would rewrite the file and drop everything else in it.
  if (read.problem) {
    return {
      ok: false,
      reason:
        'Host key verification failed: ' + read.problem + '. Nothing can be verified against it, ' +
        'and recording a new key would overwrite the hosts already trusted there. Repair or remove ' +
        'that file, then connect again.',
      fp,
      firstSeen: false,
    }
  }
  if (recorded && fingerprintsEqual(recorded.fingerprint, fp)) {
    return { ok: true, reason: 'host key matches the recorded fingerprint', fp, firstSeen: false }
  }
  // A record that exists but holds no fingerprint is not a changed key: the file
  // was edited or truncated. Saying "HOST KEY CHANGED" for it raises the one
  // alarm that should mean interception, over a broken file.
  if (recorded && (typeof recorded.fingerprint !== 'string' || recorded.fingerprint.length === 0)) {
    return {
      ok: false,
      // Starts with the ssh wording on purpose: pool.connectFailure() passes it
      // through untouched instead of prefixing "Could not connect", which reads
      // like a network problem.
      reason:
        'Host key verification failed: the recorded entry for ' + label + ' in ' + file +
        ' has no usable fingerprint (' + fingerprintState(recorded.fingerprint) + '), so nothing can be verified ' +
        'against it. Remove that entry and connect again to record the key you verify out of band.',
      fp,
      firstSeen: false,
    }
  }
  if (recorded && !fingerprintsEqual(recorded.fingerprint, fp)) {
    // A changed key is the classic man-in-the-middle signal. Never auto-heal.
    return {
      ok: false,
      reason:
        'HOST KEY CHANGED for ' + label + ': recorded ' + recorded.fingerprint + ', presented ' + fp +
        '. This can mean the server was reinstalled — or that traffic is being intercepted. ' +
        'Refusing to connect. If the server was legitimately rebuilt, remove the entry from ' +
        file + ' after verifying the new fingerprint out of band.',
      fp,
      firstSeen: false,
    }
  }
  // No record yet.
  if (policy === 'tofu' || trustHostKey === true) {
    recordHost(file, id, fp)
    return { ok: true, reason: 'first connection to this host; fingerprint recorded', fp, firstSeen: true }
  }
  return {
    ok: false,
    reason:
      'Unknown host ' + label + ' with fingerprint ' + fp + '. This machine is not in ' + file +
      '. Verify the fingerprint out of band, then either set hostKeyPolicy to "tofu" for this ' +
      'machine or call ssh_connect with trustHostKey: true once.',
    fp,
    firstSeen: true,
  }
}
