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

import { createHash, timingSafeEqual } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync, chmodSync, renameSync } from 'node:fs'
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
  return host + ':' + port
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
  const id = keyId(host, port)
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
        'Host key verification failed: the recorded entry for ' + id + ' in ' + file +
        ' has no usable fingerprint (' + typeof recorded.fingerprint + '), so nothing can be verified ' +
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
        'HOST KEY CHANGED for ' + id + ': recorded ' + recorded.fingerprint + ', presented ' + fp +
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
      'Unknown host ' + id + ' with fingerprint ' + fp + '. This machine is not in ' + file +
      '. Verify the fingerprint out of band, then either set hostKeyPolicy to "tofu" for this ' +
      'machine or call ssh_connect with trustHostKey: true once.',
    fp,
    firstSeen: true,
  }
}
