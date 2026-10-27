// dsh-ssh-safe — host key verification (TOFU store).
//
// Default policy is STRICT: a host must already be trusted, or the caller must
// pass trustHostKey: true exactly once for that fingerprint. There is no
// "accept anything" default, which is the single most common SSH mistake.
//
// The store lives in <DSH_HOME>/dsh-ssh-safe/known_hosts.json with mode 0600
// where the platform supports it. It contains host, port and fingerprint only —
// never a username, password, or key.

import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync, chmodSync, renameSync } from 'node:fs'
import path from 'node:path'

const STORE_VERSION = 1

export function storePath(dshHome) {
  return path.join(dshHome, 'dsh-ssh-safe', 'known_hosts.json')
}

function readStore(file) {
  try {
    const raw = JSON.parse(readFileSync(file, 'utf8'))
    if (raw && raw.version === STORE_VERSION && raw.hosts && typeof raw.hosts === 'object') return raw
  } catch { /* missing or corrupt → treat as empty, never throw */ }
  return { version: STORE_VERSION, hosts: {} }
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
  fresh.hosts[id] = { fingerprint: fingerprintValue, firstSeenAt: new Date().toISOString() }
  writeStore(file, fresh)
}

export function keyId(host, port) {
  return host + ':' + port
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
  const store = readStore(file)
  const recorded = store.hosts[id]

  if (policy === 'off') {
    return { ok: true, reason: 'host key verification disabled by policy', fp, firstSeen: !recorded }
  }
  if (recorded && recorded.fingerprint === fp) {
    return { ok: true, reason: 'host key matches the recorded fingerprint', fp, firstSeen: false }
  }
  if (recorded && recorded.fingerprint !== fp) {
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
