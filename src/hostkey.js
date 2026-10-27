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
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs'
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

function writeStore(file, store) {
  mkdirSync(path.dirname(file), { recursive: true })
  writeFileSync(file, JSON.stringify(store, null, 2), { encoding: 'utf8', mode: 0o600 })
  try { chmodSync(file, 0o600) } catch { /* best effort on Windows */ }
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
    store.hosts[id] = { fingerprint: fp, firstSeenAt: new Date().toISOString() }
    writeStore(file, store)
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
