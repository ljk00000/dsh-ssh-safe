import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, statSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { checkHostKey, fingerprint, keyId, storePath, fingerprintsEqual } from '../src/hostkey.js'

const keyA = Buffer.from('key-A')
const keyB = Buffer.from('key-B')

function freshHome() {
  return mkdtempSync(path.join(tmpdir(), 'dsh-ssh-safe-'))
}

test('fingerprint is stable and ssh-shaped', () => {
  assert.match(fingerprint(keyA), /^SHA256:[A-Za-z0-9+/]+$/)
  assert.equal(fingerprint(keyA), fingerprint(keyA))
  assert.notEqual(fingerprint(keyA), fingerprint(keyB))
})

test('keyId joins host and port', () => {
  assert.equal(keyId('h', 22), 'h:22')
})

test('strict refuses an unknown host', () => {
  const home = freshHome()
  try {
    const v = checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'strict' })
    assert.equal(v.ok, false)
    assert.equal(v.firstSeen, true)
    assert.match(v.reason, /Unknown host/)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('trustHostKey accepts first contact and records it', () => {
  const home = freshHome()
  try {
    const first = checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'strict', trustHostKey: true })
    assert.equal(first.ok, true)
    assert.equal(first.firstSeen, true)

    const second = checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'strict' })
    assert.equal(second.ok, true, 'a recorded host passes without trustHostKey')
    assert.equal(second.firstSeen, false)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('a changed host key is always fatal, even with trustHostKey', () => {
  const home = freshHome()
  try {
    checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'strict', trustHostKey: true })
    const v = checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyB, policy: 'strict', trustHostKey: true })
    assert.equal(v.ok, false, 'trustHostKey must not override a changed key')
    assert.match(v.reason, /HOST KEY CHANGED/)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('tofu records on first contact without an explicit flag', () => {
  const home = freshHome()
  try {
    const v = checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'tofu' })
    assert.equal(v.ok, true)
    assert.equal(v.firstSeen, true)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('policy off accepts anything but still reports the fingerprint', () => {
  const home = freshHome()
  try {
    const v = checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyB, policy: 'off' })
    assert.equal(v.ok, true)
    assert.match(v.fp, /^SHA256:/)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('fingerprint comparison is constant-time and length-safe', () => {
  assert.equal(fingerprintsEqual('SHA256:abc', 'SHA256:abc'), true)
  assert.equal(fingerprintsEqual('SHA256:abc', 'SHA256:abd'), false)
  assert.equal(fingerprintsEqual('SHA256:abc', 'SHA256:ab'), false, 'length mismatch is not an error')
  assert.equal(fingerprintsEqual('', ''), true)
  assert.equal(fingerprintsEqual(null, null), true)
})

test('two hosts recorded in sequence both survive', () => {
  const home = freshHome()
  try {
    checkHostKey({ dshHome: home, host: 'one', port: 22, keyBlob: keyA, policy: 'tofu' })
    checkHostKey({ dshHome: home, host: 'two', port: 22, keyBlob: keyB, policy: 'tofu' })
    const store = JSON.parse(readFileSync(storePath(home), 'utf8'))
    assert.ok(store.hosts['one:22'], 'the first host was not lost')
    assert.ok(store.hosts['two:22'], 'the second host was recorded')
    assert.equal(Object.keys(store.hosts).length, 2)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('a store write leaves no temporary file behind', () => {
  const home = freshHome()
  try {
    checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'tofu' })
    const dir = path.dirname(storePath(home))
    const strays = readdirSync(dir).filter((f) => f.includes('.tmp-'))
    assert.deepEqual(strays, [], 'the atomic write must rename, not leave temp files')
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('the store is written with restrictive permissions', () => {
  const home = freshHome()
  try {
    checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'tofu' })
    const mode = statSync(storePath(home)).mode & 0o777
    // Windows ignores POSIX bits; only assert on POSIX platforms.
    if (process.platform !== 'win32') assert.equal(mode, 0o600)
  } finally { rmSync(home, { recursive: true, force: true }) }
})
test('a recorded entry without a fingerprint is not reported as a changed key', async () => {
  // is documented: an unreadable file means 'unknown'. An entry that exists but
  // holds no fingerprint is a corrupt record, not evidence of interception --
  // 'HOST KEY CHANGED' is the one alarm that has to keep its meaning.
  const dir = mkdtempSync(path.join(tmpdir(), 'dsh-hk-'))
  const file = path.join(dir, 'known_hosts.json')
  for (const entry of ['garbage', { firstSeenAt: 'x' }, { fingerprint: 12345 }]) {
    writeFileSync(file, JSON.stringify({ version: 1, hosts: { ['h.example:22']: entry } }))
    const verdict = checkHostKey({
      dshHome: dir, host: 'h.example', port: 22, keyBlob: keyA,
      policy: 'strict', trustHostKey: false, knownHostsFile: file,
    })
    assert.equal(verdict.ok, false, 'a corrupt record must still refuse')
    assert.doesNotMatch(verdict.reason, /HOST KEY CHANGED/)
    assert.match(verdict.reason, /Host key verification failed/)
    assert.match(verdict.reason, /no usable fingerprint/)
  }
})