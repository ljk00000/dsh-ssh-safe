import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { checkHostKey, fingerprint, keyId, storePath } from '../src/hostkey.js'

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

test('the store is written with restrictive permissions', () => {
  const home = freshHome()
  try {
    checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'tofu' })
    const mode = statSync(storePath(home)).mode & 0o777
    // Windows ignores POSIX bits; only assert on POSIX platforms.
    if (process.platform !== 'win32') assert.equal(mode, 0o600)
  } finally { rmSync(home, { recursive: true, force: true }) }
})
