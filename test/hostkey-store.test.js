import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { checkHostKey, storePath } from '../src/hostkey.js'

// A corrupt trust store used to read as an empty one: the host looked unknown,
// the caller was told to connect once with trustHostKey, and doing that rewrote
// the file with a single entry -- discarding every other host that had been
// trusted. Measured against the previous implementation: a 40-byte truncated
// store became 189 bytes holding only the new host.

let home
let file

before(() => {
  home = mkdtempSync(path.join(tmpdir(), 'dsh-kh-corrupt-'))
  mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
  file = storePath(home)
})

after(() => {
  rmSync(home, { recursive: true, force: true })
})

const key = Buffer.from('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial')

function store() {
  return {
    version: 1,
    hosts: {
      'shown.example:22': { fingerprint: 'SHA256:keep-me', firstSeenAt: new Date().toISOString() },
      'other.example:22': { fingerprint: 'SHA256:keep-me-too', firstSeenAt: new Date().toISOString() },
    },
  }
}

test('a corrupt store refuses the connection and is left alone', () => {
  writeFileSync(file, JSON.stringify(store()).slice(0, 40))
  const before = readFileSync(file, 'utf8')
  for (const policy of ['strict', 'tofu']) {
    const verdict = checkHostKey({
      dshHome: home, host: 'shown.example', port: 22, keyBlob: key,
      policy, trustHostKey: true,
    })
    assert.equal(verdict.ok, false, policy + ' must refuse rather than trust')
    assert.match(verdict.reason, /Host key verification failed: the host key store/)
    assert.match(verdict.reason, /could not be parsed/)
    assert.match(verdict.reason, /would overwrite the hosts already trusted there/)
  }
  assert.equal(readFileSync(file, 'utf8'), before, 'the file must not be rewritten')
})

test('a store in the wrong shape is named as such', () => {
  writeFileSync(file, JSON.stringify({ version: 99, hosts: {} }))
  const verdict = checkHostKey({
    dshHome: home, host: 'shown.example', port: 22, keyBlob: key,
    policy: 'strict', trustHostKey: false,
  })
  assert.equal(verdict.ok, false)
  assert.match(verdict.reason, /is not in the expected format \(version 99\)/)
  assert.equal(readFileSync(file, 'utf8'), JSON.stringify({ version: 99, hosts: {} }))
})

test('hostKeyPolicy off still connects, and still does not rewrite the store', () => {
  writeFileSync(file, 'not json at all')
  const verdict = checkHostKey({
    dshHome: home, host: 'shown.example', port: 22, keyBlob: key,
    policy: 'off', trustHostKey: false,
  })
  assert.equal(verdict.ok, true)
  assert.equal(readFileSync(file, 'utf8'), 'not json at all')
})

test('a missing store is a first run, not a problem', () => {
  const empty = mkdtempSync(path.join(tmpdir(), 'dsh-kh-missing-'))
  const verdict = checkHostKey({
    dshHome: empty, host: 'new.example', port: 22, keyBlob: key,
    policy: 'tofu', trustHostKey: false,
  })
  assert.equal(verdict.ok, true)
  assert.equal(verdict.firstSeen, true)
  rmSync(empty, { recursive: true, force: true })
})

test('a healthy store still records new hosts without losing the existing ones', () => {
  writeFileSync(file, JSON.stringify(store()))
  const verdict = checkHostKey({
    dshHome: home, host: 'new.example', port: 2222, keyBlob: key,
    policy: 'tofu', trustHostKey: false,
  })
  assert.equal(verdict.ok, true)
  const after = JSON.parse(readFileSync(file, 'utf8'))
  assert.deepEqual(Object.keys(after.hosts).sort(), ['new.example:2222', 'other.example:22', 'shown.example:22'])
})
