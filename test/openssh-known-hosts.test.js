import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac, randomBytes } from 'node:crypto'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import ssh2 from 'ssh2'

import { checkHostKey, fingerprint, looksLikeOpenSshKnownHosts, parseOpenSshKnownHosts } from '../src/hostkey.js'

// The setting is called knownHosts, which means the OpenSSH file to everybody who
// has one. Pointing it at ~/.ssh/known_hosts used to answer with a JSON syntax
// error; it is verified against that format now, read-only.

let home
let file
let blob
let b64

before(() => {
  home = mkdtempSync(path.join(tmpdir(), 'dsh-openssh-kh-'))
  mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
  file = path.join(home, 'known_hosts')
  const { public: pub } = ssh2.utils.generateKeyPairSync('ed25519')
  blob = Buffer.from(String(pub).trim().split(/\s+/)[1], 'base64')
  b64 = blob.toString('base64')
})

after(() => {
  rmSync(home, { recursive: true, force: true })
})

const verdict = (args) => checkHostKey({ dshHome: home, knownHostsFile: file, keyBlob: blob, policy: 'strict', ...args })

test('the OpenSSH format is recognised, and JSON is not confused for it', () => {
  assert.equal(looksLikeOpenSshKnownHosts('github.com ssh-ed25519 ' + b64), true)
  assert.equal(looksLikeOpenSshKnownHosts('# only a comment\n\n'), false)
  assert.equal(looksLikeOpenSshKnownHosts('{"version":1,"hosts":{}}'), false)
})

test('a matching entry verifies, including wildcards and bracketed ports', () => {
  writeFileSync(file, [
    '# comment',
    'github.com ssh-ed25519 ' + b64,
    '*.internal ssh-ed25519 ' + b64,
    '[example.com]:2222 ssh-ed25519 ' + b64,
  ].join('\n') + '\n')
  assert.equal(verdict({ host: 'github.com', port: 22 }).ok, true)
  assert.equal(verdict({ host: 'build.internal', port: 22 }).ok, true)
  assert.equal(verdict({ host: 'example.com', port: 2222 }).ok, true)
  // The bracketed entry covers only its port; the bare ones cover every port,
  // which is what OpenSSH does.
  assert.equal(verdict({ host: 'example.com', port: 22 }).ok, false)
  assert.match(verdict({ host: 'example.com', port: 22 }).reason, /Unknown host example\.com:22/)
})

test('hashed entries are matched the way OpenSSH matches them', () => {
  const salt = randomBytes(20)
  const hashed = (name) => '|1|' + salt.toString('base64') + '|' +
    createHmac('sha1', salt).update(name).digest('base64')
  writeFileSync(file, [
    hashed('hashed.example') + ' ssh-ed25519 ' + b64,
    hashed('[hashed.example]:2222') + ' ssh-ed25519 ' + b64,
  ].join('\n') + '\n')
  assert.equal(verdict({ host: 'hashed.example', port: 22 }).ok, true)
  assert.equal(verdict({ host: 'hashed.example', port: 2222 }).ok, true)
  assert.equal(verdict({ host: 'other.example', port: 22 }).ok, false)
})

test('a changed key is refused, and a revoked key is refused', () => {
  const other = Buffer.from('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAveryDifferentKeyMaterial')
  writeFileSync(file, 'github.com ssh-ed25519 ' + b64 + '\n')
  const changed = verdict({ host: 'github.com', port: 22, keyBlob: other })
  assert.equal(changed.ok, false)
  assert.match(changed.reason, /HOST KEY CHANGED for github\.com:22/)

  writeFileSync(file, '@revoked github.com ssh-ed25519 ' + b64 + '\n')
  const revoked = verdict({ host: 'github.com', port: 22 })
  assert.equal(revoked.ok, false)
  assert.match(revoked.reason, /marked @revoked/)
})

test('an unknown host says how to add it, and trustHostKey writes nothing', () => {
  writeFileSync(file, 'github.com ssh-ed25519 ' + b64 + '\n')
  const before = readFileSync(file, 'utf8')

  const strict = verdict({ host: 'new.example', port: 2222 })
  assert.equal(strict.ok, false)
  assert.match(strict.reason, /Unknown host new\.example:2222/)
  assert.match(strict.reason, /ssh-keyscan -p 2222 new\.example/)

  const tofu = verdict({ host: 'new.example', port: 2222, policy: 'tofu' })
  assert.equal(tofu.ok, false, 'tofu cannot record into an OpenSSH file, so it must not pretend to')
  assert.match(tofu.reason, /verifies but does not write to/)

  const trusted = verdict({ host: 'new.example', port: 2222, trustHostKey: true })
  assert.equal(trusted.ok, true)
  assert.match(trusted.reason, /nothing was written to/)
  assert.equal(readFileSync(file, 'utf8'), before, 'the OpenSSH file is never modified')
})

test('policy off wins over the knownHosts file', () => {
  writeFileSync(file, 'github.com ssh-ed25519 ' + b64 + '\n')
  assert.equal(verdict({ host: 'unknown.example', port: 22, policy: 'off' }).ok, true)
})

test('the parser keeps only usable lines', () => {
  writeFileSync(file, [
    '# comment',
    '',
    'github.com ssh-ed25519 ' + b64,
    '@cert-authority ca.example ssh-ed25519 ' + b64,
    'broken line',
    'nowhere.example not-a-key-type whatever',
  ].join('\n') + '\n')
  const parsed = parseOpenSshKnownHosts(readFileSync(file, 'utf8'))
  assert.deepEqual(parsed.entries.map((entry) => entry.hostField), ['github.com'])
  assert.deepEqual(parsed.revoked, [])
})

test('a JSON store passed as knownHosts is still read as one', () => {
  const jsonFile = path.join(home, 'plugin-store.json')
  writeFileSync(jsonFile, JSON.stringify({
    version: 1,
    hosts: { 'json.example:22': { fingerprint: fingerprint(blob), firstSeenAt: new Date().toISOString() } },
  }))
  const ok = checkHostKey({ dshHome: home, knownHostsFile: jsonFile, keyBlob: blob, policy: 'strict', host: 'json.example', port: 22 })
  assert.equal(ok.ok, true)
})
