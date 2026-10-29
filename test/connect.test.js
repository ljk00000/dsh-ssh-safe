import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { connectOptions, expandHome } from '../src/connect.js'

// This mapping used to exist twice -- once in the pool, once in the settings
// page -- and the two copies drifted: the page authenticated with a stored
// password while the pool sent no authentication at all. Sharing one function
// is the fix; these tests keep it honest.

const machine = { host: 'h.invalid', port: 2222, username: 'root' }

test('a password becomes connectConfig.password', () => {
  const options = connectOptions(machine, { password: 'pw' })
  assert.equal(options.password, 'pw')
  assert.equal(options.host, 'h.invalid')
  assert.equal(options.port, 2222)
  assert.equal(options.username, 'root')
})

test('a key becomes a Buffer and a passphrase is carried', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-connect-'))
  const keyPath = join(dir, 'id')
  writeFileSync(keyPath, '-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n')
  const options = connectOptions(machine, { keyPath, passphrase: 'pp' })
  assert.ok(Buffer.isBuffer(options.privateKey))
  assert.equal(options.passphrase, 'pp')
  assert.equal(options.password, undefined)
})

test('an agent socket is passed through', () => {
  const options = connectOptions(machine, { agent: '/tmp/agent.sock' })
  assert.equal(options.agent, '/tmp/agent.sock')
})

test('nothing configured leaves every auth field absent', () => {
  const options = connectOptions(machine, {})
  assert.equal(options.password, undefined)
  assert.equal(options.privateKey, undefined)
  assert.equal(options.agent, undefined)
})

test('port defaults to 22', () => {
  assert.equal(connectOptions({ host: 'h', username: 'u' }, {}).port, 22)
})

test('timing defaults are overridable and keepalive can be turned off', () => {
  const options = connectOptions(machine, {}, { readyTimeout: 1000, keepaliveInterval: 0 })
  assert.equal(options.readyTimeout, 1000)
  assert.equal(options.keepaliveInterval, 0, '0 must survive: it disables keepalive')
})

test('a missing key file throws instead of connecting without a credential', () => {
  assert.throws(() => connectOptions(machine, { keyPath: '/nonexistent/id_ed25519' }), /ENOENT|no such file/i)
})

test('expandHome only touches a leading tilde', () => {
  assert.ok(expandHome('~/.ssh/id_ed25519').endsWith('/.ssh/id_ed25519') || expandHome('~/.ssh/id_ed25519').endsWith('\\.ssh\\id_ed25519'))
  assert.equal(expandHome('/abs/~file'), '/abs/~file')
  assert.equal(expandHome('a~b'), 'a~b')
})
