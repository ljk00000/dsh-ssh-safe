import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import ssh2 from 'ssh2'
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
  // A real key: connectOptions now parses it so a broken file names itself.
  //
  // RSA on purpose: ssh2's ed25519 generator occasionally produced a private key
  // its own parser rejected ("Malformed OpenSSH private key"), which made this
  // test fail about once in fifty full-suite runs and never on its own.
  writeFileSync(keyPath, ssh2.utils.generateKeyPairSync('rsa', { bits: 2048 }).private)
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
test('a key file that cannot be read or parsed names itself', () => {
  // readFileSync's EISDIR message has no path in it, and ssh2's parse error is
  // thrown later with nothing to say which file it read.
  const dir = mkdtempSync(join(tmpdir(), 'dsh-connect-'))
  assert.throws(
    () => connectOptions(machine, { keyPath: dir }),
    (err) => {
      assert.match(err.message, /cannot read the private key/)
      assert.ok(err.message.includes(dir), 'the path must be in the message: ' + err.message)
      return true
    },
  )
  const junk = join(dir, 'junk')
  writeFileSync(junk, 'not a key')
  assert.throws(
    () => connectOptions(machine, { keyPath: junk }),
    (err) => {
      assert.match(err.message, /could not be parsed/)
      assert.ok(err.message.includes(junk), 'the path must be in the message: ' + err.message)
      return true
    },
  )
})
