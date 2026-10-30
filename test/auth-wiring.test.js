import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import ssh2 from 'ssh2'
import { SshPool } from '../src/pool.js'

// The credential-to-connectConfig mapping in SshPool#open was reachable only
// through a real network handshake, so no test ever ran it. It named four
// credential kinds explicitly and dropped every other one; a DPAPI password in
// the credential file -- the documented way to store a changing password --
// therefore connected with NO authentication at all, which surfaces only as the
// bare "All configured authentication methods failed".
//
// deps.clientClass is the seam that makes this testable without a server.

class RecordingClient {
  constructor(sink) {
    this.sink = sink
    this.handlers = {}
  }
  on(event, fn) { (this.handlers[event] ||= []).push(fn) }
  once(event, fn) { this.on(event, fn) }
  fire(event, ...args) { for (const fn of this.handlers[event] || []) fn(...args) }
  connect(config) {
    this.sink.push(config)
    setImmediate(() => this.fire('ready'))
  }
  end() {}
  exec(_cmd, cb) { cb(null, { on() {}, stderr: { on() {} }, close() {}, destroy() {} }) }
}

function pooling(dshHome, sink, config = {}) {
  class Client extends RecordingClient {
    constructor() { super(sink) }
  }
  return new SshPool(
    { maxConnections: 4, hostKeyPolicy: 'off', reconnectCooldownMs: 0, ...config },
    { dshHome, clientClass: Client }
  )
}

/** An isolated DSH_HOME with an empty credential directory. */
function home() {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-ssh-auth-'))
  mkdirSync(join(dir, 'dsh-ssh-safe'), { recursive: true })
  return dir
}

test('a plaintext password in the credential file reaches ssh2 when allowed', async () => {
  const dshHome = home()
  writeFileSync(join(dshHome, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
    box: { host: 'example.invalid', port: 22, user: 'root', password: 'file-secret' },
  }))
  const sink = []
  const pool = pooling(dshHome, sink, { allowPlaintextPassword: true })
  await pool.connect('box', {})
  assert.equal(sink.length, 1)
  assert.equal(sink[0].username, 'root')
  assert.equal(sink[0].password, 'file-secret', 'the file password must be used, not dropped')
})

test('a password typed into the settings form reaches ssh2 when plaintext is allowed', async () => {
  const dshHome = home()
  const sink = []
  const pool = pooling(dshHome, sink, {
    allowPlaintextPassword: true,
    machines: { cfg: { host: 'h.invalid', user: 'u', password: 'cfg-secret' } },
  })
  await pool.connect('cfg', {})
  assert.equal(sink[0].password, 'cfg-secret')
})

test('a key configured in the settings form is read and passed', async () => {
  const dshHome = home()
  const keyPath = join(dshHome, 'id_test')
  writeFileSync(keyPath, ssh2.utils.generateKeyPairSync('ed25519').private)
  const sink = []
  const pool = pooling(dshHome, sink, {
    machines: { keyed: { host: 'h.invalid', user: 'u', keyPath } },
  })
  await pool.connect('keyed', {})
  assert.ok(Buffer.isBuffer(sink[0].privateKey), 'privateKey must be a Buffer')
  assert.match(String(sink[0].privateKey), /BEGIN OPENSSH PRIVATE KEY/)
})

test('an env password still reaches ssh2', async () => {
  const dshHome = home()
  const sink = []
  const pool = pooling(dshHome, sink)
  process.env.DSH_SSH_ENVBOX_HOST = 'env.invalid'
  process.env.DSH_SSH_ENVBOX_USER = 'envuser'
  process.env.DSH_SSH_ENVBOX_PASSWORD = 'env-secret'
  try {
    await pool.connect('envbox', {})
    assert.equal(sink[0].password, 'env-secret')
  } finally {
    delete process.env.DSH_SSH_ENVBOX_HOST
    delete process.env.DSH_SSH_ENVBOX_USER
    delete process.env.DSH_SSH_ENVBOX_PASSWORD
  }
})

test('a session password the profile forbids does not change connection identity', async () => {
  // credentialFor() ignores a session password when allowSessionPassword is
  // false, but the pool still folded it into the cache key. Two calls that
  // differed only in the (unused) password therefore forced a needless
  // reconnect, and the pool claimed to hold a credential it never used.
  const dshHome = home()
  const sink = []
  let created = 0
  class Counting extends RecordingClient {
    constructor() { super(sink); created += 1 }
  }
  const pool = new SshPool(
    { maxConnections: 4, hostKeyPolicy: 'off', reconnectCooldownMs: 0, allowSessionPassword: false },
    { dshHome, clientClass: Counting }
  )
  process.env.DSH_SSH_IDBOX_HOST = 'id.invalid'
  process.env.DSH_SSH_IDBOX_USER = 'u'
  process.env.DSH_SSH_IDBOX_PASSWORD = 'stored'
  try {
    await pool.connect('idbox', { sessionPassword: 'first-ignored' })
    await pool.connect('idbox', { sessionPassword: 'second-ignored' })
    assert.equal(created, 1, 'the live connection must be reused')
    assert.equal(sink[0].password, 'stored')
  } finally {
    delete process.env.DSH_SSH_IDBOX_HOST
    delete process.env.DSH_SSH_IDBOX_USER
    delete process.env.DSH_SSH_IDBOX_PASSWORD
  }
})

test('a machine with no credentials at all is refused before connecting', async () => {
  const dshHome = home()
  const sink = []
  const pool = pooling(dshHome, sink, {
    machines: { empty: { host: 'h.invalid', user: 'u' } },
  })
  await assert.rejects(
    () => pool.connect('empty', {}),
    (err) => { assert.match(err.message, /no credentials/i); return true }
  )
  assert.equal(sink.length, 0, 'nothing must be dialled without a credential')
})