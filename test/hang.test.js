import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'

// A stalled SFTP write stream is the scenario that used to hang forever:
// ssh2 emits neither 'error' nor 'close' when the server drops the channel
// mid-transfer. These tests drive the pool with a fake client, so they need
// no network and no ssh2 install.

class FakeWriteStream extends EventEmitter {
  constructor() { super(); this.ended = false; this.destroyed = false }
  end() { this.ended = true /* never emits close/finish: simulates the stall */ }
  destroy() { this.destroyed = true }
}

class FakeSftp {
  constructor(behavior) { this.behavior = behavior; this.stream = null }
  createWriteStream() { this.stream = new FakeWriteStream(); return this.stream }
  createReadStream() {
    const rs = new EventEmitter()
    rs.destroy = () => { rs.destroyed = true }
    if (this.behavior === 'stall') { /* emit nothing */ }
    return rs
  }
  readdir(_p, cb) { /* never calls back: simulates a stall */ }
}

class FakeClient {
  constructor(behavior) { this.behavior = behavior; this.ended = false }
  sftp(cb) { cb(null, new FakeSftp(this.behavior)) }
  once() {}
  end() { this.ended = true }
  on() {}
}

function poolWith(client) {
  // Import lazily so the test file works without the DSH host packages.
  return import('../src/pool.js').then(({ SshPool }) => {
    const pool = new SshPool(
      { sftpTimeoutMs: 60, commandTimeoutMs: 60, maxOutputChars: 1024, maxFileBytes: 1024, reconnectCooldownMs: 0, hostKeyPolicy: 'off', allowSessionPassword: true },
      { dshHome: '/tmp/dsh-ssh-safe-test' }
    )
    // Skip the real handshake entirely.
    pool.connect = async () => client
    return pool
  })
}

test('a stalled SFTP write rejects at the deadline instead of hanging', async () => {
  // normalizeRemotePath needs an absolute path, and hostKeyPolicy is off so no
  // store lookup happens.
  process.env.DSH_SSH_T_HOST = 'h'
  process.env.DSH_SSH_T_USER = 'u'
  process.env.DSH_SSH_T_PASSWORD = 'p'
  try {
    const pool = await poolWith(new FakeClient('stall'))
    const started = Date.now()
    await assert.rejects(
      () => pool.writeFile('t', '/tmp/x', 'hi'),
      (err) => { assert.match(err.message, /did not complete within/); return true }
    )
    assert.ok(Date.now() - started < 2000, 'it must not wait long after the deadline')
  } finally {
    delete process.env.DSH_SSH_T_HOST
    delete process.env.DSH_SSH_T_USER
    delete process.env.DSH_SSH_T_PASSWORD
  }
})

test('a stalled directory listing rejects at the deadline', async () => {
  const pool = await poolWith(new FakeClient('stall'))
  await assert.rejects(
    () => pool.list('t', '/tmp'),
    (err) => { assert.match(err.message, /did not complete within/); return true }
  )
})

test('closeOne reports whether a live connection existed', async () => {
  const pool = await poolWith(new FakeClient('ok'))
  assert.equal(await pool.closeOne('nope'), false)
  const e = pool.entry('t2')
  e.client = new FakeClient('ok')
  assert.equal(await pool.closeOne('t2'), true)
  assert.equal(e.client, null, 'the entry is left usable but disconnected')
})
