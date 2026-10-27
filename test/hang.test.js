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

test('maxBytes can tighten the configured cap but never exceed it', async () => {
  // A tool argument must not be able to raise the configured ceiling.
  class Counting {
    constructor() { this.requestedRead = 0 }
    sftp(cb) {
      const self = this
      cb(null, {
        createReadStream() {
          const rs = new EventEmitter()
          self.requestedRead++
          setImmediate(() => { rs.emit('data', Buffer.from('x'.repeat(4096))); rs.emit('end') })
          rs.destroy = () => {}
          return rs
        },
      })
    }
  }
  const pool = await poolWith(new Counting())
  pool.config.maxFileBytes = 64
  const r = await pool.readFile('t', '/tmp/big', { maxBytes: 10_000_000 })
  assert.equal(r.bytes, 64, 'the configured 64-byte ceiling wins over a huge argument')
  assert.equal(r.truncated, true)
})

test('a listing reports the path it actually used', async () => {
  class L extends FakeClient {
    sftp(cb) {
      cb(null, {
        readdir(_p, done) {
          done(null, [{ filename: 'a.txt', attrs: { size: 3, mode: 0o100644, mtime: 0 } }])
        },
      })
    }
  }
  const pool = await poolWith(new L('ok'))
  const r = await pool.list('t', '/home//user/./')
  assert.equal(r.path, '/home/user', 'the normalised path is reported back')
  assert.equal(r.items.length, 1)
})

test('closeOne reports whether a live connection existed and whether it was confirmed', async () => {
  const pool = await poolWith(new FakeClient('ok'))
  const missing = await pool.closeOne('nope')
  assert.equal(missing.closed, false, 'no entry at all')

  const e = pool.entry('t2')
  e.client = new FakeClient('ok')
  const result = await pool.closeOne('t2')
  assert.equal(result.closed, true, 'a connection existed')
  assert.equal(result.confirmed, false, 'this fake never emits close')
  assert.equal(e.client, null, 'the entry is left usable but disconnected')
})
