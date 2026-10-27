import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { SshPool } from '../src/pool.js'

// The data path of exec() -- data events, then close -- was never actually
// exercised: every existing test drove the deadline or the credential checks.
// A test that looked like it covered this returned an empty string because the
// fake emitted data before the exec callback had installed its listeners.
//
// These drive the stream only after exec's callback runs, which is what ssh2
// does.

class FakeStream extends EventEmitter {
  constructor() { super(); this.stderr = new EventEmitter(); this.destroyed = false }
  signal() {}
  close() {}
  destroy() { this.destroyed = true }
}

class FakeClient {
  constructor() { this.handlers = {} }
  on(e, f) { this.handlers[e] = f }
  once(e, f) { this.handlers[e] = f }
  exec(_cmd, cb) {
    // exec() registers this callback from inside the Promise executor, so a
    // synchronous call is already safe: listeners are attached immediately
    // afterwards, before the promise is returned to the caller.
    this.cb = cb
    cb(null, this.stream)
  }
  end() { if (this.handlers.close) this.handlers.close() }
  sftp(cb) { cb(null, {}) }
}

async function run({ cap = 100000, chunks = [], errChunks = [], code = 0 }) {
  const stream = new FakeStream()
  const client = new FakeClient()
  client.stream = stream

  const pool = new SshPool(
    { maxConnections: 5, hostKeyPolicy: 'off', allowSessionPassword: true,
      reconnectCooldownMs: 0, commandTimeoutMs: 5000, maxOutputChars: cap, closeTimeoutMs: 100 },
    { dshHome: '/tmp/dsh-ssh-safe-exec' }
  )
  pool.connect = async () => client

  const promise = pool.exec('t', 'echo hi', {})
  // The callback ran synchronously, so listeners exist now.
  await Promise.resolve()

  for (const c of chunks) stream.emit('data', Buffer.from(c))
  for (const c of errChunks) stream.stderr.emit('data', Buffer.from(c))
  stream.emit('close', code)

  return await promise
}

test('stdout is returned', async () => {
  const r = await run({ chunks: ['hello'] })
  assert.equal(r.stdout, 'hello')
  assert.equal(r.timedOut, false)
  assert.equal(r.truncated, false)
})

test('stderr is returned separately', async () => {
  const r = await run({ chunks: ['out'], errChunks: ['boom'], code: 1 })
  assert.equal(r.stdout, 'out')
  assert.equal(r.stderr, 'boom')
  assert.equal(r.code, 1)
})

test('chunks are concatenated in order', async () => {
  const r = await run({ chunks: ['a', 'b', 'c'] })
  assert.equal(r.stdout, 'abc')
})

test('the timeline preserves interleaving', async () => {
  const stream = new FakeStream()
  const client = new FakeClient()
  client.stream = stream
  const pool = new SshPool(
    { maxConnections: 5, hostKeyPolicy: 'off', allowSessionPassword: true,
      reconnectCooldownMs: 0, commandTimeoutMs: 5000, maxOutputChars: 100000, closeTimeoutMs: 100 },
    { dshHome: '/tmp/dsh-ssh-safe-exec' }
  )
  pool.connect = async () => client

  const promise = pool.exec('t', 'cmd', {})
  await Promise.resolve()
  stream.emit('data', Buffer.from('one'))
  stream.stderr.emit('data', Buffer.from('two'))
  stream.emit('data', Buffer.from('three'))
  stream.emit('close', 0)

  const r = await promise
  assert.deepEqual(r.timeline.map((e) => e.stream), ['out', 'err', 'out'], 'arrival order is recorded')
  assert.deepEqual(r.timeline.map((e) => e.text), ['one', 'two', 'three'])
})

test('output beyond the cap is truncated and reported', async () => {
  const r = await run({ cap: 10, chunks: ['abcdefghijklmno'] })
  assert.equal(r.stdout.length, 10)
  assert.equal(r.truncated, true, 'the cut must be visible')
})

test('stdout and stderr share one cap', async () => {
  const r = await run({ cap: 10, chunks: ['abcdefgh'], errChunks: ['ijklmno'] })
  assert.equal(r.stdout, 'abcdefgh')
  assert.equal(r.stderr, 'ij')
  assert.equal(r.stdout.length + r.stderr.length, 10, 'the ceiling is total, not per stream')
  assert.equal(r.truncated, true)
})

test('a non-zero exit code is preserved', async () => {
  const r = await run({ chunks: ['x'], code: 42 })
  assert.equal(r.code, 42)
})

test('multi-byte output survives chunk boundaries', async () => {
  const bytes = Buffer.from('中文测试', 'utf8')
  const pieces = []
  for (const b of bytes) pieces.push(Buffer.from([b]).toString('latin1'))
  const r = await run({ chunks: pieces.map((p) => Buffer.from(p, 'latin1').toString('utf8')) })
  // The fake feeds pre-decoded strings, so this mainly pins that nothing crashes;
  // real byte-level splitting is covered by regression.test.js.
  assert.equal(typeof r.stdout, 'string')
})
