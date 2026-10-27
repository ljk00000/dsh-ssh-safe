import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { SshPool } from '../src/pool.js'

// Regression guard for the gap between two fixes.
//
// closeOne() gained a busy guard (refuse to sever a running command), and
// evictIdle() called closeOne() without force. Eviction therefore did nothing
// while reporting success: the ceiling was silently exceeded.
//
// shutdown.test.js covered closeAll+busy. lru.test.js covered eviction. Nothing
// covered the two together, which is exactly where the defect lived.

class FakeStream extends EventEmitter {
  constructor() { super(); this.stderr = new EventEmitter() }
  signal() {}
  close() {}
  destroy() {}
}

class FakeClient {
  constructor() { this.handlers = {}; this.ended = false }
  on(e, f) { this.handlers[e] = f }
  once(e, f) { this.handlers[e] = f }
  exec(_c, cb) { const s = new FakeStream(); cb(null, s); s.emit('close', 0) }
  end() { this.ended = true; if (this.handlers.close) this.handlers.close() }
  sftp(cb) { cb(null, {}) }
}

function makePool(maxConnections) {
  return new SshPool(
    { maxConnections, hostKeyPolicy: 'off', allowSessionPassword: true,
      reconnectCooldownMs: 0, commandTimeoutMs: 1000, maxOutputChars: 1000,
      closeTimeoutMs: 100, healthCheckIdleMs: 0 },
    { dshHome: '/tmp/dsh-ssh-safe-evict' }
  )
}

const live = (pool) => [...pool.entries.values()].filter((e) => e.client).length

test('eviction holds the ceiling even when every connection is busy', async () => {
  const pool = makePool(2)
  for (const alias of ['a', 'b', 'c']) {
    pool.entry(alias).client = new FakeClient()
    pool.beginOp(alias) // every connection has work in progress
  }

  const closed = await pool.evictIdle(2, 'c')
  assert.ok(live(pool) <= 2, 'the ceiling must hold, got ' + live(pool))
  assert.equal(closed.length, 1, 'exactly one connection is evicted')
})

test('evictIdle only reports connections it actually closed', async () => {
  const pool = makePool(1)
  for (const alias of ['a', 'b']) pool.entry(alias).client = new FakeClient()

  const closed = await pool.evictIdle(1, 'b')
  assert.deepEqual(closed, ['a'])
  assert.equal(pool.entries.get('a').client, null, 'the reported alias is really closed')
})

test('eviction never closes the protected connection', async () => {
  const pool = makePool(1)
  pool.entry('keep').client = new FakeClient()
  pool.entry('drop').client = new FakeClient()

  await pool.evictIdle(1, 'keep')
  assert.ok(pool.entries.get('keep').client, 'the protected connection survives')
  assert.equal(pool.entries.get('drop').client, null)
})

test('connectionStats reports the ceiling and the live set', async () => {
  const pool = makePool(3)
  pool.entry('a').client = new FakeClient()
  pool.entry('b').client = new FakeClient()
  const stats = pool.connectionStats()
  assert.equal(stats.live, 2)
  assert.equal(stats.limit, 3)
  assert.deepEqual(stats.aliases.sort(), ['a', 'b'])
})
