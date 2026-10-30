import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { SshPool } from '../src/pool.js'

// Eviction and work in progress.
//
// History: closeOne() gained a busy guard (refuse to sever a running command),
// then evictIdle() called it without force and reported a ceiling it did not
// hold. The fix at the time was to force-close -- which kept the ceiling and
// killed a running command whenever the agent touched one machine too many:
// 'sleep 2; echo done' on machine A came back as "connection closed before the
// command reported an exit status" because machine B was used meanwhile.
//
// The policy is now: evict idle connections, leave a busy one alone, report the
// overflow, and enforce the ceiling on the next acquire. A resource ceiling is
// not a reason to abort work the user asked for.
//
// shutdown.test.js covers closeAll+busy; lru.test.js covers ordering.

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

test('a connection running a command is not evicted', async () => {
  const pool = makePool(2)
  for (const alias of ['a', 'b', 'c']) {
    pool.entry(alias).client = new FakeClient()
    pool.beginOp(alias) // every connection has work in progress
  }

  const closed = await pool.evictIdle(2, 'c')
  assert.equal(closed.length, 0, 'nothing may be severed while it runs')
  assert.equal(live(pool), 3, 'the overflow is temporary and bounded by the callers')
  assert.equal(pool.connectionStats().overLimit, true, 'and it is reported as such')
})

test('an idle connection is evicted even when another one is busy', async () => {
  const pool = makePool(2)
  for (const alias of ['a', 'b', 'c']) pool.entry(alias).client = new FakeClient()
  pool.beginOp('c') // the newest is the one working

  const closed = await pool.evictIdle(2, 'c')
  assert.deepEqual(closed, ['a'], 'the oldest idle one goes')
  assert.ok(pool.entries.get('c').client, 'the working one survives')
})

test('the ceiling is enforced once the busy connection drains', async () => {
  const pool = makePool(1)
  for (const alias of ['a', 'b']) pool.entry(alias).client = new FakeClient()
  pool.beginOp('a')

  assert.equal((await pool.evictIdle(1, 'b')).length, 0)
  assert.equal(live(pool), 2)

  pool.endOp('a') // the command finished
  const closed = await pool.evictIdle(1, 'b')
  assert.deepEqual(closed, ['a'])
  assert.equal(live(pool), 1)
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
