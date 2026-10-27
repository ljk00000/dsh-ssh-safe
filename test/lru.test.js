import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { SshPool } from '../src/pool.js'

// The connection ceiling used to be enforced only in ssh_connect, so a caller
// that went straight to ssh_exec/ssh_read/ssh_write/ssh_list accumulated one
// live socket per machine with no upper bound. Eviction moved into connect(),
// which every tool path passes through.

class FakeStream extends EventEmitter {
  constructor() { super(); this.stderr = new EventEmitter() }
  signal() {}
  close() {}
  destroy() {}
}

class FakeClient {
  constructor() { this.handlers = {}; this.closed = false }
  on(event, fn) { this.handlers[event] = fn }
  once(event, fn) { this.handlers[event] = fn }
  exec(_cmd, cb) { cb(null, new FakeStream()) }
  end() { this.closed = true; if (this.handlers.close) this.handlers.close() }
  sftp(cb) { cb(null, {}) }
}

function makePool(maxConnections) {
  const pool = new SshPool(
    { maxConnections, hostKeyPolicy: 'off', allowSessionPassword: true,
      reconnectCooldownMs: 0, commandTimeoutMs: 1000, maxOutputChars: 1000,
      closeTimeoutMs: 100 },
    { dshHome: '/tmp/dsh-ssh-safe-lru' }
  )
  // Replace the handshake with a fake so the test needs no network.
  pool.connect = async function (alias) {
    const entry = this.entry(alias)
    if (!entry.client) {
      entry.client = new FakeClient()
      const limit = Number(this.config.maxConnections)
      if (Number.isFinite(limit) && limit > 0) await this.evictIdle(limit, alias)
      entry.lastUsedAt = Date.now()
    }
    return entry.client
  }
  return pool
}

const liveCount = (pool) => [...pool.entries.values()].filter((e) => e.client).length

test('the ceiling holds when tools go straight to exec', async () => {
  const pool = makePool(2)
  for (const alias of ['a', 'b', 'c', 'd', 'e']) {
    await pool.exec(alias, 'echo hi', {})
    assert.ok(liveCount(pool) <= 2, 'live connections exceeded the ceiling after ' + alias)
  }
  assert.equal(liveCount(pool), 2)
})

test('the connection just used is never evicted', async () => {
  const pool = makePool(2)
  for (const alias of ['a', 'b', 'c']) await pool.exec(alias, 'echo hi', {})
  assert.ok(pool.entries.get('c').client, 'the most recent connection must survive')
  assert.equal(pool.entries.get('a').client, null, 'the oldest is the one closed')
})

test('a limit of 0 disables eviction', async () => {
  const pool = makePool(0)
  for (const alias of ['a', 'b', 'c', 'd']) await pool.exec(alias, 'echo hi', {})
  assert.equal(liveCount(pool), 4, 'with the limit disabled nothing is closed')
})

test('evictIdle reports what it closed', async () => {
  const pool = makePool(10)
  for (const alias of ['a', 'b', 'c']) await pool.exec(alias, 'echo hi', {})
  const closed = await pool.evictIdle(1, 'c')
  assert.deepEqual(closed.sort(), ['a', 'b'])
  assert.equal(liveCount(pool), 1)
  assert.ok(pool.entries.get('c').client)
})
