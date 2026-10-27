import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { SshPool } from '../src/pool.js'

// closeAll() used to end every client unconditionally, severing whatever was
// running. Cutting an apt upgrade or a database import in half is a
// data-integrity problem, so shutdown now respects work in progress.

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

function pool() {
  return new SshPool(
    { closeTimeoutMs: 100, hostKeyPolicy: 'off', allowSessionPassword: true, reconnectCooldownMs: 0 },
    { dshHome: '/tmp/dsh-ssh-safe-shutdown' }
  )
}

test('a busy connection is not closed by closeAll', async () => {
  const p = pool()
  const e = p.entry('prod')
  e.client = new FakeClient()
  p.beginOp('prod')

  const result = await p.closeAll()
  assert.deepEqual(result.busy, ['prod'], 'the busy alias is reported')
  assert.deepEqual(result.closed, [])
  assert.equal(e.client.ended, false, 'the socket was left open')

  p.endOp('prod')
})

test('closeAll with force closes a busy connection', async () => {
  const p = pool()
  const e = p.entry('prod')
  e.client = new FakeClient()
  p.beginOp('prod')

  const result = await p.closeAll({ force: true })
  assert.deepEqual(result.closed, ['prod'])
  assert.equal(e.client, null)
})

test('an idle connection is closed by closeAll', async () => {
  const p = pool()
  const e = p.entry('idle')
  e.client = new FakeClient()

  const result = await p.closeAll()
  assert.deepEqual(result.closed, ['idle'])
  assert.equal(p.entries.size, 0, 'the entry is dropped with the connection')
})

test('closeOne refuses a busy alias without force', async () => {
  const p = pool()
  p.entry('prod').client = new FakeClient()
  p.beginOp('prod')

  const blocked = await p.closeOne('prod')
  assert.equal(blocked.busy, true)
  assert.equal(blocked.closed, false)

  const forced = await p.closeOne('prod', { force: true })
  assert.equal(forced.closed, true)
  p.endOp('prod')
})

test('in-flight counts nest and drain correctly', () => {
  const p = pool()
  assert.equal(p.isBusy('x'), false)
  p.beginOp('x')
  p.beginOp('x')
  assert.equal(p.isBusy('x'), true)
  p.endOp('x')
  assert.equal(p.isBusy('x'), true, 'still one operation running')
  p.endOp('x')
  assert.equal(p.isBusy('x'), false)
})

test('closeAll can wait for in-flight work to drain', async () => {
  const p = pool()
  p.entry('slow').client = new FakeClient()
  p.beginOp('slow')
  // Release the operation shortly after the drain window opens.
  setTimeout(() => p.endOp('slow'), 60)

  const result = await p.closeAll({ drainMs: 400 })
  assert.deepEqual(result.closed, ['slow'], 'it waited for the operation to finish')
  assert.deepEqual(result.busy, [])
})
