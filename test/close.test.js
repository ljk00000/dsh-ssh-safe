import { test } from 'node:test'
import assert from 'node:assert/strict'
import { closeClient } from '../src/close.js'
import { EventEmitter } from 'node:events'

class Silent {
  once() {}
  end() {}
}

class Prompt extends EventEmitter {
  end() { setTimeout(() => this.emit('close'), 1) }
}

class Throwing {
  once() { throw new Error('broken client') }
  end() { throw new Error('broken client') }
}

test('a silent peer does not hang shutdown', async () => {
  const started = Date.now()
  const confirmed = await closeClient(new Silent(), 120)
  const elapsed = Date.now() - started
  assert.equal(confirmed, false, 'an unconfirmed close is reported as such')
  assert.ok(elapsed >= 100, 'it waited for the deadline, got ' + elapsed + 'ms')
  assert.ok(elapsed < 1500, 'it did not wait far past it, got ' + elapsed + 'ms')
})

test('a responsive peer is confirmed quickly', async () => {
  const started = Date.now()
  const confirmed = await closeClient(new Prompt(), 1500)
  assert.equal(confirmed, true)
  assert.ok(Date.now() - started < 500)
})

test('a broken client is tolerated rather than thrown out of shutdown', async () => {
  const confirmed = await closeClient(new Throwing(), 120)
  assert.equal(confirmed, false)
})

test('a missing client resolves immediately', async () => {
  assert.equal(await closeClient(null, 1000), false)
  assert.equal(await closeClient(undefined, 1000), false)
})
