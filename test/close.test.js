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

test('an unconfirmed close destroys the socket instead of leaving it half-closed', async () => {
  // client.destroy() is guarded by isWritable() inside ssh2, and end() has already
  // ended the writable side, so it did nothing: the pool dropped its reference and
  // the socket sat in FIN_WAIT until the OS timed it out. A real socket proves it.
  const net = await import('node:net')
  // allowHalfOpen keeps the peer from answering our FIN, which is what a wedged
  // peer looks like from here.
  const server = net.createServer({ allowHalfOpen: true }, (socket) => {
    socket.on('error', () => {})
    socket.pause()
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const socket = net.connect(server.address().port, '127.0.0.1')
  await new Promise((resolve) => socket.once('connect', resolve))
  // Our own socket is the one that must be gone: a destroyed socket emits 'close'
  // at once, while a half-closed one waits for a FIN the peer never sends.
  const closed = new Promise((resolve) => socket.once('close', resolve))
  const fake = {
    _sock: socket,
    once: (event, handler) => socket.once(event, handler),
    end: () => socket.end(),
  }
  try {
    const confirmed = await closeClient(fake, 120)
    assert.equal(confirmed, false)
    const verdict = await Promise.race([
      closed.then(() => 'closed'),
      new Promise((resolve) => setTimeout(() => resolve('still open'), 1500)),
    ])
    assert.equal(verdict, 'closed', 'the socket must not stay open after an unconfirmed close')
  } finally {
    server.close()
  }
})
