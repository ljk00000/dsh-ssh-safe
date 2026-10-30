import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { SshPool } from '../src/pool.js'
import { startServer, machineFor } from './helpers/local-ssh-server.js'

// These drive the real ssh2 client against a real ssh2 server on loopback.
// Everything below the tool layer — auth, host-key policy, channel streaming,
// timeout signalling, the in-flight counter, LRU eviction — only runs for real
// here; the other tests reach those lines through fakes.

let srv
let home
before(async () => {
  srv = await startServer()
  home = mkdtempSync(path.join(tmpdir(), 'dsh-ssh-live-'))
})
after(async () => {
  await srv.close()
  rmSync(home, { recursive: true, force: true })
})

function poolFor(machines, overrides = {}) {
  return new SshPool(
    {
      hostKeyPolicy: 'tofu',
      allowPlaintextPassword: true,
      commandTimeoutMs: 5000,
      connectTimeoutMs: 3000,
      maxOutputChars: 10000,
      maxConnections: 8,
      reconnectCooldownMs: 0,
      machines,
      ...overrides,
    },
    { dshHome: home },
  )
}

test('exec returns stdout and the exit code', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) })
  const r = await pool.exec('t', 'echo hello', {})
  assert.equal(r.stdout, 'ran: echo hello\n')
  assert.equal(r.code, 0)
  assert.equal(r.timedOut, false)
  await pool.closeAll({ force: true })
})

test('stderr is captured separately from stdout', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) })
  const r = await pool.exec('t', 'stderr', {})
  assert.equal(r.stderr, 'an error line\n')
  assert.equal(r.stdout, 'ok\n')
  await pool.closeAll({ force: true })
})

test('a non-zero exit code survives', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) })
  const r = await pool.exec('t', 'exit 7', {})
  assert.equal(r.code, 7)
  await pool.closeAll({ force: true })
})

test('the deadline returns partial output and marks the result', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) })
  const started = Date.now()
  const r = await pool.exec('t', 'sleep 5', { timeoutMs: 250 })
  assert.equal(r.timedOut, true)
  assert.ok(Date.now() - started < 2000, 'the deadline must not wait for the command')
  await pool.closeAll({ force: true })
})

test('maxOutputChars caps what one call collects', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) }, { maxOutputChars: 100 })
  const r = await pool.exec('t', 'big 5000', {})
  assert.ok(r.stdout.length <= 100, 'collected ' + r.stdout.length + ' characters')
  assert.equal(r.truncated, true)
  await pool.closeAll({ force: true })
})

test('a signal-terminated command reports the signal, not an exit code', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) })
  const r = await pool.exec('t', 'kill', {})
  assert.equal(r.code, null)
  assert.equal(r.signal, 'SIGKILL')
  await pool.closeAll({ force: true })
})

test('a changed host key is refused once the fingerprint is known', async () => {
  const first = await startServer()
  const tofu = poolFor({ h: machineFor('h', first.port) })
  await tofu.exec('h', 'echo ok', {})          // stores the fingerprint
  await tofu.closeAll({ force: true })
  await first.close()

  // Same address, different key: the shape a man-in-the-middle takes.
  const replacement = await startServer({ port: first.port })
  try {
    const strict = poolFor({ h: machineFor('h', first.port) }, { hostKeyPolicy: 'strict' })
    await assert.rejects(
      () => strict.exec('h', 'echo ok', {}),
      (err) => {
        assert.match(err.message, /host key|fingerprint/i, err.message)
        return true
      },
    )
    await strict.closeAll({ force: true })
  } finally {
    await replacement.close()
  }
})

test('a refused connection enters a cooldown instead of retrying every call', async () => {
  const dead = await startServer()
  const port = dead.port
  await dead.close()
  const pool = poolFor({ d: machineFor('d', port) }, { reconnectCooldownMs: 5000, connectTimeoutMs: 1000 })
  await assert.rejects(() => pool.exec('d', 'echo hi', {}), (err) => /ECONNREFUSED|connect|refus/i.test(err.message))
  await assert.rejects(
    () => pool.exec('d', 'echo hi', {}),
    (err) => {
      assert.match(err.message, /cooldown|retry|too soon/i, err.message)
      return true
    },
  )
  await pool.closeAll({ force: true })
})

test('closeOne refuses a busy connection unless forced', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) })
  await pool.exec('t', 'echo warm', {})
  const running = pool.exec('t', 'sleep 3', {}).then(() => 'settled', (e) => 'rejected: ' + e.message)
  await new Promise((r) => setTimeout(r, 250))

  const idle = await pool.closeOne('t')
  assert.equal(idle.busy, true, 'a running command must keep the connection open')

  const forced = await pool.closeOne('t', { force: true })
  assert.equal(forced.closed, true)
  // The command was cut off, so its call must settle one way or the other.
  assert.match(await running, /settled|rejected/)
  await pool.closeAll({ force: true })
})

test('maxConnections evicts one connection when the ceiling is exceeded', async () => {
  const pool = poolFor({
    a: machineFor('a', srv.port),
    b: machineFor('b', srv.port),
    c: machineFor('c', srv.port),
  }, { maxConnections: 2 })
  try {
    await pool.exec('a', 'echo a', {})
    await pool.exec('b', 'echo b', {})
    assert.ok(pool.entry('a').client, 'a must be connected')
    await pool.exec('c', 'echo c', {})       // third connection: evicts the oldest

    const live = [...pool.entries.values()].filter((e) => e.client).length
    assert.equal(live, 2, 'exactly maxConnections may stay open, saw ' + live)
    assert.ok(pool.entry('c').client, 'the connection just used must survive')
    const evicted = ['a', 'b'].filter((alias) => pool.entry(alias).client === null)
    // The oldest is a on a quiet machine, but millisecond timestamps can tie;
    // the invariant that matters is that exactly one of the two was dropped.
    assert.equal(evicted.length, 1, 'exactly one of a/b should be evicted, got ' + JSON.stringify(evicted))
  } finally {
    await pool.closeAll({ force: true })
  }
})

test('a second connection to the same host reuses the pooled client', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) })
  await pool.exec('t', 'echo one', {})
  const first = pool.entry('t').client
  await pool.exec('t', 'echo two', {})
  assert.equal(pool.entry('t').client, first, 'the client must be reused')
  await pool.closeAll({ force: true })
})
