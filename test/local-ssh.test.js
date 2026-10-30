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
test('maxConnections 0 means no ceiling', async () => {
  const pool = poolFor({
    a: machineFor('a', srv.port),
    b: machineFor('b', srv.port),
    c: machineFor('c', srv.port),
  }, { maxConnections: 0 })
  try {
    for (const alias of ['a', 'b', 'c']) await pool.exec(alias, 'echo ' + alias, {})
    const live = [...pool.entries.values()].filter((e) => e.client).length
    assert.equal(live, 3, 'all three connections must stay open')
  } finally {
    await pool.closeAll({ force: true })
  }
})

test('closeAll with a drain window waits for work in flight', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) })
  try {
    await pool.exec('t', 'echo warm', {})
    const running = pool.exec('t', 'sleep 1', {})
    await new Promise((r) => setTimeout(r, 100))
    const result = await pool.closeAll({ drainMs: 3000 })
    assert.deepEqual(result.busy, [], 'the drain window must let the command finish')
    assert.ok(result.closed.includes('t'), 'the connection should be closed after draining')
    const out = await running
    assert.match(out.stdout, /slept 1/)
  } finally {
    await pool.closeAll({ force: true })
  }
})
test('an enormous timeout is clamped instead of firing immediately', async () => {
  // setTimeout rejects anything above 2^31-1 by firing after 1 ms, so a
  // timeoutMs of 10000000000 used to abort the command instantly.
  const pool = poolFor({ t: machineFor('t', srv.port) })
  try {
    const started = Date.now()
    const result = await pool.exec('t', 'sleep 0.4', { timeoutMs: 10000000000 })
    assert.equal(result.timedOut, false, 'the deadline must not fire early')
    assert.ok(Date.now() - started >= 300, 'the command should have been allowed to finish')
    assert.match(result.stdout, /slept 0\.4/)
  } finally {
    await pool.closeAll({ force: true })
  }
})
test('ten commands run at once on one connection', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) })
  try {
    const results = await Promise.all(Array.from({ length: 10 }, (_, i) => pool.exec('t', 'echo p' + i, {})))
    results.forEach((r, i) => assert.match(r.stdout, new RegExp('p' + i), 'call ' + i + ' got ' + JSON.stringify(r.stdout)))
  } finally {
    await pool.closeAll({ force: true })
  }
})

test('a dropped connection is noticed and re-established', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) }, { healthCheckIdleMs: 0 })
  try {
    const first = await pool.exec('t', 'echo before', {})
    assert.match(first.stdout, /before/)
    const before = pool.entry('t').client
    assert.ok(before, 'the first call must connect')

    srv.killClients()
    await new Promise((r) => setTimeout(r, 150))

    const after = await pool.exec('t', 'echo after', {})
    assert.match(after.stdout, /after/, 'the next call must not reuse a dead client')
    assert.notEqual(pool.entry('t').client, before, 'a new client should have been created')
  } finally {
    await pool.closeAll({ force: true })
  }
})
test('a timed-out command leaves the connection usable', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) })
  try {
    await pool.exec('t', 'echo warm', {})
    const client = pool.entry('t').client
    for (let i = 0; i < 3; i++) {
      const r = await pool.exec('t', 'sleep 2', { timeoutMs: 120 })
      assert.equal(r.timedOut, true)
    }
    assert.equal(pool.entry('t').client, client, 'the pooled client must survive a deadline')
    const after = await pool.exec('t', 'echo still-here', {})
    assert.match(after.stdout, /still-here/, 'the next command must run on the same connection')
  } finally {
    await pool.closeAll({ force: true })
  }
})
test('two calls on a cold alias open one connection, not two', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) })
  try {
    const before = srv.clientCount()
    const [one, two] = await Promise.all([
      pool.exec('t', 'sleep 0.2', {}),
      pool.exec('t', 'echo second', {}),
    ])
    assert.match(one.stdout, /slept/)
    assert.match(two.stdout, /second/)
    assert.equal(srv.clientCount() - before, 1, 'the connect must be shared, not duplicated')
  } finally {
    await pool.closeAll({ force: true })
  }
})

test('a five megabyte answer is capped, not buffered whole', async () => {
  const pool = poolFor({ t: machineFor('t', srv.port) }, { maxOutputChars: 2048 })
  try {
    const r = await pool.exec('t', 'big 5000000', {})
    assert.equal(r.truncated, true)
    assert.ok(r.stdout.length <= 2048, 'collected ' + r.stdout.length)
  } finally {
    await pool.closeAll({ force: true })
  }
})

test('fifty aliases under a ceiling of eight leave eight connections', async () => {
  const machines = {}
  const aliases = []
  for (let i = 0; i < 50; i++) {
    const alias = 'm' + i
    aliases.push(alias)
    machines[alias] = machineFor(alias, srv.port)
  }
  const pool = poolFor(machines, { maxConnections: 8 })
  try {
    for (const alias of aliases) await pool.exec(alias, 'echo ' + alias, {})
    const live = [...pool.entries.values()].filter((e) => e.client).length
    assert.equal(live, 8, 'the ceiling must hold, saw ' + live)
    assert.ok(srv.clientCount() <= 12, 'the server should not see every alias, saw ' + srv.clientCount())
  } finally {
    await pool.closeAll({ force: true })
  }
})
test('a connection closed mid-command is reported as incomplete', async () => {
  // maxConnections 2 with three aliases: the third connect force-closes the
  // oldest, which is running a command. The caller must not be told the
  // command finished normally with no output.
  const pool = poolFor({
    a: machineFor('a', srv.port),
    b: machineFor('b', srv.port),
    c: machineFor('c', srv.port),
  }, { maxConnections: 2 })
  try {
    await pool.exec('a', 'echo warm', {})
    const running = pool.exec('a', 'sleep 3', {})
    await new Promise((r) => setTimeout(r, 200))
    await pool.exec('b', 'echo b', {})
    await pool.exec('c', 'echo c', {})   // evicts a, whose command is running

    const result = await Promise.race([running, new Promise((r) => setTimeout(() => r('HUNG'), 5000))])
    assert.notEqual(result, 'HUNG', 'the evicted call must settle')
    const value = await running
    assert.equal(value.dropped, true, 'a channel that died without an exit status is incomplete')
    assert.equal(value.timedOut, false)
  } finally {
    await pool.closeAll({ force: true })
  }
})