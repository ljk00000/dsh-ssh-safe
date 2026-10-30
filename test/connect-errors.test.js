import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:net'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { SshPool } from '../src/pool.js'
import { startServer, machineFor } from './helpers/local-ssh-server.js'

// ssh2 reports the bare socket error. "read ECONNRESET" with several machines
// configured says neither which one nor what to do; these pin the wrapped form.

function pool(machines, overrides = {}) {
  return new SshPool({
    hostKeyPolicy: 'off',
    allowPlaintextPassword: true,
    commandTimeoutMs: 5000,
    sftpTimeoutMs: 5000,
    connectTimeoutMs: 3000,
    closeTimeoutMs: 500,
    maxOutputChars: 10000,
    maxFileBytes: 1048576,
    maxConnections: 2,
    reconnectCooldownMs: 0,
    healthCheckIdleMs: 0,
    machines,
    ...overrides,
  }, { dshHome: mkdtempSync(path.join(tmpdir(), 'dsh-conn-')) })
}

test('a port that is not sshd names the target and the likely cause', async () => {
  const sockets = new Set()
  const server = createServer((socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.destroy() })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  const p = pool({ box: { host: '127.0.0.1', port, user: 'tester', password: 'x' } })
  try {
    await assert.rejects(
      () => p.connect('box', {}),
      (err) => {
        assert.match(err.message, /Could not connect to tester@127\.0\.0\.1:/, err.message)
        assert.match(err.message, /ECONNRESET/)
        assert.match(err.message, /may not be sshd/)
        return true
      },
    )
  } finally {
    for (const socket of sockets) { try { socket.destroy() } catch {} }
    await new Promise((resolve) => server.close(resolve))
    await p.closeAll({ force: true })
  }
})

test('a wrong password says the credentials were rejected', async () => {
  const srv = await startServer()
  const p = pool({ box: machineFor('box', srv.port, { password: 'definitely-wrong' }) })
  try {
    await assert.rejects(
      () => p.connect('box', {}),
      (err) => {
        assert.match(err.message, /Could not connect to tester@127\.0\.0\.1:/)
        assert.match(err.message, /authentication methods failed|Permission denied/i)
        assert.match(err.message, /authorized_keys/)
        return true
      },
    )
  } finally {
    await p.closeAll({ force: true })
    await srv.close()
  }
})

test('a closed port says nothing is listening', async () => {
  // Bind and release, so the port is certainly closed.
  const server = createServer()
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  await new Promise((resolve) => server.close(resolve))

  const p = pool({ box: { host: '127.0.0.1', port, user: 'tester', password: 'x' } })
  try {
    await assert.rejects(
      () => p.connect('box', {}),
      (err) => {
        assert.match(err.message, /Could not connect to tester@127\.0\.0\.1:/)
        assert.match(err.message, /ECONNREFUSED/)
        assert.match(err.message, /nothing is listening/)
        return true
      },
    )
  } finally {
    await p.closeAll({ force: true })
  }
})

test('an untrusted host key points at trustHostKey', async () => {
  const srv = await startServer()
  const p = pool({ box: machineFor('box', srv.port) }, { hostKeyPolicy: 'strict' })
  try {
    await assert.rejects(
      () => p.connect('box', {}),
      (err) => {
        assert.match(err.message, /Host key|Unknown host/i)
        assert.match(err.message, /trustHostKey/)
        return true
      },
    )
  } finally {
    await p.closeAll({ force: true })
    await srv.close()
  }
})
test('an unreadable key file names the machine and does not start a cooldown', async () => {
  const p = pool({ box: { host: '127.0.0.1', port: 22, user: 'deploy', keyPath: '/definitely/not/here' } })
  try {
    for (let attempt = 1; attempt <= 2; attempt++) {
      await assert.rejects(
        () => p.connect('box', {}),
        (err) => {
          assert.match(err.message, /Machine "box" cannot use its credential/, 'attempt ' + attempt)
          assert.match(err.message, /ENOENT/)
          assert.doesNotMatch(err.message, /Refusing to retry/, 'a config error must not start the cooldown')
          return true
        },
      )
    }
  } finally {
    await p.closeAll({ force: true })
  }
})
test('a host that holds a URL, a user or a port is explained', async () => {
  // A resolve failure says "the host name did not resolve", which is true and
  // useless when the field holds something that is not a host name at all.
  const { connectFailure } = await import('../src/pool.js')
  const resolveError = new Error('getaddrinfo ENOTFOUND whatever')
  const cases = [
    ['ssh://10.0.0.5', /looks like a URL/],
    ['root@10.0.0.5', /the user name belongs in the user field/],
    ['10.0.0.5:2222', /ends with a port/],
    ['  10.0.0.5  ', /leading or trailing spaces/],
  ]
  for (const [host, pattern] of cases) {
    const wrapped = connectFailure(resolveError, { host, port: 22, username: 'u' })
    assert.match(wrapped.message, pattern, host + ' -> ' + wrapped.message)
    assert.match(wrapped.message, /Could not connect to u@/)
  }
  const plain = connectFailure(resolveError, { host: 'example.com', port: 22, username: 'u' })
  assert.doesNotMatch(plain.message, /looks like a URL|belongs in the user field|ends with a port/)
})
test('an out-of-range port is a configuration error, not a raw socket error', async () => {
  // The settings form is schema-validated; the credential file and the
  // environment are not, so 99999 reached net.connect and came back as
  // "Port should be >= 0 and < 65536" with no machine and nothing to fix.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-port-'))
  mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
  writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
    box: { host: '127.0.0.1', port: 99999, user: 'u', password: 'p' },
  }))
  const p = new SshPool({
    hostKeyPolicy: 'off', allowPlaintextPassword: true, commandTimeoutMs: 5000,
    sftpTimeoutMs: 5000, connectTimeoutMs: 3000, closeTimeoutMs: 500, maxOutputChars: 10000,
    maxFileBytes: 1048576, maxConnections: 2, reconnectCooldownMs: 0, healthCheckIdleMs: 0,
    machines: {},
  }, { dshHome: home })
  try {
    for (let attempt = 1; attempt <= 2; attempt++) {
      await assert.rejects(
        () => p.connect('box', {}),
        (err) => {
          assert.match(err.message, /Machine "box" cannot be used: port 99999 from the file/)
          assert.match(err.message, /not an integer between 1 and 65535/)
          assert.doesNotMatch(err.message, /Port should be >= 0/, 'no raw socket error')
          assert.doesNotMatch(err.message, /Refusing to retry/)
          return true
        },
      )
    }
  } finally {
    await p.closeAll({ force: true })
    rmSync(home, { recursive: true, force: true })
  }
})
test('a user name holding @ explains that the host does not belong there', async () => {
  // 'tester@host' in the user field fails authentication, and the server's
  // 'All configured authentication methods failed' points at the credentials.
  const { connectFailure } = await import('../src/pool.js')
  const authError = new Error('All configured authentication methods failed')
  const wrapped = connectFailure(authError, { host: '10.0.0.5', port: 22, username: 'tester@nowhere' })
  assert.match(wrapped.message, /the server rejected the credentials/)
  assert.match(wrapped.message, /the user contains "@" — put only the account name/)

  const plain = connectFailure(authError, { host: '10.0.0.5', port: 22, username: 'tester' })
  assert.doesNotMatch(plain.message, /the user contains/)
})
test('machineInventory: alias hides the address in the error too', async () => {
  // Every failure message said "Could not connect to root@10.9.8.7:22", which is
  // the sentence most likely to end up in a shared transcript.
  const { connectFailure } = await import('../src/pool.js')
  const err = new Error('Timed out while waiting for handshake')
  const machine = { alias: 'prod', host: '10.9.8.7', port: 22, username: 'root' }
  const masked = connectFailure(err, machine, { lean: true })
  assert.doesNotMatch(masked.message, /10\.9\.8\.7/)
  assert.doesNotMatch(masked.message, /root@/)
  assert.match(masked.message, /machine "prod" \(address hidden\)/)

  const full = connectFailure(err, machine)
  assert.match(full.message, /root@10\.9\.8\.7:22/, 'the default still names the target')
})
