import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
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
