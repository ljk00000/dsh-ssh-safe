import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import ssh2 from 'ssh2'

import { SshPool } from '../src/pool.js'
import { Utf8Collector } from '../src/buffer.js'

// A channel delivers bytes, and a chunk boundary can fall inside a multi-byte
// character. Decoding each chunk on its own turned one 3-byte character into
// three U+FFFD, so 'cat' of any non-ASCII file lost characters at the seams.

const { Server } = ssh2

/** A server that answers exec with the given payload, split at the given byte. */
async function servingText(payload, splitAt) {
  const server = new Server(
    { hostKeys: [ssh2.utils.generateKeyPairSync('ed25519').private] },
    (client) => {
      client.on('error', () => {})
      client.on('authentication', (ctx) => ctx.accept())
      client.on('ready', () => client.on('session', (accept) => {
        const session = accept()
        session.on('exec', (acceptExec) => {
          const stream = acceptExec()
          stream.write(payload.subarray(0, splitAt))
          // A separate packet, so the split is a real protocol boundary.
          setTimeout(() => {
            stream.write(payload.subarray(splitAt))
            stream.exit(0)
            stream.end()
          }, 20)
        })
      }))
    },
  )
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(undefined)))
  return server
}

function poolFor(server) {
  return new SshPool({
    hostKeyPolicy: 'off',
    allowPlaintextPassword: true,
    maxConnections: 2,
    commandTimeoutMs: 5000,
    maxOutputChars: 200000,
    closeTimeoutMs: 500,
    reconnectCooldownMs: 0,
    healthCheckIdleMs: 0,
    machines: { t: { host: '127.0.0.1', port: server.address().port, user: 'u', password: 'p' } },
  }, { dshHome: mkdtempSync(path.join(tmpdir(), 'dsh-utf8-')) })
}

test('a character split across two chunks survives the exec output', async () => {
  const text = '中文测试'.repeat(50)
  const payload = Buffer.from(text, 'utf8')
  const server = await servingText(payload, 1) // one byte into the first 3-byte character
  const pool = poolFor(server)
  try {
    const result = await pool.exec('t', 'cat file', {})
    assert.equal(result.stdout, text)
    assert.ok(!result.stdout.includes('\uFFFD'), 'no replacement characters')
  } finally {
    await pool.closeAll({ force: true })
    server.close()
  }
})

test('the same holds for stderr', async () => {
  const text = '错误信息'.repeat(10)
  const payload = Buffer.from(text, 'utf8')
  const server = new Server(
    { hostKeys: [ssh2.utils.generateKeyPairSync('ed25519').private] },
    (client) => {
      client.on('error', () => {})
      client.on('authentication', (ctx) => ctx.accept())
      client.on('ready', () => client.on('session', (accept) => {
        const session = accept()
        session.on('exec', (acceptExec) => {
          const stream = acceptExec()
          stream.stderr.write(payload.subarray(0, 2))
          setTimeout(() => {
            stream.stderr.write(payload.subarray(2))
            stream.exit(0)
            stream.end()
          }, 20)
        })
      }))
    },
  )
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(undefined)))
  const pool = poolFor(server)
  try {
    const result = await pool.exec('t', 'noisy', {})
    assert.equal(result.stderr, text)
  } finally {
    await pool.closeAll({ force: true })
    server.close()
  }
})

test('the read collector also joins split characters', () => {
  const collector = new Utf8Collector()
  const payload = Buffer.from('中文', 'utf8')
  collector.push(payload.subarray(0, 2))
  collector.push(payload.subarray(2))
  assert.equal(collector.toString(), '中文')
})
