import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import ssh2 from 'ssh2'

import { SshPool } from '../src/pool.js'
import { alternateHostKey } from './helpers/local-ssh-server.js'
import { Utf8Collector, OutputBudget, countCodePoints } from '../src/buffer.js'

// A channel delivers bytes, and a chunk boundary can fall inside a multi-byte
// character. Decoding each chunk on its own turned one 3-byte character into
// three U+FFFD, so 'cat' of any non-ASCII file lost characters at the seams.

const { Server } = ssh2

// The helper's cached RSA key, not a fresh ed25519 one: ssh2's ed25519 key
// generation occasionally produced a key its own server parser rejected
// ("Malformed OpenSSH private key"), which failed these tests for a reason that
// has nothing to do with what they check. The helper documented the same flake.
const HOST_KEY = alternateHostKey()

/** A server that answers exec with the given payload, split at the given byte. */
async function servingText(payload, splitAt) {
  const server = new Server(
    { hostKeys: [HOST_KEY] },
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
    { hostKeys: [HOST_KEY] },
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
test('the error line survives when stdout has used the whole budget', async () => {
  // 'make' prints thousands of lines and then one line that says why it failed.
  // The shared budget spent it all on stdout, so stderr arrived to nothing: the
  // exit code was 2 and the explanation had been thrown away.
  const server = new Server(
    { hostKeys: [HOST_KEY] },
    (client) => {
      client.on('error', () => {})
      client.on('authentication', (ctx) => ctx.accept())
      client.on('ready', () => client.on('session', (accept) => {
        const session = accept()
        session.on('exec', (acceptExec) => {
          const stream = acceptExec()
          stream.write('ordinary output line\n'.repeat(4000))
          setTimeout(() => {
            stream.stderr.write('make: *** [build] Error 2\n')
            stream.exit(2)
            stream.end()
          }, 40)
        })
      }))
    },
  )
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(undefined)))
  const pool = new SshPool({
    hostKeyPolicy: 'off',
    allowPlaintextPassword: true,
    maxConnections: 1,
    commandTimeoutMs: 5000,
    maxOutputChars: 1000,
    closeTimeoutMs: 500,
    reconnectCooldownMs: 0,
    healthCheckIdleMs: 0,
    machines: { t: { host: '127.0.0.1', port: server.address().port, user: 'u', password: 'p' } },
  }, { dshHome: mkdtempSync(path.join(tmpdir(), 'dsh-errbudget-')) })
  try {
    const result = await pool.exec('t', 'make', {})
    assert.match(result.stderr, /Error 2/, 'the reason for the failure is kept')
    assert.equal(result.code, 2)
    assert.ok(result.stdout.length + result.stderr.length <= 1000, 'the budget still holds: ' + (result.stdout.length + result.stderr.length))
    assert.equal(result.truncated, true, 'and the loss is still reported')
    assert.ok(result.timeline.some((entry) => entry.stream === 'err'), 'the error reaches the rendered output')
  } finally {
    await pool.closeAll({ force: true })
    server.close()
  }
})

test('the dropped count is in characters, not UTF-16 units', () => {
  assert.equal(countCodePoints('abc'), 3)
  assert.equal(countCodePoints('中文'), 2)
  assert.equal(countCodePoints('\u{1F600}\u{1F600}'), 2, 'an emoji is one character')
  assert.equal(countCodePoints(''), 0)

  // 2000 emoji, a 1024-unit budget: 512 emoji fit, so 1488 are dropped. Counting
  // units reported 2976 -- twice the truth for exactly the characters a reader
  // cannot eyeball.
  const budget = new OutputBudget(1024)
  const state = { text: '', truncated: false }
  budget.append(state, '\u{1F600}'.repeat(2000))
  assert.equal(budget.dropped, 1488)
})