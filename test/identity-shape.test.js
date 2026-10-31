import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { SshPool, identityProblem } from '../src/pool.js'

// A host with a space failed at DNS ("the host name did not resolve") and a user
// with a newline stalled until the handshake timed out. Neither message named the
// field, and both cost a timeout before the caller learned anything.

const pool = (machines) => new SshPool({
  hostKeyPolicy: 'tofu',
  allowPlaintextPassword: true,
  connectTimeoutMs: 1000,
  commandTimeoutMs: 1000,
  reconnectCooldownMs: 0,
  healthCheckIdleMs: 0,
  machines,
}, { dshHome: mkdtempSync(path.join(tmpdir(), 'dsh-identity-')) })

test('a host that can never resolve is refused before dialling', async () => {
  const cases = [
    ['exa mple.com', /the host contains a space/],
    ['example.com # a note', /the host contains '#'/],
    ['http://example.com', /holds a URL/],
  ]
  for (const [host, expected] of cases) {
    const p = pool({ t: { host, port: 22, user: 'u', password: 'p' } })
    await assert.rejects(
      () => p.exec('t', 'echo hi', {}),
      (err) => {
        assert.match(err.message, /cannot be used/)
        assert.match(err.message, expected)
        assert.match(err.message, /"t"/)
        return true
      },
      host,
    )
  }
})

test('a user name with a control character is refused before dialling', async () => {
  const p = pool({ t: { host: 'example.com', port: 22, user: 'u\nroot', password: 'p' } })
  await assert.rejects(
    () => p.exec('t', 'echo hi', {}),
    /the user field is unusable: the user contains a control character/,
  )
})

test('ordinary names still pass the check', () => {
  for (const m of [
    { host: 'example.com', username: 'deploy' },
    { host: '10.0.0.5', username: 'root' },
    { host: 'fe80::1', username: 'u' },
    { host: 'example.com', username: 'DOMAIN\\user' },
    { host: '', username: '' },
  ]) {
    assert.equal(identityProblem(m), '', JSON.stringify(m))
  }
})
