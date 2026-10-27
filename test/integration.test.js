import { test } from 'node:test'
import assert from 'node:assert/strict'
import { SshPool } from '../src/pool.js'

// The rest of the suite drives fake clients. That is deliberate -- it keeps the
// tests fast and dependency-free -- but it also means nothing proves the plugin
// can talk to a real sshd.
//
// This file closes that gap WITHOUT making the suite depend on a server: it runs
// only when DSH_SSH_TEST_TARGET names a configured alias, and skips otherwise.
//
//   DSH_SSH_TEST_TARGET=prod npm test
//   (with DSH_SSH_PROD_HOST/_USER/_KEY_PATH set as usual)
//
// Opt-in means CI stays green while a maintainer can still verify end to end.

const target = process.env.DSH_SSH_TEST_TARGET || ''
const skip = target ? false : 'set DSH_SSH_TEST_TARGET=<alias> to run against a real server'

function pool() {
  const alias = target.toUpperCase().replace(/[^A-Z0-9]/g, '_')
  const env = process.env
  return new SshPool(
    {
      hostKeyPolicy: env['DSH_SSH_' + alias + '_HOST_KEY_POLICY'] || 'tofu',
      allowSessionPassword: false,
      commandTimeoutMs: 15000,
      sftpTimeoutMs: 15000,
      connectTimeoutMs: 15000,
      closeTimeoutMs: 1500,
      maxOutputChars: 100000,
      maxFileBytes: 1048576,
      maxConnections: 4,
      reconnectCooldownMs: 0,
      healthCheckIdleMs: 0,
    },
    { dshHome: process.env.DSH_HOME || '.' }
  )
}

test('connects to a real server and runs a command', { skip }, async () => {
  const p = pool()
  try {
    const result = await p.exec(target, 'echo integration-ok', {})
    assert.match(String(result.stdout), /integration-ok/)
    assert.equal(result.code, 0)
  } finally {
    await p.closeAll({ force: true })
  }
})

test('reads a real file over SFTP', { skip }, async () => {
  const p = pool()
  try {
    const result = await p.readFile(target, '/etc/hostname', { maxBytes: 4096 })
    assert.equal(typeof result.content, 'string')
    assert.ok(result.bytes >= 0)
  } finally {
    await p.closeAll({ force: true })
  }
})

test('an invalid path is rejected before any connection attempt', { skip }, async () => {
  const p = pool()
  try {
    // Path validation runs first, so this must fail on the path, not the network.
    await assert.rejects(
      () => p.readFile(target, '~/definitely-relative', {}),
      (err) => {
        assert.match(err.message, /absolute|expand/i)
        return true
      }
    )
  } finally {
    await p.closeAll({ force: true })
  }
})

test('the host key store records the real fingerprint', { skip }, async () => {
  const p = pool()
  try {
    await p.connect(target, { trustHostKey: true })
    const entry = p.entry(target)
    assert.match(String(entry.fingerprint), /^SHA256:/)
  } finally {
    await p.closeAll({ force: true })
  }
})
