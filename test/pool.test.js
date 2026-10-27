import { test } from 'node:test'
import assert from 'node:assert/strict'
import { SshPool, expandHome } from '../src/pool.js'

const baseConfig = {
  commandTimeoutMs: 5000,
  connectTimeoutMs: 3000,
  maxOutputChars: 200000,
  maxFileBytes: 1048576,
  reconnectCooldownMs: 15000,
  hostKeyPolicy: 'strict',
  allowSessionPassword: false,
}

test('expandHome only rewrites a leading ~', () => {
  assert.match(expandHome('~/.ssh/id_ed25519'), /^[A-Za-z]:\\|\.ssh/ , 'expands to a real path')
  assert.equal(expandHome('/abs/path'), '/abs/path')
  assert.equal(expandHome('rel/path'), 'rel/path')
  assert.equal(expandHome('~notahome/x'), '~notahome/x')
})

test('entry() returns a stable record per alias', () => {
  const pool = new SshPool(baseConfig, { dshHome: '/tmp/x' })
  assert.equal(pool.entry('a'), pool.entry('a'))
  assert.notEqual(pool.entry('a'), pool.entry('b'))
})

test('connecting an unconfigured machine fails without touching the network', async () => {
  const pool = new SshPool(baseConfig, { dshHome: '/tmp/x' })
  // No DSH_SSH_* variables exist for this alias, so it must refuse immediately.
  await assert.rejects(
    () => pool.connect('definitely_no_such_alias'),
    (err) => {
      assert.match(err.message, /is not configured/)
      assert.match(err.message, /DSH_SSH_DEFINITELY_NO_SUCH_ALIAS_HOST/)
      assert.doesNotMatch(err.message, /password/i, 'the error must not mention a credential value')
      return true
    }
  )
})

test('a machine with host+user but no credentials is refused', async () => {
  process.env.DSH_SSH_NOAUTH_HOST = '127.0.0.1'
  process.env.DSH_SSH_NOAUTH_USER = 'nobody'
  process.env.DSH_SSH_NOAUTH_PORT = '1'
  try {
    const pool = new SshPool(baseConfig, { dshHome: '/tmp/x' })
    await assert.rejects(
      () => pool.connect('noauth'),
      (err) => {
        assert.match(err.message, /no credentials/)
        assert.match(err.message, /disabled for this profile/, 'explains why a session password is refused')
        return true
      }
    )
  } finally {
    delete process.env.DSH_SSH_NOAUTH_HOST
    delete process.env.DSH_SSH_NOAUTH_USER
    delete process.env.DSH_SSH_NOAUTH_PORT
  }
})

test('closeAll empties the pool', () => {
  const pool = new SshPool(baseConfig, { dshHome: '/tmp/x' })
  pool.entry('a')
  pool.entry('b')
  pool.closeAll()
  assert.equal(pool.entries.size, 0)
})
