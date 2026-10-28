import { test } from 'node:test'
import assert from 'node:assert/strict'
import { envNames, machineFromEnv, resolveAuth, redact, redactObject, expectedEnv } from '../src/credentials.js'

test('envNames maps an alias to variable names', () => {
  const n = envNames('prod')
  assert.equal(n.host, 'DSH_SSH_PROD_HOST')
  assert.equal(n.password, 'DSH_SSH_PROD_PASSWORD')
  assert.equal(n.keyPath, 'DSH_SSH_PROD_KEY_PATH')
})

test('envNames normalises punctuation into underscores', () => {
  assert.equal(envNames('my-box.eu').host, 'DSH_SSH_MY_BOX_EU_HOST')
})

test('machineFromEnv reads only what is present', () => {
  const env = { DSH_SSH_PROD_HOST: '10.0.0.5', DSH_SSH_PROD_USER: 'ubuntu' }
  const m = machineFromEnv('prod', env)
  assert.equal(m.host, '10.0.0.5')
  assert.equal(m.username, 'ubuntu')
  assert.equal(m.port, 22, 'port defaults to 22')
  assert.equal(m.password, '', 'absent password is an empty string, not undefined')
  // Empty, not 'strict'. effectivePolicy(global, machine) lets the machine win
  // when it holds a valid value, so a default here would make the global
  // hostKeyPolicy setting unreachable. (pool.test.js covers the fallback.)
  assert.equal(m.hostKeyPolicy, '', 'unset policy is empty so the global one applies')
  assert.deepEqual(m.present, ['DSH_SSH_PROD_HOST', 'DSH_SSH_PROD_USER'])
})

test('machineFromEnv reports nothing when the environment is empty', () => {
  const m = machineFromEnv('ghost', {})
  assert.equal(m.host, '')
  assert.deepEqual(m.present, [])
})

test('resolveAuth prefers env password, then env key, then session password', () => {
  const env = { DSH_SSH_A_HOST: 'h', DSH_SSH_A_USER: 'u', DSH_SSH_A_PASSWORD: 'pw' }
  const saved = process.env
  try {
    process.env.DSH_SSH_A_HOST = 'h'
    process.env.DSH_SSH_A_USER = 'u'
    process.env.DSH_SSH_A_PASSWORD = 'pw'
    assert.equal(resolveAuth('a', { sessionPassword: 'other', allowSessionPassword: true }).kind, 'env-password')
  } finally { process.env = saved }
})

test('resolveAuth refuses a session password unless explicitly allowed', () => {
  const saved = process.env
  try {
    process.env.DSH_SSH_B_HOST = 'h'
    process.env.DSH_SSH_B_USER = 'u'
    delete process.env.DSH_SSH_B_PASSWORD
    delete process.env.DSH_SSH_B_KEY_PATH
    assert.equal(resolveAuth('b', { sessionPassword: 'pw', allowSessionPassword: false }).kind, 'none')
    assert.equal(resolveAuth('b', { sessionPassword: 'pw', allowSessionPassword: true }).kind, 'session-password')
  } finally { process.env = saved }
})

test('redact strips env-var assignments and PEM bodies', () => {
  assert.match(redact('DSH_SSH_PROD_PASSWORD=hunter2'), /<redacted>/)
  assert.doesNotMatch(redact('DSH_SSH_PROD_PASSWORD=hunter2'), /hunter2/)
  const pem = '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----'
  assert.doesNotMatch(redact(pem), /abc/)
})

test('redactObject redacts secret-looking keys', () => {
  const out = redactObject({ password: 'p', keyPath: '/k', host: 'h' })
  assert.equal(out.password, '<redacted>')
  assert.equal(out.keyPath, '/k', 'a path is not a secret')
  assert.equal(out.host, 'h')
})

test('expectedEnv names the required and auth variables', () => {
  const e = expectedEnv('prod')
  assert.deepEqual(e.required, ['DSH_SSH_PROD_HOST', 'DSH_SSH_PROD_USER'])
  assert.equal(e.auth.length, 1)
})
