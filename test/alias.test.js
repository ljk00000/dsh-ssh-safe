import { test } from 'node:test'
import assert from 'node:assert/strict'
import { envNames, machineFromEnv } from '../src/credentials.js'

test('aliases are case-insensitive, so the same machine cannot list twice', () => {
  // envNames uppercases, so 'PROD' and 'prod' resolve to identical variables.
  assert.deepEqual(envNames('PROD'), envNames('prod'))
  assert.deepEqual(envNames('Prod'), envNames('prod'))
})

test('a mixed-case alias reads the same environment variables', () => {
  const env = { DSH_SSH_PROD_HOST: '10.0.0.1', DSH_SSH_PROD_USER: 'root' }
  const upper = machineFromEnv('PROD', env)
  const lower = machineFromEnv('prod', env)
  assert.equal(upper.host, '10.0.0.1')
  assert.equal(lower.host, '10.0.0.1')
  assert.deepEqual(upper, { ...lower, alias: 'PROD' })
})
