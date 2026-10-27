import { test } from 'node:test'
import assert from 'node:assert/strict'
import { resolveAuth, agentSocket } from '../src/credentials.js'

// An agent is the safest credential source: the private key never reaches this
// plugin, only a signature does.

test('agentSocket reports SSH_AUTH_SOCK when set', () => {
  assert.equal(agentSocket({ SSH_AUTH_SOCK: '/tmp/agent.sock' }), '/tmp/agent.sock')
  assert.equal(agentSocket({}), '')
  assert.equal(agentSocket({ SSH_AUTH_SOCK: '' }), '')
})

test('an agent is used when nothing else is configured', () => {
  const saved = { ...process.env }
  try {
    process.env.SSH_AUTH_SOCK = '/tmp/agent.sock'
    process.env.DSH_SSH_AG_HOST = 'h'
    process.env.DSH_SSH_AG_USER = 'u'
    delete process.env.DSH_SSH_AG_PASSWORD
    delete process.env.DSH_SSH_AG_KEY_PATH

    const auth = resolveAuth('ag', { allowSessionPassword: false })
    assert.equal(auth.kind, 'agent')
    assert.equal(auth.agent, '/tmp/agent.sock')
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k]
    Object.assign(process.env, saved)
  }
})

test('an explicit password beats the agent', () => {
  const saved = { ...process.env }
  try {
    process.env.SSH_AUTH_SOCK = '/tmp/agent.sock'
    process.env.DSH_SSH_PW_HOST = 'h'
    process.env.DSH_SSH_PW_USER = 'u'
    process.env.DSH_SSH_PW_PASSWORD = 'secret'
    assert.equal(resolveAuth('pw', {}).kind, 'env-password')
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k]
    Object.assign(process.env, saved)
  }
})

test('useAgent: false disables the fallback', () => {
  const saved = { ...process.env }
  try {
    process.env.SSH_AUTH_SOCK = '/tmp/agent.sock'
    process.env.DSH_SSH_NOAG_HOST = 'h'
    process.env.DSH_SSH_NOAG_USER = 'u'
    delete process.env.DSH_SSH_NOAG_PASSWORD
    delete process.env.DSH_SSH_NOAG_KEY_PATH
    assert.equal(resolveAuth('noag', { useAgent: false }).kind, 'none')
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k]
    Object.assign(process.env, saved)
  }
})
