import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { agentSocket } from '../src/credentials.js'
import { credentialFor } from '../src/machines.js'

// An agent is the safest credential source: the private key never reaches this
// plugin, only a signature does.
//
// These used to exercise resolveAuth(), a second resolver in credentials.js
// that nothing in the product called -- so the agent fallback was covered in a
// function no user could reach, while credentialFor() carried the real
// behaviour untested. They now drive the resolver the tools actually use.

const home = () => mkdtempSync(join(tmpdir(), 'dsh-agent-'))
const withEnv = (vars, fn) => {
  const saved = { ...process.env }
  try {
    Object.assign(process.env, vars)
    return fn()
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k]
    Object.assign(process.env, saved)
  }
}

test('agentSocket reports SSH_AUTH_SOCK when set', () => {
  assert.equal(agentSocket({ SSH_AUTH_SOCK: '/tmp/agent.sock' }), '/tmp/agent.sock')
  assert.equal(agentSocket({}), '')
  assert.equal(agentSocket({ SSH_AUTH_SOCK: '' }), '')
})

test('an agent is used when nothing else is configured', () => {
  withEnv({ SSH_AUTH_SOCK: '/tmp/agent.sock', DSH_SSH_AG_HOST: 'h', DSH_SSH_AG_USER: 'u' }, () => {
    delete process.env.DSH_SSH_AG_PASSWORD
    delete process.env.DSH_SSH_AG_KEY_PATH
    const auth = credentialFor('ag', { dshHome: home(), allowSessionPassword: false })
    assert.equal(auth.kind, 'agent')
    assert.equal(auth.agent, '/tmp/agent.sock')
  })
})

test('an explicit password beats the agent', () => {
  withEnv({ SSH_AUTH_SOCK: '/tmp/agent.sock', DSH_SSH_PW_HOST: 'h', DSH_SSH_PW_USER: 'u', DSH_SSH_PW_PASSWORD: 'secret' }, () => {
    assert.equal(credentialFor('pw', { dshHome: home() }).kind, 'env-password')
  })
})

test('useAgent: false disables the fallback', () => {
  withEnv({ SSH_AUTH_SOCK: '/tmp/agent.sock', DSH_SSH_NOAG_HOST: 'h', DSH_SSH_NOAG_USER: 'u' }, () => {
    delete process.env.DSH_SSH_NOAG_PASSWORD
    delete process.env.DSH_SSH_NOAG_KEY_PATH
    assert.equal(credentialFor('noag', { dshHome: home(), useAgent: false }).kind, 'none')
  })
})

test('a session password that a stored credential shadows says so', () => {
  withEnv({ DSH_SSH_SHADOW_HOST: 'h', DSH_SSH_SHADOW_USER: 'u', DSH_SSH_SHADOW_PASSWORD: 'stored' }, () => {
    const auth = credentialFor('shadow', { dshHome: home(), allowSessionPassword: true, sessionPassword: 'typed' })
    assert.equal(auth.kind, 'env-password', 'the stored credential wins')
    assert.equal(auth.password, 'stored')
    assert.ok(
      auth.warnings.some((w) => /stored credential was used instead/.test(w)),
      'the caller must be told the supplied password was not used'
    )
  })
})
