import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { apply } from '../src/index.js'
import { encryptDpapi, dpapiAvailable } from '../src/dpapi.js'
import { startServer } from './helpers/local-ssh-server.js'

// The credential file is the page's other half: the page writes it, the plugin
// reads it on every connection. That "no restart needed" claim is what this
// file checks, along with the file actually being what authenticated.

const skip = !dpapiAvailable() && 'DPAPI unavailable'

function writeCredentialFile(home, alias, entry) {
  const dir = path.join(home, 'dsh-ssh-safe')
  mkdirSync(dir, { recursive: true })
  writeFileSync(path.join(dir, 'credentials.json'), JSON.stringify({ [alias]: entry }, null, 2) + '\n')
}

test('a password stored by the page authenticates the plugin', { skip }, async () => {
  const srv = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-cred-'))
  process.env.DSH_HOME = home
  writeCredentialFile(home, 'box', {
    host: '127.0.0.1',
    port: srv.port,
    user: 'tester',
    passwordDpapi: encryptDpapi('test-pass'),
  })
  const tools = {}
  await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 'box',
    hostKeyPolicy: 'tofu',
    healthCheckIdleMs: 0,
    machines: {},
  })
  try {
    const result = await tools.ssh_exec.execute({ command: 'echo from-file' }, {})
    assert.match(String(result.text), /from-file/)

    const creds = String((await tools.ssh_credentials.execute({}, {})).text)
    assert.match(creds, /file-dpapi|凭据文件|credential file/i, creds)
    assert.ok(!creds.includes('test-pass'), 'the value must never be printed')

    // Rotation takes effect on the next connection, without a restart.
    writeCredentialFile(home, 'box', {
      host: '127.0.0.1',
      port: srv.port,
      user: 'tester',
      passwordDpapi: encryptDpapi('rotated-wrong'),
    })
    await tools.ssh_close.execute({ force: true }, {})
    await assert.rejects(
      () => tools.ssh_exec.execute({ command: 'echo after-rotate' }, {}),
      /authentication|permission denied/i,
      'the rotated (wrong) password must be used',
    )
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await srv.close()
    delete process.env.DSH_HOME
    rmSync(home, { recursive: true, force: true })
  }
})

test('useCredentialFile: false ignores the file', { skip }, async () => {
  const srv = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-cred-'))
  process.env.DSH_HOME = home
  writeCredentialFile(home, 'box', {
    host: '127.0.0.1',
    port: srv.port,
    user: 'tester',
    passwordDpapi: encryptDpapi('test-pass'),
  })
  const tools = {}
  await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 'box',
    hostKeyPolicy: 'tofu',
    healthCheckIdleMs: 0,
    useCredentialFile: false,
    machines: {},
  })
  try {
    // With the file disabled the machine has no host at all, so the failure is
    // the configuration one -- and it must not have read the file to find it.
    await assert.rejects(
      () => tools.ssh_exec.execute({ command: 'echo nope' }, {}),
      (err) => {
        assert.match(err.message, /not configured/i)
        assert.match(err.message, /Nothing was read from disk/)
        return true
      },
      'the disabled credential file must not be used',
    )
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await srv.close()
    delete process.env.DSH_HOME
    rmSync(home, { recursive: true, force: true })
  }
})
test('ssh_doctor also ignores a disabled credential file', { skip }, async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-cred-'))
  process.env.DSH_HOME = home
  writeCredentialFile(home, 'box', {
    host: '127.0.0.1',
    port: 22,
    user: 'tester',
    passwordDpapi: encryptDpapi('test-pass'),
  })
  const tools = {}
  await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 'box',
    hostKeyPolicy: 'tofu',
    healthCheckIdleMs: 0,
    useCredentialFile: false,
    machines: {},
  })
  try {
    const text = String((await tools.ssh_doctor.execute({}, {})).text)
    assert.match(text, /\[FAIL\] configuration: missing DSH_SSH_BOX_HOST/)
    assert.match(text, /Stopped: fix the above/)
    assert.doesNotMatch(text, /\[ok\] configuration/, 'the disabled file must not provide a host')
  } finally {
    delete process.env.DSH_HOME
    rmSync(home, { recursive: true, force: true })
  }
})
