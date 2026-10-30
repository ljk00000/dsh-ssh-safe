import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
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
  // `register` is the 0.2.1+ entry point: the harness compiles a definition
  // through @deepseek-ai/dsh-tools and hands the service the result, exactly as
  // this fake does, so tests exercise the path the host actually runs.
  const ctx = {
    tools: { register: (def) => { tools[def.name] = def } },
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

test('apply registers every documented tool and nothing else', () => {
  const { tools, restore } = capture()
  try {
    const expected = [
      'ssh_machines', 'ssh_connect', 'ssh_exec', 'ssh_read', 'ssh_write',
      'ssh_list', 'ssh_close', 'ssh_doctor', 'ssh_audit', 'ssh_config',
      'ssh_credentials', 'ssh_workspace',
    ]
    for (const name of expected) assert.ok(tools[name], 'missing tool: ' + name)
    // A count as well as a list: ssh_credentials was added to the plugin while
    // this test kept checking ten names, so nothing failed when the eleventh
    // arrived unannounced.
    assert.deepEqual(Object.keys(tools).sort(), expected.slice().sort())
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
test('machineInventory: alias also hides the topology in ssh_credentials', async () => {
  // ssh_credentials prints user@host:port for each machine. Its output goes
  // into the same conversation that machineInventory exists to keep clean.
  const { tools, restore } = capture({ machineInventory: 'alias' }, {
    DSH_SSH_PROD_HOST: '10.1.2.3',
    DSH_SSH_PROD_USER: 'deploy',
    DSH_SSH_PROD_KEY_PATH: '~/.ssh/id_secret_name',
  })
  try {
    const text = textOf(await tools['ssh_credentials'].execute({}))
    assert.match(text, /prod/)
    assert.doesNotMatch(text, /10\.1\.2\.3/, 'the host must be hidden here too')
    assert.doesNotMatch(text, /deploy@/, 'the user must be hidden here too')
    assert.match(text, /<host hidden>/)
  } finally { restore() }
})

test('machineInventory: full still shows it', async () => {
  const { tools, restore } = capture({}, {
    DSH_SSH_PROD_HOST: '10.1.2.3',
    DSH_SSH_PROD_USER: 'deploy',
  })
  try {
    const text = textOf(await tools['ssh_credentials'].execute({}))
    assert.match(text, /deploy@10\.1\.2\.3:22/)
  } finally { restore() }
})
test('a misspelled argument is rejected instead of silently ignored', async () => {
  // The harness compiles parameters into an open object schema, so the tool has
  // to police its own names: 'timeout: 500' used to run with the configured
  // 30 seconds and look like it worked.
  const { tools, restore } = capture({}, { DSH_SSH_PROD_HOST: '10.1.2.3', DSH_SSH_PROD_USER: 'deploy' })
  try {
    await assert.rejects(
      () => tools['ssh_exec'].execute({ command: 'ls', timeout: 500 }),
      (err) => {
        assert.match(err.message, /Unknown argument\(s\) for ssh_exec: "timeout"/)
        assert.match(err.message, /did you mean "timeoutMs"/)
        assert.match(err.message, /Accepted: machine, command/)
        return true
      },
    )
    await assert.rejects(
      () => tools['ssh_write'].execute({ path: '/x', content: 'y', createDir: true }),
      /did you mean "createDirs"/,
    )
    await assert.rejects(
      () => tools['ssh_list'].execute({ path: '/x', depth: 2 }),
      (err) => {
        assert.match(err.message, /"depth"/)
        assert.doesNotMatch(err.message, /did you mean/, 'nothing is close to depth')
        return true
      },
    )
  } finally { restore() }
})
test('a misspelled field in the settings form is reported, not silently dropped', async () => {
  // schemastery drops unknown keys, so 'keypath' parsed fine and the machine
  // then reported "no password, key or agent available".
  const { tools, restore } = capture({
    defaultMachine: 'box',
    machines: {
      box: { host: '127.0.0.1', port: 1, user: 'u', keypath: '/nope' },
      fine: { host: '127.0.0.1', port: 1, user: 'u', keyPath: '/tmp/k' },
    },
  })
  try {
    const doctor = String((await tools['ssh_doctor'].execute({ machine: 'box' }, {})).text)
    assert.match(doctor, /\[warn\] configuration: machine "box" in the settings form has an unknown field "keypath"/)
    assert.match(doctor, /did you mean "keyPath"/)

    const clean = String((await tools['ssh_doctor'].execute({ machine: 'fine' }, {})).text)
    assert.doesNotMatch(clean, /unknown field/, 'another machine\'s typo is not this machine\'s problem')

    const inventory = String((await tools['ssh_machines'].execute({}, {})).text)
    assert.match(inventory, /Configuration problems:/)
    assert.match(inventory, /machine "box" in the settings form has an unknown field "keypath"/)
    assert.doesNotMatch(inventory, /machine "fine" in the settings form has an unknown field/)
  } finally { restore() }
})
test('a misspelled field in the credential file is reported against that file', async () => {
  const { tools, restore } = capture({ defaultMachine: 'box' }, {})
  try {
    // capture() set an isolated DSH_HOME; the file lives under it.
    const dir = path.join(process.env.DSH_HOME, 'dsh-ssh-safe')
    mkdirSync(dir, { recursive: true })
    writeFileSync(path.join(dir, 'credentials.json'), JSON.stringify({
      box: { host: '127.0.0.1', port: 1, user: 'u', keypath: '/nope' },
      ok: { host: '127.0.0.1', port: 1, user: 'u', username: 'deploy', passwordDpapi: 'x' },
    }))
    const doctor = String((await tools['ssh_doctor'].execute({ machine: 'box' }, {})).text)
    assert.match(doctor, /machine "box" in the credential file has an unknown field "keypath"/)
    assert.match(doctor, /did you mean "keyPath"/)

    const clean = String((await tools['ssh_doctor'].execute({ machine: 'ok' }, {})).text)
    assert.doesNotMatch(clean, /unknown field/, 'username and passwordDpapi are valid file fields')
  } finally { restore() }
})
test('useCredentialFile: false hides the credential file and its machines', async () => {
  const { tools, restore } = capture({
    defaultMachine: 'real',
    useCredentialFile: false,
    machines: { real: { host: '127.0.0.1', port: 1, user: 'u', keyPath: '/tmp/k' } },
  })
  try {
    // capture() gave us an isolated DSH_HOME; put a machine in the file the
    // plugin was told not to read.
    const dir = path.join(process.env.DSH_HOME, 'dsh-ssh-safe')
    mkdirSync(dir, { recursive: true })
    writeFileSync(path.join(dir, 'credentials.json'), JSON.stringify({
      ghost: { host: '127.0.0.1', port: 1, user: 'u', password: 'p' },
    }))
    const inventory = String((await tools['ssh_machines'].execute({}, {})).text)
    assert.doesNotMatch(inventory, /ghost/, 'a disabled file must not contribute machines')
    assert.match(inventory, /real/)
    const creds = String((await tools['ssh_credentials'].execute({}, {})).text)
    assert.match(creds, /\[DISABLED\]/, 'the credential page must say the file is off')
  } finally { restore() }
})
test('ssh_audit survives a non-object line in the log file', async () => {
  const { tools, restore } = capture({ auditLog: true })
  try {
    const dir = path.join(process.env.DSH_HOME, 'dsh-ssh-safe')
    mkdirSync(dir, { recursive: true })
    writeFileSync(path.join(dir, 'audit.ndjson'), [
      'null',
      '42',
      JSON.stringify({ at: '2026-10-31T00:00:00.000Z', machine: 't', kind: 'exec', outcome: 'ok', command: 'echo ok' }),
    ].join('\n') + '\n')
    const text = String((await tools['ssh_audit'].execute({ limit: 10 }, {})).text)
    assert.match(text, /\[unreadable record\] null/)
    assert.match(text, /echo ok/)
  } finally { restore() }
})
