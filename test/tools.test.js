import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// Every other suite tests a module in isolation. None of them called apply()
// and asserted on what a tool actually returns, which is why three defects
// shipped in one round: ssh_config omitted two settings, the refusal message
// named the wrong setting, and the audit renderer dropped every detail field.
//
// These tests drive the registered tools through a fake ctx -- no network, no
// ssh2 -- and assert on the shape of their output.

import { apply, keyModeWarning } from '../src/index.js'
import { AuditLog } from '../src/audit.js'

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
test('a credential file that is an array or nests under machines is explained', async () => {
  const { tools, restore } = capture({ machines: { real: { host: '127.0.0.1', port: 1, user: 'u', keyPath: '/tmp/k' } } })
  try {
    const dir = path.join(process.env.DSH_HOME, 'dsh-ssh-safe')
    mkdirSync(dir, { recursive: true })
    const file = path.join(dir, 'credentials.json')

    // An array is an object to typeof: its indices used to become machines.
    writeFileSync(file, JSON.stringify([{ host: '9.9.9.9', user: 'u' }]))
    let inventory = String((await tools['ssh_machines'].execute({}, {})).text)
    assert.doesNotMatch(inventory, /• 0 /, 'an array must not become a machine named 0')

    // The settings-form shape, pasted into the file.
    writeFileSync(file, JSON.stringify({ machines: { prod: { host: '1.2.3.4', user: 'u' } } }))
    inventory = String((await tools['ssh_machines'].execute({}, {})).text)
    assert.match(inventory, /the credential file has a "machines" key/)
    assert.match(inventory, /keyed by alias directly/)
    assert.doesNotMatch(inventory, /unknown field "prod"/, 'the nested key is explained, not just misspelled')
  } finally { restore() }
})
test('an invalid port in the credential file is shown as configured, not as 22', async () => {
  const { tools, restore } = capture({})
  try {
    const dir = path.join(process.env.DSH_HOME, 'dsh-ssh-safe')
    mkdirSync(dir, { recursive: true })
    writeFileSync(path.join(dir, 'credentials.json'), JSON.stringify({
      box: { host: '10.0.0.5', port: 99999, user: 'u', password: 'p' },
    }))
    const inventory = String((await tools['ssh_machines'].execute({}, {})).text)
    assert.match(inventory, /box  u@10\.0\.0\.5:99999/, 'the value you have to fix is visible')
    assert.match(inventory, /BAD PORT: port 99999 from the file/,
      'and it is marked as wrong: ' + inventory.slice(0, 200))

    const doctor = String((await tools['ssh_doctor'].execute({ machine: 'box' }, {})).text)
    assert.match(doctor, /\[FAIL\] configuration: port 99999 from the file/)
  } finally { restore() }
})
test('the doctor probe line hides the port under machineInventory: alias', async () => {
  // ssh_machines says "host, port and key paths are hidden"; the TCP stage
  // printed "port 2299 accepts connections" regardless.
  const { tools, restore } = capture({
    defaultMachine: 'box',
    machineInventory: 'alias',
    connectTimeoutMs: 1000,
    machines: { box: { host: '127.0.0.1', port: 2299, user: 'root', keyPath: '/tmp/k' } },
  })
  try {
    const doctor = String((await tools['ssh_doctor'].execute({}, {})).text)
    assert.doesNotMatch(doctor, /2299/, doctor)
    assert.match(doctor, /the configured port|configuration: <host hidden>/)
  } finally { restore() }
})
test('ssh_credentials lists every source in the order actually used', async () => {
  // The header used to say "encrypted file > environment > SSH agent" and
  // omitted the settings password, the plaintext file and the key -- three of
  // the six sources a user has to check when a password is not the one used.
  const { tools, restore } = capture({ machines: { box: { host: 'h', user: 'u' } } })
  try {
    const text = String((await tools['ssh_credentials'].execute({}, {})).text)
    const line = text.split('\n').filter((l) => l.includes('precedence')).join(' ') +
      ' ' + (text.split('\n')[text.split('\n').findIndex((l) => l.includes('precedence')) + 1] || '')
    // With the default allowPlaintextPassword: false the first two sources are
    // refused, so the line must not put a settings password ahead of the file --
    // every machine below it carried a WARNING that said exactly the opposite.
    assert.doesNotMatch(line, /settings password > encrypted file/)
    for (const part of ['encrypted file', 'environment', 'key file', 'session password', 'SSH agent']) {
      assert.ok(line.includes(part), 'the precedence line omits ' + part + ': ' + line)
    }
    assert.match(text, /plaintext passwords — settings form and credential file —/)
    assert.match(text, /are refused while allowPlaintextPassword is off/)
    assert.doesNotMatch(text, /\n\n  encryption/, 'no blank line inside the header')
  } finally { restore() }
})
test('allowPlaintextPassword on restores the full precedence and the source lines', async () => {
  const { tools, restore } = capture({ allowPlaintextPassword: true, machines: { box: { host: 'h', user: 'u', password: 'pw' } } })
  try {
    const text = String((await tools['ssh_credentials'].execute({}, {})).text)
    const head = text.split('\n').slice(0, 10).join('\n')
    assert.match(head, /settings password > encrypted file > plaintext file > environment/)
    assert.match(head, /a usable password always outranks a key/)
    assert.match(text, /password   config/)
    assert.doesNotMatch(text, /IGNORED/)
  } finally { restore() }
  delete process.env.DSH_SSH_BOX_PASSWORD
})

test('a plaintext settings password is shown as ignored, with what wins instead', async () => {
  // The line said 'config' and only the next one admitted it was never used.
  process.env.DSH_SSH_BOX_PASSWORD = 'env-secret'
  const { tools, restore } = capture({ machines: { box: { host: 'h', user: 'u', password: 'cfg-secret' } } })
  try {
    const text = String((await tools['ssh_credentials'].execute({}, {})).text)
    assert.match(text, /password   config \(IGNORED: plaintext\) — this connection uses env/)
  } finally {
    restore()
    delete process.env.DSH_SSH_BOX_PASSWORD
  }
})

test('the defaults in the README table match the defaults in the code', async () => {
  // A default that drifts silently makes the documentation a trap: someone tunes
  // maxFileBytes to 2 MB because the README said 1 MB, and it was already 1 MB.
  const here = path.dirname(fileURLToPath(import.meta.url))
  const readme = readFileSync(path.join(here, '..', 'README.md'), 'utf8')
  const { tools, restore } = capture({})
  try {
    const actual = {}
    for (const line of String((await tools['ssh_config'].execute({})).text).split('\n')) {
      const match = line.match(/^  (\w+)\s+(.*?)(?:\s{2,}#|$)/)
      if (match) actual[match[1]] = match[2].trim().replace(/^"|"$/g, '')
    }
    let checked = 0
    for (const line of readme.split('\n')) {
      const row = line.match(/^\|\s*`([A-Za-z]+)`\s*\|\s*`?([^|`]+?)`?\s*\|/)
      if (!row) continue
      const [, key, documented] = row
      // Only literal defaults: the three collection settings have display forms
      // ('{}', '' , '9 条') that are not the value itself.
      if (!/^\d+$/.test(documented) && !/^(true|false)$/.test(documented) && !/^"[a-z]+"$/.test(documented)) continue
      assert.ok(key in actual, 'README documents ' + key + ' but ssh_config does not report it')
      assert.equal(actual[key], documented.replace(/^"/, '').replace(/"$/, ''),
        'README says ' + key + ' = ' + documented + ', the code says ' + actual[key])
      checked++
    }
    assert.ok(checked >= 15, 'expected to compare most settings, compared ' + checked)
  } finally { restore() }
})
test('a gated read says read, not write', async () => {
  // ssh_read is gated under execGuard: confirm (a read can copy a private key
  // off the host), but the message told the caller to confirm a WRITE and
  // explained why writes are dangerous.
  const { tools, restore } = capture({ execGuard: 'confirm' }, {
    DSH_SSH_T_HOST: '127.0.0.1', DSH_SSH_T_PORT: '1',
    DSH_SSH_T_USER: 'u', DSH_SSH_T_PASSWORD: 'p',
  })
  try {
    await assert.rejects(
      () => tools['ssh_read'].execute({ machine: 't', path: '/etc/hostname' }),
      (err) => {
        assert.match(err.message, /pass confirm: true to read from the remote host/)
        assert.match(err.message, /copy a private key/)
        assert.doesNotMatch(err.message, /to write to the remote host/)
        return true
      },
    )
    // Listing a directory reads names only, so it stays ungated.
    await assert.rejects(
      () => tools['ssh_list'].execute({ machine: 't', path: '/' }),
      (err) => { assert.doesNotMatch(err.message, /confirm: true/); return true },
    )
  } finally { restore() }
})
test('a refused command is described, not quoted as a regular expression', async () => {
  // The message used to read 'Command refused: (?:^|[\s;&|()`])rm\s+-[rf]{1,2}...'
  // -- something matched, but nothing a person can act on.
  const { tools, restore } = capture({ execGuard: 'allow' }, {
    DSH_SSH_T_HOST: '127.0.0.1', DSH_SSH_T_PORT: '1', DSH_SSH_T_USER: 'u', DSH_SSH_T_PASSWORD: 'p',
  })
  try {
    await assert.rejects(
      () => tools['ssh_exec'].execute({ machine: 't', command: 'rm -rf /' }),
      (err) => {
        assert.match(err.message, /it deletes the filesystem root/)
        assert.doesNotMatch(err.message, /\^\|\[\\s/)
        assert.match(err.message, /Adjust denyPatterns/)
        return true
      },
    )
    await assert.rejects(
      () => tools['ssh_exec'].execute({ machine: 't', command: 'echo hi | bash' }),
      (err) => {
        assert.match(err.message, /pipes into bash/)
        return true
      },
    )
  } finally { restore() }
})

test('a rule the user added is quoted, and keeps its own order', async () => {
  // A custom rule placed before the defaults must not shift the labels of the
  // defaults: the name is looked up by pattern, not by position.
  const { tools, restore } = capture({
    execGuard: 'allow',
    denyPatterns: ['\\bkillall\\b', '\\brm\\s+-rf\\s+/+keyword\\b'],
  }, {
    DSH_SSH_T_HOST: '127.0.0.1', DSH_SSH_T_PORT: '1', DSH_SSH_T_USER: 'u', DSH_SSH_T_PASSWORD: 'p',
  })
  try {
    await assert.rejects(
      () => tools['ssh_exec'].execute({ machine: 't', command: 'killall nginx' }),
      (err) => {
        assert.match(err.message, /it matches a denyPatterns rule \(\\bkillall\\b\)/)
        return true
      },
    )
  } finally { restore() }
})

test('a tool with no parameters says so instead of ". Accepted: ."', async () => {
  // 'Accepted: .' was the message for every zero-argument tool: the list of
  // accepted names was empty.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-args-zero-'))
  const tools = {}
  await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined },
    { defaultMachine: 't', hostKeyPolicy: 'tofu', machines: {} })
  for (const name of ['ssh_config', 'ssh_credentials', 'ssh_machines']) {
    await assert.rejects(
      () => tools[name].execute({ machine: 't' }, {}),
      (err) => {
        assert.match(err.message, /takes no arguments, so the call was refused/)
        assert.doesNotMatch(err.message, /Accepted: \./)
        return true
      },
      name,
    )
  }
  // A tool that does take one still lists it.
  await assert.rejects(
    () => tools.ssh_audit.execute({ machine: 't' }, {}),
    /Unknown argument\(s\) for ssh_audit: "machine"\. Accepted: limit\./,
  )
  rmSync(home, { recursive: true, force: true })
})

test('the inventory lists only the fields that are missing', async () => {
  // A machine with a host configured was told its HOST variable was missing
  // too, which sends the user to set something that is already set.
  const own = {}
  await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    hostKeyPolicy: 'tofu',
    machines: {
      onlyhost: { host: '10.0.0.1' },
      onlyuser: { user: 'root' },
    },
  })
  const text = String((await own.ssh_machines.execute({}, {})).text)
  const row = (alias) => text.split('\u2022 ').find((block) => block.startsWith(alias + ' ')) || ''
  assert.match(row('onlyhost'), /MISSING: DSH_SSH_ONLYHOST_USER/)
  assert.doesNotMatch(row('onlyhost'), /ONLYHOST_HOST/, 'the host is configured')
  assert.match(row('onlyuser'), /MISSING: DSH_SSH_ONLYUSER_HOST/)
  assert.doesNotMatch(row('onlyuser'), /ONLYUSER_USER/, 'the user is configured')
})

test('an audit limit of 0 asks for nothing and says so', async () => {
  // 0 and -5 were clamped up to 1, so a request for no records answered with one
  // record and no explanation.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-limit0-'))
  const own = {}
  await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 't', hostKeyPolicy: 'tofu', auditLog: true,
    connectTimeoutMs: 1000, commandTimeoutMs: 1000,
    machines: { t: { host: '127.0.0.1', port: 1, user: 'u', password: 'p' } },
  })
  await own.ssh_exec.execute({ machine: 't', command: 'echo hi' }, {}).catch(() => {})

  const zero = String((await own.ssh_audit.execute({ limit: 0 }, {})).text)
  assert.match(zero, /limit is 0: no records were requested/)
  assert.doesNotMatch(zero, /echo hi/)
  await assert.rejects(() => own.ssh_audit.execute({ limit: -5 }, {}), /limit must be 0 or more/)
  const some = String((await own.ssh_audit.execute({ limit: 2 }, {})).text)
  assert.match(some, /echo hi/)
  rmSync(home, { recursive: true, force: true })
})

test('ssh_config describes the credential file that is actually there', async () => {
  // '(mode 0600)' was printed unconditionally: a fresh profile looked like it
  // already had an encrypted store on disk, and on Windows stat() reports 0666
  // whatever the ACL says.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-cfgfit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const own = {}
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'a', hostKeyPolicy: 'tofu', machines: { a: { host: '10.1.1.1', user: 'root' } },
    })
    const lineOf = async () => {
      const text = String((await own.ssh_config.execute({}, {})).text)
      return text.split('\n').find((l) => l.startsWith('Credential file:')) || ''
    }
    const absent = await lineOf()
    assert.match(absent, /not created yet/, 'a missing file must not claim a mode')
    assert.doesNotMatch(absent, /mode 0600/)

    const file = path.join(home, 'dsh-ssh-safe', 'credentials.json')
    mkdirSync(path.dirname(file), { recursive: true })
    writeFileSync(file, '{}')
    const present = await lineOf()
    assert.doesNotMatch(present, /not created yet/)
    if (process.platform === 'win32') {
      assert.match(present, /Windows ACLs/)
    } else {
      assert.match(present, /mode 0\d{3}/)
    }
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('ssh_config says when a custom deny list replaced the built-in rules', async () => {
  // Writing ONE pattern replaces the whole built-in set, which is not what
  // 'add a rule' looks like: it dropped rm -rf / protection without a word.
  const lineOf = async (extra) => {
    const { tools, restore } = capture({ machines: { box: { host: 'h', user: 'u' } }, ...extra })
    try {
      const text = String((await tools['ssh_config'].execute({}, {})).text)
      return text.split('\n').find((line) => line.includes('denyPatterns')) || ''
    } finally { restore() }
  }

  assert.match(await lineOf({}), /\(the built-in set\)/)
  assert.match(await lineOf({ denyPatterns: ['^shutdown'] }), /replaces the 10 built-in rules/)
  assert.match(await lineOf({ denyPatterns: [] }), /the destructive-command guard is OFF/)
})

test('ssh_audit says the log could not be read instead of claiming it is empty', async () => {
  // A directory where the log file should be made readFileSync throw EISDIR,
  // which recent() swallowed: the answer was 'No operations recorded yet.' — the
  // one answer that makes an operator stop looking.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-auddir-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'), { recursive: true })
    const own = {}
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'a', hostKeyPolicy: 'tofu', auditLog: true, machines: { a: { host: 'h', user: 'u' } },
    })
    const text = String((await own.ssh_audit.execute({ limit: 5 }, {})).text)
    assert.match(text, /could not be read/)
    assert.doesNotMatch(text, /No operations recorded yet/)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a private key anyone can read is called out', () => {
  // OpenSSH refuses such a key outright; this plugin was silent about it while
  // being careful about its own files.
  assert.equal(keyModeWarning(0o600), '')
  assert.equal(keyModeWarning(0o400), '')
  assert.match(keyModeWarning(0o644), /readable by group\/others \(mode 0644\)/)
  assert.match(keyModeWarning(0o644), /OpenSSH would refuse it/)
  assert.match(keyModeWarning(0o666), /mode 0666/)
})

test('ssh_machines does not present an ignored password as the auth source', async () => {
  // It said 'auth: password (config)' while ssh_credentials said 'IGNORED:
  // plaintext' and ssh_doctor said 'no password, key or agent available'.
  const plain = capture({ machines: { p: { host: 'h', user: 'u', password: 'pw' } } })
  try {
    const text = String((await plain.tools['ssh_machines'].execute({}, {})).text)
    assert.match(text, /auth: NONE \(a plaintext settings-form password is set but ignored/)
    assert.doesNotMatch(text, /auth: password \(config\)/)
  } finally { plain.restore() }

  // With a key as well, the key is what authenticates.
  const keyed = capture({ machines: { k: { host: 'h', user: 'u', password: 'pw', keyPath: '/k/id' } } })
  try {
    const text = String((await keyed.tools['ssh_machines'].execute({}, {})).text)
    assert.match(text, /auth: key \/k\/id \(config\)/)
    assert.doesNotMatch(text, /auth: password \(config\)/)
  } finally { keyed.restore() }

  // And when the profile allows plaintext, the password is the source again.
  const allowed = capture({ allowPlaintextPassword: true, machines: { p: { host: 'h', user: 'u', password: 'pw' } } })
  try {
    const text = String((await allowed.tools['ssh_machines'].execute({}, {})).text)
    assert.match(text, /auth: password \(config\)/)
  } finally { allowed.restore() }
})

test('asking for more records than the cap says the view is capped', async () => {
  // 500 records and 200 records produced the same answer.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-capfit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const log = new AuditLog(path.join(home, 'dsh-ssh-safe'))
    for (let i = 0; i < 250; i++) {
      log.write({ kind: 'exec', machine: 'm', command: 'c' + i, outcome: 'ok', exitCode: 0 })
    }
    const own = {}
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'm', hostKeyPolicy: 'tofu', auditLog: true, machines: { m: { host: 'h', user: 'u' } },
    })
    const capped = String((await own.ssh_audit.execute({ limit: 500 }, {})).text)
    assert.match(capped, /Showing the newest 200 records/)
    assert.equal(capped.split('\n').filter((line) => / exec /.test(line)).length, 200)

    const exact = String((await own.ssh_audit.execute({ limit: 200 }, {})).text)
    assert.doesNotMatch(exact, /Showing the newest 200 records/)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})
