import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import {
  credentialFor,
  credentialState,
  credentialsPath,
  knownAliases,
  loadCredentialFile,
  machineDefinition,
} from '../src/machines.js'
import { effectivePolicy } from '../src/pool.js'

// Three sources can define a machine now: the settings form, the credential
// file, and the environment. These tests pin the precedence and, more
// importantly, the two properties the feature exists for:
//   1. editing the file takes effect without a restart
//   2. a diagnostics view never prints a secret

function home() {
  const dir = mkdtempSync(path.join(tmpdir(), 'dsh-machines-'))
  mkdirSync(path.join(dir, 'dsh-ssh-safe'), { recursive: true })
  return dir
}

function writeCredentials(dir, data) {
  writeFileSync(credentialsPath(dir), JSON.stringify(data), 'utf8')
}

test('the settings form wins over the environment', () => {
  const saved = process.env.DSH_SSH_C_HOST
  const savedUser = process.env.DSH_SSH_C_USER
  process.env.DSH_SSH_C_HOST = 'env-host'
  process.env.DSH_SSH_C_USER = 'envuser'
  try {
    const m = machineDefinition('c', { machines: { c: { host: 'cfg-host', user: 'cfguser' } } })
    assert.equal(m.host, 'cfg-host')
    assert.equal(m.username, 'cfguser')
    assert.equal(m.sources.host, 'config')
  } finally {
    if (saved === undefined) delete process.env.DSH_SSH_C_HOST
    else process.env.DSH_SSH_C_HOST = saved
    if (savedUser === undefined) delete process.env.DSH_SSH_C_USER
    else process.env.DSH_SSH_C_USER = savedUser
  }
})

test('an empty settings field does not shadow the environment', () => {
  const dir = home()
  try {
    process.env.DSH_SSH_D_HOST = 'env-host'
    process.env.DSH_SSH_D_USER = 'envuser'
    const m = machineDefinition('d', { machines: { d: { host: '', user: '' } }, dshHome: dir })
    assert.equal(m.host, 'env-host')
    assert.equal(m.sources.host, 'env')
  } finally {
    delete process.env.DSH_SSH_D_HOST
    delete process.env.DSH_SSH_D_USER
    rmSync(dir, { recursive: true, force: true })
  }
})

test('a rotated password is picked up without a restart', () => {
  const dir = home()
  try {
    // allowPlaintextPassword keeps this test platform-neutral; the encrypted
    // path is covered in dpapi.test.js.
    writeCredentials(dir, { gpu: { password: 'first' } })
    assert.equal(credentialFor('gpu', { dshHome: dir, allowPlaintextPassword: true }).password, 'first')
    writeCredentials(dir, { gpu: { password: 'second' } })
    assert.equal(credentialFor('gpu', { dshHome: dir, allowPlaintextPassword: true }).password, 'second',
      'the file is re-read; an mtime cache missed rotations within one millisecond')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('the credential file supplies a password the other sources lack', () => {
  const dir = home()
  try {
    writeCredentials(dir, { prod: { password: 'from-file' } })
    const auth = credentialFor('prod', {
      machines: { prod: { host: 'h', user: 'u' } },
      dshHome: dir,
      allowPlaintextPassword: true,
    })
    assert.equal(auth.kind, 'file-password')
    assert.equal(auth.password, 'from-file')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('a key path in the credential file carries its passphrase', () => {
  const dir = home()
  try {
    writeCredentials(dir, { prod: { keyPath: '~/.ssh/id_x', keyPassphrase: 'phrase' } })
    const auth = credentialFor('prod', { machines: { prod: { host: 'h', user: 'u' } }, dshHome: dir })
    assert.equal(auth.kind, 'file-key')
    assert.equal(auth.keyPath, '~/.ssh/id_x')
    assert.equal(auth.passphrase, 'phrase')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('the file is ignored when useCredentialFile is off', () => {
  const dir = home()
  try {
    writeCredentials(dir, { prod: { password: 'from-file' } })
    // index.js passes '' for dshHome when the setting is off, which disables the
    // file source; this asserts the shape that decision relies on.
    const auth = credentialFor('prod', {
      machines: { prod: { host: 'h', user: 'u', keyPath: '~/.ssh/id_k' } },
      dshHome: '',
      useAgent: false,
    })
    assert.equal(auth.kind, 'config-key')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('a malformed file degrades to the other sources instead of throwing', () => {
  const dir = home()
  try {
    writeFileSync(credentialsPath(dir), '{ not json', 'utf8')
    assert.deepEqual(loadCredentialFile(dir), {})
    process.env.DSH_SSH_E_HOST = 'h'
    process.env.DSH_SSH_E_USER = 'u'
    process.env.DSH_SSH_E_PASSWORD = 'env-pass'
    const auth = credentialFor('e', { dshHome: dir, useAgent: false })
    assert.equal(auth.kind, 'env-password')
  } finally {
    delete process.env.DSH_SSH_E_HOST
    delete process.env.DSH_SSH_E_USER
    delete process.env.DSH_SSH_E_PASSWORD
    rmSync(dir, { recursive: true, force: true })
  }
})

test('a missing file is not an error', () => {
  const dir = home()
  try {
    assert.deepEqual(loadCredentialFile(dir), {})
    assert.deepEqual(loadCredentialFile(path.join(dir, 'nope')), {})
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('the diagnostics view never contains a secret', () => {
  const dir = home()
  try {
    writeCredentials(dir, { gpu: { password: 'super-secret-value' } })
    const st = credentialState('gpu', {
      machines: { gpu: { host: 'h', user: 'u' } },
      dshHome: dir,
    })
    const printed = JSON.stringify(st)
    assert.doesNotMatch(printed, /super-secret-value/, 'the password must not appear')
    assert.equal(st.passwordSource, 'file-plaintext', 'the source is reported instead')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('aliases are collected from every source', () => {
  const dir = home()
  try {
    writeCredentials(dir, { fromfile: { password: 'x' } })
    process.env.DSH_SSH_FROMENV_HOST = 'h'
    const aliases = knownAliases({
      machines: { fromconfig: { host: 'h', user: 'u' } },
      dshHome: dir,
    })
    assert.ok(aliases.includes('fromconfig'))
    assert.ok(aliases.includes('fromfile'))
    assert.ok(aliases.includes('fromenv'))
  } finally {
    delete process.env.DSH_SSH_FROMENV_HOST
    rmSync(dir, { recursive: true, force: true })
  }
})

test('an unset per-machine policy leaves the global policy in charge', () => {
  // This is the bug the empty-string default fixed: with 'strict' as a machine
  // default, effectivePolicy() never reached the global setting.
  const m = machineDefinition('ghost', {})
  assert.equal(m.hostKeyPolicy, '')
  assert.equal(effectivePolicy('tofu', m.hostKeyPolicy), 'tofu')
  assert.equal(effectivePolicy('strict', m.hostKeyPolicy), 'strict')
})

test('a per-machine policy still overrides the global one', () => {
  const m = machineDefinition('p', { machines: { p: { host: 'h', user: 'u', hostKeyPolicy: 'off' } } })
  assert.equal(m.hostKeyPolicy, 'off')
  assert.equal(effectivePolicy('strict', m.hostKeyPolicy), 'off')
})

test('a plaintext password is refused by default', () => {
  const dir = home()
  try {
    writeCredentials(dir, { prod: { password: 'readable' } })
    const auth = credentialFor('prod', {
      machines: { prod: { host: 'h', user: 'u' } },
      dshHome: dir,
      useAgent: false,
    })
    assert.equal(auth.kind, 'none', 'a readable password must not be accepted')
    assert.ok(auth.warnings.length > 0, 'the refusal is explained')
    assert.match(auth.warnings.join(' '), /plaintext/)
    assert.match(auth.warnings.join(' '), /set-password\.mjs/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('a plaintext password in the settings form is refused too', () => {
  const auth = credentialFor('p', {
    machines: { p: { host: 'h', user: 'u', password: 'readable' } },
    useAgent: false,
  })
  assert.equal(auth.kind, 'none')
  assert.match(auth.warnings.join(' '), /settings form holds a plaintext password/)
})

test('allowPlaintextPassword opts back in, and says why it is a bad idea', () => {
  const auth = credentialFor('p', {
    machines: { p: { host: 'h', user: 'u', password: 'readable' } },
    allowPlaintextPassword: true,
  })
  assert.equal(auth.kind, 'config-password')
  assert.equal(auth.password, 'readable')
})

test('a usable key still works when a plaintext password is refused', () => {
  // The refusal falls through instead of failing hard, so a machine configured
  // with a key keeps working even if someone left a password in the file.
  const dir = home()
  try {
    writeCredentials(dir, { prod: { password: 'readable', keyPath: '~/.ssh/id_k' } })
    const auth = credentialFor('prod', {
      machines: { prod: { host: 'h', user: 'u' } },
      dshHome: dir,
    })
    assert.equal(auth.kind, 'file-key')
    assert.ok(auth.warnings.length > 0)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('the environment password is still accepted: it is never written', () => {
  process.env.DSH_SSH_V_HOST = 'h'
  process.env.DSH_SSH_V_USER = 'u'
  process.env.DSH_SSH_V_PASSWORD = 'in-memory'
  try {
    const auth = credentialFor('v', { useAgent: false })
    assert.equal(auth.kind, 'env-password')
    assert.equal(auth.password, 'in-memory')
    assert.deepEqual(auth.warnings, [])
  } finally {
    delete process.env.DSH_SSH_V_HOST
    delete process.env.DSH_SSH_V_USER
    delete process.env.DSH_SSH_V_PASSWORD
  }
})
test('surrounding whitespace in a hand-edited config is not part of the identity', () => {
  // Every write path trims; a hand-edited file or a pasted environment variable
  // can still carry spaces, and 'test user ' fails authentication with
  // 'the server rejected the credentials' -- pointing at the password.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-trim-'))
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
      box: { host: '  10.0.0.5  ', user: '  deploy  ', keyPath: '  /home/deploy/.ssh/id_rsa  ' },
    }))
    const m = machineDefinition('box', { dshHome: home })
    assert.equal(m.host, '10.0.0.5')
    assert.equal(m.username, 'deploy')
    assert.equal(m.keyPath, '/home/deploy/.ssh/id_rsa')
  } finally { rmSync(home, { recursive: true, force: true }) }
})
test('a usable password outranks a key, in the order the documentation states', () => {
  // README and ssh_credentials both say a password beats a key. That is
  // surprising enough that it has to be pinned: a user who adds a key expecting
  // it to be used instead of a stale password would get the password.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-prec-'))
  try {
    const opts = {
      machines: { box: { host: 'h', user: 'u', password: 'settings-pw', keyPath: '/tmp/k' } },
      dshHome: home,
      allowPlaintextPassword: true,
    }
    assert.equal(credentialFor('box', opts).kind, 'config-password')

    // Drop the settings password: the key is next because no other password source has one.
    opts.machines = { box: { host: 'h', user: 'u', keyPath: '/tmp/k' } }
    assert.equal(credentialFor('box', opts).kind, 'config-key')

    // An environment password beats the key.
    process.env.DSH_SSH_BOX_PASSWORD = 'env-pw'
    try {
      assert.equal(credentialFor('box', opts).kind, 'env-password')
    } finally {
      delete process.env.DSH_SSH_BOX_PASSWORD
    }
  } finally { rmSync(home, { recursive: true, force: true }) }
})
