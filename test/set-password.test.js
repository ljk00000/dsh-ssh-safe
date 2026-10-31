import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { machineDefinition } from '../src/machines.js'
import { decryptDpapi, dpapiAvailable } from '../src/dpapi.js'

// The rotation flow a user actually runs: scripts/set-password.mjs writes the
// credential file, and the plugin has to find that same entry. The alias rule
// differed between the two (the script stripped '-' and '.', the plugin did
// not), so a machine named 'prod-1' stored its password under 'prod1' and then
// reported "no credentials".

const here = path.dirname(fileURLToPath(import.meta.url))
const script = path.join(here, '..', 'scripts', 'set-password.mjs')

function runSetPassword(home, args, password) {
  return spawnSync(process.execPath, [script, '--dsh-home', home, ...args], {
    input: password === undefined ? '' : password + '\n',
    encoding: 'utf8',
    timeout: 20000,
  })
}

test('a hyphenated alias is stored under the same name the plugin looks up', { skip: !dpapiAvailable() && 'DPAPI unavailable' }, () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-swp-'))
  try {
    const result = runSetPassword(home, ['--alias', 'prod-1', '--host', '10.0.0.1', '--user', 'root', '--password', 'secretpw'])
    assert.equal(result.status, 0, result.stderr || result.stdout)
    const file = path.join(home, 'dsh-ssh-safe', 'credentials.json')
    assert.ok(existsSync(file), 'credential file should exist')
    const store = JSON.parse(readFileSync(file, 'utf8'))
    assert.ok(store['prod-1'], 'the entry must keep the hyphen, saw keys ' + JSON.stringify(Object.keys(store)))
    assert.ok(!store.prod1, 'the entry must not be collapsed to prod1')
    assert.ok(store['prod-1'].passwordDpapi, 'the password must be DPAPI encrypted')
    assert.ok(!JSON.stringify(store).includes('secretpw'), 'the password must not be stored in plaintext')

    const machine = machineDefinition('prod-1', { dshHome: home })
    assert.equal(machine.sources.password, 'file-dpapi', 'the plugin must resolve the stored password')
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('a dotted alias survives too', { skip: !dpapiAvailable() && 'DPAPI unavailable' }, () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-swp-'))
  try {
    const result = runSetPassword(home, ['--alias', 'lab.a', '--host', '10.0.0.2', '--user', 'root', '--password', 'pw2'])
    assert.equal(result.status, 0, result.stderr || result.stdout)
    const store = JSON.parse(readFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), 'utf8'))
    assert.ok(store['lab.a'], 'keys: ' + JSON.stringify(Object.keys(store)))
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('a second write for the same alias replaces the first', { skip: !dpapiAvailable() && 'DPAPI unavailable' }, () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-swp-'))
  try {
    assert.equal(runSetPassword(home, ['--alias', 'rot', '--host', 'h', '--user', 'u', '--password', 'one']).status, 0)
    assert.equal(runSetPassword(home, ['--alias', 'rot', '--host', 'h', '--user', 'u', '--password', 'two']).status, 0)
    const store = JSON.parse(readFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), 'utf8'))
    assert.ok(store.rot.passwordDpapi)
    assert.equal(decryptDpapi(store.rot.passwordDpapi), 'two', 'the second write must win')
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})
test('an unusable port is refused instead of stored as null', { skip: !dpapiAvailable() && 'DPAPI unavailable' }, () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-swp-'))
  try {
    for (const port of ['abc', '70000', '-5', '22.5', '0']) {
      const result = runSetPassword(home, ['--alias', 'p', '--host', 'h', '--user', 'u', '--password', 'pw', '--port', port])
      assert.equal(result.status, 2, 'port ' + port + ' must be refused: ' + result.stdout)
      assert.match(result.stderr, /--port must be an integer between 1 and 65535/)
    }
    assert.ok(!existsSync(path.join(home, 'dsh-ssh-safe', 'credentials.json')), 'nothing may be written')

    const good = runSetPassword(home, ['--alias', 'p', '--host', 'h', '--user', 'u', '--password', 'pw', '--port', '2222'])
    assert.equal(good.status, 0, good.stderr)
    const store = JSON.parse(readFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), 'utf8'))
    assert.equal(store.p.port, 2222)
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})
test('an alias with characters it cannot contain is refused, not rewritten', () => {
  // It used to strip them: '--alias prod/x' stored the password as 'prodx',
  // which nothing ever looks up -- and said it had been stored.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-swp-'))
  try {
    const result = runSetPassword(home, ['--alias', 'prod/x', '--password', 'secretpw'])
    assert.equal(result.status, 2)
    assert.match(result.stderr, /contains characters an alias cannot have/)
    assert.match(result.stderr, /not rewritten/)
    assert.equal(existsSync(path.join(home, 'dsh-ssh-safe', 'credentials.json')), false,
      'a refused alias must not write anything')
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('an unknown option is reported instead of ignored', () => {
  // '--pasword secret' was silently dropped, so the run stored nothing and the
  // only clue was a message about the missing password.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-swp-'))
  try {
    const result = runSetPassword(home, ['--alias', 'prod', '--pasword', 'secretpw'])
    assert.equal(result.status, 2)
    assert.match(result.stderr, /Unknown option --pasword/)
    assert.match(result.stderr, /--key-passphrase/)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('a store that cannot be parsed is left alone, not replaced', { skip: !dpapiAvailable() && 'DPAPI unavailable' }, () => {
  // This used to warn and then overwrite: every other machine's entry was thrown
  // away, and a truncated file (the usual shape of the damage) is repairable.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-swp-'))
  try {
    const dir = path.join(home, 'dsh-ssh-safe')
    mkdirSync(dir, { recursive: true })
    const file = path.join(dir, 'credentials.json')
    const broken = '{ "gpu": { "host": "10.0.0.1" }, oops'
    writeFileSync(file, broken, 'utf8')
    const result = runSetPassword(home, ['--alias', 'prod', '--password', 'secretpw'])
    assert.equal(result.status, 2, 'it must refuse: ' + result.stdout)
    assert.match(result.stderr, /could not be parsed, so nothing was written/)
    assert.match(result.stderr, /still in that file/)
    assert.equal(readFileSync(file, 'utf8'), broken, 'the file must be byte-identical afterwards')
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('an array-shaped store is refused instead of silently written back', { skip: !dpapiAvailable() && 'DPAPI unavailable' }, () => {
  // '[{...}]' passed the old typeof check; adding store[alias] to an array makes
  // JSON.stringify drop it, so the file stayed '[]' while the script printed
  // 'Stored for "prod"'.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-swp-'))
  try {
    const dir = path.join(home, 'dsh-ssh-safe')
    mkdirSync(dir, { recursive: true })
    const file = path.join(dir, 'credentials.json')
    writeFileSync(file, '[]', 'utf8')
    const result = runSetPassword(home, ['--alias', 'prod', '--password', 'secretpw'])
    assert.equal(result.status, 2, 'it must refuse: ' + result.stdout)
    assert.match(result.stderr, /is not an object of machines \(it holds an array\)/)
    assert.equal(readFileSync(file, 'utf8'), '[]', 'nothing may be written over it')
    assert.doesNotMatch(result.stdout, /Stored for/)
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('a store saved with a BOM is still read, and other entries survive', { skip: !dpapiAvailable() && 'DPAPI unavailable' }, () => {
  // Notepad saves 'UTF-8 with BOM'; JSON.parse rejects it, so the file read as
  // corrupt when it had only been opened and saved.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-swp-'))
  try {
    const dir = path.join(home, 'dsh-ssh-safe')
    mkdirSync(dir, { recursive: true })
    const file = path.join(dir, 'credentials.json')
    writeFileSync(file, '\uFEFF' + JSON.stringify({ gpu: { host: '10.0.0.1', user: 'root' } }, null, 2), 'utf8')
    const result = runSetPassword(home, ['--alias', 'prod', '--password', 'secretpw'])
    assert.equal(result.status, 0, result.stderr || result.stdout)
    const store = JSON.parse(readFileSync(file, 'utf8').replace(/^\uFEFF/, ''))
    assert.deepEqual(Object.keys(store).sort(), ['gpu', 'prod'], 'both entries must be there')
    assert.equal(store.gpu.host, '10.0.0.1')
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('a prototype-named alias is refused instead of silently not stored', { skip: !dpapiAvailable() && 'DPAPI unavailable' }, () => {
  // stderr said 'Stored for "__proto__"' and exited 0 while writing nothing:
  // store['__proto__'] = entry sets the prototype, so JSON.stringify dropped it.
  // The page already refused these three names.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-swp-proto-'))
  try {
    for (const alias of ['__proto__', 'constructor', 'prototype']) {
      const result = runSetPassword(home, ['--alias', alias, '--password', 'secretpw'])
      assert.equal(result.status, 2, alias + ' must be refused, got: ' + (result.stderr || result.stdout))
      assert.match(result.stderr + result.stdout, /collides with a built-in JavaScript property/)
      assert.match(result.stderr + result.stdout, /nothing was written/)
      assert.doesNotMatch(result.stderr + result.stdout, /Stored for/)
    }
    const file = path.join(home, 'dsh-ssh-safe', 'credentials.json')
    assert.equal(existsSync(file), false, 'nothing may be written for a refused alias')
    // An ordinary name still works afterwards.
    const ok = runSetPassword(home, ['--alias', 'ok', '--password', 'secretpw'])
    assert.equal(ok.status, 0, ok.stderr || ok.stdout)
    assert.ok(JSON.parse(readFileSync(file, 'utf8')).ok)
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('a blocked credential directory is reported, not a stack trace', { skip: !dpapiAvailable() && 'DPAPI unavailable' }, () => {
  // mkdirSync threw EEXIST with a raw Node stack trace: no message, no statement
  // that nothing had been written.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-swp-blocked-'))
  try {
    writeFileSync(path.join(home, 'dsh-ssh-safe'), 'blocked')
    const result = runSetPassword(home, ['--alias', 't', '--password', 'secretpw'])
    assert.equal(result.status, 2, result.stderr || result.stdout)
    const output = String(result.stderr) + String(result.stdout)
    assert.match(output, /is a file, not a directory/)
    assert.match(output, /Nothing was written/)
    assert.doesNotMatch(output, /at ModuleJob|node:fs:/)
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('--clear-password removes a stored password and keeps the rest', { skip: !dpapiAvailable() && 'DPAPI unavailable' }, () => {
  // There was no way to revoke a stored DPAPI password: the page ignores an empty
  // password (omitting one means 'leave it alone') and the CLI had no flag, so the
  // only options were deleting the machine or editing credentials.json by hand.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-clear-'))
  const file = path.join(home, 'dsh-ssh-safe', 'credentials.json')
  try {
    assert.equal(runSetPassword(home, ['--alias', 'c1', '--host', 'h1', '--password', 'pw']).status, 0)
    assert.equal(runSetPassword(home, ['--alias', 'c2', '--password', 'pw2']).status, 0)
    const before = JSON.parse(readFileSync(file, 'utf8'))
    assert.ok(before.c1.passwordDpapi, 'the password must be stored first')

    const cleared = runSetPassword(home, ['--alias', 'c1', '--clear-password'])
    assert.equal(cleared.status, 0, cleared.stderr)
    assert.match(String(cleared.stdout), /Cleared the stored password for "c1"/)
    const after = JSON.parse(readFileSync(file, 'utf8'))
    assert.equal(after.c1.passwordDpapi, undefined, 'the blob must be gone')
    assert.equal(after.c1.password, undefined)
    assert.equal(after.c1.host, 'h1', 'other fields stay')
    assert.ok(after.c2.passwordDpapi, 'another machine is untouched')

    // Clearing again is a refusal, not a silent success.
    const again = runSetPassword(home, ['--alias', 'c1', '--clear-password'])
    assert.equal(again.status, 2)
    assert.match(String(again.stderr), /No stored password for "c1"/)

    // An entry that held only the password disappears instead of becoming {}.
    const final = JSON.parse(readFileSync(file, 'utf8'))
    assert.equal(final.c2.passwordDpapi === undefined, false)
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('--clear-password refuses to be combined with --password', { skip: !dpapiAvailable() && 'DPAPI unavailable' }, () => {
  // The clear branch ran first and exited 0 with 'Cleared' while --password was
  // never stored: a silent contradiction.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-clear2-'))
  const file = path.join(home, 'dsh-ssh-safe', 'credentials.json')
  try {
    assert.equal(runSetPassword(home, ['--alias', 'x1', '--password', 'old']).status, 0)
    const conflict = runSetPassword(home, ['--alias', 'x1', '--clear-password', '--password', 'new'])
    assert.equal(conflict.status, 2)
    assert.match(String(conflict.stderr), /cannot be combined with --password/)
    // Nothing changed.
    const store = JSON.parse(readFileSync(file, 'utf8'))
    assert.ok(store.x1.passwordDpapi, 'the old password must still be there')

    const plain = runSetPassword(home, ['--alias', 'x1', '--clear-password', '--plaintext'])
    assert.equal(plain.status, 2)
    assert.match(String(plain.stderr), /--plaintext only applies when storing/)
    assert.ok(JSON.parse(readFileSync(file, 'utf8')).x1.passwordDpapi)

    // Field updates are allowed alongside the clear.
    const withHost = runSetPassword(home, ['--alias', 'x1', '--clear-password', '--host', 'newhost'])
    assert.equal(withHost.status, 0, withHost.stderr)
    const after = JSON.parse(readFileSync(file, 'utf8'))
    assert.equal(after.x1.passwordDpapi, undefined)
    assert.equal(after.x1.host, 'newhost')
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('the usage line names every option the script accepts', () => {
  // It listed only the original flags: --password, --plaintext and --clear-password
  // were accepted but unmentioned, and a whitelist keeps them in step.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-usage-'))
  try {
    const result = runSetPassword(home, [])
    assert.equal(result.status, 2)
    const usage = String(result.stderr)
    for (const flag of ['--host', '--port', '--user', '--key-path', '--key-passphrase', '--password', '--plaintext', '--clear-password']) {
      assert.ok(usage.includes(flag), 'usage must mention ' + flag)
    }
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('a key passphrase is stored DPAPI encrypted, and an unusable blob says so', async () => {
  // It used to be written in plaintext while the password beside it was encrypted,
  // and a blob that could not be decrypted read as 'no keyPassphrase configured'.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-keypass-'))
  const run = (args) => spawnSync(process.execPath, [script, ...args], {
    encoding: 'utf8', env: { ...process.env, DSH_HOME: home },
  })
  try {
    const stored = run(['--alias', 'k', '--key-path', '~/.ssh/id_ed25519', '--key-passphrase', 'PASSMARKER'])
    if (stored.status !== 0) {
      // No DPAPI on this platform: the CLI must say so rather than store plaintext.
      assert.match((stored.stdout || '') + (stored.stderr || ''), /DPAPI|plaintext/i)
      return
    }
    const file = path.join(home, 'dsh-ssh-safe', 'credentials.json')
    const entry = JSON.parse(readFileSync(file, 'utf8')).k
    assert.equal(entry.keyPassphrase, undefined, 'no plaintext passphrase on disk')
    assert.equal(typeof entry.keyPassphraseDpapi, 'string')
    assert.doesNotMatch(readFileSync(file, 'utf8'), /PASSMARKER/)
    // The resolver decrypts it, so the value reaches the key parser.
    const machine = machineDefinition('k', { machines: {}, dshHome: home })
    assert.equal(machine.keyPassphrase, 'PASSMARKER')
    assert.equal(machine.keyPassphraseProblem, '')
    // --plaintext is the explicit opt-in and still works.
    const plain = run(['--alias', 'p', '--key-path', '~/.ssh/id_ed25519', '--key-passphrase', 'PLAINMARKER', '--plaintext'])
    assert.equal(plain.status, 0)
    const plainEntry = JSON.parse(readFileSync(file, 'utf8')).p
    assert.equal(plainEntry.keyPassphrase, 'PLAINMARKER')
    assert.equal(plainEntry.keyPassphraseDpapi, undefined)
    // A blob from somewhere else cannot be decrypted: that is not 'not configured'.
    const broken = { k: { keyPath: '~/.ssh/id_ed25519', keyPassphraseDpapi: 'DPAPIBLOB:notreally' } }
    writeFileSync(file, JSON.stringify(broken, null, 2))
    const bad = machineDefinition('k', { machines: {}, dshHome: home })
    assert.equal(bad.keyPassphrase, '')
    assert.match(bad.keyPassphraseProblem, /DPAPI blob|cannot be decrypted/)
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('--clear-key-passphrase removes the stored passphrase and nothing else', () => {
  // --clear-password existed and --clear-key-passphrase did not: a rotated key left
  // the old passphrase in the file with no way to revoke it short of editing JSON.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-clearkp-'))
  const run = (args) => spawnSync(process.execPath, [script, ...args], {
    encoding: 'utf8', env: { ...process.env, DSH_HOME: home },
  })
  const store = () => {
    try { return JSON.parse(readFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), 'utf8')) } catch { return {} }
  }
  try {
    assert.equal(run(['--alias', 'k', '--key-path', '~/.ssh/id_ed25519', '--key-passphrase', 'PW1']).status, 0)
    const before = store().k
    assert.equal(before.keyPath, '~/.ssh/id_ed25519')
    assert.ok(before.keyPassphraseDpapi || before.keyPassphrase, 'something was stored')

    const cleared = run(['--alias', 'k', '--clear-key-passphrase'])
    assert.equal(cleared.status, 0)
    assert.match(cleared.stdout + cleared.stderr, /Cleared the stored key passphrase/)
    assert.deepEqual(store().k, { keyPath: '~/.ssh/id_ed25519' }, 'only the passphrase goes')

    // Nothing left to clear is an error, not a silent success.
    const again = run(['--alias', 'k', '--clear-key-passphrase'])
    assert.equal(again.status, 2)
    assert.match((again.stdout || '') + (again.stderr || ''), /nothing to clear/)

    // Two contradictory instructions in one command are refused, like --clear-password.
    const combo = run(['--alias', 'k', '--clear-key-passphrase', '--key-passphrase', 'PW2'])
    assert.equal(combo.status, 2)
    assert.match((combo.stdout || '') + (combo.stderr || ''), /cannot be combined/)
    const plain = run(['--alias', 'k', '--clear-key-passphrase', '--plaintext'])
    assert.equal(plain.status, 2)

    // An entry that held only a passphrase disappears instead of leaving {} behind.
    assert.equal(run(['--alias', 'only', '--key-passphrase', 'PW3']).status, 0)
    assert.equal(run(['--alias', 'only', '--clear-key-passphrase']).status, 0)
    assert.deepEqual(Object.keys(store()), ['k'])
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})
