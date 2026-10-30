import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs'
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
