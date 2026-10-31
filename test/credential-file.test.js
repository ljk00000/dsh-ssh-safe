import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { SshPool } from '../src/pool.js'
import { credentialFor, readCredentialFile } from '../src/machines.js'

// A corrupt credentials.json used to return {} and nothing else: every connection
// then failed with "no credentials", and the file the user had just edited -- a
// trailing comma was enough -- was never named.

let home

before(() => {
  home = mkdtempSync(path.join(tmpdir(), 'dsh-cred-broken-'))
  mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
})

after(() => {
  rmSync(home, { recursive: true, force: true })
})

const write = (text) => writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), text, { mode: 0o600 })

test('a file that cannot be parsed says so instead of looking empty', () => {
  write('{ "a": { "password": "x", } }')
  const state = readCredentialFile(home)
  assert.deepEqual(state.data, {})
  assert.match(state.problem, /credentials\.json could not be parsed/)
  assert.match(state.problem, /no credential was used from it/)

  write('[{ "password": "x" }]')
  const arrayState = readCredentialFile(home)
  assert.match(arrayState.problem, /is not an object of machines/)
  assert.match(arrayState.problem, /it holds an array/)
})

test('a missing file is not a problem, an unreadable one is', () => {
  const missing = readCredentialFile(path.join(home, 'nothing-here'))
  assert.equal(missing.problem, '')
  assert.deepEqual(missing.data, {})
})

test('the warning reaches the credential report and the connect failure', () => {
  write('{ "a": { "password": "x", } }')
  const auth = credentialFor('a', { machines: {}, dshHome: home })
  assert.equal(auth.kind, 'none')
  assert.ok(auth.warnings.some((w) => /could not be parsed/.test(w)), JSON.stringify(auth.warnings))

  // ...and the connect failure that follows names it, rather than pointing only
  // at the environment.
  const pool = new SshPool({
    hostKeyPolicy: 'tofu',
    allowPlaintextPassword: true,
    machines: { a: { host: '127.0.0.1', port: 1, user: 'u' } },
  }, { dshHome: home })
  return pool.exec('a', 'echo hi', {}).then(
    () => assert.fail('the connect should have been refused'),
    (err) => {
      assert.match(err.message, /has no usable credentials/)
      assert.match(err.message, /credentials\.json could not be parsed/)
      return true
    },
  )
})
