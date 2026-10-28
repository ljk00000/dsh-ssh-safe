import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// The helper is how a password reaches the credential file without passing
// through a conversation. These tests pin the parts that matter: it writes the
// file the plugin reads, it merges instead of overwriting, and it never prints
// the secret back.

const here = path.dirname(fileURLToPath(import.meta.url))
const script = path.join(here, '..', 'scripts', 'set-password.mjs')

function run(args) {
  return spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' })
}

test('the helper writes a credential the plugin can read', () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-helper-'))
  try {
    const r = run(['--alias', 'gpu', '--host', 'h.example.com', '--port', '2222',
      '--user', 'root', '--password', 'dummy-secret', '--dsh-home', home])
    assert.equal(r.status, 0, r.stderr)
    const file = path.join(home, 'dsh-ssh-safe', 'credentials.json')
    const body = JSON.parse(readFileSync(file, 'utf8'))
    assert.equal(body.gpu.host, 'h.example.com')
    assert.equal(body.gpu.port, 2222)
    assert.equal(body.gpu.user, 'root')
    assert.equal(body.gpu.password, 'dummy-secret')
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('the helper does not echo the secret it stored', () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-helper-'))
  try {
    const r = run(['--alias', 'gpu', '--password', 'never-print-me', '--dsh-home', home])
    assert.equal(r.status, 0, r.stderr)
    const printed = String(r.stdout) + String(r.stderr)
    assert.doesNotMatch(printed, /never-print-me/, 'the value must not be printed')
    assert.match(printed, /<set, not shown>/)
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('a second run preserves the other machines', () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-helper-'))
  try {
    run(['--alias', 'gpu', '--password', 'one', '--dsh-home', home])
    run(['--alias', 'prod', '--password', 'two', '--dsh-home', home])
    const body = JSON.parse(readFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), 'utf8'))
    assert.ok(body.gpu, 'gpu must survive')
    assert.ok(body.prod, 'prod must be added')
    assert.equal(body.gpu.password, 'one')
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('a rerun updates the password in place', () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-helper-'))
  try {
    run(['--alias', 'gpu', '--host', 'h', '--password', 'old', '--dsh-home', home])
    run(['--alias', 'gpu', '--password', 'new', '--dsh-home', home])
    const body = JSON.parse(readFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), 'utf8'))
    assert.equal(body.gpu.password, 'new')
    assert.equal(body.gpu.host, 'h', 'fields not passed this time are kept')
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('it refuses to write an empty entry', () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-helper-'))
  try {
    // Non-interactive stdin with nothing on it: no password to store.
    const r = spawnSync(process.execPath, [script, '--alias', 'gpu', '--dsh-home', home],
      { encoding: 'utf8', input: '' })
    assert.notEqual(r.status, 0)
    assert.match(String(r.stderr), /Nothing to store/)
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})
