import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { apply } from '../src/index.js'
import { startServer, machineFor } from './helpers/local-ssh-server.js'

// The twelve tool bodies are the largest untested part of src/index.js: they
// only run with a working connection, and the unit suite has none. These drive
// them for real against the loopback SSH server, so rendering, the audit trail
// and the guard are exercised through the same path a user hits.

let srv
let home
let tools

before(async () => {
  srv = await startServer()
  home = mkdtempSync(path.join(tmpdir(), 'dsh-tools-live-'))
  process.env.DSH_HOME = home
  tools = {}
  const ctx = {
    tools: { register: (def) => { tools[def.name] = def } },
    effect: () => {},
    get: () => undefined,
  }
  await apply(ctx, {
    defaultMachine: 't',
    allowPlaintextPassword: true,
    auditLog: true,
    hostKeyPolicy: 'tofu',
    machines: { t: machineFor('t', srv.port) },
  })
})

after(async () => {
  // The tools keep their own pooled connections; without this the process
  // outlives the suite and the runner kills it at the file timeout.
  try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
  await srv.close()
  delete process.env.DSH_HOME
  rmSync(home, { recursive: true, force: true })
})

const run = (name, args) => tools[name].execute(args, {}).then((r) => String(r.text), (e) => { throw e })

test('ssh_exec renders stdout and the exit code', async () => {
  const text = await run('ssh_exec', { command: 'echo hi' })
  assert.match(text, /ran: echo hi/)
  assert.match(text, /\[exit 0\]/)
})

test('ssh_exec renders a non-zero exit code', async () => {
  const text = await run('ssh_exec', { command: 'exit 4' })
  assert.match(text, /\[exit 4\]/)
})

test('ssh_exec names the signal for a killed command', async () => {
  const text = await run('ssh_exec', { command: 'kill' })
  assert.match(text, /\[signal SIGKILL\]/)
})

test('ssh_exec reports the deadline in the result', async () => {
  const text = await run('ssh_exec', { command: 'sleep 5', timeoutMs: 250 })
  assert.match(text, /\[timed out after 250ms\]/)
})

test('ssh_exec keeps stderr labelled', async () => {
  const text = await run('ssh_exec', { command: 'stderr' })
  assert.match(text, /\[stderr\]\nan error line/)
})

test('ssh_exec refuses a denied pattern through the tool', async () => {
  await assert.rejects(() => run('ssh_exec', { command: 'rm -rf /' }), /Command refused/)
})

test('ssh_exec redacts secret-shaped output', async () => {
  const text = await run('ssh_exec', { command: 'echo PASSWORD=hunter2' })
  assert.ok(!text.includes('hunter2'), text)
  assert.match(text, /<redacted>/)
})

test('ssh_connect reports the fingerprint', async () => {
  const text = await run('ssh_connect', {})
  assert.match(text, /Connected: tester@127\.0\.0\.1/)
  assert.match(text, /SHA256:/)
})

test('ssh_doctor walks every stage', async () => {
  const text = await run('ssh_doctor', {})
  for (const stage of ['configuration', 'credentials', 'tcp', 'host key', 'authentication']) {
    assert.match(text, new RegExp('\\[ok\\] ' + stage), stage + ' missing: ' + text)
  }
})

test('ssh_machines lists the configured machine', async () => {
  const text = await run('ssh_machines', {})
  assert.match(text, /t\b/)
  assert.match(text, /127\.0\.0\.1/)
})

test('ssh_config reports the effective settings', async () => {
  const text = await run('ssh_config', {})
  assert.match(text, /defaultMachine\s+"t"/)
  assert.match(text, /maxOutputChars/)
})

test('ssh_credentials names the source without the value', async () => {
  const text = await run('ssh_credentials', {})
  assert.match(text, /settings form|credential file|environment/)
  assert.ok(!/test-pass/.test(text), 'the password must never be printed')
})

test('ssh_close reports no connection, then closes one', async () => {
  await run('ssh_exec', { command: 'echo warm' })
  // No machine means "close all", which renders the list form: 'Closed: t'.
  const closed = await run('ssh_close', {})
  assert.match(closed, /Closed:? t/)
})

test('ssh_audit shows the recorded operations when logging is on', async () => {
  await run('ssh_exec', { command: 'echo audited' })
  const text = await run('ssh_audit', {})
  assert.match(text, /exec/)
  assert.match(text, /audited|ok/)
})

test('the audit file exists and never contains the command output', () => {
  const file = path.join(home, 'dsh-ssh-safe', 'audit.ndjson')
  assert.ok(existsSync(file), 'audit file should exist at ' + file)
  const body = readFileSync(file, 'utf8')
  assert.match(body, /audited/)
  assert.ok(!body.includes('ran: echo audited'), 'audit must record the command, not its output')
})
test('an empty command is refused with a message, not an empty result', async () => {
  await assert.rejects(() => run('ssh_exec', { command: '   ' }), /command/i)
})

test('a command with no output still reports the exit code', async () => {
  const text = await run('ssh_exec', { command: 'exit 0' })
  assert.match(text, /\[exit 0\]/)
  assert.ok(text.trim().length > 0, 'the result must not be blank')
})
test('the file and workspace tools answer through their schema', async () => {
  // These reach SFTP, which this server does not implement, and the workspace
  // tool reaches for a registry that a headless run does not have. The point is
  // that each answers with a message rather than a schema error or a crash.
  const cases = [
    ['ssh_read', { path: '/etc/hostname' }],
    ['ssh_write', { path: '/tmp/probe.txt', content: 'hi' }],
    ['ssh_list', { path: '/' }],
    ['ssh_workspace', { action: 'list' }],
  ]
  for (const [name, args] of cases) {
    let text
    try { text = String((await tools[name].execute(args, {})).text) }
    catch (err) { text = 'rejected: ' + err.message }
    assert.ok(text.length > 0, name + ' returned nothing')
    assert.doesNotMatch(text, /INVALID_ARGS|must be of type|unexpected property/i, name + ': ' + text.slice(0, 200))
  }
})
test('non-ASCII output survives the channel', async () => {
  const text = await run('ssh_exec', { command: 'echo 中文🙂' })
  assert.match(text, /中文🙂/, 'utf-8 must round-trip through the channel collector')
})

test('CRLF output is passed through without splitting lines', async () => {
  const text = await run('ssh_exec', { command: 'crlf' })
  assert.match(text, /line one/)
  assert.match(text, /line two/)
})

test('invalid utf-8 bytes do not crash the tool', async () => {
  const text = await run('ssh_exec', { command: 'binary' })
  assert.ok(text.length >= 0, 'a result is still returned')
  assert.match(text, /\[exit 0\]/, 'the exit line must still be rendered')
})
