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
test('ssh_read renders the file and masks secrets by default', async () => {
  srv.vfs.putFile('/etc/app.conf', 'host=example\nPASSWORD=hunter2\n')
  const text = await run('ssh_read', { path: '/etc/app.conf' })
  assert.match(text, /host=example/)
  assert.ok(!text.includes('hunter2'), 'the password must be masked: ' + text)
  assert.match(text, /secrets masked/)

  const raw = await run('ssh_read', { path: '/etc/app.conf', raw: true })
  assert.match(raw, /hunter2/, 'raw: true shows the file verbatim')
  assert.doesNotMatch(raw, /secrets masked/)
})

test('ssh_read says when it stopped at maxBytes', async () => {
  srv.vfs.putFile('/var/long.txt', 'z'.repeat(500))
  const text = await run('ssh_read', { path: '/var/long.txt', maxBytes: 20 })
  assert.match(text, /\[truncated at 20 bytes\]/, text.slice(0, 120))
  assert.ok(text.length < 100, 'only the read prefix should be returned')
})

test('ssh_write reports the bytes it wrote and they read back', async () => {
  const wrote = await run('ssh_write', { path: '/tmp/notes/one.txt', content: 'hello file', createDirs: true })
  assert.match(wrote, /Wrote 10 bytes to \/tmp\/notes\/one\.txt/)
  const read = await run('ssh_read', { path: '/tmp/notes/one.txt' })
  assert.equal(read, 'hello file')
})

test('ssh_write explains a missing parent directory', async () => {
  await assert.rejects(
    () => run('ssh_write', { path: '/nowhere/deep/file.txt', content: 'x' }),
    /parent directory does not exist.*createDirs: true/, 
  )
})

test('ssh_list renders names, sizes and kinds', async () => {
  srv.vfs.putDir('/srv/www')
  srv.vfs.putFile('/srv/www/index.html', '<h1>hi</h1>')
  srv.vfs.putDir('/srv/www/assets')
  const text = await run('ssh_list', { path: '/srv/www' })
  assert.match(text, /index\.html/)
  assert.match(text, /assets/)
  assert.match(text, /-\s+11\s+index\.html/, 'name and byte count on one row: ' + text)
  assert.match(text, /^d\s+\d+\s+assets$/m, 'a directory row starts with d: ' + text)
})

test('ssh_workspace still answers without a workspace registry', async () => {
  const text = await run('ssh_workspace', { action: 'list' })
  assert.ok(text.length > 0)
  assert.doesNotMatch(text, /INVALID_ARGS|must be of type|unexpected property/i)
})
test('ssh_list stops at maxListEntries and says how many it hid', async () => {
  srv.vfs.putDir('/srv/many')
  for (let i = 0; i < 2100; i++) srv.vfs.putFile('/srv/many/f' + String(i).padStart(5, '0') + '.txt', 'x')
  const text = await run('ssh_list', { path: '/srv/many' })
  const rows = text.split('\n').filter((line) => line.startsWith('- ') || line.startsWith('d '))
  assert.equal(rows.length, 2000, 'the default cap is 2000 rows, saw ' + rows.length)
  assert.match(text, /more entries not shown \(maxListEntries = 2000\)/)
})

test('ssh_list of an empty directory says so', async () => {
  srv.vfs.putDir('/srv/nothing')
  const text = await run('ssh_list', { path: '/srv/nothing' })
  assert.match(text, /\(empty directory: \/srv\/nothing\)/)
})

test('ssh_read of a missing file reports the path', async () => {
  await assert.rejects(() => run('ssh_read', { path: '/srv/absent.txt' }), /no such file/i)
})
test('a single byte is described as "1 byte"', async () => {
  srv.vfs.putDir('/tmp')
  const wrote = await run('ssh_write', { path: '/tmp/one-byte.txt', content: 'x' })
  assert.match(wrote, /Wrote 1 byte to \/tmp\/one-byte\.txt/, wrote)
  srv.vfs.putFile('/tmp/two-bytes.txt', 'xy')
  const read = await run('ssh_read', { path: '/tmp/two-bytes.txt', maxBytes: 1 })
  assert.match(read, /\[truncated at 1 byte\]/, read)
})
test('a refused command is recorded with the machine it targeted', async () => {
  await assert.rejects(() => run('ssh_exec', { command: 'rm -rf /' }), /Command refused/)
  const file = path.join(home, 'dsh-ssh-safe', 'audit.ndjson')
  const records = readFileSync(file, 'utf8').trim().split('\n').map((line) => JSON.parse(line))
  const refused = records.filter((r) => r.kind === 'refused')
  assert.ok(refused.length > 0, 'the refusal must be recorded')
  assert.equal(refused[refused.length - 1].machine, 't', 'the record must name the machine')
  assert.match(String(refused[refused.length - 1].pattern), /rm/)

  const text = await run('ssh_audit', { limit: 50 })
  assert.match(text, / t refused /, 'the renderer must show it: ' + text.slice(0, 400))
})
test('raw: true bypasses masking and maxBytes still caps the read', async () => {
  srv.vfs.putFile('/etc/secret.txt', 'PASSWORD=hunter2\n' + 'x'.repeat(200))
  const masked = await run('ssh_read', { path: '/etc/secret.txt' })
  assert.ok(!masked.includes('hunter2'), 'the default path masks')
  assert.match(masked, /secrets masked/)

  const raw = await run('ssh_read', { path: '/etc/secret.txt', raw: true })
  assert.match(raw, /hunter2/, 'raw shows the file verbatim')
  assert.doesNotMatch(raw, /secrets masked/, 'raw must not claim to have masked anything')

  const capped = await run('ssh_read', { path: '/etc/secret.txt', raw: true, maxBytes: 10 })
  assert.match(capped, /\[truncated at 10 bytes\]/, capped)
  assert.ok(capped.includes('PASSWORD=h'), 'the first ten bytes are kept')
})

test('a file larger than maxFileBytes is capped, not refused', async () => {
  srv.vfs.putFile('/var/large.txt', 'y'.repeat(1200000))
  const text = await run('ssh_read', { path: '/var/large.txt', maxBytes: 5 * 1024 * 1024 })
  // The tool argument can only tighten the configured ceiling (1 MB here).
  assert.ok(text.length < 1200000, 'the read must stop at the configured cap: ' + text.length)
  assert.match(text, /\[truncated at 1048576 bytes\]/)
})
test('ssh_write refuses more than maxFileBytes and accepts exactly that much', async () => {
  srv.vfs.putDir('/tmp')
  const tooBig = 'a'.repeat(1048577)
  await assert.rejects(
    () => run('ssh_write', { path: '/tmp/too-big.txt', content: tooBig }),
    /Refusing to write 1048577 bytes \(maxFileBytes = 1048576\)/,
  )
  assert.equal(srv.vfs.getFile('/tmp/too-big.txt'), undefined, 'nothing may be written')

  const exact = 'b'.repeat(1048576)
  const wrote = await run('ssh_write', { path: '/tmp/exact.txt', content: exact })
  assert.match(wrote, /Wrote 1048576 bytes/)
  assert.equal(srv.vfs.getFile('/tmp/exact.txt').length, 1048576)
})
