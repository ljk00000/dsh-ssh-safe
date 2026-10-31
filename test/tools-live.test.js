import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { apply } from '../src/index.js'
import { looksBinary } from '../src/sftp.js'
import { SshPool } from '../src/pool.js'
import ssh2 from 'ssh2'
import { startServer, machineFor, alternateHostKey } from './helpers/local-ssh-server.js'

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
  assert.match(text, /timed out after 250ms/)
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
  assert.match(text, /\[truncated: the first 20 bytes of a larger file/, text.slice(0, 140))
  // Only the prefix: twenty characters, not the 500 in the file.
  assert.equal((text.match(/z/g) || []).length, 20, 'only the read prefix should be returned')
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
  assert.match(text, /-\s+11\s+(\S+Z\s+)?index\.html/, 'name and byte count on one row: ' + text)
  assert.match(text, /^d\s+\d+\s+(\S+Z\s+)?assets$/m, 'a directory row starts with d: ' + text)
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
  assert.match(read, /\[truncated: the first 1 byte of a larger file/, read)
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
  assert.match(capped, /\[truncated: the first 10 bytes of a larger file/, capped)
  assert.ok(capped.includes('PASSWORD=h'), 'the first ten bytes are kept')
})

test('a file larger than maxFileBytes is capped, not refused', async () => {
  srv.vfs.putFile('/var/large.txt', 'y'.repeat(1200000))
  const text = await run('ssh_read', { path: '/var/large.txt', maxBytes: 5 * 1024 * 1024 })
  // The tool argument can only tighten the configured ceiling (1 MB here).
  assert.ok(text.length < 1200000, 'the read must stop at the configured cap: ' + text.length)
  assert.match(text, /\[truncated: the first 1048576 bytes of a larger file/)
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
test('a command killed at the deadline keeps what it had already printed', async () => {
  const text = await run('ssh_exec', { command: 'slowout', timeoutMs: 250 })
  assert.match(text, /started/, 'stdout produced before the deadline must survive')
  assert.match(text, /\[stderr\]\nwarming up/, 'so must stderr')
  assert.doesNotMatch(text, /finished/, 'the tail never arrived')
  assert.match(text, /timed out after 250ms/)
})
test('two commands on one machine run at the same time, not one after the other', async () => {
  const started = Date.now()
  const [a, b] = await Promise.all([
    run('ssh_exec', { command: 'sleep 1' }),
    run('ssh_exec', { command: 'echo quick' }),
  ])
  const elapsed = Date.now() - started
  assert.match(a, /slept 1/)
  assert.match(b, /quick/)
  // One connection carries several channels; if the pool serialised them this
  // would take two seconds.
  assert.ok(elapsed < 1900, 'the two commands should overlap, took ' + elapsed + 'ms')
})

test('output beyond maxOutputChars is cut and the cut is announced', async () => {
  // maxOutputChars is left at its 200000 default here.
  const text = await run('ssh_exec', { command: 'big 300000' })
  assert.match(text, /\[output truncated at maxOutputChars: \d+ more characters were dropped from the end/)
  // Which end survived is the part a reader needs; "truncated" alone left the
  // beginning looking like the command's whole verdict.
  assert.match(text, /what is shown is the beginning of the output/)
  assert.match(text, /Raise maxOutputChars, or send the output to a file/)
  assert.ok(text.length <= 200500, 'the tool must not return everything: ' + text.length)
  assert.ok(text.length > 100000, 'it should still return most of the cap: ' + text.length)
  assert.match(text, /\[exit 0\]|exit 0/)
})
test('ssh_close during a command settles it and says the output is partial', async () => {
  const started = Date.now()
  const running = tools.ssh_exec.execute({ command: 'sleep 5' }, {})
  await new Promise((r) => setTimeout(r, 300))
  await tools.ssh_close.execute({ force: true }, {})
  const text = String((await running).text)
  assert.ok(Date.now() - started < 3000, 'a disconnect must not wait out the command')
  assert.match(text, /connection closed before the command reported an exit status/)
})
test('a huge directory is cut at maxListEntries and says how much is missing', async () => {
  srv.vfs.putDir('/many')
  for (let i = 0; i < 10000; i++) srv.vfs.putFile('/many/f' + String(i).padStart(5, '0') + '.txt', 'x')
  const started = Date.now()
  const text = await run('ssh_list', { path: '/many' })
  const elapsed = Date.now() - started
  const rows = text.split('\n').filter((line) => /^[d-] /.test(line))
  assert.equal(rows.length, 2000, 'the default cap is 2000 rows')
  assert.match(text, /8000 more entries not shown \(maxListEntries = 2000\)/)
  assert.ok(elapsed < 15000, 'ten thousand entries should not take that long: ' + elapsed + 'ms')
})

test('filenames that could forge a listing row are escaped', async () => {
  srv.vfs.putDir('/odd')
  srv.vfs.putFile('/odd/plain.txt', 'x')
  srv.vfs.putFile('/odd/with\nnewline.txt', 'x')
  srv.vfs.putFile('/odd/with\ttab.txt', 'x')
  srv.vfs.putFile('/odd/bell\u0007.txt', 'x')
  const text = await run('ssh_list', { path: '/odd' })
  const rows = text.split('\n').filter((line) => /^[d-] /.test(line))
  assert.equal(rows.length, 4, 'a newline in a name must not create a row: ' + JSON.stringify(text))
  assert.match(text, /with\\nnewline\.txt/)
  assert.match(text, /with\\ttab\.txt/)
  assert.match(text, /bell\\x07\.txt/)
  assert.doesNotMatch(text, /\u0007/, 'no raw control character may reach the caller')
})

test('line separators and bidi overrides in a name are escaped too', async () => {
  // C0 alone was escaped. A C1 control, a Unicode line separator or a
  // right-to-left override still reached the caller: '\u202Etxt.exe' renders as
  // 'exe.txt' and '\u2028' breaks the row the escaping exists to protect.
  srv.vfs.putDir('/odd2')
  srv.vfs.putFile('/odd2/nel\u0085break.txt', 'x')
  srv.vfs.putFile('/odd2/line\u2028sep.txt', 'x')
  srv.vfs.putFile('/odd2/para\u2029sep.txt', 'x')
  srv.vfs.putFile('/odd2/rtl\u202etxt.exe', 'x')
  srv.vfs.putFile('/odd2/iso\u2066late.txt', 'x')
  const text = await run('ssh_list', { path: '/odd2' })
  const rows = text.split('\n').filter((line) => /^[d-] /.test(line))
  assert.equal(rows.length, 5, 'no separator may forge a row: ' + JSON.stringify(text))
  assert.match(text, /nel\\x85break\.txt/)
  assert.match(text, /line\\u2028sep\.txt/)
  assert.match(text, /para\\u2029sep\.txt/)
  assert.match(text, /rtl\\u202etxt\.exe/)
  assert.match(text, /iso\\u2066late\.txt/)
  for (const raw of ['\u0085', '\u2028', '\u2029', '\u202e', '\u2066']) {
    assert.ok(!text.includes(raw), 'raw U+' + raw.charCodeAt(0).toString(16) + ' reached the caller')
  }
})
test('ssh_doctor does not sever a command that started while it was running', async () => {
  // The doctor connects, probes, and closes what it opened. If a command
  // started in the meantime, force-closing took that command's channel with it
  // and the caller saw a dropped result for no visible reason.
  const [executed, diagnosed] = await Promise.all([
    tools.ssh_exec.execute({ command: 'sleep 1' }, {}),
    tools.ssh_doctor.execute({}, {}),
  ])
  assert.match(String(diagnosed.text), /\[ok\] authentication: command channel works/)
  assert.match(String(executed.text), /slept 1/, 'the command must survive the diagnosis: ' + String(executed.text))
  assert.doesNotMatch(String(executed.text), /connection closed before the command reported an exit status/)
})
test('a write that never opened does not claim the file was damaged', async () => {
  // The partial-write note belongs to a transfer that actually sent bytes.
  // An open failure (missing parent, or a path component that is a file) wrote
  // nothing, and saying otherwise sends the caller hunting for damage.
  await assert.rejects(
    () => run('ssh_write', { path: '/var/missing/x.txt', content: 'y' }),
    (err) => {
      assert.match(err.message, /parent directory does not exist/)
      assert.doesNotMatch(err.message, /partially written/)
      return true
    },
  )
  srv.vfs.putFile('/var/file.txt', 'x')
  await assert.rejects(
    () => run('ssh_write', { path: '/var/file.txt/child.txt', content: 'y', createDirs: true }),
    (err) => {
      assert.match(err.message, /\/var\/file\.txt already exists and is a file, not a directory/)
      assert.doesNotMatch(err.message, /partially written/)
      return true
    },
  )
})
test('a command that cannot fit in one SSH request is refused with a reason', async () => {
  // ssh2 answers 'Unable to exec' for a command over the transport packet
  // limit, with nothing to say it was the size. Refuse it first, and do not
  // open a connection to discover the problem.
  const before = srv.clientCount()
  await assert.rejects(
    () => run('ssh_exec', { command: 'echo ' + 'a'.repeat(40000) }),
    (err) => {
      assert.match(err.message, /a single SSH exec request carries at most 34000/)
      assert.match(err.message, /Write the script with ssh_write/)
      return true
    },
  )
  assert.equal(srv.clientCount(), before, 'nothing should be sent for a doomed command')

  const ok = await run('ssh_exec', { command: 'echo ' + 'b'.repeat(33000) })
  assert.match(ok, /\[exit 0\]/, 'a command under the limit still runs')
})
test('a cancelled command stops at once and leaves the connection usable', async () => {
  // The harness aborts exec.signal when the user stops the turn. The remote
  // command used to keep running (a real side effect) until its deadline.
  const controller = new AbortController()
  const started = Date.now()
  const running = tools.ssh_exec.execute({ command: 'sleep 5' }, { signal: controller.signal })
  setTimeout(() => controller.abort(), 200)
  const result = await running
  const elapsed = Date.now() - started
  assert.ok(elapsed < 2000, 'cancellation must not wait for the command: ' + elapsed + 'ms')
  const text = String(result.text)
  assert.match(text, /\[cancelled at the caller request/)
  assert.doesNotMatch(text, /\[timed out/, 'a cancelled call is not a timeout')
  assert.doesNotMatch(text, /exit unknown/, 'there is no exit status to report')

  const after = await tools.ssh_exec.execute({ command: 'echo back' }, {})
  assert.match(String(after.text), /back/, 'the connection must survive a cancellation')
})

test('a signal that is already aborted never starts the command', async () => {
  const controller = new AbortController()
  controller.abort()
  await assert.rejects(
    () => tools.ssh_exec.execute({ command: 'echo never' }, { signal: controller.signal }),
    /cancelled before it started/,
  )
})
test('machineInventory: alias hides the host from every tool that prints one', async () => {
  // One tool leaking the topology undoes the setting for the whole transcript:
  // the workspace listing and ssh_connect used to print user@host:port.
  // A dedicated server, so this test cannot disturb the shared one's teardown.
  const own = await startServer()
  const home2 = mkdtempSync(path.join(tmpdir(), 'dsh-lean-'))
  process.env.DSH_HOME = home2
  const leanTools = {}
  await apply({ tools: { register: (d) => { leanTools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 't',
    machineInventory: 'alias',
    hostKeyPolicy: 'tofu',
    allowPlaintextPassword: true,
    machines: { t: machineFor('t', own.port) },
  })
  try {
    const texts = [
      String((await leanTools.ssh_machines.execute({}, {})).text),
      String((await leanTools.ssh_workspace.execute({ action: 'list' }, {})).text),
      String((await leanTools.ssh_connect.execute({ machine: 't' }, {})).text),
      String((await leanTools.ssh_doctor.execute({ machine: 't' }, {})).text),
    ]
    for (const text of texts) {
      assert.doesNotMatch(text, /127\.0\.0\.1/, text.slice(0, 120))
      // The setting hides host AND port (that is what ssh_machines promises), so
      // a probe line naming the port is a leak too.
      assert.ok(!new RegExp('(^|[^0-9])' + own.port + '([^0-9]|$)').test(text),
        'the port must not appear: ' + text.slice(0, 200))
    }
    assert.match(texts[2], /<host hidden>/, 'ssh_connect still names the target, without the address')
  } finally {
    await leanTools.ssh_close.execute({ force: true }, {})
    await own.close()
    rmSync(home2, { recursive: true, force: true })
  }
})
test('no tool output echoes the configured password', async () => {
  // The plugin's whole claim is that secrets stay out of the conversation. This
  // is the property, checked against a value nobody would type by accident.
  const CANARY = 'S3CRET-CANARY-42'
  const own = await startServer()
  const home2 = mkdtempSync(path.join(tmpdir(), 'dsh-canary-'))
  process.env.DSH_HOME = home2
  const canaryTools = {}
  await apply({ tools: { register: (d) => { canaryTools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 't',
    hostKeyPolicy: 'tofu',
    auditLog: true,
    machines: { t: { ...machineFor('t', own.port), password: 'wrong-password-for-the-canary' } },
  })
  const outputs = []
  const run = async (name, args = {}) => {
    try { outputs.push(String((await canaryTools[name].execute(args, {})).text)) }
    catch (err) { outputs.push(String(err.message)) }
  }
  try {
    await run('ssh_machines')
    await run('ssh_config')
    await run('ssh_credentials')
    await run('ssh_doctor')
    await run('ssh_connect')
    await run('ssh_exec', { command: 'echo hi' })
    await run('ssh_audit')
    for (const text of outputs) {
      assert.ok(!text.includes(CANARY), 'a tool output echoed the password: ' + text.slice(0, 120))
      assert.ok(!text.includes('wrong-password-for-the-canary'), 'the settings password appears in output: ' + text.slice(0, 120))
    }
    // The audit file is on disk in the isolated home: it must not hold it either.
    const auditFile = path.join(home2, 'dsh-ssh-safe', 'audit.ndjson')
    if (existsSync(auditFile)) {
      const auditText = readFileSync(auditFile, 'utf8')
      assert.ok(!auditText.includes(CANARY))
      assert.ok(!auditText.includes('wrong-password-for-the-canary'))
    }
  } finally {
    await canaryTools.ssh_close.execute({ force: true }, {})
    await own.close()
    rmSync(home2, { recursive: true, force: true })
  }
})
test('machineInventory: alias hides the address in a failed connection too', async () => {
  const tools2 = {}
  const home3 = mkdtempSync(path.join(tmpdir(), 'dsh-lean2-'))
  process.env.DSH_HOME = home3
  await apply({ tools: { register: (d) => { tools2[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 'dead',
    machineInventory: 'alias',
    hostKeyPolicy: 'tofu',
    connectTimeoutMs: 1000,
    allowPlaintextPassword: true,
    // 127.0.0.1 with nothing listening: the failure message is the one under test.
    machines: { dead: { host: '127.0.0.1', port: 1, user: 'root', password: 'p' } },
  })
  try {
    await assert.rejects(
      () => tools2.ssh_exec.execute({ command: 'echo hi' }, {}),
      (err) => {
        assert.doesNotMatch(err.message, /127\.0\.0\.1/, 'the address must not appear: ' + err.message)
        assert.match(err.message, /machine "dead" \(address hidden\)/)
        return true
      },
    )
  } finally {
    await tools2.ssh_close.execute({ force: true }, {})
    rmSync(home3, { recursive: true, force: true })
  }
})
test('a file path with a trailing slash is refused, not silently used', async () => {
  srv.vfs.putFile('/etc/keep.txt', 'precious')
  await assert.rejects(
    () => run('ssh_write', { path: '/etc/keep.txt/', content: 'x' }),
    (err) => {
      assert.match(err.message, /names a directory, not a file/)
      return true
    },
  )
  assert.equal(srv.vfs.getFile('/etc/keep.txt').toString(), 'precious', 'the file must be untouched')
  // A listing still accepts the directory spelling.
  const listed = await run('ssh_list', { path: '/etc/' })
  assert.match(listed, /keep\.txt/)
})
test('ssh_write reports the mode and refuses a mode that is not octal digits', async () => {
  const text = await run('ssh_write', { path: '/tmp/mode-note.txt', content: 'x', mode: '600' })
  assert.match(text, /Wrote 1 byte to \/tmp\/mode-note\.txt \(mode 0600\)/, text)
  assert.equal(srv.vfs.modeOf('/tmp/mode-note.txt'), 0o600)

  await assert.rejects(
    () => run('ssh_write', { path: '/tmp/mode-bad.txt', content: 'x', mode: '999' }),
    (err) => {
      assert.match(err.message, /mode must be octal digits like "600" or "0644"/)
      return true
    },
  )
})
test('ssh_doctor records its login, and alias mode keeps the host out of the log', async () => {
  const own = await startServer()
  const home2 = mkdtempSync(path.join(tmpdir(), 'dsh-doctor-audit-'))
  process.env.DSH_HOME = home2
  const doctorTools = {}
  await apply({ tools: { register: (d) => { doctorTools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 'good',
    hostKeyPolicy: 'tofu',
    allowPlaintextPassword: true,
    auditLog: true,
    machineInventory: 'alias',
    machines: {
      good: machineFor('good', own.port),
      bad: { ...machineFor('bad', own.port), password: 'wrong' },
    },
  })
  try {
    await doctorTools.ssh_doctor.execute({ machine: 'good' }, {})
    await doctorTools.ssh_doctor.execute({ machine: 'bad' }, {})
    const lines = readFileSync(path.join(home2, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8').trim().split('\n')
    const records = lines.map((line) => JSON.parse(line))
    const doctor = records.filter((r) => r.kind === 'doctor')
    assert.equal(doctor.length, 2, 'every doctor run is recorded: ' + JSON.stringify(records))
    assert.deepEqual(doctor.map((r) => r.outcome).sort(), ['error', 'ok'])
    const whole = lines.join('\n')
    assert.ok(!whole.includes(String(own.port)), 'the audit log holds the port under alias mode')
    assert.ok(!whole.includes('127.0.0.1'), 'the audit log holds the host under alias mode')
    const shown = String((await doctorTools.ssh_audit.execute({}, {})).text)
    assert.ok(!shown.includes(String(own.port)), 'ssh_audit shows the port under alias mode')
  } finally {
    await doctorTools.ssh_close.execute({ force: true }, {})
    await own.close()
    rmSync(home2, { recursive: true, force: true })
  }
})

test('a mode that could not be applied says so instead of staying silent', async () => {
  // mode is only applied when the file is created. Writing an existing script
  // with mode 700 left it 0644, and the only clue was a four-digit number the
  // caller had to compare with what they asked for.
  srv.vfs.putFile('/tmp/script.sh', 'old', 0o644)
  const existing = await tools.ssh_write.execute({ machine: 't', path: '/tmp/script.sh', content: 'new', mode: '700' }, {})
  assert.match(existing.text, /asked for 0700/)
  assert.match(existing.text, /already existed/)

  const fresh = await tools.ssh_write.execute({ machine: 't', path: '/tmp/new.sh', content: 'new', mode: '700', createDirs: true }, {})
  assert.match(fresh.text, /mode 0700/)
  assert.doesNotMatch(fresh.text, /asked for/, 'a new file gets what was asked for')

  const plain = await tools.ssh_write.execute({ machine: 't', path: '/tmp/script.sh', content: 'again' }, {})
  assert.doesNotMatch(plain.text, /asked for/, 'no mode, no note')
})

test('a NUL byte in a command is refused instead of being sent', async () => {
  // Measured before the fix: the command went to the channel as-is and the tool
  // reported 'ran: echo a b [exit 0]'. A shell truncates at the NUL, so what
  // would run is not what was sent. Paths already refused one.
  await assert.rejects(
    () => tools.ssh_exec.execute({ machine: 't', command: 'echo a\u0000b' }, {}),
    (err) => {
      assert.match(err.message, /contains a NUL byte/)
      assert.match(err.message, /truncates the command/)
      assert.ok(!err.message.includes('\u0000'), 'the message must not carry the byte itself')
      return true
    },
  )
})

test('a blank argument says it is blank, not missing', async () => {
  // 'path is required' for a path of spaces sent the caller looking for a
  // missing argument they had passed.
  await assert.rejects(
    () => tools.ssh_read.execute({ machine: 't', path: '   ' }, {}),
    /path is blank/
  )
  await assert.rejects(
    () => tools.ssh_exec.execute({ machine: 't', command: '\n' }, {}),
    /command is blank/
  )
  // A truly missing argument still says required.
  await assert.rejects(() => tools.ssh_exec.execute({ machine: 't', command: '' }, {}), /command is required/)
})

test('a write through a symlinked directory lands where the server put it', async () => {
  // The fake server created the entry at the literal path, so a write through
  // '/linkdir/new.txt' reported success and then nothing could read the bytes:
  // follow() sent every later read to /real/dir/new.txt. A real server resolves
  // the intermediate link, so the file has to land there.
  srv.vfs.putDir('/realdir/sub')
  srv.vfs.putLink('/dirlink', '/realdir')

  const wrote = await tools.ssh_write.execute({ machine: 't', path: '/dirlink/new.txt', content: 'hello' }, {})
  assert.match(String(wrote.text), /Wrote 5 bytes/)
  assert.equal(srv.vfs.getFile('/realdir/new.txt').toString(), 'hello')

  // Readable through either path afterwards.
  const viaLink = await tools.ssh_read.execute({ machine: 't', path: '/dirlink/new.txt' }, {})
  assert.match(String(viaLink.text), /hello/)
  const viaReal = await tools.ssh_read.execute({ machine: 't', path: '/realdir/new.txt' }, {})
  assert.match(String(viaReal.text), /hello/)

  // createDirs through the link creates the directory at the target too.
  const nested = await tools.ssh_write.execute({ machine: 't', path: '/dirlink/sub/deep.txt', content: 'x', createDirs: true }, {})
  assert.match(String(nested.text), /Wrote 1 byte/)
  assert.equal(srv.vfs.getFile('/realdir/sub/deep.txt').toString(), 'x')
})

test('a binary file says it is binary instead of posing as text', async () => {
  // The bytes are always decoded as UTF-8, so a PNG arrived as replacement
  // characters and NULs with nothing to say it was not the file's text.
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0xff, 0xfe, 0xfd])
  srv.vfs.putFile('/tmp/photo.png', png)
  const binary = await tools.ssh_read.execute({ machine: 't', path: '/tmp/photo.png' }, {})
  assert.match(String(binary.text), /\[binary file: 13 bytes decoded as UTF-8/)

  // Text that merely contains a stray replacement character is not binary.
  srv.vfs.putFile('/tmp/notes.txt', 'hello 中文 world')
  const text = await tools.ssh_read.execute({ machine: 't', path: '/tmp/notes.txt' }, {})
  assert.doesNotMatch(String(text.text), /\[binary file/)
  assert.match(String(text.text), /hello 中文 world/)
})

test('the binary heuristic keeps ordinary text out of it', () => {
  assert.equal(looksBinary('hello world').binary, false)
  assert.equal(looksBinary('中文内容，正常读取').binary, false)
  assert.equal(looksBinary('🙂 emoji text').binary, false)
  assert.equal(looksBinary('').binary, false)
  assert.equal(looksBinary('one \uFFFD stray').binary, false, 'a single stray byte is not a binary file')
  assert.equal(looksBinary('\uFFFDPNG\u0000\u0000').binary, true)
})

test('the doctor does not call an unverified host key ok', async () => {
  // With hostKeyPolicy: off the key is never checked, yet the report said
  // '[ok] host key: SHA256:...', which reads as verified.
  const off = {}
  await apply({ tools: { register: (d) => { off[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 't', hostKeyPolicy: 'off', allowPlaintextPassword: true,
    connectTimeoutMs: 4000, commandTimeoutMs: 4000,
    machines: { t: { host: '127.0.0.1', port: srv.port, user: 'tester', password: 'test-pass' } },
  })
  const text = String((await off.ssh_doctor.execute({ machine: 't' }, {})).text)
  assert.match(text, /\[warn\] host key: NOT verified: hostKeyPolicy is "off"/)
  assert.doesNotMatch(text, /\[ok\] host key/)
  await off.ssh_close.execute({ machine: 't', force: true }, {})
})

test('the doctor says when its own run recorded the key', async () => {
  const tofu = {}
  await apply({ tools: { register: (d) => { tofu[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
    connectTimeoutMs: 4000, commandTimeoutMs: 4000,
    machines: { t: { host: '127.0.0.1', port: srv.port, user: 'tester', password: 'test-pass' } },
  })
  const first = String((await tofu.ssh_doctor.execute({ machine: 't' }, {})).text)
  assert.match(first, /\[ok\] host key: SHA256:[^ ]+ \(first contact: recorded now\)/)
  await tofu.ssh_close.execute({ machine: 't', force: true }, {})
  const second = String((await tofu.ssh_doctor.execute({ machine: 't' }, {})).text)
  assert.doesNotMatch(second, /first contact/)
  await tofu.ssh_close.execute({ machine: 't', force: true }, {})
})

test('trustHostKey retries past the cooldown the rejection just started', async () => {
  // The host-key error says to call ssh_connect with trustHostKey: true, and the
  // rejection that produced it also starts a reconnect cooldown, so the advice
  // used to fail for the next minute. A fresh server on a fresh port keeps the
  // key unknown to this run's store.
  const other = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'fresh', hostKeyPolicy: 'strict', allowPlaintextPassword: true,
      connectTimeoutMs: 4000, commandTimeoutMs: 4000, reconnectCooldownMs: 60000,
      machines: { fresh: { host: '127.0.0.1', port: other.port, user: 'tester', password: 'test-pass' } },
    })
    await assert.rejects(() => own.ssh_connect.execute({}, {}), /Unknown host|not in/)

    const trusted = await own.ssh_connect.execute({ trustHostKey: true }, {})
    assert.match(String(trusted.text), /Connected:/)
    assert.match(String(trusted.text), /Host key: SHA256:/)
    await own.ssh_close.execute({ machine: 'fresh', force: true }, {})

    // The next plain connect uses the record.
    const second = await own.ssh_connect.execute({}, {})
    assert.match(String(second.text), /Connected:/)
    await own.ssh_close.execute({ machine: 'fresh', force: true }, {})
  } finally {
    await other.close().catch(() => {})
  }
})

test('trustHostKey does not override a changed key', async () => {
  // One-shot trust is for FIRST contact. A changed key means something else is
  // answering, and accepting it because the caller repeated trustHostKey would be
  // the interception this store exists to catch.
  const first = await startServer()
  const own = {}
  await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 'chg', hostKeyPolicy: 'strict', allowPlaintextPassword: true,
    connectTimeoutMs: 4000, commandTimeoutMs: 4000, reconnectCooldownMs: 0,
    machines: { chg: { host: '127.0.0.1', port: first.port, user: 'tester', password: 'test-pass' } },
  })
  await own.ssh_connect.execute({ trustHostKey: true }, {})
  await own.ssh_close.execute({ machine: 'chg', force: true }, {})
  await first.close()

  const second = await startServer({ port: first.port, key: alternateHostKey() })
  try {
    await assert.rejects(() => own.ssh_connect.execute({ trustHostKey: true }, {}), /HOST KEY CHANGED/)
  } finally {
    await second.close().catch(() => {})
  }
})

test('ssh_list pages through a directory larger than the row cap', async () => {
  // maxListEntries is a config value, so before the offset argument a directory
  // with more entries than the cap could never be read past the first page.
  const own = {}
  await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
    connectTimeoutMs: 4000, commandTimeoutMs: 4000, maxListEntries: 3,
    machines: { t: { host: '127.0.0.1', port: srv.port, user: 'tester', password: 'test-pass' } },
  })
  srv.vfs.putDir('/tmp/page')
  for (let i = 0; i < 7; i++) srv.vfs.putFile('/tmp/page/p' + i + '.txt', 'x')

  const first = String((await own.ssh_list.execute({ machine: 't', path: '/tmp/page' }, {})).text)
  assert.match(first, /p0\.txt/)
  assert.match(first, /4 more entries not shown \(maxListEntries = 3\) — pass offset: 3 to continue/)

  const second = String((await own.ssh_list.execute({ machine: 't', path: '/tmp/page', offset: 3 }, {})).text)
  assert.match(second, /3 entries above not shown \(offset = 3\)/)
  assert.match(second, /p3\.txt/)
  assert.doesNotMatch(second, /p0\.txt/)

  // Past the end is not an error, but it must not claim the directory is empty.
  const past = String((await own.ssh_list.execute({ machine: 't', path: '/tmp/page', offset: 99 }, {})).text)
  assert.match(past, /offset 99 is past the last of 7 entries/)
  await assert.rejects(() => own.ssh_list.execute({ machine: 't', path: '/tmp/page', offset: -1 }, {}), /offset must be 0 or more/)
  await own.ssh_close.execute({ machine: 't', force: true }, {})
})

test('cancelling a call stops the dial, not just the operation', async () => {
  // Aborting ssh_connect during a stalled handshake waited out the whole
  // connectTimeoutMs (measured: 8s for an 8s timeout with the abort at 300ms).
  // A port that accepts TCP and never sends a banner is what that looks like.
  const net = await import('node:net')
  const silent = net.createServer(() => {})
  await new Promise((resolve) => silent.listen(0, '127.0.0.1', resolve))
  const port = silent.address().port
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-cancelfit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const own = {}
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'silent', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
      connectTimeoutMs: 6000, commandTimeoutMs: 6000, sftpTimeoutMs: 6000, reconnectCooldownMs: 0,
      machines: { silent: { host: '127.0.0.1', port, user: 'tester', password: 'pw' } },
    })
    const cancelAfter = (ms) => { const controller = new AbortController(); setTimeout(() => controller.abort(), ms); return controller.signal }
    const calls = [
      ['ssh_connect', () => own.ssh_connect.execute({}, { signal: cancelAfter(250) })],
      ['ssh_exec', () => own.ssh_exec.execute({ command: 'echo hi' }, { signal: cancelAfter(250) })],
      ['ssh_list', () => own.ssh_list.execute({ path: '/tmp' }, { signal: cancelAfter(250) })],
    ]
    for (const [label, call] of calls) {
      const started = Date.now()
      await assert.rejects(call, /was cancelled/)
      const elapsed = Date.now() - started
      assert.ok(elapsed < 2000, label + ' waited ' + elapsed + 'ms instead of stopping at the abort')
    }
  } finally {
    silent.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('an empty file says it is empty instead of returning nothing', async () => {
  // An empty tool result is ambiguous: an empty file, or a read that returned
  // nothing for a reason the caller cannot see. 'ssh_list' already answers
  // '(empty directory: …)'.
  srv.vfs.putFile('/tmp/zero.txt', '')
  const text = String((await tools.ssh_read.execute({ machine: 't', path: '/tmp/zero.txt' }, {})).text)
  assert.match(text, /\(empty file: \/tmp\/zero\.txt — 0 bytes\)/)

  // A file holding only a newline is not empty and must come back as content.
  srv.vfs.putFile('/tmp/newline.txt', '\n')
  const blank = String((await tools.ssh_read.execute({ machine: 't', path: '/tmp/newline.txt' }, {})).text)
  assert.equal(blank, '\n')
})

test('an audit record says a signal killed the command, not that it exited', async () => {
  // 'outcome: exit' with no code made a SIGKILL look like an exit whose status
  // went missing, and the record carried no signal at all.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-audsig-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const own = {}
    const srv2 = await startServer()
    try {
      await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
        defaultMachine: 's', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, auditLog: true,
        connectTimeoutMs: 4000, commandTimeoutMs: 4000,
        machines: { s: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
      })
      await own.ssh_exec.execute({ machine: 's', command: 'kill' }, {}).catch(() => {})
      const records = readFileSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8')
        .split('\n').filter(Boolean).map((line) => JSON.parse(line))
      const killed = records.find((record) => record.command === 'kill')
      assert.equal(killed.outcome, 'signal')
      assert.equal(killed.signal, 'SIGKILL')
      assert.equal(killed.exitCode, null, 'a signal death has no exit code')

      const shown = String((await own.ssh_audit.execute({ limit: 5 }, {})).text)
      assert.match(shown, /signal=SIGKILL/)
    } finally {
      await own.ssh_close.execute({ machine: 's', force: true }, {}).catch(() => {})
      await srv2.close()
    }
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a mode that the server did not apply says so for a new file too', async () => {
  // The note used to claim 'the file already existed' whenever the modes
  // differed, which is a guess — and '4755' dropped its setuid bit without a word.
  srv.vfs.putDir('/tmp')
  const result = await tools.ssh_write.execute(
    { machine: 't', path: '/tmp/suid.sh', content: '#!/bin/sh', mode: '4755' },
    {},
  )
  const text = String(result.text)
  assert.match(text, /asked for 4755/)
  assert.match(text, /the server applies its umask/)
  assert.doesNotMatch(text, /the file already existed, so it kept/)
})

test('stderr survives a budget that stdout already used up', async () => {
  // The 'make' case: thousands of lines on stdout, then the one line that says
  // what went wrong. The reserve existed but nothing exercised it end to end.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-tailerrfit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const srv2 = await startServer()
    const own = {}
    try {
      await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
        defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, maxOutputChars: 1024,
        connectTimeoutMs: 4000, commandTimeoutMs: 4000,
        machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
      })
      const text = String((await own.ssh_exec.execute({ machine: 't', command: 'tailerr 5000' }, {})).text)
      assert.match(text, /\[stderr\]/)
      assert.match(text, /ERROR: the reason it failed/)
      assert.match(text, /\[exit 2\]/)
      assert.match(text, /output truncated at maxOutputChars: \d+ more characters were dropped/)
      // The cap applies to the command output, not to the notes explaining it:
      // count only the characters the command produced.
      // The leading run only: the notes themselves contain letters 'x'.
      const stderrKept = text.includes('ERROR: the reason it failed') ? 'ERROR: the reason it failed\n'.length : 0
      const produced = (text.match(/^x+/) || [''])[0].length + stderrKept
      assert.ok(produced <= 1024, 'the output itself must fit the budget: ' + produced)
      assert.ok(produced > 900, 'the budget should be used, not wasted: ' + produced)
    } finally {
      await own.ssh_close.execute({ machine: 't', force: true }, {}).catch(() => {})
      await srv2.close()
    }
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('both streams present says the order between them is not guaranteed', async () => {
  // ssh2 gives stdout and stderr as two Readables: 'echo one; echo two >&2; echo
  // three' arrives as two blocks, so [stderr] can look like it came last.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-ordernote-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const srv2 = await startServer()
    const own = {}
    try {
      await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
        defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
        connectTimeoutMs: 4000, commandTimeoutMs: 4000,
        machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
      })
      const both = String((await own.ssh_exec.execute({ machine: 't', command: 'stderr' }, {})).text)
      assert.match(both, /\[stderr\]/)
      assert.match(both, /does not preserve the order between them/)

      // One stream only: no note, nothing to qualify.
      const one = String((await own.ssh_exec.execute({ machine: 't', command: 'echo hi' }, {})).text)
      assert.doesNotMatch(one, /does not preserve the order/)
    } finally {
      await own.ssh_close.execute({ machine: 't', force: true }, {}).catch(() => {})
      await srv2.close()
    }
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('every refused call is in the audit log, and the row names the rule', async () => {
  // The confirmation gate refused in silence: only deny-pattern refusals were
  // recorded, and their rows said 'matches deny pattern' without saying which.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-audref-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const srv2 = await startServer()
    try {
      const own = {}
      await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
        defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
        execGuard: 'confirm', auditLog: true,
        connectTimeoutMs: 4000, commandTimeoutMs: 4000,
        machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
      })
      await own.ssh_exec.execute({ machine: 't', command: 'echo gated' }, {}).catch(() => {})
      await own.ssh_write.execute({ machine: 't', path: '/tmp/x', content: 'x' }, {}).catch(() => {})
      await own.ssh_read.execute({ machine: 't', path: '/tmp/x' }, {}).catch(() => {})
      await own.ssh_exec.execute({ machine: 't', command: 'rm -rf /', confirm: true }, {}).catch(() => {})

      const shown = String((await own.ssh_audit.execute({ limit: 10 }, {})).text)
      const refusals = shown.split('\n').filter((line) => line.includes(' refused '))
      assert.equal(refusals.length, 4, 'every refusal is recorded: ' + shown)
      assert.match(shown, /rule: it deletes the filesystem root/)
      assert.match(shown, /write to/)
      assert.match(shown, /read from/)
    } finally {
      await srv2.close()
    }
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a timeout says the command was TERMed and may still be running', async () => {
  // The cancel path said so; the deadline path said only 'timed out', which reads
  // as 'the remote process stopped'.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-tonote-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const srv2 = await startServer()
    const own = {}
    try {
      await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
        defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
        connectTimeoutMs: 4000, commandTimeoutMs: 4000,
        machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
      })
      const text = String((await own.ssh_exec.execute({ machine: 't', command: 'sleep 3', timeoutMs: 300 }, {})).text)
      assert.match(text, /timed out after 300ms/)
      assert.match(text, /was sent SIGTERM/)
      assert.match(text, /ignores SIGTERM can still be running/)
    } finally {
      await own.ssh_close.execute({ machine: 't', force: true }, {}).catch(() => {})
      await srv2.close()
    }
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('the audit log records the end of a connection too', async () => {
  // connect, exec and doctor were recorded; close was not, so a log never showed
  // that a session ended, or that a close was refused because a command was
  // still running.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-audclose-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const srv2 = await startServer()
    const own = {}
    try {
      await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
        defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, auditLog: true,
        connectTimeoutMs: 4000, commandTimeoutMs: 4000,
        machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
      })
      await own.ssh_exec.execute({ machine: 't', command: 'echo x' }, {})

      // Refused because a command is running.
      const running = own.ssh_exec.execute({ machine: 't', command: 'sleep 1' }, {})
      await new Promise((resolve) => setTimeout(resolve, 150))
      await own.ssh_close.execute({ machine: 't' }, {})
      await running.catch(() => {})
      await own.ssh_close.execute({ machine: 't', force: true }, {})

      const records = readFileSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8')
        .split('\n').filter(Boolean).map((line) => JSON.parse(line))
      const closes = records.filter((record) => record.kind === 'close')
      assert.equal(closes.length, 2, 'both close calls are recorded')
      assert.equal(closes[0].outcome, 'busy')
      assert.equal(closes[0].forced, undefined)
      assert.equal(closes[1].outcome, 'ok')
      assert.equal(closes[1].forced, true)
    } finally {
      await own.ssh_close.execute({ machine: 't', force: true }, {}).catch(() => {})
      await srv2.close()
    }
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a ceiling exceeded while a command ran is enforced once it is idle again', async () => {
  // Only a NEW connection evicted, so reusing an alias left maxConnections-1
  // sockets open indefinitely (measured: maxConnections 1 kept 2 after both idle).
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-maxcfit-'))
  const srv2 = await startServer()
  const pool = new SshPool({
    hostKeyPolicy: 'tofu', allowPlaintextPassword: true, connectTimeoutMs: 4000,
    commandTimeoutMs: 4000, reconnectCooldownMs: 0, maxConnections: 1,
    machines: { a: machineFor('a', srv2.port), b: machineFor('b', srv2.port) },
  }, { dshHome: home })
  try {
    // a runs a command; b is used meanwhile, so both are connected at once.
    const slow = pool.exec('a', 'sleep 0.4', {})
    await new Promise((resolve) => setTimeout(resolve, 120))
    await pool.exec('b', 'echo b', {})
    assert.equal(srv2.clientCount(), 2, 'the busy connection is protected')
    await slow

    // Both idle now: the next acquire trims back to the ceiling.
    await pool.exec('b', 'echo again', {})
    assert.equal(srv2.clientCount(), 1, 'the ceiling is enforced again')
  } finally {
    await pool.closeAll({ force: true })
    await srv2.close()
    rmSync(home, { recursive: true, force: true })
  }
})

test('the cooldown advice names an option the caller actually has', async () => {
  // ssh_exec said 'Pass force: true to try immediately' and ssh_exec has no force
  // argument, so the way out it described did not exist in the tool printing it.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-cooldfit-'))
  const srv2 = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 30000,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'wrong-on-purpose' } },
    })
    await own.ssh_exec.execute({ machine: 't', command: 'echo hi' }, {}).catch(() => {})
    const message = await own.ssh_exec.execute({ machine: 't', command: 'echo hi' }, {})
      .then(() => '', (err) => String(err.message))
    assert.match(message, /Refusing to retry t for another 30s/)
    assert.match(message, /ssh_connect accepts force: true/)
    assert.match(message, /do not have a force option/)
    assert.doesNotMatch(message, /^.*Pass force: true to try immediately, or trustHostKey/m)
  } finally {
    await own.ssh_close?.execute?.({}, {})
    await srv2.close()
    rmSync(home, { recursive: true, force: true })
  }
})

test('the doctor names a passphrase-protected key before dialling', async () => {
  // The header check passed, so the doctor said [ok] credentials and the failure
  // only appeared after the TCP step, filed under 'connect'.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-dockeyfit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  const own = {}
  try {
    const { private: encrypted } = ssh2.utils.generateKeyPairSync('rsa', { bits: 2048, passphrase: 'right-pass', cipher: 'aes256-cbc' })
    const keyPath = path.join(home, 'id_encrypted')
    writeFileSync(keyPath, encrypted, { mode: 0o600 })
    const build = async (machine) => {
      const tools = {}
      await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
        defaultMachine: 'k', hostKeyPolicy: 'tofu', reconnectCooldownMs: 0,
        connectTimeoutMs: 2000, commandTimeoutMs: 2000,
        machines: { k: { host: '127.0.0.1', port: srv2.port, user: 'tester', ...machine } },
      })
      return tools
    }

    const none = String((await (await build({ keyPath })).ssh_doctor.execute({ machine: 'k' }, {})).text)
    assert.match(none, /\[FAIL\] credentials: the private key .* is passphrase-protected/)
    assert.match(none, /set keyPassphrase/)
    assert.doesNotMatch(none, /accepts connections/, 'no dial is needed to say this')

    const wrong = String((await (await build({ keyPath, keyPassphrase: 'nope' })).ssh_doctor.execute({ machine: 'k' }, {})).text)
    assert.match(wrong, /\[FAIL\] credentials: .*could not be parsed/i)

    const right = String((await (await build({ keyPath, keyPassphrase: 'right-pass' })).ssh_doctor.execute({ machine: 'k' }, {})).text)
    assert.match(right, /\[ok\] credentials: config-key/)
  } finally {
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('the truncation advice names the ceiling that actually applied', async () => {
  // The note always said 'raise maxFileBytes', which does nothing when the call's
  // own maxBytes was the tighter cap.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-capnote-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  const own = {}
  try {
    srv2.vfs.putDir('/tmp')
    srv2.vfs.putFile('/tmp/f.txt', 'A'.repeat(2048))
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
      connectTimeoutMs: 4000, commandTimeoutMs: 4000, maxFileBytes: 1024,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })

    const byConfig = String((await own.ssh_read.execute({ machine: 't', path: '/tmp/f.txt' }, {})).text)
    assert.match(byConfig, /raise maxFileBytes in the plugin config/)
    assert.doesNotMatch(byConfig, /raise maxBytes in this call/)

    const byMaxBytes = String((await own.ssh_read.execute({ machine: 't', path: '/tmp/f.txt', maxBytes: 10 }, {})).text)
    assert.match(byMaxBytes, /first 10 bytes/)
    assert.match(byMaxBytes, /raise maxBytes in this call/,
      'advice must name the cap that applied: ' + byMaxBytes.slice(0, 160))
  } finally {
    await own.ssh_close.execute({}, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('credentials, doctor and the audit trail escape what the config supplies', async () => {
  // The inventory was fixed first; these three still printed a host, user or
  // command verbatim, so an escape sequence or bidi override in a config file
  // repainted whatever the operator was reading.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-esc3-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  const own = {}
  const ESC = '\u001b'
  const RLO = '\u202e'
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, auditLog: true,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: {
        t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' },
        hostile: { host: 'h' + ESC + '[31mevil' + RLO + 'x.example', port: 22, user: 'u' + ESC + 'v' },
      },
    })

    const creds = String((await own.ssh_credentials.execute({}, {})).text)
    assert.ok(creds.includes('h\\x1b[31mevil\\u202ex.example'), creds.slice(0, 200))
    assert.doesNotMatch(creds, /\u001b/)
    assert.doesNotMatch(creds, /\u202e/)

    const doc = String((await own.ssh_doctor.execute({ machine: 'hostile' }, {})).text)
    assert.match(doc, /\[ok\] configuration: u\\x1bv@h\\x1b\[31mevil\\u202ex\.example:22/)
    assert.doesNotMatch(doc, /\u001b/)

    await own.ssh_exec.execute({ machine: 't', command: 'echo hi' + ESC + '[31mred' }, {})
    const audit = String((await own.ssh_audit.execute({ limit: 5 }, {})).text)
    assert.ok(audit.includes('echo hi\\x1b[31mred'), audit.slice(0, 200))
    assert.doesNotMatch(audit, /\u001b/)
  } finally {
    await own.ssh_close.execute({}, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})
