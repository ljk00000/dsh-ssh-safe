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
  assert.match(text, /\[timed out after 250ms\]/)
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
  assert.match(text, /\[output truncated at maxOutputChars: \d+ more characters were dropped/)
    assert.match(text, /raise maxOutputChars, or send the output to a file/)
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
