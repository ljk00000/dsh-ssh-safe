import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import net from 'node:net'

import { apply } from '../src/index.js'
import { looksBinary } from '../src/sftp.js'
import { SshPool } from '../src/pool.js'
import ssh2 from 'ssh2'
import { startServer, machineFor, alternateHostKey, testHostKey, testKeyPair } from './helpers/local-ssh-server.js'

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
test('maxFileBytes counts UTF-8 bytes, not characters', async () => {
  // A naive content.length check would allow three times too much for CJK text.
  // This fixture allows 1 MiB, so 349,525 characters (1,048,575 bytes) fit and
  // 350,000 (1,050,000 bytes) do not — same character count shape, different bytes.
  srv.vfs.putDir('/mb')
  const fits = '汉'.repeat(349525)
  const allowed = await run('ssh_write', { path: '/mb/fits.txt', content: fits })
  assert.match(allowed, /Wrote 1048575 bytes/)
  assert.equal(srv.vfs.getFile('/mb/fits.txt').length, 1048575)
  await assert.rejects(
    () => run('ssh_write', { path: '/mb/too-big.txt', content: '汉'.repeat(350000) }),
    /Refusing to write 1050000 bytes \(maxFileBytes = 1048576\)/,
  )
  assert.equal(srv.vfs.getFile('/mb/too-big.txt'), undefined, 'nothing may be written')
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
  assert.ok(elapsed < 45000, 'ten thousand entries should not take that long: ' + elapsed + 'ms')
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
    // Every tool that reaches the host: a single leak undoes the setting for the
    // whole transcript, and only four of them were checked here.
    const lean = (name, args) => leanTools[name].execute(args, {})
    await lean('ssh_exec', { machine: 't', command: 'echo lean' })
    await lean('ssh_read', { machine: 't', path: '/lean-guard.txt' }).catch(() => {})
    await lean('ssh_write', { machine: 't', path: '/lean-guard.txt', content: 'x' }).catch(() => {})
    await lean('ssh_list', { machine: 't', path: '/' })
    const texts = [
      String((await lean('ssh_machines', {})).text),
      String((await lean('ssh_workspace', { action: 'list' }, {})).text),
      String((await lean('ssh_connect', { machine: 't' }, {})).text),
      String((await lean('ssh_doctor', { machine: 't' }, {})).text),
      String((await lean('ssh_credentials', {}, {})).text),
      String((await lean('ssh_config', {}, {})).text),
      String((await lean('ssh_audit', { limit: 20 }, {})).text),
      String((await lean('ssh_exec', { machine: 't', command: 'echo again' }, {})).text),
      String((await lean('ssh_list', { machine: 't', path: '/' }, {})).text),
      String((await lean('ssh_read', { machine: 't', path: '/lean-guard.txt' }, {})).text),
      String((await lean('ssh_close', { machine: 't', force: true }, {})).text),
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



test('a key trusted against an OpenSSH known_hosts says it was not recorded', async () => {
  // The file is verified but never written, so trustHostKey accepts the key for
  // this connection only. The reply used to look like any other success, and the
  // next plain connect failed with the same 'Unknown host'.
  const home2 = mkdtempSync(path.join(tmpdir(), 'dsh-readonlytrust-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home2
  try {
    const srv2 = await startServer()
    const knownHosts = path.join(home2, 'kh')
    writeFileSync(knownHosts, '# empty\n', 'utf8')
    const own = {}
    try {
      await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
        defaultMachine: 't', hostKeyPolicy: 'strict', allowPlaintextPassword: true, reconnectCooldownMs: 0,
        connectTimeoutMs: 4000, commandTimeoutMs: 4000,
        machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass', knownHosts } },
      })
      const shown = String((await own.ssh_connect.execute({ machine: 't', trustHostKey: true }, {})).text)
      assert.match(shown, /\[note\] that key was accepted for this connection only/)
      assert.match(shown, /ssh-keyscan -p \d+ 127\.0\.0\.1 >>/)
      // The path is local config, not remote text: printable() escaped every
      // backslash, so a Windows path read as C:\\Users\\… (a different path).
      assert.ok(shown.includes(knownHosts), 'the note shows the path as it is: ' + shown.slice(0, 240))
      assert.equal(readFileSync(knownHosts, 'utf8'), '# empty\n', 'the file is not written')
      await own.ssh_close.execute({ force: true }, {})
      const again = await own.ssh_connect.execute({ machine: 't' }, {}).then((r) => String(r.text), (e) => 'ERR: ' + e.message)
      assert.match(again, /Unknown host/, 'the next connection asks again')
    } finally {
      await own.ssh_close.execute({ force: true }, {}).catch(() => {})
      await srv2.close()
    }
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home2, { recursive: true, force: true })
  }
})

test('the connect record says whether the host key was verified', async () => {
  // 'connect ok' could not answer the question the audit trail exists for: was
  // this session protected against a man-in-the-middle?
  const home2 = mkdtempSync(path.join(tmpdir(), 'dsh-audithostkey-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home2
  try {
    const srv2 = await startServer()
    const make = (policy) => {
      const own = {}
      return apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
        defaultMachine: 't', hostKeyPolicy: policy, allowPlaintextPassword: true, auditLog: true, reconnectCooldownMs: 0,
        connectTimeoutMs: 4000, commandTimeoutMs: 4000,
        machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
      }).then(() => own)
    }
    const records = () => readFileSync(path.join(home2, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8')
      .split('\n').filter(Boolean).map((line) => JSON.parse(line))
    try {
      const tofu = await make('tofu')
      await tofu.ssh_connect.execute({ machine: 't' }, {})
      await tofu.ssh_close.execute({ force: true }, {})
      await tofu.ssh_connect.execute({ machine: 't' }, {})
      await tofu.ssh_close.execute({ force: true }, {})
      const states = records().filter((r) => r.kind === 'connect').map((r) => r.hostKey)
      assert.deepEqual(states, ['first-seen', 'verified'])
      assert.match(records().find((r) => r.hostKey === 'verified').fingerprint, /^SHA256:/)

      const off = await make('off')
      await off.ssh_connect.execute({ machine: 't' }, {})
      const unverified = records().filter((r) => r.kind === 'connect').pop()
      assert.equal(unverified.hostKey, 'unverified', 'policy off is recorded as unverified')
      const shown = String((await off.ssh_audit.execute({}, {})).text)
      assert.match(shown, /host key first-seen/)
      assert.match(shown, /host key verified/)
      assert.match(shown, /host key unverified/)
      await off.ssh_close.execute({ force: true }, {})
    } finally {
      await srv2.close()
    }
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home2, { recursive: true, force: true })
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

    // A maxBytes LARGER than the configured ceiling still leaves maxFileBytes in
    // charge: naming maxBytes there sends the caller to a knob they already went
    // past.
    const byBoth = String((await own.ssh_read.execute({ machine: 't', path: '/tmp/f.txt', maxBytes: 9000 }, {})).text)
    assert.match(byBoth, /first 1024 bytes/)
    assert.match(byBoth, /raise maxFileBytes in the plugin config/)
    assert.doesNotMatch(byBoth, /raise maxBytes in this call/)
  } finally {
    await own.ssh_close?.execute?.({}, {}).catch(() => {})
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

test('an error message escapes the remote path it echoes', async () => {
  // The path in 'no such file: …' came from the caller or from a listing, and it
  // was printed verbatim: an escape sequence there repainted the transcript.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-escerr-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  const own = {}
  const ESC = '\u001b'
  const RLO = '\u202e'
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    const nasty = '/tmp/' + ESC + '[31mevil' + RLO + 'name.txt'
    const missing = await own.ssh_read.execute({ machine: 't', path: nasty }, {})
      .then(() => '', (err) => String(err.message))
    assert.match(missing, /no such file: \/tmp\/\\x1b\[31mevil\\u202ename\.txt/, missing)
    assert.doesNotMatch(missing, /\u001b/)
    assert.doesNotMatch(missing, /\u202e/)
    // The same path through ssh_list and ssh_write.
    for (const call of [
      () => own.ssh_list.execute({ machine: 't', path: nasty }, {}),
      () => own.ssh_write.execute({ machine: 't', path: nasty + '/child', content: 'x' }, {}),
    ]) {
      const message = await call().then(() => '', (err) => String(err.message))
      assert.doesNotMatch(message, /\u001b/, message)
      assert.match(message, /\\x1b/)
    }
  } finally {
    await own.ssh_close.execute({}, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a read in flight settles when the connection is force-closed', async () => {
  // The timeout path awaited a stat for the FIFO explanation. After a forced
  // close the session is gone, stat never answers, and the await kept the read
  // pending forever: still pending 12s after a 3s timeout.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-closeread-'))
  const srv2 = await startServer()
  const own = {}
  try {
    srv2.vfs.putDir('/tmp')
    srv2.vfs.putFile('/tmp/big.txt', 'y'.repeat(500))
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000, sftpTimeoutMs: 3000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    srv2.vfs.control.stallReads = true
    const read = own.ssh_read.execute({ machine: 't', path: '/tmp/big.txt' }, {})
    // The handler is attached before the close, which is what a tool does: a
    // rejection that lands while nobody is listening is reported by Node as an
    // unhandled rejection.
    const settled = read.then((r) => 'ok: ' + String(r.text).slice(0, 40), (err) => 'err: ' + String(err.message).slice(0, 90))
    await new Promise((resolve) => setTimeout(resolve, 200))
    await own.ssh_close.execute({ machine: 't', force: true }, {})
    const outcome = await Promise.race([
      settled,
      new Promise((resolve) => setTimeout(() => resolve('still pending'), 9000)),
    ])
    assert.notEqual(outcome, 'still pending', 'the read must settle after the connection is gone')
    // Force-close now aborts the transfer, so it stops at once instead of waiting
    // for sftpTimeoutMs; this pins the faster, more specific outcome.
    assert.match(outcome, /(was cancelled \(the connection was closed with force: true\)|is gone: it was closed while the operation was starting or running)/)
  } finally {
    srv2.vfs.control.stallReads = false
    await own.ssh_close.execute({}, {}).catch(() => {})
    await srv2.close()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a timed-out write does not claim previous content was destroyed on a new file', async () => {
  // 'so its previous content is gone' was printed for a file that never existed;
  // the server confirms size 0 either way, so the message names that state.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-wstate-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  const own = {}
  try {
    srv2.vfs.putDir('/tmp')
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000, sftpTimeoutMs: 1000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    srv2.vfs.control.stallWrites = true
    const message = await own.ssh_write.execute({ machine: 't', path: '/tmp/never.txt', content: 'x'.repeat(50) }, {})
      .then(() => '', (err) => String(err.message))
    assert.match(message, /so it is empty now/)
    assert.match(message, /if it existed before, that content is gone/)
    assert.equal(srv2.vfs.getFile('/tmp/never.txt').length, 0, 'the server has an empty file, as the message says')
  } finally {
    srv2.vfs.control.stallWrites = false
    await own.ssh_close.execute({}, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('the doctor does not call a regular file an SSH agent', async () => {
  // SSH_AUTH_SOCK pointing at a leftover file passed the credential step as
  // '[ok] credentials: agent' and the connection had nothing to authenticate with.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-agentfit-'))
  const previous = { home: process.env.DSH_HOME, sock: process.env.SSH_AUTH_SOCK }
  process.env.DSH_HOME = home
  const fake = path.join(home, 'agent.sock')
  writeFileSync(fake, 'not a socket')
  process.env.SSH_AUTH_SOCK = fake
  try {
    const own = {}
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', connectTimeoutMs: 2000, commandTimeoutMs: 2000,
      machines: { t: { host: 'h.example', user: 'u' } },
    })
    const text = String((await own.ssh_doctor.execute({ machine: 't' }, {})).text)
    assert.match(text, /\[FAIL\] credentials: the agent path .* is a file, not a socket/)
    assert.doesNotMatch(text, /\[ok\] credentials: agent/)

    // A missing path keeps its own message.
    process.env.SSH_AUTH_SOCK = path.join(home, 'missing.sock')
    const missing = String((await own.ssh_doctor.execute({ machine: 't' }, {})).text)
    assert.match(missing, /agent socket not found/)
  } finally {
    if (previous.home === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous.home
    if (previous.sock === undefined) delete process.env.SSH_AUTH_SOCK
    else process.env.SSH_AUTH_SOCK = previous.sock
    rmSync(home, { recursive: true, force: true })
  }
})

test('a failed audit write is reported instead of leaving a quiet hole', async () => {
  // failures was counted and never read: with the log path unwritable every
  // command still reported success and the trail silently lost the records.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-audfailfit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const dir = path.join(home, 'dsh-ssh-safe')
  mkdirSync(dir, { recursive: true })
  // A directory where the log file goes: every append fails with EISDIR.
  mkdirSync(path.join(dir, 'audit.ndjson'))
  const srv2 = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, auditLog: true,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    // The command still succeeds: auditing must never break an operation.
    const ran = await own.ssh_exec.execute({ machine: 't', command: 'echo works' }, {})
    assert.match(String(ran.text), /exit 0/)
    const text = String((await own.ssh_audit.execute({ limit: 5 }, {})).text)
    assert.match(text, /Warning: 1 audit write failed since the plugin started/)
    assert.match(text, /EISDIR/)
    assert.match(text, /incomplete/)
  } finally {
    await own.ssh_close?.execute?.({}, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('the doctor warns about audit records that were lost', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-auddoc-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const dir = path.join(home, 'dsh-ssh-safe')
  mkdirSync(dir, { recursive: true })
  mkdirSync(path.join(dir, 'audit.ndjson'))
  const srv2 = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, auditLog: true,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    await own.ssh_exec.execute({ machine: 't', command: 'echo x' }, {})
    const text = String((await own.ssh_doctor.execute({ machine: 't' }, {})).text)
    assert.match(text, /\[warn\] audit: 1 record could not be written/)
    assert.match(text, /is writable/)
  } finally {
    await own.ssh_close?.execute?.({}, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('the pool reports an exceeded ceiling only while it is exceeded for a reason', async () => {
  // overLimit came from the flag the last eviction set, so it stayed true after
  // the protected command finished and ssh_config explained a state that was gone.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-overfit-'))
  const srv2 = await startServer()
  const pool = new SshPool({
    hostKeyPolicy: 'tofu', allowPlaintextPassword: true, connectTimeoutMs: 4000,
    commandTimeoutMs: 4000, reconnectCooldownMs: 0, maxConnections: 1,
    machines: { a: machineFor('a', srv2.port), b: machineFor('b', srv2.port) },
  }, { dshHome: home })
  try {
    const slow = pool.exec('a', 'sleep 0.5', {})
    await new Promise((resolve) => setTimeout(resolve, 120))
    await pool.exec('b', 'echo b', {})
    assert.equal(pool.connectionStats().overLimit, true, 'busy connection justifies the excess')
    await slow
    assert.equal(pool.connectionStats().overLimit, false, 'nothing is busy any more')
  } finally {
    await pool.closeAll({ force: true })
    await srv2.close()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a trust record without a fingerprint is reported as not trusted', async () => {
  // 'trusted: undefined' (and 'trusted: ' for an empty string) claimed trust for a
  // record the check refuses with 'no usable fingerprint'.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-trustfit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const dir = path.join(home, 'dsh-ssh-safe')
  mkdirSync(dir, { recursive: true })
  writeFileSync(path.join(dir, 'known_hosts.json'), JSON.stringify({
    version: 1,
    hosts: {
      'a.example:22': { fingerprint: '' },
      'b.example:22': {},
      'c.example:22': { fingerprint: 'SHA256:abc' },
      'd.example:22': 'not an object',
    },
  }), 'utf8')
  try {
    const own = {}
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'a', hostKeyPolicy: 'tofu',
      machines: {
        a: { host: 'a.example', user: 'u' },
        b: { host: 'b.example', user: 'u' },
        c: { host: 'c.example', user: 'u' },
        d: { host: 'd.example', user: 'u' },
      },
    })
    const text = String((await own.ssh_machines.execute({}, {})).text)
    assert.doesNotMatch(text, /trusted: (undefined|)\s*\n/)
    const lines = text.split('\n').filter((line) => /trusted/.test(line))
    assert.equal(lines.filter((line) => /trusted: NO — the recorded entry has no usable fingerprint/.test(line)).length, 3, text)
    assert.match(text, /trusted: SHA256:abc/)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('the truncation note agrees with its own number', async () => {
  // '1 more character were dropped' — singular subject, plural verb. The number and
  // the verb now change together, and the boundary stays exact: a body of exactly
  // maxOutputChars is not truncated.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-plural-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
      connectTimeoutMs: 3000, commandTimeoutMs: 5000, maxOutputChars: 1024,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    const atCap = String((await own.ssh_exec.execute({ machine: 't', command: 'big 1024' }, {})).text)
    assert.doesNotMatch(atCap, /truncated/,
      'exactly maxOutputChars must not be reported as truncated')
    assert.equal(atCap.split('\n')[0].length, 1024)

    const one = String((await own.ssh_exec.execute({ machine: 't', command: 'big 1025' }, {})).text)
    assert.match(one, /1 more character was dropped from the end/)
    assert.doesNotMatch(one, /1 more character were/)

    const two = String((await own.ssh_exec.execute({ machine: 't', command: 'big 1026' }, {})).text)
    assert.match(two, /2 more characters were dropped from the end/)
  } finally {
    await own.ssh_close.execute({}, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a local filesystem failure is not reported as a connection failure', async () => {
  // DSH_HOME under a file made the key store unwritable, and the error arrived as
  // 'Could not connect to tester@host:port: ENOTDIR …' — the wrong machine entirely.
  const root = mkdtempSync(path.join(tmpdir(), 'dsh-badhomefit-'))
  const blocked = path.join(root, 'blocked')
  writeFileSync(blocked, 'not a directory')
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = blocked
  const srv2 = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    const message = await own.ssh_connect.execute({ machine: 't' }, {})
      .then(() => '', (err) => String(err.message))
    assert.match(message, /could not prepare its local SSH state/)
    assert.match(message, /filesystem problem on this machine, not the connection/)
    assert.doesNotMatch(message, /Could not connect to/)
  } finally {
    await own.ssh_close?.execute?.({}, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(root, { recursive: true, force: true })
  }
})

test('a clipped audit error says it was clipped', async () => {
  // A bare slice(0, 200) stored an error that looked complete but ended mid-sentence.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-clip-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  srv2.vfs.putDir('/tmp')
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, auditLog: true,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    await own.ssh_read.execute({ machine: 't', path: '/tmp/' + 'x'.repeat(500) + '.txt' }, {}).catch(() => {})
    const line = readFileSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8').trim().split('\n').pop()
    const record = JSON.parse(line)
    const error = String(record.error || '')
    assert.ok(error.length > 0, 'the record should keep the error')
    assert.ok(error.length <= 200, 'got ' + error.length)
    assert.match(error, /…$/, 'a clipped error must say so: ' + JSON.stringify(error.slice(-20)))
  } finally {
    await own.ssh_close.execute({}, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a refused session password names the setting that allows it', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-sesspwfit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const own = {}
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 's', hostKeyPolicy: 'tofu', reconnectCooldownMs: 0, connectTimeoutMs: 2000,
      machines: { s: { host: '127.0.0.1', port: 1, user: 'u' } },
    })
    const message = await own.ssh_connect.execute({ machine: 's', password: 'secret' }, {})
      .then(() => '', (err) => String(err.message))
    assert.match(message, /allowSessionPassword to true/)
    assert.match(message, /disabled for this profile/)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a timed-out or cancelled transfer records the same outcome as exec', async () => {
  // exec said 'timeout'/'cancel' while read, write and list said 'error' for the same
  // situations, so filtering the log by outcome found some of them and not others.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-outcomefit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  srv2.vfs.putDir('/tmp')
  srv2.vfs.putFile('/tmp/f.txt', 'x'.repeat(30))
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, auditLog: true,
      sftpTimeoutMs: 1000, connectTimeoutMs: 3000, commandTimeoutMs: 1000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    await own.ssh_read.execute({ machine: 't', path: '/tmp/f.txt' }, {})
    srv2.vfs.control.stallReads = true
    await own.ssh_read.execute({ machine: 't', path: '/tmp/f.txt' }, {}).catch(() => {})
    srv2.vfs.control.stallReads = false
    await own.ssh_list.execute({ machine: 't', path: '/nope' }, {}).catch(() => {})
    const records = readFileSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8')
      .trim().split('\n').map((line) => JSON.parse(line))
    const reads = records.filter((r) => r.kind === 'read')
    assert.equal(reads[0].outcome, 'ok')
    assert.equal(reads[1].outcome, 'timeout', JSON.stringify(reads[1]))
    assert.equal(records.find((r) => r.kind === 'list').outcome, 'error',
      'a missing path is a plain error, not a timeout')
  } finally {
    await own.ssh_close.execute({ force: true }, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a host with a control character is refused before dialling, and named as such', async () => {
  // A newline or a tab was reported as 'the host contains a space', and a host with
  // an escape sequence was not refused at all: it went to DNS, and the failure
  // message carried the raw bytes.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-hostshape-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const own = {}
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'tab', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 2000, commandTimeoutMs: 2000,
      machines: {
        space: { host: 'bad host.example', user: 'u', password: 'p' },
        tab: { host: 'a\tb', user: 'u', password: 'p' },
        esc: { host: 'evil\u001b[31mhost', user: 'u', password: 'p' },
      },
    })
    const messageFor = (alias) => own.ssh_connect.execute({ machine: alias }, {})
      .then(() => '', (err) => String(err.message))
    const tab = await messageFor('tab')
    assert.match(tab, /the host contains a control character/)
    assert.doesNotMatch(tab, /contains a space/)
    const esc = await messageFor('esc')
    assert.match(esc, /the host field is unusable/)
    assert.doesNotMatch(esc, /\u001b/, 'the refusal must not carry the raw escape byte')
    assert.doesNotMatch(esc, /getaddrinfo/, 'it must be refused before dialling')
    assert.match(await messageFor('space'), /the host contains a space/)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('every audit record carries an outcome, and the README lists them all', () => {
  // A refused record had no outcome at all, so filtering the trail by outcome skipped
  // exactly the operations that were stopped on purpose. The README table had also
  // missed 'none' (nothing to close) until a probe produced it.
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
  for (const outcome of ['ok', 'error', 'warn', 'timeout', 'cancel', 'incomplete', 'blocked', 'none', 'pending', 'busy', 'unconfirmed']) {
    assert.ok(readme.includes('`' + outcome + '`'), 'the README must document the outcome ' + outcome)
  }
  for (const kind of ['connect', 'exec', 'read', 'write', 'list', 'close', 'doctor', 'refused']) {
    assert.ok(readme.includes('`' + kind + '`'), 'the README must name the kind ' + kind)
  }
})

test('a refused command is recorded with an outcome and a reason', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-refusedfit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, auditLog: true,
      execGuard: 'confirm', connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    await own.ssh_exec.execute({ machine: 't', command: 'echo needs-confirm' }, {}).catch(() => {})
    const record = JSON.parse(readFileSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8').trim().split('\n').pop())
    assert.equal(record.kind, 'refused')
    assert.equal(record.outcome, 'blocked')
    assert.match(String(record.reason || ''), /execGuard/)
  } finally {
    await own.ssh_close?.execute?.({}, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('every doctor run leaves exactly one record, naming the stage that stopped it', async () => {
  // A run that stopped at the credentials or TCP step left no record at all, so the
  // log could not tell 'never called' from 'called and stopped early'. The reason was
  // also built as 'stage: detail', which redaction turned into 'host key: <redacted>
  // verified' — the opposite of what happened.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-docfit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', allowPlaintextPassword: true, auditLog: true, reconnectCooldownMs: 0, hostKeyPolicy: 'tofu',
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: {
        t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' },
        dead: { host: '127.0.0.1', port: 1, user: 'tester', password: 'test-pass' },
        nocred: { host: '127.0.0.1', port: srv2.port, user: 'tester' },
      },
    })
    for (const alias of ['t', 'dead', 'nocred']) {
      await own.ssh_doctor.execute({ machine: alias }, {})
    }
    const records = readFileSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8')
      .trim().split('\n').map((line) => JSON.parse(line)).filter((r) => r.kind === 'doctor')
    assert.equal(records.length, 3, 'one record per run: ' + JSON.stringify(records))
    assert.deepEqual(records.map((r) => r.machine).sort(), ['dead', 'nocred', 't'])
    assert.equal(records.find((r) => r.machine === 't').outcome, 'ok')
    const dead = records.find((r) => r.machine === 'dead')
    assert.equal(dead.outcome, 'error')
    assert.match(String(dead.reason), /^tcp — /, JSON.stringify(dead.reason))
    const nocred = records.find((r) => r.machine === 'nocred')
    assert.match(String(nocred.reason), /^credentials — /, JSON.stringify(nocred.reason))
  } finally {
    await own.ssh_close.execute({ force: true }, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a warning-only doctor run records warn, and the reason survives redaction', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-docwarn-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', allowPlaintextPassword: true, auditLog: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000, hostKeyPolicy: 'off',
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    await own.ssh_doctor.execute({ machine: 't' }, {})
    const record = readFileSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8')
      .trim().split('\n').map((line) => JSON.parse(line)).find((r) => r.kind === 'doctor')
    assert.equal(record.outcome, 'warn')
    assert.match(String(record.reason), /NOT verified/)
    assert.doesNotMatch(String(record.reason), /<redacted>/, 'the reason must not be masked by its own wording')
  } finally {
    await own.ssh_close.execute({ force: true }, {}).catch(() => {})
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})


test('an exit code is shown once, not twice', async () => {
  // The row read 't exec exit exit=3 exit 3': kind, outcome and status said the same
  // word three times before the command itself.
  await run('ssh_exec', { command: 'exit 3' })
  await run('ssh_exec', { command: 'kill' })
  const shown = String((await tools.ssh_audit.execute({ limit: 40 }, {})).text)
  assert.doesNotMatch(shown, /exec exit exit=/)
  assert.match(shown, /exec exit=\d/)
  assert.doesNotMatch(shown, /exec signal signal=/)
  assert.match(shown, /exec signal=\w+/)
  // A record whose outcome is not implied by the detail keeps its word.
  assert.match(shown, /exec ok exit=\d/)
})





test('binary output from a command says it is a lossy rendering', async () => {
  // ssh_read said '[binary file: …]' but ssh_exec handed back replacement
  // characters with nothing said: 'cat a.bin' looked like ordinary output.
  const srv4 = await startServer()
  const own = {}
  await apply(
    { tools: { register: (def) => { own[def.name] = def } }, effect: () => {}, get: () => undefined },
    {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
      connectTimeoutMs: 4000, commandTimeoutMs: 4000,
      machines: { t: { host: '127.0.0.1', port: srv4.port, user: 'tester', password: 'test-pass' } },
    },
  )
  try {
    const binary = String((await own.ssh_exec.execute({ machine: 't', command: 'binary' }, {})).text)
    assert.match(binary, /not valid UTF-8/, binary.slice(0, 200))
    assert.match(binary, /lossy rendering/)
    // Nothing may fire for text that happened to contain U+FFFD itself, or an emoji.
    for (const command of ['echo hello', 'echo \uFFFD\uFFFD', 'echo 😀']) {
      const text = String((await own.ssh_exec.execute({ machine: 't', command }, {})).text)
      assert.doesNotMatch(text, /not valid UTF-8/, command + ' -> ' + text.slice(0, 80))
    }
  } finally {
    await own.ssh_close.execute({ force: true }, {}).catch(() => {})
    srv4.killClients()
    await Promise.race([srv4.close(), new Promise((r) => setTimeout(r, 1500))])
  }
})

test('a handshake timeout is recorded as timeout, not error', async () => {
  // pool.exec() throws for a dialling failure, and the catch in ssh_exec wrote a
  // hardcoded 'error' while outcomeOf() classified the same failure as 'timeout'
  // for ssh_connect. The README lists the handshake under timeout.
  const net = await import('node:net')
  const sockets = []
  const blackhole = net.createServer((socket) => { sockets.push(socket) })
  await new Promise((resolve) => blackhole.listen(0, '127.0.0.1', resolve))
  const port = /** @type {any} */ (blackhole.address()).port
  const home2 = mkdtempSync(path.join(tmpdir(), 'dsh-handshakefit-'))
  const own = {}
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home2
  try {
    await apply(
      { tools: { register: (def) => { own[def.name] = def } }, effect: () => {}, get: () => undefined },
      {
        defaultMachine: 'dead', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, auditLog: true,
        reconnectCooldownMs: 0, connectTimeoutMs: 1000, commandTimeoutMs: 1000,
        machines: { dead: { host: '127.0.0.1', port, user: 'tester', password: 'test-pass' } },
      },
    )
    const message = await own.ssh_exec.execute({ machine: 'dead', command: 'echo hi' }, {})
      .then(() => 'connected?!', (e) => e.message)
    assert.match(message, /Timed out while waiting for handshake/)
    const records = readFileSync(path.join(home2, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8')
      .split('\n').filter(Boolean).map((line) => JSON.parse(line))
    const exec = records.find((record) => record.kind === 'exec')
    assert.ok(exec, 'the failure is recorded')
    assert.equal(exec.outcome, 'timeout')
  } finally {
    for (const socket of sockets) { try { socket.destroy() } catch {} }
    await new Promise((resolve) => blackhole.close(resolve))
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home2, { recursive: true, force: true })
  }
})

test('closing a connection while a command starts says so, instead of a TypeError', async () => {
  // connect() awaits the health probe and the eviction ceiling, and a concurrent
  // ssh_close can null the client inside that await. Returning it unchecked gave
  // the caller 'Cannot read properties of null (reading exec)' two times in eight.
  const srv3 = await startServer()
  const own = {}
  await apply(
    { tools: { register: (def) => { own[def.name] = def } }, effect: () => {}, get: () => undefined },
    {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 4000, commandTimeoutMs: 8000,
      machines: { t: { host: '127.0.0.1', port: srv3.port, user: 'tester', password: 'test-pass' } },
    },
  )
  const messages = []
  try {
    for (let attempt = 0; attempt < 8; attempt++) {
      const running = own.ssh_exec.execute({ machine: 't', command: 'sleep 1' }, {})
        .then((r) => String(r.text), (e) => e.message)
      own.ssh_close.execute({ machine: 't', force: true }, {}).catch(() => {})
      messages.push(await running)
    }
    for (const message of messages) {
      assert.doesNotMatch(message, /Cannot read properties of null/)
      assert.match(message, /is gone|ran: sleep 1|closed before the command reported/, message.slice(0, 120))
    }
  } finally {
    await own.ssh_close.execute({ force: true }, {}).catch(() => {})
    srv3.killClients()
    await Promise.race([srv3.close(), new Promise((r) => setTimeout(r, 1500))])
  }
})

test('the connection ceiling is enforced when work finishes, not only on the next call', async () => {
  // maxConnections: 1 with three concurrent commands left three sockets open
  // until something asked for a connection again: the report said '3 / 1 max'
  // and the server still had three clients 400 ms later.
  const srv2 = await startServer()
  const own = {}
  await apply(
    { tools: { register: (def) => { own[def.name] = def } }, effect: () => {}, get: () => undefined },
    {
      defaultMachine: 'a', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 5000, commandTimeoutMs: 8000, maxConnections: 1,
      machines: {
        a: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' },
        b: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' },
        c: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' },
      },
    },
  )
  try {
    await Promise.all(['a', 'b', 'c'].map((m) => own.ssh_exec.execute({ machine: m, command: 'echo x-' + m }, {})))
    // The close is asynchronous, so give the sockets a moment to go.
    await new Promise((resolve) => setTimeout(resolve, 400))
    const line = String((await own.ssh_config.execute({}, {})).text).split('\n').find((l) => /Live connections/.test(l)) || ''
    assert.match(line, /Live connections: 1 \/ 1 max/)
    assert.equal(srv2.clientCount(), 1)
  } finally {
    await own.ssh_close.execute({ force: true }, {}).catch(() => {})
    srv2.killClients()
    await Promise.race([srv2.close(), new Promise((r) => setTimeout(r, 1500))])
  }
})

test('closing every connection leaves a record for each one', async () => {
  // ssh_close with no machine is what people call at the end of a session, and it
  // wrote nothing: the per-machine form recorded what it did, this one did not.
  const auditFile = path.join(home, 'dsh-ssh-safe', 'audit.ndjson')
  const count = () => (existsSync(auditFile) ? readFileSync(auditFile, 'utf8').split('\n').filter(Boolean).length : 0)
  await tools.ssh_exec.execute({ machine: 't', command: 'echo x' }, {})
  const before = count()
  await tools.ssh_close.execute({}, {})
  await tools.ssh_close.execute({}, {})

  const added = readFileSync(auditFile, 'utf8').split('\n').filter(Boolean).slice(before)
    .map((line) => JSON.parse(line)).filter((record) => record.kind === 'close')
  assert.equal(added.length, 2, 'both close-all calls are recorded')
  assert.deepEqual({ machine: added[0].machine, outcome: added[0].outcome }, { machine: 't', outcome: 'ok' })
  assert.deepEqual({ machine: added[1].machine, outcome: added[1].outcome }, { machine: undefined, outcome: 'none' })
})

test('an operation on a dropped connection explains itself and the next one reconnects', async () => {
  // ssh2 answers a request on a dead socket with a bare 'No response from server':
  // no machine, no advice, and it reads like a plugin bug. Measured 5/5 after the
  // peer dropped: every SFTP call said exactly that until the entry was evicted.
  srv.vfs.putDir('/gone')
  await run('ssh_exec', { command: 'echo warm' })
  srv.killClients()
  // run() rejects on failure, so the message is captured here rather than thrown.
  let first
  try { first = await run('ssh_list', { path: '/gone' }) } catch (err) { first = 'ERR: ' + err.message }
  if (/^ERR:/.test(first)) {
    assert.match(first, /stopped answering before the operation finished/)
    assert.match(first, /next call opens a new connection/)
    assert.doesNotMatch(first, /^ERR: No response from server$/, 'the raw ssh2 text must not be the whole message')
  }
  const next = await run('ssh_list', { path: '/gone' })
  assert.doesNotMatch(next, /^ERR:/, 'the next call must reconnect: ' + next)
})

test('a symlink loop on the way is not reported as a missing directory', async () => {
  // stat on the loop fails, the old code called that 'missing', tried mkdir, and
  // answered 'could not create remote directory /w/loop: already exists' — true,
  // and useless: the directory never had to be created.
  srv.vfs.putDir('/loopdir')
  srv.vfs.putLink('/loopdir/self', '/loopdir/self')
  srv.vfs.putLink('/loopdir/a', '/loopdir/b')
  srv.vfs.putLink('/loopdir/b', '/loopdir/a')
  // run() rejects on failure, so the messages are captured here.
  const attempt = async (args) => {
    try { return await run('ssh_write', args) } catch (err) { return 'ERR: ' + err.message }
  }
  const first = await attempt({ path: '/loopdir/self/x.txt', content: 'x', createDirs: true })
  assert.match(first, /symbolic link loop/)
  assert.match(first, /nothing can be created through it/)
  assert.doesNotMatch(first, /already exists/)
  const second = await attempt({ path: '/loopdir/a/x.txt', content: 'x', createDirs: true })
  assert.match(second, /symbolic link loop/)
  // Without createDirs the server says only 'No such file'; the loop surfaces when
  // createDirs makes the plugin look at the components, which is covered above.
})

test('reading through a symlink loop names the loop, not just "no such file"', async () => {
  // The server answers 'No such file' for the whole path when a component is a
  // loop, so /w/self/x.txt said only 'no such file: /w/self/x.txt' while
  // /w/self itself was explained properly.
  srv.vfs.putDir('/links')
  srv.vfs.putLink('/links/self', '/links/self')
  srv.vfs.putLink('/links/x', '/links/y')
  srv.vfs.putLink('/links/y', '/links/x')
  srv.vfs.putLink('/links/gone', '/links/nowhere.txt')
  const attempt = async (name, args) => {
    try { return await run(name, args) } catch (err) { return 'ERR: ' + err.message }
  }
  const loop = await attempt('ssh_read', { path: '/links/self/f.txt' })
  assert.match(loop, /is a symbolic link loop/)
  assert.match(loop, /nothing below it can be reached/)
  assert.doesNotMatch(loop, /^ERR: no such file:/)
  const cycle = await attempt('ssh_read', { path: '/links/x/f.txt' })
  assert.match(cycle, /\/links\/x is a symbolic link loop/)
  const broken = await attempt('ssh_read', { path: '/links/gone/deep/f.txt' })
  assert.match(broken, /\/links\/gone is a symbolic link to \/links\/nowhere\.txt/)
  assert.match(broken, /that target does not exist/)
  const listed = await attempt('ssh_list', { path: '/links/gone/x' })
  assert.match(listed, /is a symbolic link to \/links\/nowhere\.txt/)
})

test('a dangling link above the target is named for writes with createDirs too', async () => {
  // '/w/gone/a/b/x.txt' answered 'could not create remote directory /w/gone/a: not a
  // directory' — about a path that was never the problem. The one-level case already
  // named the link, so the two disagreed about the same condition.
  srv.vfs.putDir('/dl')
  srv.vfs.putLink('/dl/gone', '/dl/nowhere.txt')
  const attempt = async (args) => {
    try { return await run('ssh_write', args) } catch (err) { return 'ERR: ' + err.message }
  }
  const one = await attempt({ path: '/dl/gone/x.txt', content: 'x', createDirs: true })
  assert.match(one, /\/dl\/gone is a symbolic link to \/dl\/nowhere\.txt/)
  const deep = await attempt({ path: '/dl/gone/a/b/x.txt', content: 'x', createDirs: true })
  assert.match(deep, /\/dl\/gone is a symbolic link to \/dl\/nowhere\.txt/)
  assert.match(deep, /that target cannot be reached/)
  assert.doesNotMatch(deep, /not a directory/)
})

test('a denied directory above the target is named as a possibility', async () => {
  srv.vfs.putDir('/deny')
  srv.vfs.putDir('/deny/inner')
  srv.vfs.putFile('/deny/inner/f.txt', 'x')
  srv.vfs.control.deny('/deny')
  try {
    const attempt = async (name, args) => {
      try { return await run(name, args) } catch (err) { return 'ERR: ' + err.message }
    }
    const read = await attempt('ssh_read', { path: '/deny/inner/f.txt' })
    assert.match(read, /may not read this file/)
    assert.match(read, /and of the directories above it/)
    const listed = await attempt('ssh_list', { path: '/deny/inner' })
    assert.match(listed, /search permission on the directories above it/)
  } finally {
    srv.vfs.control.undeny()
  }
})

test('a .pub file, a directory or junk as keyPath is explained, not passed to ssh2', async () => {
  // A public key parses cleanly, so it reached ssh2 as privateKey and the connection
  // died with 'privateKey value does not contain a (valid) private key' — no
  // machine, no path, no fix. A directory answered 'EISDIR: illegal operation on a
  // directory, read'.
  const ssh2 = (await import('ssh2')).default
  const dir = mkdtempSync(path.join(tmpdir(), 'dsh-keypath-'))
  const pair = testKeyPair()
  const pub = path.join(dir, 'id.pub')
  const junk = path.join(dir, 'junk.pem')
  const asDir = path.join(dir, 'ssh-dir')
  writeFileSync(pub, pair.public)
  writeFileSync(junk, 'not a key')
  mkdirSync(asDir)
  const srv2 = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: {
        t: { host: '127.0.0.1', port: srv2.port, user: 'tester' },
        pub: { host: '127.0.0.1', port: srv2.port, user: 'tester', keyPath: pub },
        dir: { host: '127.0.0.1', port: srv2.port, user: 'tester', keyPath: asDir },
        junk: { host: '127.0.0.1', port: srv2.port, user: 'tester', keyPath: junk },
      },
    })
    const attempt = async (machine) => {
      try { return String((await own.ssh_exec.execute({ machine, command: 'echo hi' }, {})).text) }
      catch (err) { return 'ERR: ' + err.message }
    }
    const publicKey = await attempt('pub')
    assert.match(publicKey, /holds a public key, not a private one/)
    assert.match(publicKey, /without the \.pub/)
    assert.doesNotMatch(publicKey, /privateKey value does not contain/)
    const directory = await attempt('dir')
    assert.match(directory, /is a directory, not a key file/)
    assert.doesNotMatch(directory, /EISDIR/)
    const notAKey = await attempt('junk')
    assert.match(notAKey, /Unsupported key format/)
    assert.match(notAKey, /a \.pub file is the public half/)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    await srv2.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

test('the doctor and the connection agree about a .pub file and a directory keyPath', async () => {
  // The connection path says 'is a directory, not a key file' and names the .pub
  // half; the doctor still printed the errno or the bare header verdict, so the two
  // disagreed about the same mistake.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-dockeyfit2-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  const own = {}
  try {
    const pair = testKeyPair()
    const pub = path.join(home, 'id_ed25519.pub')
    const asDir = path.join(home, 'ssh-dir')
    writeFileSync(pub, pair.public)
    mkdirSync(asDir)
    const build = async (machine) => {
      const tools = {}
      await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
        defaultMachine: 'k', hostKeyPolicy: 'tofu', reconnectCooldownMs: 0,
        connectTimeoutMs: 2000, commandTimeoutMs: 2000,
        machines: { k: { host: '127.0.0.1', port: srv2.port, user: 'tester', ...machine } },
      })
      return tools
    }
    const pubReport = String((await (await build({ keyPath: pub })).ssh_doctor.execute({ machine: 'k' }, {})).text)
    assert.match(pubReport, /\[FAIL\] credentials: key file does not look like a private key/)
    assert.match(pubReport, /a \.pub file is the public half/)
    const dirReport = String((await (await build({ keyPath: asDir })).ssh_doctor.execute({ machine: 'k' }, {})).text)
    assert.match(dirReport, /\[FAIL\] credentials: key file is a directory, not a key/)
    assert.doesNotMatch(dirReport, /EISDIR/)
  } finally {
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('force-close stops a transfer that is already running', async () => {
  // closeOne({force: true}) closed the client but an in-flight write kept waiting for
  // its own sftpTimeoutMs: measured 6.3 s for a write told to stop at 120 ms.
  const srv2 = await startServer()
  srv2.vfs.putDir('/st')
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-forceclose-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000, sftpTimeoutMs: 20000, maxFileBytes: 4 * 1048576,
      closeTimeoutMs: 1000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    const attempt = async (promise) => {
      try { return String((await promise).text) } catch (err) { return 'ERR: ' + err.message }
    }
    await attempt(own.ssh_exec.execute({ machine: 't', command: 'echo warm' }, {}))
    srv2.vfs.control.stallWrites = true
    const startedAt = Date.now()
    const writing = attempt(own.ssh_write.execute({ machine: 't', path: '/st/partial.txt', content: 'z'.repeat(2 * 1048576) }, {}))
    await new Promise((r) => setTimeout(r, 120))
    const closed = await attempt(own.ssh_close.execute({ machine: 't', force: true }, {}))
    assert.match(closed, /Closed/)
    const wrote = await writing
    const elapsed = Date.now() - startedAt
    assert.match(wrote, /(was cancelled|unexpected SFTP session termination)/i)
    assert.match(wrote, /no data was sent|termination/i)
    assert.ok(elapsed < 4000, 'the transfer must stop with the close, took ' + elapsed + 'ms')
  } finally {
    srv2.vfs.control.stallWrites = false
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('every operation settles when the turn is cancelled', async () => {
  // Removing the signal argument from readRemoteFile kept tsc and the whole suite
  // green: nothing asked whether a read stops when the caller aborts. All four now
  // have to answer within a second, with a message that says what happened.
  srv.vfs.putDir('/cx')
  srv.vfs.putFile('/cx/small.txt', 'x'.repeat(400))
  const attempt = async (name, args, stall, release) => {
    const ctrl = new AbortController()
    const startedAt = Date.now()
    const settled = tools[name].execute(args, { signal: ctrl.signal }).then(
      (r) => 'ok: ' + String(r.text),
      (err) => 'ERR: ' + String(err.message),
    )
    stall()
    setTimeout(() => ctrl.abort(), 150)
    const outcome = await Promise.race([
      settled,
      new Promise((resolve) => setTimeout(() => resolve('STILL PENDING'), 8000)),
    ])
    release()
    return { ms: Date.now() - startedAt, outcome }
  }
  try {
    const read = await attempt('ssh_read', { machine: 't', path: '/cx/small.txt' },
      () => { srv.vfs.control.stallReads = true }, () => { srv.vfs.control.stallReads = false })
    assert.match(read.outcome, /reading .* was cancelled/)
    assert.ok(read.ms < 3000, 'the read must not wait for sftpTimeoutMs, took ' + read.ms + 'ms')

    const listed = await attempt('ssh_list', { machine: 't', path: '/cx' },
      () => { srv.vfs.control.stallDirs = true }, () => { srv.vfs.control.stallDirs = false })
    assert.match(listed.outcome, /listing .* was cancelled/)
    assert.ok(listed.ms < 3000, 'the listing must stop, took ' + listed.ms + 'ms')

    const wrote = await attempt('ssh_write', { machine: 't', path: '/cx/big.txt', content: 'y'.repeat(500000) },
      () => { srv.vfs.control.stallWrites = true }, () => { srv.vfs.control.stallWrites = false })
    assert.match(wrote.outcome, /writing .* was cancelled/)
    assert.ok(wrote.ms < 3000, 'the write must stop, took ' + wrote.ms + 'ms')

    const ran = await attempt('ssh_exec', { machine: 't', command: 'sleep 9' }, () => {}, () => {})
    assert.match(ran.outcome, /cancelled at the caller request/)
    assert.ok(ran.ms < 3000, 'the command must stop, took ' + ran.ms + 'ms')
  } finally {
    srv.vfs.control.stallReads = false
    srv.vfs.control.stallDirs = false
    srv.vfs.control.stallWrites = false
  }
})

test('close reports the retry gate it clears', async () => {
  // 'No live connection for dead' was all it said, while the close also reset a 20s
  // reconnect cooldown: the next call connected at once with nothing explaining why.
  const net = await import('node:net')
  const probe = net.createServer()
  await new Promise((r) => probe.listen(0, '127.0.0.1', r))
  const deadPort = probe.address().port
  await new Promise((r) => probe.close(r))
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gate-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const srv2 = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'dead', hostKeyPolicy: 'tofu', allowPlaintextPassword: true,
      connectTimeoutMs: 2000, commandTimeoutMs: 3000, reconnectCooldownMs: 20000,
      machines: {
        good: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' },
        dead: { host: '127.0.0.1', port: deadPort, user: 'tester', password: 'x' },
      },
    })
    const attempt = async (promise) => {
      try { return String((await promise).text) } catch (err) { return 'ERR: ' + err.message }
    }
    const first = await attempt(own.ssh_exec.execute({ machine: 'dead', command: 'echo hi' }, {}))
    assert.match(first, /ECONNREFUSED/)
    const second = await attempt(own.ssh_exec.execute({ machine: 'dead', command: 'echo hi' }, {}))
    assert.match(second, /Refusing to retry dead/)
    const closed = await attempt(own.ssh_close.execute({ machine: 'dead' }, {}))
    assert.match(closed, /No live connection for dead/)
    assert.match(closed, /retry gate was cleared/)
    assert.match(closed, /connects right away/)
    const third = await attempt(own.ssh_exec.execute({ machine: 'dead', command: 'echo hi' }, {}))
    assert.doesNotMatch(third, /Refusing to retry/)
    assert.match(third, /ECONNREFUSED/)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a boolean or array port in the file is a problem, not a silent port 1', async () => {
  // Number(true) is 1 and Number([22]) is 22, so a hand-edited credentials.json with
  // 'port: true' dialled port 1 while the page showed the machine green. The plugin
  // config schema already refuses these (invalid configuration at load); the file is
  // raw JSON and reaches machineDefinition directly.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-porttype-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
  writeFileSync(
    path.join(home, 'dsh-ssh-safe', 'credentials.json'),
    JSON.stringify({
      yes: { host: '127.0.0.1', port: true, user: 'tester' },
      arr: { host: '127.0.0.1', port: [22], user: 'tester' },
      fine: { host: '127.0.0.1', port: 2222, user: 'tester' },
    }),
    'utf8',
  )
  const srv2 = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 1500, commandTimeoutMs: 1500,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    const attempt = async (promise) => {
      try { return String((await promise).text) } catch (err) { return 'ERR: ' + err.message }
    }
    const listing = await attempt(own.ssh_machines.execute({}, {}))
    assert.match(listing, /port true from the file is not an integer between 1 and 65535/)
    assert.match(listing, /port \[22\] from the file is not an integer between 1 and 65535/)
    // The valid one is untouched.
    assert.match(listing, /root@|tester@127\.0\.0\.1:2222/)
    const doc = await attempt(own.ssh_doctor.execute({ machine: 'yes' }, {}))
    assert.match(doc, /\[FAIL\] configuration: port true from the file/)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a field that cannot be text is refused, not stringified', async () => {
  // keyPath: {} became "[object Object]" and the failure named a file with that
  // name; host: ['a','b'] became 'a,b'; password: true was listed as a credential
  // source while the connection refused it.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-fieldtype-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
  writeFileSync(
    path.join(home, 'dsh-ssh-safe', 'credentials.json'),
    JSON.stringify({
      objkey: { host: '127.0.0.1', port: 22, user: 'tester', keyPath: { a: 1 } },
      arrhost: { host: ['127.0.0.1'], port: 22, user: 'tester' },
      boolpwd: { host: '127.0.0.1', port: 22, user: 'tester', password: true },
      numuser: { host: '127.0.0.1', port: 22, user: 123 },
    }),
    'utf8',
  )
  const srv2 = await startServer()
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 1000, commandTimeoutMs: 1000,
      machines: {
        t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' },
        ok: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' },
      },
    })
    const attempt = async (promise) => {
      try { return String((await promise).text) } catch (err) { return 'ERR: ' + err.message }
    }
    const key = await attempt(own.ssh_exec.execute({ machine: 'objkey', command: 'echo hi' }, {}))
    assert.match(key, /the keyPath from the file is not text \(it is object\)/)
    assert.doesNotMatch(key, /\[object Object\]/, 'nothing may present it as a path')
    const host = await attempt(own.ssh_exec.execute({ machine: 'arrhost', command: 'echo hi' }, {}))
    assert.match(host, /the host from the file is not text \(it is an array\)/)
    const password = await attempt(own.ssh_exec.execute({ machine: 'boolpwd', command: 'echo hi' }, {}))
    assert.match(password, /the password from the file is not text \(it is boolean\)/)
    // A numeric user is still a name.
    const numeric = await attempt(own.ssh_machines.execute({}, {}))
    assert.match(numeric, /• numuser.*123@127\.0\.0\.1:22/)
    const doc = await attempt(own.ssh_doctor.execute({ machine: 'objkey' }, {}))
    assert.match(doc, /\[FAIL\] configuration: the keyPath from the file is not text/)
    assert.match(doc, /\[FAIL\] credentials: the keyPath from the file is not text/)
    assert.doesNotMatch(doc, /\[ok\] credentials/)
    const inventory = await attempt(own.ssh_machines.execute({}, {}))
    assert.match(inventory, /BAD FIELD: the keyPath from the file is not text/)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    await srv2.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a server without SFTP is named by the file tools and by the doctor', async () => {
  // ssh2 answers 'Unable to start subsystem: sftp', which names neither the cause nor
  // the fix; the doctor passed such a machine because it never tried the subsystem.
  const ssh2 = (await import('ssh2')).default
  const hostKey = testHostKey()
  const server = new ssh2.Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => ctx.accept())
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept()
        session.on('sftp', (_acceptSftp, rejectSftp) => { if (rejectSftp) rejectSftp() })
        session.on('exec', (acceptExec) => {
          const stream = acceptExec()
          stream.on('close', () => {})
          stream.exit(0)
          stream.end('doctor-ok\n')
        })
      })
    })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-nosftp-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'n', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000, sftpTimeoutMs: 4000,
      machines: { n: { host: '127.0.0.1', port, user: 'tester', password: 'x' } },
    })
    const attempt = async (name, args) => {
      try { return String((await own[name].execute(args, {})).text) } catch (err) { return 'ERR: ' + err.message }
    }
    const listed = await attempt('ssh_list', { machine: 'n', path: '/tmp' })
    assert.match(listed, /did not start the SFTP subsystem/)
    assert.match(listed, /Subsystem sftp/)
    assert.doesNotMatch(listed, /^ERR: Unable to start subsystem: sftp$/)
    const read = await attempt('ssh_read', { machine: 'n', path: '/tmp/x' })
    assert.match(read, /did not start the SFTP subsystem/)
    // exec keeps working, so the failure is specific to the file tools.
    const ran = await attempt('ssh_exec', { machine: 'n', command: 'echo hi' })
    assert.match(ran, /doctor-ok/)
    const doc = await attempt('ssh_doctor', { machine: 'n' })
    assert.match(doc, /\[FAIL\] sftp: the server did not start the SFTP subsystem/)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    server.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a server that refuses exec is named by ssh_exec and by the doctor', async () => {
  // ssh2 answers 'Unable to exec' with nothing about the machine, and the doctor
  // reported it as [FAIL] connect, pointing at the connection instead of the shell.
  const ssh2 = (await import('ssh2')).default
  const hostKey = testHostKey()
  const server = new ssh2.Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => ctx.accept())
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept()
        session.on('exec', (acceptExec, rejectExec) => {
          if (rejectExec) { rejectExec(); return }
          const stream = acceptExec()
          stream.close()
        })
      })
    })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-noexec-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'n', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { n: { host: '127.0.0.1', port, user: 'tester', password: 'x' } },
    })
    const attempt = async (name, args) => {
      try { return String((await own[name].execute(args, {})).text) } catch (err) { return 'ERR: ' + err.message }
    }
    const ran = await attempt('ssh_exec', { machine: 'n', command: 'echo hi' })
    assert.match(ran, /the server refused to run a command/)
    assert.match(ran, /ForceCommand|restricted shell|session limit/)
    assert.doesNotMatch(ran, /^ERR: Unable to exec$/)
    const doc = await attempt('ssh_doctor', { machine: 'n' })
    assert.match(doc, /\[FAIL\] shell: the server refused to run a command/)
    assert.doesNotMatch(doc, /\[FAIL\] connect/)
    assert.match(doc, /\[ok\] authentication: connected/)
    // One host key line, not two.
    assert.equal((doc.match(/host key:/g) || []).length, 1)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    server.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a server that only offers keyboard-interactive accepts the password', async () => {
  // Debian/Ubuntu sshd backs password logins with PAM and offers only
  // keyboard-interactive. ssh2 does not try that method unless asked, so a correct
  // password failed with 'All configured authentication methods failed'.
  const ssh2 = (await import('ssh2')).default
  const hostKey = testHostKey()
  const answers = []
  const server = new ssh2.Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => {
      if (ctx.method !== 'keyboard-interactive') { ctx.reject(['keyboard-interactive']); return }
      // A password prompt and an unrelated one: the second must never see the password.
      ctx.prompt([{ prompt: 'Password: ', echo: false }, { prompt: 'Verification code: ', echo: false }], (given) => {
        answers.push(given)
        if (given[0] === 'test-pass') ctx.accept()
        else ctx.reject()
      })
    })
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept()
        session.on('exec', (acceptExec) => {
          const stream = acceptExec()
          stream.on('close', () => {})
          stream.exit(0)
          stream.end('kbd-ok\n')
        })
      })
    })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-kbd-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'k', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 4000, commandTimeoutMs: 4000,
      machines: {
        k: { host: '127.0.0.1', port, user: 'tester', password: 'test-pass' },
        bad: { host: '127.0.0.1', port, user: 'tester', password: 'wrong' },
      },
    })
    const attempt = async (machine) => {
      try { return String((await own.ssh_exec.execute({ machine, command: 'echo hi' }, {})).text) } catch (err) { return 'ERR: ' + err.message }
    }
    assert.match(await attempt('k'), /kbd-ok\s+\[exit 0\]/)
    assert.match(await attempt('bad'), /All configured authentication methods failed/)
    // The password went to the prompt that asked for one and nowhere else.
    assert.deepEqual(answers[0], ['test-pass', ''])
    assert.deepEqual(answers[1], ['wrong', ''])
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    server.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('an auth refusal says which credential was offered', async () => {
  // 'check the user, the key or password' reads the same whether the password was
  // wrong or the server only accepts keys; the message now names the attempt.
  const ssh2 = (await import('ssh2')).default
  const hostKey = testHostKey()
  const server = new ssh2.Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => {
      if (ctx.method !== 'publickey') { ctx.reject(['publickey']); return }
      ctx.accept()
    })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-tried-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'n', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { n: { host: '127.0.0.1', port, user: 'tester', password: 'x' } },
    })
    let message = ''
    try {
      await own.ssh_exec.execute({ machine: 'n', command: 'echo hi' }, {})
    } catch (err) { message = err.message }
    assert.match(message, /All configured authentication methods failed/)
    assert.match(message, /this attempt offered config-password/)
    assert.match(message, /a server that requires a method you have not configured/)
    // One parenthesis, not two.
    assert.equal((message.match(/\(/g) || []).length, (message.match(/\)/g) || []).length)
    assert.doesNotMatch(message, /\)\(/)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    server.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a refused channel is reported as a session limit, not a dead connection', async () => {
  // sshd answers 'Channel open failure' at MaxSessions. The plugin mapped that to
  // 'The connection ... is gone', which sent the reader to reconnect instead of
  // looking at the limit.
  const ssh2 = (await import('ssh2')).default
  const hostKey = testHostKey()
  const server = new ssh2.Server({ hostKeys: [hostKey] }, (client) => {
    let used = 0
    client.on('authentication', (ctx) => ctx.accept())
    client.on('ready', () => {
      client.on('session', (accept, reject) => {
        // One session per connection: the second request is refused the way a
        // server at its MaxSessions limit refuses it.
        used += 1
        if (used > 1) { if (reject) reject(); return }
        const session = accept()
        session.on('exec', (acceptExec) => {
          const stream = acceptExec()
          stream.on('close', () => {})
          stream.exit(0)
          stream.end('first-ok\n')
        })
      })
    })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-maxsess-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'n', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 4000,
      machines: { n: { host: '127.0.0.1', port, user: 'tester', password: 'x' } },
    })
    const attempt = async () => {
      try { return String((await own.ssh_exec.execute({ machine: 'n', command: 'echo hi' }, {})).text) } catch (err) { return 'ERR: ' + err.message }
    }
    assert.match(await attempt(), /first-ok/)
    const refused = await attempt()
    assert.match(refused, /refused to open another channel/)
    assert.match(refused, /Channel open failure/)
    assert.match(refused, /MaxSessions/)
    assert.match(refused, /still up/)
    assert.doesNotMatch(refused, /is gone/)
    // The reader is a user of THIS plugin: the remedy it can actually run is
    // ssh_close, which gives the next call a fresh session budget.
    assert.match(refused, /ssh_close \{ machine: "n" \}/)
    // One parenthesis, no stray empty reason.
    assert.doesNotMatch(refused, /\)\)|\(\s*\)/)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    server.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a dropped connection stops in-flight transfers instead of waiting for the timeout', async () => {
  // The server closed the socket while a stalled read/listing/write was waiting:
  // each one sat until its own 5000 ms timeout and then guessed that the channel
  // 'may have dropped'.
  const srv2 = await startServer()
  srv2.vfs.putFile('/big.txt', Buffer.alloc(8 * 1024 * 1024, 0x61))
  srv2.vfs.putDir('/dir')
  for (let i = 0; i < 50; i += 1) srv2.vfs.putFile('/dir/f' + i + '.txt', Buffer.from('x'))
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-dropmid-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000, sftpTimeoutMs: 5000,
      maxFileBytes: 32 * 1024 * 1024,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    const attempt = async (name, args) => {
      const started = Date.now()
      let text
      try { text = String((await own[name].execute(args, {})).text) } catch (err) { text = 'ERR: ' + err.message }
      return { text, ms: Date.now() - started }
    }
    // Warm the connection so the drop lands on an established session.
    await attempt('ssh_exec', { machine: 't', command: 'echo warm' })
    await attempt('ssh_list', { machine: 't', path: '/dir' })
    srv2.vfs.control.stallReads = true
    const readPromise = attempt('ssh_read', { machine: 't', path: '/big.txt' })
    setTimeout(() => { srv2.killClients(); srv2.vfs.control.stallReads = false }, 600)
    const read = await readPromise
    assert.match(read.text, /reading \/big.txt did not finish — the connection dropped/)
    assert.doesNotMatch(read.text, /was cancelled/)
    assert.ok(read.ms < 2500, 'the read must not wait for its 5000 ms timeout, took ' + read.ms)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    await Promise.race([srv2.close(), new Promise((r) => setTimeout(r, 1500))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a read .netrc or .pgpass is masked on the way out', async () => {
  // The rules existed for flags and KEY=value text; a credential file with neither
  // shape reached the transcript verbatim.
  const srv2 = await startServer()
  srv2.vfs.putFile('/home/u/.netrc', Buffer.from('machine db.example.com\n  login admin\n  password AAA1\n'))
  srv2.vfs.putFile('/home/u/.pgpass', Buffer.from('db.example.com:5432:mydb:user:AAA2\n'))
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-read-redact-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    const read = async (p) => String((await own.ssh_read.execute({ machine: 't', path: p }, {})).text)
    const netrc = await read('/home/u/.netrc')
    assert.match(netrc, /password <redacted>/)
    assert.doesNotMatch(netrc, /AAA1/)
    assert.match(netrc, /pass raw: true/)
    const pgpass = await read('/home/u/.pgpass')
    assert.match(pgpass, /db\.example\.com:5432:mydb:user:<redacted>/)
    assert.doesNotMatch(pgpass, /AAA2/)
    // raw: true is the escape hatch and still returns the file verbatim.
    const raw = String((await own.ssh_read.execute({ machine: 't', path: '/home/u/.netrc', raw: true }, {})).text)
    assert.match(raw, /AAA1/)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    await Promise.race([srv2.close(), new Promise((r) => setTimeout(r, 1500))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('ssh_exec masks secret-shaped output and raw: true bypasses the mask', async () => {
  // The README promises masked exec output, and it did mask -- but there was no way
  // out when the masker hid something the caller needed (a count, a checksum),
  // while ssh_read already had raw: true.
  const ssh2 = (await import('ssh2')).default
  const hostKey = testHostKey()
  const server = new ssh2.Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => ctx.accept())
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept()
        session.on('exec', (acceptExec) => {
          const stream = acceptExec()
          stream.write('DB_PASSWORD=AAA9\n')
          stream.write('token=AAA8\n')
          stream.stderr.write('Authorization: Bearer AAA7\n')
          stream.exit(0)
          stream.end()
        })
      })
    })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-execmask-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'n', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 4000,
      machines: { n: { host: '127.0.0.1', port, user: 'tester', password: 'x' } },
    })
    const run = async (args) => String((await own.ssh_exec.execute({ machine: 'n', command: 'print', ...args }, {})).text)
    const masked = await run({})
    assert.match(masked, /DB_PASSWORD=<redacted>/)
    assert.match(masked, /token=<redacted>/)
    assert.match(masked, /Authorization: <redacted>/)
    assert.doesNotMatch(masked, /AAA7|AAA8|AAA9/)
    // The escape hatch returns the bytes as they arrived, stderr included.
    const raw = await run({ raw: true })
    assert.match(raw, /DB_PASSWORD=AAA9/)
    assert.match(raw, /token=AAA8/)
    assert.match(raw, /Authorization: Bearer AAA7/)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    server.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('the doctor description names every stage the doctor reports', async () => {
  // The description listed configuration/TCP/host key/authentication. The sftp
  // stage arrived in 0.7.241 and was never added, so the one stage that fails on a
  // server without the subsystem was undocumented.
  const srv2 = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-docstages-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    const report = String((await own.ssh_doctor.execute({ machine: 't' }, {})).text)
    const stages = new Set()
    for (const line of report.split('\n')) {
      const match = line.match(/^\[(?:ok|FAIL|warn|skip)\] ([a-z ]+):/)
      if (match) stages.add(match[1])
    }
    assert.ok(stages.size >= 5, 'expected several stages, saw ' + [...stages].join(', '))
    const description = String(own.ssh_doctor.description || '')
    for (const stage of stages) {
      // 'tcp' is written as 'TCP reachability' in the prose; compare the words.
      const words = stage.toLowerCase().split(' ')
      const mentioned = words.every((word) => description.toLowerCase().includes(word))
      assert.ok(mentioned, 'the description must mention the ' + stage + ' stage')
    }
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    await Promise.race([srv2.close(), new Promise((r) => setTimeout(r, 1500))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('no listing tool ever prints a password, a key body or file content', async () => {
  // Four tool descriptions promise exactly this ('never returns a password',
  // 'secrets are never included', 'never includes command output, file contents or
  // credentials'). Promises in prose need a test or they rot.
  const srv2 = await startServer()
  const ssh2 = (await import('ssh2')).default
  const pair = testKeyPair()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-nopromise-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const keyPath = path.join(home, 'id_ed25519')
  writeFileSync(keyPath, String(pair.private))
  srv2.vfs.putFile('/secret.txt', Buffer.from('FILECONTENTMARKER\n'))
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000, auditLog: true, useCredentialFile: true,
      machines: {
        t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' },
        p: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'PASSWORDMARKER' },
        k: { host: '127.0.0.1', port: srv2.port, user: 'tester', keyPath },
      },
    })
    const text = async (p, args = {}) => {
      try { return String((await own[p].execute(args, {})).text) } catch (err) { return 'ERR: ' + err.message }
    }
    assert.match(await text('ssh_read', { machine: 't', path: '/secret.txt' }), /FILECONTENTMARKER/)
    const outputs = {
      machines: await text('ssh_machines'),
      config: await text('ssh_config'),
      credentials: await text('ssh_credentials'),
      audit: await text('ssh_audit', { limit: 20 }),
      doctorPassword: await text('ssh_doctor', { machine: 'p' }),
      doctorKey: await text('ssh_doctor', { machine: 'k' }),
    }
    // The middle line of the key is body: shorter than the header, longer than the tail.
    const keyBody = String(pair.private).split('\n')[2]
    for (const [name, out] of Object.entries(outputs)) {
      assert.doesNotMatch(out, /PASSWORDMARKER/, name + ' must not print the password')
      assert.doesNotMatch(out, /FILECONTENTMARKER/, name + ' must not print file content')
      assert.ok(!out.includes(keyBody), name + ' must not print key material')
    }
    // The audit row says the read happened without carrying what it read.
    assert.match(outputs.audit, /read ok \/secret\.txt/)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    await Promise.race([srv2.close(), new Promise((r) => setTimeout(r, 1500))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('nine mixed calls in flight at once all land, and the audit stays parseable', async () => {
  // The pool shares one connection per alias and each call owns a channel; a
  // regression there shows up as a dropped call or a torn audit line, and neither
  // is covered by the sequential tests.
  const srv2 = await startServer()
  srv2.vfs.putFile('/c.txt', Buffer.from('concurrent-file\n'))
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-conc-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 5000, auditLog: true,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    const run = (name, args) => own[name].execute(args, {}).then((r) => String(r.text), (e) => 'ERR: ' + e.message)
    const calls = []
    for (let i = 0; i < 3; i += 1) {
      calls.push(run('ssh_exec', { machine: 't', command: 'echo run' + i }))
      calls.push(run('ssh_read', { machine: 't', path: '/c.txt' }))
      calls.push(run('ssh_write', { machine: 't', path: '/w' + i + '.txt', content: 'body' + i }))
    }
    const results = await Promise.all(calls)
    const errors = results.filter((text) => text.startsWith('ERR:'))
    assert.deepEqual(errors, [], 'every concurrent call must succeed')
    assert.equal(results.filter((text) => text.includes('concurrent-file')).length, 3)
    assert.equal(results.filter((text) => /^Wrote \d+ bytes/.test(text)).length, 3)
    assert.equal(results.filter((text) => /\[exit 0\]/.test(text)).length, 3)
    // The log is NDJSON: one record per line, every line parseable. A torn write
    // would make the whole history unreadable for the operator.
    const raw = readFileSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8').split('\n').filter(Boolean)
    assert.equal(raw.length, 9)
    for (const line of raw) JSON.parse(line)
    const kinds = raw.map((line) => JSON.parse(line).kind).sort()
    assert.deepEqual(kinds, ['exec', 'exec', 'exec', 'read', 'read', 'read', 'write', 'write', 'write'])
    // One connection carried all nine: the pool is shared, not per call.
    assert.equal(srv2.clientCount(), 1)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    await Promise.race([srv2.close(), new Promise((r) => setTimeout(r, 1500))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('aborting one call does not disturb a sibling on the same connection', async () => {
  // Cancellation tears down one channel. If it reached the connection instead, the
  // sibling would fail or the pool would be left broken.
  const srv2 = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-cancelsib-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 8000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    const controller = new AbortController()
    const doomed = own.ssh_exec.execute({ machine: 't', command: 'sleep 5' }, { signal: controller.signal })
      .then((r) => String(r.text), (e) => 'ERR: ' + e.message)
    setTimeout(() => controller.abort(), 250)
    const sibling = String((await own.ssh_exec.execute({ machine: 't', command: 'echo sibling' }, {})).text)
    assert.match(sibling, /sibling/)
    const cancelled = await doomed
    assert.match(cancelled, /\[cancelled at the caller request/)
    const after = String((await own.ssh_exec.execute({ machine: 't', command: 'echo after' }, {})).text)
    assert.match(after, /after/, 'the connection survives one cancellation')
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    await Promise.race([srv2.close(), new Promise((r) => setTimeout(r, 1500))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('writing through a symlink chain names where the bytes actually landed', async () => {
  // readlink answers one hop. '/d/hop1' -> '/d/link-file' -> '/d/target.txt' used to
  // report 'a symbolic link to /d/link-file; the content was written there', which
  // is a path that is itself a link: the bytes went to the end of the chain.
  const srv2 = await startServer()
  srv2.vfs.putDir('/d')
  srv2.vfs.putFile('/d/target.txt', Buffer.from('original\n'))
  srv2.vfs.putLink('/d/link-file', '/d/target.txt')
  srv2.vfs.putLink('/d/hop1', '/d/link-file')
  // A relative target names 'next to the link', not a file in some other directory.
  srv2.vfs.putLink('/d/rel-link', 'target.txt')
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-linkchain-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass' } },
    })
    const reply = String((await own.ssh_write.execute({ machine: 't', path: '/d/hop1', content: 'HOP' }, {})).text)
    assert.match(reply, /chain ending at \/d\/target\.txt/)
    assert.match(reply, /the first hop was \/d\/link-file/)
    // The claim must be true: the bytes are in the file at the end of the chain.
    const landed = String((await own.ssh_read.execute({ machine: 't', path: '/d/target.txt', raw: true }, {})).text)
    assert.equal(landed, 'HOP')
    // A single hop keeps its shorter sentence.
    const single = String((await own.ssh_write.execute({ machine: 't', path: '/d/link-file', content: 'ONE' }, {})).text)
    assert.match(single, /symbolic link to \/d\/target\.txt/)
    assert.doesNotMatch(single, /chain ending at/)
    assert.equal(String((await own.ssh_read.execute({ machine: 't', path: '/d/target.txt', raw: true }, {})).text), 'ONE')
    // A single relative hop used to report a chain: the raw target "target.txt" and
    // the resolved "/d/target.txt" were compared as strings, so one hop looked like
    // two and the note named a path relative to nothing in particular.
    const rel = String((await own.ssh_write.execute({ machine: 't', path: '/d/rel-link', content: 'REL' }, {})).text)
    assert.match(rel, /symbolic link to \/d\/target\.txt/)
    assert.doesNotMatch(rel, /chain ending at/)
    assert.equal(String((await own.ssh_read.execute({ machine: 't', path: '/d/target.txt', raw: true }, {})).text), 'REL')
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    await Promise.race([srv2.close(), new Promise((r) => setTimeout(r, 1500))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('the doctor reports sftp on a host that refuses the command channel', async () => {
  // An SFTP-only account is common. The doctor used to stop at [FAIL] shell, so the
  // reader had no way to learn that the file tools work and only ssh_exec does not.
  const ssh2 = (await import('ssh2')).default
  const hostKey = testHostKey()
  const server = new ssh2.Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => ctx.accept())
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept()
        session.on('exec', (acceptExec, rejectExec) => { if (rejectExec) rejectExec() })
        session.on('sftp', (acceptSftp) => {
          const sftp = acceptSftp()
          sftp.on('REALPATH', (reqid) => sftp.name(reqid, [{ filename: '/var/empty', longname: '/var/empty', attrs: {} }]))
          sftp.on('OPENDIR', (reqid) => sftp.handle(reqid, Buffer.from([1, 0, 0, 0])))
          sftp.on('READDIR', (reqid) => sftp.status(reqid, 1))
          sftp.on('CLOSE', (reqid) => sftp.status(reqid, 0))
        })
      })
    })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-doctor-sftponly-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'n', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 4000,
      machines: { n: { host: '127.0.0.1', port, user: 'tester', password: 'x' } },
    })
    const report = String((await own.ssh_doctor.execute({ machine: 'n' }, {})).text)
    assert.match(report, /\[ok\] authentication: connected/)
    assert.match(report, /\[FAIL\] shell: /)
    // The stage that matters for the file tools is still reported.
    assert.match(report, /\[ok\] sftp: subsystem works/)
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    server.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('every doctor run names all seven stages, however early it stops', async () => {
  // A stage that is absent read like a stage that passed. Measured before the fix:
  // a dead port printed configuration/credentials/tcp and nothing else; a rejected
  // host key stopped after 'skip authentication' with shell and sftp simply missing.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-doctor-stages-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'dead', hostKeyPolicy: 'strict', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 2000, commandTimeoutMs: 2000,
      machines: {
        dead: { host: '127.0.0.1', port: 45999, user: 'u', password: 'x' },
        nokey: { host: '127.0.0.1', port: 22, user: 'u', keyPath: '/nonexistent/key' },
      },
    })
    const run = async (alias) => String((await own.ssh_doctor.execute({ machine: alias }, {})).text)
    const expected = ['configuration', 'credentials', 'tcp', 'host key', 'authentication', 'shell', 'sftp']
    for (const alias of ['dead', 'nokey']) {
      const report = await run(alias)
      for (const stage of expected) {
        assert.match(report, new RegExp('^\\[(ok|FAIL|warn|skip)\\] ' + stage + ':', 'm'),
          alias + ' must report the ' + stage + ' stage:\n' + report)
      }
    }
    // A dead port stops before the network stages and says so.
    const deadText = await run('dead')
    assert.match(deadText, /\[FAIL\] tcp:/)
    assert.match(deadText, /\[skip\] shell: not reached: the host is unreachable/)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('the dropped-character count is exact at the maxOutputChars boundary', async () => {
  // 'big N' prints exactly N 'x', so the true length is known: the message can be
  // checked against arithmetic instead of against a guess.
  const own = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-capexact-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own2 = {}
  try {
    await apply({ tools: { register: (d) => { own2[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 8000, maxOutputChars: 1024,
      machines: { t: machineFor('t', own.port) },
    })
    const run = async (n) => String((await own2.ssh_exec.execute({ machine: 't', command: 'big ' + n }, {})).text)
    const exact = await run(1024)
    assert.doesNotMatch(exact, /output truncated/, 'exactly the cap must not truncate')
    assert.equal((exact.match(/(?:^|\n)x+/g) || []).join('').replace(/\n/g, '').length, 1024)

    const one = await run(1025)
    assert.match(one, /\[output truncated at maxOutputChars: 1 more character was dropped from the end/)

    const many = await run(2000)
    assert.match(many, /maxOutputChars: 976 more characters were dropped from the end/)
    // The kept part is the beginning, and it is exactly the cap.
    const body = many.slice(0, many.indexOf('[output truncated'))
    assert.equal((body.match(/x/g) || []).length, 1024)
  } finally {
    try { await own2.ssh_close.execute({ force: true }, {}) } catch {}
    await own.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('timeoutMs: 0 means the configured value, and a negative one is refused', async () => {
  // The parameter description promises '0 = configured value'. That sentence had
  // no test, and it is the kind of promise that rots: a caller passing 0 got the
  // configured timeout, a caller passing -1 got a clear error.
  const own = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-timeoutzero-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own2 = {}
  try {
    await apply({ tools: { register: (d) => { own2[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 8000,
      machines: { t: machineFor('t', own.port) },
    })
    const run = async (args) => String((await own2.ssh_exec.execute({ machine: 't', ...args }, {})).text)
    // 1ms is a real override, so it must time out; 0 must not.
    const tiny = await run({ command: 'sleep 1; echo late', timeoutMs: 1 })
    assert.match(tiny, /timed out after 1ms/)
    const zero = await run({ command: 'echo ontime', timeoutMs: 0 })
    assert.match(zero, /ran: echo ontime/)
    assert.doesNotMatch(zero, /timed out/)
    const negative = await run({ command: 'echo hi', timeoutMs: -1 }).catch((err) => 'ERR: ' + err.message)
    assert.match(negative, /timeoutMs must be a positive number/)
  } finally {
    try { await own2.ssh_close.execute({ force: true }, {}) } catch {}
    await own.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a null host-key record is refused, not treated as never seen', async () => {
  // '!recorded' was true for null, so a hand-edited '{"h:22": null}' read as
  // 'first contact' and a tofu connection overwrote the record the user had.
  const ssh2 = (await import('ssh2')).default
  const own = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-khnull-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  try {
    const dir = path.join(home, 'dsh-ssh-safe')
    mkdirSync(dir, { recursive: true })
    const key = '127.0.0.1:' + own.port
    const file = path.join(dir, 'known_hosts.json')
    writeFileSync(file, JSON.stringify({ version: 1, hosts: { [key]: null } }))
    await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: machineFor('t', own.port) },
    })
    const outcome = await tools.ssh_connect.execute({ machine: 't' }, {}).then(
      (r) => String(r.text), (err) => 'ERR: ' + err.message)
    assert.match(outcome, /Host key verification failed/)
    assert.match(outcome, /is not an object \(null\)/)
    // The store must be untouched: recording here would replace a user's entry.
    const after = JSON.parse(readFileSync(file, 'utf8'))
    assert.equal(after.hosts[key], null)
    // The inventory must not claim the host was never seen.
    const inventory = String((await tools.ssh_machines.execute({}, {})).text)
    assert.match(inventory, /trusted: NO — the recorded entry has no usable fingerprint/)
    assert.doesNotMatch(inventory, /not trusted yet \(no fingerprint recorded\)/)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await own.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a listing says when names had to be escaped', async () => {
  // A name holding a newline or ESC is displayed escaped, so the shown spelling is
  // not a path a caller can pass back. The listing used to say nothing about it.
  const own = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-escnames-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  try {
    own.vfs.putDir('/e')
    own.vfs.putFile('/e/plain.txt', Buffer.from('a'))
    own.vfs.putFile('/e/line\nbreak.txt', Buffer.from('b'))
    own.vfs.putFile('/e/esc\u001b[31mred.txt', Buffer.from('c'))
    await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: machineFor('t', own.port) },
    })
    const out = String((await tools.ssh_list.execute({ machine: 't', path: '/e' }, {})).text)
    // The reply never carries a raw control character.
    assert.doesNotMatch(out, /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/)
    assert.match(out, /line\\nbreak\.txt/)
    assert.match(out, /esc\\x1b\[31mred\.txt/)
    assert.match(out, /\[note\] 2 names were shown escaped/)
    assert.match(out, /printf %q/)
    // A clean directory gets no note.
    own.vfs.putDir('/clean')
    own.vfs.putFile('/clean/only.txt', Buffer.from('x'))
    const clean = String((await tools.ssh_list.execute({ machine: 't', path: '/clean' }, {})).text)
    assert.doesNotMatch(clean, /shown escaped/)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await own.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('lean mode hides the address in ssh_doctor and in every failure path', async () => {
  // machineInventory: 'alias' is a privacy setting: the same conversation must not
  // learn the host and port from a different tool. The success paths were checked
  // when the setting was added; these are the paths that print a network error.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-leandoc-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  const deadPort = 65001
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, machineInventory: 'alias',
      connectTimeoutMs: 2000, commandTimeoutMs: 2000,
      machines: { dead: { host: '203.0.113.77', port: deadPort, user: 'tester', password: 'test-pass' } },
    })
    const doctor = String((await own.ssh_doctor.execute({ machine: 'dead' }, {})).text)
    assert.match(doctor, /\[FAIL\] tcp/)
    assert.match(doctor, /<host hidden>/)
    assert.doesNotMatch(doctor, /203\.0\.113\.77/)
    assert.doesNotMatch(doctor, new RegExp(String(deadPort)))
    assert.doesNotMatch(doctor, /tester/)

    for (const [name, args] of [
      ['ssh_exec', { machine: 'dead', command: 'echo hi' }],
      ['ssh_connect', { machine: 'dead' }],
      ['ssh_list', { machine: 'dead', path: '/' }],
    ]) {
      const out = await own[name].execute(args, {}).then((r) => String(r.text), (err) => 'ERR: ' + err.message)
      assert.doesNotMatch(out, /203\.0\.113\.77/, name + ' leaked the host: ' + out.slice(0, 200))
      assert.doesNotMatch(out, new RegExp(String(deadPort)), name + ' leaked the port')
      assert.match(out, /address hidden|host hidden/, name + ' must say the address is hidden')
    }
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('an empty write is a write, not a missing argument', async () => {
  // content: '' used to read as 'no content given', so a caller could neither create
  // an empty file nor truncate one.
  const own = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-emptywrite-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  try {
    own.vfs.putDir('/e')
    own.vfs.putFile('/e/full.txt', Buffer.from('0123456789'))
    await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: machineFor('t', own.port) },
    })
    const wrote = String((await tools.ssh_write.execute({ machine: 't', path: '/e/new.txt', content: '' }, {})).text)
    assert.match(wrote, /Wrote 0 bytes to \/e\/new\.txt/)
    const read = String((await tools.ssh_read.execute({ machine: 't', path: '/e/new.txt' }, {})).text)
    assert.match(read, /empty file: \/e\/new\.txt /)
    const truncated = String((await tools.ssh_write.execute({ machine: 't', path: '/e/full.txt', content: '' }, {})).text)
    assert.match(truncated, /Wrote 0 bytes to \/e\/full\.txt/)
    assert.match(String((await tools.ssh_read.execute({ machine: 't', path: '/e/full.txt' }, {})).text), /empty file/)
    // The three path-type mistakes still name the right tool.
    const readDir = await tools.ssh_read.execute({ machine: 't', path: '/e' }, {}).then(
      (r) => String(r.text), (err) => 'ERR: ' + err.message)
    assert.match(readDir, /not a file: \/e \(it is a directory; use ssh_list\)/)
    const writeDir = await tools.ssh_write.execute({ machine: 't', path: '/e', content: 'x' }, {}).then(
      (r) => String(r.text), (err) => 'ERR: ' + err.message)
    assert.match(writeDir, /not a file: \/e /)
    const listFile = await tools.ssh_list.execute({ machine: 't', path: '/e/full.txt' }, {}).then(
      (r) => String(r.text), (err) => 'ERR: ' + err.message)
    assert.match(listFile, /not a directory: \/e\/full\.txt \(it is a file; use ssh_read\)/)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await own.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a command cannot forge an audit row with a carriage return', async () => {
  // A lone CR repaints the line a terminal is showing. A command holding one could
  // make the trail look like it recorded something else, so neither the NDJSON file
  // nor ssh_audit may carry the raw byte.
  const own = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-auditcr-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  try {
    await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000, auditLog: true,
      machines: { t: machineFor('t', own.port) },
    })
    await tools.ssh_exec.execute({ machine: 't', command: 'echo ok\rFORGED exec ok exit=0 whoami' }, {})
    const file = path.join(home, 'dsh-ssh-safe', 'audit.ndjson')
    const raw = readFileSync(file, 'utf8')
    // One physical line per record: the CR is stored as the two characters \r.
    assert.equal(raw.split('\n').filter(Boolean).length, 1)
    assert.ok(!raw.includes('\r'), 'the record must not contain a raw CR')
    const record = JSON.parse(raw.trim())
    assert.match(record.command, /^echo ok/)
    const shown = String((await tools.ssh_audit.execute({ limit: 5 }, {})).text)
    assert.ok(!shown.includes('\r'), 'ssh_audit must not print a raw CR')
    assert.match(shown, /echo ok/)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await own.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('an unwritable DSH home is reported by every surface that writes there', async () => {
  // A file where dsh-ssh-safe belongs makes every write fail with ENOTDIR. The
  // audit is not the point: the point is that each tool says so instead of
  // pretending the key was recorded or the workspace was created.
  const own = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-rohome-'))
  writeFileSync(path.join(home, 'dsh-ssh-safe'), 'not a directory')
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  try {
    await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000, auditLog: true,
      machines: { t: machineFor('t', own.port) },
    })
    // A key that cannot be recorded is not silently accepted.
    const connect = await tools.ssh_connect.execute({ machine: 't' }, {}).then(
      (r) => String(r.text), (err) => 'ERR: ' + err.message)
    assert.match(connect, /could not be recorded, so the connection was refused/)
    assert.match(connect, /not the connection/)
    // The audit tool says its own records are missing rather than showing an empty log.
    const audit = String((await tools.ssh_audit.execute({ limit: 5 }, {})).text)
    assert.match(audit, /audit write[s]? failed since the plugin started/)
    assert.match(audit, /these records are incomplete/)
    // The workspace refuses, and names the file that blocks the directory.
    const workspace = await tools.ssh_workspace.execute({ action: 'create', machine: 't' }, {}).then(
      (r) => String(r.text), (err) => 'ERR: ' + err.message)
    assert.match(workspace, /dsh-ssh-safe/)
    assert.match(workspace, /删掉或改名|Cannot|not a directory|already a file/)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await own.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('closing a connection mid-command is refused without force, and said out loud with it', async () => {
  // ssh_close has a force flag precisely because a running command would be cut
  // off. Without it the tool must refuse (and the command must survive); with it the
  // interrupted command has to report that its output is partial.
  const own = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-closemid-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  try {
    await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 8000,
      machines: { t: machineFor('t', own.port) },
    })
    const running = tools.ssh_exec.execute({ machine: 't', command: 'sleep 1' }, {})
    await new Promise((r) => setTimeout(r, 250))
    const plain = String((await tools.ssh_close.execute({ machine: 't' }, {})).text)
    assert.match(plain, /Not closing t: a command is still running on it/)
    assert.match(plain, /pass force: true to cut it off/)
    // The command was not disturbed.
    // The output is 'slept 1' and the status is on the next line.
    const undisturbed = String((await running).text)
    assert.match(undisturbed, /slept 1/)
    assert.match(undisturbed, /\[exit 0\]/)

    const cut = tools.ssh_exec.execute({ machine: 't', command: 'sleep 5' }, {})
    await new Promise((r) => setTimeout(r, 250))
    const forced = String((await tools.ssh_close.execute({ machine: 't', force: true }, {})).text)
    assert.match(forced, /Closed: t/)
    const partial = await cut.then((r) => String(r.text), (err) => 'ERR: ' + err.message)
    assert.match(partial, /connection closed before the command reported an exit status/)
    assert.match(partial, /the output above is partial/)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await own.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('an alias with a newline cannot forge a listing line or split an audit row', async () => {
  // A settings-form key can hold anything JSON accepts. The listing escapes the
  // alias (\\n stays escaped) and the audit row keeps it inside one JSON string,
  // so neither a fake 'WARNING' line nor a second record can be produced.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-aliasnl-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const evil = 'evil\n  WARNING  forged line'
  const tools = {}
  try {
    await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0, auditLog: true,
      machines: JSON.parse(JSON.stringify({
        [evil]: { host: '127.0.0.1', port: 1, user: 'nobody', password: 'x' },
        plain: { host: '127.0.0.1', port: 1, user: 'nobody', password: 'x' },
      })),
    })
    const listing = String((await tools.ssh_machines.execute({}, {})).text)
    assert.doesNotMatch(listing, /^\s*WARNING\s+forged line/m, 'the alias produced a line of its own')
    assert.match(listing, /evil\\n\s+warning\s+forged line/)

    // The dangerous-command guard refuses before connecting, so this writes a
    await assert.rejects(() => tools.ssh_exec.execute({ machine: evil, command: 'rm -rf /' }, {}))
    const rows = readFileSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8').trim().split('\n')
    assert.ok(rows.length >= 1, 'no audit row was written')
    for (const row of rows) assert.doesNotThrow(() => JSON.parse(row), 'a newline split the record: ' + row)
    const machines = rows.map((row) => JSON.parse(row)).map((r) => r.machine)
    // The plugin normalises aliases to lower case, so compare that way; the point
    // is the escaping, not the case.
    assert.ok(
      machines.some((m) => typeof m === 'string' && m.toLowerCase() === evil.toLowerCase()),
      'the alias is stored escaped, in one row: ' + JSON.stringify(machines),
    )
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('ssh_write refuses content with an unpaired surrogate instead of writing a replacement character', async () => {
  // Buffer.from('a\\uD800b') silently becomes 'a\\uFFFDb': five bytes, none of them
  // the ones the caller passed. The tool refuses instead, and the index is named.
  srv.vfs.putDir('/tmp')
  for (const [label, content] of [
    ['high', 'a\uD800b'],
    ['low', 'a\uDC00b'],
  ]) {
    const file = '/tmp/surrogate-' + label + '.txt'
    await assert.rejects(
      () => tools.ssh_write.execute({ machine: 't', path: file, content }, {}),
      (err) => {
        assert.match(err.message, /unpaired UTF-16 surrogate at index 1/)
        assert.match(err.message, /stored as U\+FFFD instead/)
        return true
      },
    )
    await assert.rejects(
      () => tools.ssh_read.execute({ machine: 't', path: file }, {}),
      /no such file/,
      'the refused write left a file behind',
    )
  }

  // A valid pair is one character and must still be written as four bytes.
  const ok = String((await tools.ssh_write.execute({ machine: 't', path: '/tmp/emoji.txt', content: 'a\uD83D\uDE00b' }, {})).text)
  assert.match(ok, /Wrote 6 bytes/)
  assert.equal(String((await tools.ssh_read.execute({ machine: 't', path: '/tmp/emoji.txt' }, {})).text), 'a\uD83D\uDE00b')
})

test('a read that asked for more than the config ceiling says it was clamped', async () => {
  // maxBytes can only tighten maxFileBytes. Asking for 5000 with a 1024 ceiling used
  // to report 1024 bytes and advise raising maxFileBytes, as if the 5000 had never
  // been mentioned; the clamp is now named.
  // This file's config keeps the default ceiling, 1 MiB, so the file has to be bigger.
  srv.vfs.putFile('/tmp/large.txt', 'x'.repeat(1100000))
  const clamped = String((await tools.ssh_read.execute({ machine: 't', path: '/tmp/large.txt', maxBytes: 2000000 }, {})).text)
  assert.match(clamped, /\[truncated: the first 1048576 bytes of a larger file/)
  assert.match(clamped, /this call asked for up to 2000000 bytes, but maxFileBytes is 1048576/)

  // Exactly the ceiling is not a clamp, and a tighter call keeps its own advice.
  const exact = String((await tools.ssh_read.execute({ machine: 't', path: '/tmp/large.txt', maxBytes: 1048576 }, {})).text)
  assert.doesNotMatch(exact, /this call asked for up to/)
  assert.match(exact, /raise maxFileBytes in the plugin config/)
  const tighter = String((await tools.ssh_read.execute({ machine: 't', path: '/tmp/large.txt', maxBytes: 10 }, {})).text)
  assert.match(tighter, /raise maxBytes in this call/)
})

test('the workspace list hint names the precondition create enforces', async () => {
  // The hint said 'use action: "create" to rebuild' for a marker-less directory,
  // but create refuses one that holds files the plugin did not write — so the
  // advice failed for exactly the directories a user is likely to have.
  const foreign = path.join(home, 'dsh-ssh-safe', 'remotes', 't')
  mkdirSync(foreign, { recursive: true })
  writeFileSync(path.join(foreign, 'keep.txt'), 'x')
  try {
    const listed = String((await tools.ssh_workspace.execute({ action: 'list' }, {})).text)
    assert.match(listed, /目录为空时可用 action: "create" 重建/)
    assert.match(listed, /create 会拒绝/)
    await assert.rejects(
      () => tools.ssh_workspace.execute({ action: 'create', machine: 't' }, {}),
      /本插件没有创建的内容/,
    )
    assert.ok(existsSync(path.join(foreign, 'keep.txt')), 'the user file must survive the refusal')
  } finally {
    rmSync(foreign, { recursive: true, force: true })
  }
})

test('a cancelled call is audited as cancel, not as an error', async () => {
  // README lists 'cancel' as one of the outcomes, and outcomeOf() is the only
  // place that decides it. Nothing asserted the recorded value, so a regression
  // to 'error' would have been invisible: an operator filtering for cancelled
  // calls would see nothing, and 'error' reads as a failure of the remote host.
  // The log may not exist yet when this test runs alone, so read it defensively.
  const readRows = () => {
    const file = path.join(home, 'dsh-ssh-safe', 'audit.ndjson')
    return existsSync(file) ? readFileSync(file, 'utf8').trim().split('\n').filter(Boolean) : []
  }
  const before = readRows().length
  const controller = new AbortController()
  setTimeout(() => controller.abort(), 100)
  // A cancelled exec resolves with a labelled result (like a timeout or a
  // signal); only failures reject.
  const cancelled = String((await tools.ssh_exec.execute({ machine: 't', command: 'sleep 2' }, { signal: controller.signal })).text)
  assert.match(cancelled, /cancelled at the caller request/)
  const rows = readFileSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8').trim().split('\n').filter(Boolean)
  assert.ok(rows.length > before, 'the cancelled call wrote no record')
  const record = JSON.parse(rows[rows.length - 1])
  assert.equal(record.kind, 'exec')
  assert.equal(record.outcome, 'cancel')
  assert.equal(record.error, undefined, 'a cancelled call is not an error of the host')
})

test('a hand-edited audit row renders its fields instead of [object Object]', async () => {
  // ssh_audit is where an operator goes to see what happened, and the log is a
  // file a human may edit. printable() turns an object into '[object Object]',
  // which lost the content; object fields are clipped JSON now, and a rule whose
  // text is missing says so instead of printing empty parentheses.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-auditreg-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const dir = path.join(home, 'dsh-ssh-safe')
    mkdirSync(dir, { recursive: true })
    const rows = [
      { kind: 'exec', outcome: 'ok', command: { a: 1 }, machine: ['x'] },
      { kind: 'refused', outcome: 'blocked', command: 'rm -rf /', pattern: [] },
    ]
    writeFileSync(path.join(dir, 'audit.ndjson'), rows.map((r) => JSON.stringify(r)).join('\n') + '\n')
    const tools = {}
    await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      hostKeyPolicy: 'tofu', auditLog: true,
    })
    const shown = String((await tools.ssh_audit.execute({ limit: 10 }, {})).text)
    assert.doesNotMatch(shown, /\[object Object\]/, 'an object field was flattened to [object Object]')
    assert.match(shown, /\{"a":1\}/)
    assert.match(shown, /the rule text is not available/)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('closing a machine while it is still dialling is recorded as pending', async () => {
  // ssh_close has three answers beyond ok: pending (still dialling), busy (a
  // command is running) and none (nothing live). The pending one decides the
  // 'close as soon as it completes' path, and nothing covered it: a silent TCP
  // peer keeps the connection in that state for as long as the test needs.
  const silent = net.createServer((socket) => { socket.on('error', () => {}) })
  await new Promise((resolve) => silent.listen(0, '127.0.0.1', resolve))
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-pending-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      allowPlaintextPassword: true, hostKeyPolicy: 'off', auditLog: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 1000, commandTimeoutMs: 1000,
      machines: { s: { host: '127.0.0.1', port: silent.address().port, user: 'u', password: 'p' } },
    })
    const dialling = own.ssh_exec.execute({ machine: 's', command: 'echo hi' }, {})
    await new Promise((resolve) => setTimeout(resolve, 150))
    const said = String((await own.ssh_close.execute({ machine: 's', force: true }, {})).text)
    assert.match(said, /still being established/)
    assert.match(said, /closed as soon as it completes/)
    const dialled = await dialling.then(() => 'resolved', (err) => 'ERR: ' + err.message)
    assert.match(dialled, /Timed out while waiting for handshake/)
    const rows = readFileSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'), 'utf8').trim().split('\n').map((line) => JSON.parse(line))
    const close = rows.filter((row) => row.kind === 'close').pop()
    assert.equal(close.outcome, 'pending')
    const again = String((await own.ssh_close.execute({ machine: 's', force: true }, {})).text)
    assert.match(again, /No live connection/)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    silent.close()
    rmSync(home, { recursive: true, force: true })
  }
})

test('every close row carries a duration, whatever it decided', async () => {
  // close is the one kind an operator cannot time, and the rows for 'left open
  // because a command runs' and 'nothing to close' were written without ms even after
  // the closed rows got one.
  const srv2 = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-closems-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'a', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000, auditLog: true,
      machines: { a: machineFor('a', srv2.port), b: machineFor('b', srv2.port) },
    })
    const run = async (promise) => { try { await promise } catch { /* the point is the audit row */ } }
    // none: nothing is live yet
    await run(own.ssh_close.execute({ machine: 'a' }, {}))
    await run(own.ssh_connect.execute({ machine: 'a' }, {}))
    await run(own.ssh_connect.execute({ machine: 'b' }, {}))
    // ok: one machine, then everything
    await run(own.ssh_close.execute({ machine: 'a' }, {}))
    await run(own.ssh_close.execute({}, {}))
    // busy: a command runs on a and close-all is asked without force
    await run(own.ssh_connect.execute({ machine: 'a' }, {}))
    const running = own.ssh_exec.execute({ machine: 'a', command: 'sleep 1' }, {})
    await new Promise((resolve) => setTimeout(resolve, 150))
    await run(own.ssh_close.execute({}, {}))
    await run(running)
    const file = path.join(home, 'dsh-ssh-safe', 'audit.ndjson')
    const rows = readFileSync(file, 'utf8').trim().split('\n').map((line) => JSON.parse(line))
    const closes = rows.filter((row) => row.kind === 'close')
    assert.ok(closes.length >= 4, 'the four decisions must all be recorded, saw ' + closes.length)
    const outcomes = new Set(closes.map((row) => row.outcome))
    for (const expected of ['none', 'ok', 'busy']) assert.ok(outcomes.has(expected), 'missing outcome ' + expected)
    for (const row of closes) {
      assert.equal(typeof row.ms, 'number', 'close row without ms: ' + JSON.stringify(row))
    }
    // Nothing may keep the loop alive after the assertions: the busy connection was
    // left open on purpose, and an open socket makes 'node --test' wait forever.
    await run(own.ssh_close.execute({ machine: 'a', force: true }, {}))
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    await Promise.race([srv2.close(), new Promise((resolve) => setTimeout(resolve, 1000))])
    rmSync(home, { recursive: true, force: true })
  }
})

test('an over-cap pool says which kind of over it is', async () => {
  // maxConnections is a keep-alive cap: two calls in flight hold two connections and
  // the pool trims back on the next acquire. ssh_config printed '2 / 1 max' with no
  // note at all once the burst ended, because the note required a BUSY extra — the
  // line read as a broken limit.
  const srv2 = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-maxconn-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 'a', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000, maxConnections: 1,
      machines: { a: machineFor('a', srv2.port), b: machineFor('b', srv2.port) },
    })
    const live = async () => String((await own.ssh_config.execute({}, {})).text)
      .split('\n').find((line) => line.includes('Live connections')) || ''
    const running = Promise.all(['a', 'b'].map((m) => own.ssh_exec.execute({ machine: m, command: 'sleep 1' }, {})
      .catch(() => ({ text: '' }))))
    let during = ''
    for (let i = 0; i < 30; i += 1) {
      during = await live()
      if (/over the limit: the extra ones are running a command/.test(during)) break
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
    assert.match(during, /2 \/ 1 max  \(over the limit: the extra ones are running a command/)
    await running
    const after = await live()
    assert.match(after, /(2 \/ 1 max  \(over the limit: it is trimmed when the next call needs a slot\)|1 \/ 1 max)/)
    await own.ssh_exec.execute({ machine: 'b', command: 'echo hi' }, {}).catch(() => ({ text: '' }))
    const trimmed = await live()
    assert.match(trimmed, /1 \/ 1 max/)
    assert.doesNotMatch(trimmed, /over the limit/)
  } finally {
    await own.ssh_close.execute({ force: true }, {}).catch(() => {})
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    await Promise.race([srv2.close(), new Promise((resolve) => setTimeout(resolve, 1000))])
    rmSync(home, { recursive: true, force: true })
  }
})

test('a gate refusal names which direction it stopped', async () => {
  // The row ended with a bare 'read from', which read as a cut-off sentence:
  // 'reason=execGuard is "confirm" and confirm was not passed  read from'.
  const srv2 = await startServer()
  const home2 = mkdtempSync(path.join(tmpdir(), 'dsh-gate-audit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home2
  const own = {}
  const ctx2 = {
    tools: { register: (def) => { own[def.name] = def } },
    effect: () => {},
    get: () => undefined,
  }
  try {
    await apply(ctx2, {
      defaultMachine: 't', allowPlaintextPassword: true, hostKeyPolicy: 'tofu', auditLog: true,
      execGuard: 'confirm', reconnectCooldownMs: 0, connectTimeoutMs: 3000, commandTimeoutMs: 3000,
      machines: { t: machineFor('t', srv2.port) },
    })
    await assert.rejects(() => own.ssh_read.execute({ path: '/etc/passwd' }, {}), /execGuard is "confirm"/)
    await assert.rejects(() => own.ssh_write.execute({ path: '/tmp/x', content: 'x' }, {}), /execGuard is "confirm"/)
    const shown = String((await own.ssh_audit.execute({}, {})).text)
    assert.match(shown, /reason=execGuard is "confirm" and confirm was not passed  direction=read from/,
      'the read gate must be labelled: ' + shown.slice(0, 400))
    assert.match(shown, /direction=write to/, 'the write gate must be labelled: ' + shown.slice(0, 400))
    assert.doesNotMatch(shown, /not passed  read from/, 'the bare fragment must be gone')
  } finally {
    await own.ssh_close.execute({ force: true }, {}).catch(() => {})
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    await Promise.race([srv2.close(), new Promise((resolve) => setTimeout(resolve, 1000))])
    rmSync(home2, { recursive: true, force: true })
  }
})

test('a per-machine host key policy is what the reply reports', async () => {
  // The connect reply tested the GLOBAL policy: a machine set to 'off' under a
  // global 'tofu' printed a fingerprint line with no man-in-the-middle warning,
  // exactly like a verified connection. A typo ('stict') was ignored silently.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-policy-reply-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  const srv2 = await startServer()
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
      offbox: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass', hostKeyPolicy: 'off' },
      typo: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass', hostKeyPolicy: 'stict' },
      spaced: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass', hostKeyPolicy: ' OFF ' },
    }), 'utf8')
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
    })
    const attempt = async (promise) => {
      try { return String((await promise).text) } catch (err) { return 'ERR: ' + err.message }
    }
    const off = await attempt(own.ssh_connect.execute({ machine: 'offbox' }, {}))
    assert.match(off, /WARNING: the host key policy in effect is "off"/, off)
    const typo = await attempt(own.ssh_connect.execute({ machine: 'typo' }, {}))
    assert.match(typo, /sets hostKeyPolicy to "stict", which is not one of strict \| tofu \| off, so the global "tofu" was used/, typo)
    // Trimmed and lower-cased values are accepted, so no typo warning for them.
    const spaced = await attempt(own.ssh_connect.execute({ machine: 'spaced' }, {}))
    assert.doesNotMatch(spaced, /is not one of strict/, spaced)
    assert.match(spaced, /the host key policy in effect is "off"/, spaced)
    // The listing says the same thing without connecting.
    const listed = String((await own.ssh_machines.execute({}, {})).text)
    assert.match(listed, /hostKeyPolicy: stict  \(not one of strict \| tofu \| off, so the global "tofu" is used\)/)
    assert.doesNotMatch(listed, /hostKeyPolicy: " OFF "  \(not one of/)
  } finally {
    await own.ssh_close.execute({ force: true }, {}).catch(() => {})
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    await Promise.race([srv2.close(), new Promise((resolve) => setTimeout(resolve, 1000))])
    rmSync(home, { recursive: true, force: true })
  }
})

test('the doctor names a per-machine policy it had to ignore', async () => {
  // The stages use the effective policy, which is right, but nothing said the value
  // the user typed was never used. A padded but valid value must not be flagged.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-doc-policy-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  const srv2 = await startServer()
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
      typo: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass', hostKeyPolicy: 'stict' },
      spaced: { host: '127.0.0.1', port: srv2.port, user: 'tester', password: 'test-pass', hostKeyPolicy: ' OFF ' },
    }), 'utf8')
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 3000,
    })
    const typo = String((await own.ssh_doctor.execute({ machine: 'typo' }, {})).text)
    assert.match(typo,
      /\[warn\] configuration: hostKeyPolicy "stict" is not one of strict \| tofu \| off, so the global "tofu" is used/)
    const spaced = String((await own.ssh_doctor.execute({ machine: 'spaced' }, {})).text)
    assert.doesNotMatch(spaced, /is not one of strict/, 'a padded valid value must not be flagged: ' + spaced)
    // The connection really used it: the host key line is the policy-off warning.
    assert.match(spaced, /\[warn\] host key: NOT verified: hostKeyPolicy is "off"/)
  } finally {
    await own.ssh_close.execute({ force: true }, {}).catch(() => {})
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    await Promise.race([srv2.close(), new Promise((resolve) => setTimeout(resolve, 1000))])
    rmSync(home, { recursive: true, force: true })
  }
})

test('a key path with control characters is escaped, and its backslashes are not doubled', async () => {
  // keyPath is a local path and comes from a hand-editable file. The messages
  // printed it raw (a NUL and an ANSI escape reached the terminal), and printable()
  // would have doubled every Windows backslash, which is why printableText() is
  // the right escaper here.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-keypath-esc-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    const evil = path.join(home, 'k\u0000\u001b[31mred')
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
      esc: { host: '127.0.0.1', port: srv.port, user: 'tester', keyPath: evil },
    }), 'utf8')
    await apply({ tools: { register: (d) => { own[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 2000, commandTimeoutMs: 2000,
    })
    const attempt = async (promise) => {
      try { return String((await promise).text) } catch (err) { return 'ERR: ' + err.message }
    }
    const connect = await attempt(own.ssh_connect.execute({ machine: 'esc' }, {}))
    assert.doesNotMatch(connect, /\u0000|\u001b/, 'no raw control character: ' + JSON.stringify(connect))
    assert.match(connect, /\\x00\\x1b\[31mred/, 'the path is shown, escaped')
    // A doubled backslash would mean the whole path was mangled.
    assert.ok(connect.includes(home), 'the local path must stay readable: ' + connect)

    const doctor = String((await own.ssh_doctor.execute({ machine: 'esc' }, {})).text)
    assert.doesNotMatch(doctor, /\u0000|\u001b/, 'the doctor line must be escaped too: ' + JSON.stringify(doctor))
    assert.ok(doctor.includes(home), 'the doctor path must stay readable')
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a burst of connects leaves one client, and close with no machine closes both', async () => {
  // Two properties that only show up against a real server: a connect storm must
  // not leave orphaned clients behind (each is a socket and a session), and
  // ssh_close with no machine must really close every machine.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-burst-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const first = await startServer()
  const second = await startServer()
  const tools = {}
  const ctx = { tools: { register: (def) => { tools[def.name] = def } }, effect: () => {}, get: () => undefined }
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    const one = machineFor('alpha', first.port)
    const two = machineFor('beta', second.port)
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
      alpha: { host: one.host, port: one.port, user: one.user, password: one.password },
      beta: { host: two.host, port: two.port, user: two.user, password: two.password },
    }), 'utf8')
    await apply(ctx, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 4000, commandTimeoutMs: 4000,
    })

    const replies = await Promise.all(Array.from({ length: 6 }, () =>
      tools.ssh_connect.execute({ machine: 'alpha', force: true }, {}).then((r) => String(r.text), (err) => 'ERR: ' + err.message)))
    assert.equal(replies.filter((text) => /Connected/.test(text)).length, 6)
    await new Promise((resolve) => setTimeout(resolve, 300))
    assert.equal(first.clientCount(), 1, 'a connect storm must not leave orphaned clients')
    assert.match(String((await tools.ssh_exec.execute({ machine: 'alpha', command: 'echo after' }, {})).text), /ran: echo after/)

    await tools.ssh_exec.execute({ machine: 'beta', command: 'echo b' }, {})
    const closed = String((await tools.ssh_close.execute({}, {})).text)
    assert.match(closed, /alpha/)
    assert.match(closed, /beta/)
    await new Promise((resolve) => setTimeout(resolve, 300))
    assert.equal(first.clientCount(), 0)
    assert.equal(second.clientCount(), 0)
    assert.match(String((await tools.ssh_close.execute({}, {})).text), /No live connections/)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    await Promise.race([first.close(), new Promise((resolve) => setTimeout(resolve, 1000))])
    await Promise.race([second.close(), new Promise((resolve) => setTimeout(resolve, 1000))])
    rmSync(home, { recursive: true, force: true })
  }
})

test('a per-call timeout above commandTimeoutMs wins, and omitting it uses the configured one', async () => {
  // 'timeoutMs overrides commandTimeoutMs' is what the parameter promises; the
  // opposite (a global cap that a caller cannot lift) would make long jobs
  // impossible without editing the plugin config.
  const own = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-timeout-override-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  try {
    await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 3000, commandTimeoutMs: 1000,
      machines: { t: machineFor('t', own.port) },
    })
    const run = async (args) => String((await tools.ssh_exec.execute({ machine: 't', ...args }, {})).text)
    // The configured 1000 ms applies when the caller says nothing.
    const implicit = await run({ command: 'sleep 2' })
    assert.match(implicit, /timed out after 1000ms/)
    // A larger per-call value lifts it: 2 s of sleep against a 1 s default.
    const explicit = await run({ command: 'sleep 2', timeoutMs: 6000 })
    assert.doesNotMatch(explicit, /timed out/)
    assert.match(explicit, /\[exit 0\]/)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await own.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a password sent with the call is not used silently when the config forbids it', async () => {
  // allowSessionPassword defaults to off. A caller that passes `password` then got
  // the stored credential and a plain success — which reads as 'my password
  // worked'. The note names the setting; it must also survive redact(), so it
  // cannot be written as 'allowSessionPassword: true' (that looks like a secret
  // assignment and came out as '<redacted>').
  const own = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-session-off-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  const ctx = { tools: { register: (def) => { tools[def.name] = def } }, effect: () => {}, get: () => undefined }
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    const machine = machineFor('box', own.port)
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
      box: { host: machine.host, port: machine.port, user: machine.user, password: machine.password },
    }), 'utf8')
    await apply(ctx, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, allowSessionPassword: false,
      reconnectCooldownMs: 0, connectTimeoutMs: 4000, commandTimeoutMs: 4000,
    })
    const text = String((await tools.ssh_exec.execute({ machine: 'box', command: 'echo hi', password: 'typed-by-caller' }, {})).text)
    assert.match(text, /ran: echo hi/)
    assert.match(text, /allowSessionPassword is off/, 'the caller must be told: ' + text)
    assert.doesNotMatch(text, /<redacted>/, 'the note must not be mangled by redaction: ' + text)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await own.close()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a rejected connection says the session password was shadowed', async () => {
  // The stored password was stale and the one supplied with the call would have
  // worked, but a session password is the last resort. The failure named the
  // credentials in general and stopped there, so the caller had no reason to look
  // at the stored value.
  const server = await startServer({ password: 'the-right-one' })
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-session-shadow-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  const ctx = { tools: { register: (def) => { tools[def.name] = def } }, effect: () => {}, get: () => undefined }
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
      box: { host: '127.0.0.1', port: server.port, user: 'tester', password: 'stale-stored' },
    }), 'utf8')
    await apply(ctx, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, allowSessionPassword: true,
      reconnectCooldownMs: 0, connectTimeoutMs: 3000, commandTimeoutMs: 3000,
    })
    const text = String(await tools.ssh_exec.execute({ machine: 'box', command: 'echo hi', password: 'the-right-one' }, {})
      .then((result) => result.text, (err) => 'ERR: ' + err.message))
    assert.match(text, /this attempt offered file-password/, 'the offered credential is named: ' + text)
    assert.match(text, /a session password came with this call, but a stored credential was used instead/,
      'the shadowed password must be reported: ' + text)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await Promise.race([server.close(), new Promise((resolve) => setTimeout(resolve, 800))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('confirm: true opens the confirm gate and never the deny list', async () => {
  // Four cells, and the one that matters is the second: a caller who passes
  // confirm: true must still be refused by a deny pattern. A gate that a flag can
  // open is not a deny list.
  const server = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-guard-matrix-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  const ctx = { tools: { register: (def) => { tools[def.name] = def } }, effect: () => {}, get: () => undefined }
  try {
    await apply(ctx, {
      defaultMachine: 't', hostKeyPolicy: 'tofu', allowPlaintextPassword: true, execGuard: 'confirm',
      reconnectCooldownMs: 0, connectTimeoutMs: 4000, commandTimeoutMs: 4000,
      machines: { t: machineFor('t', server.port) },
    })
    const text = async (args) => String(await tools.ssh_exec.execute(args, {})
      .then((result) => result.text, (err) => 'ERR: ' + err.message))

    assert.match(await text({ command: 'rm -rf /' }), /Command refused/)
    // The one that matters: confirm does not unlock a deny pattern.
    assert.match(await text({ command: 'rm -rf /', confirm: true }), /Command refused/,
      'confirm must not bypass the deny list')
    assert.match(await text({ command: 'echo gated' }), /execGuard is "confirm"/)
    assert.match(await text({ command: 'echo gated', confirm: true }), /ran: echo gated/)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await Promise.race([server.close(), new Promise((resolve) => setTimeout(resolve, 800))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('machineInventory: alias keeps the address out of a host-key verdict', async () => {
  // hostkey.js answers a missing known_hosts entry with host, port and file path:
  // 'Unknown host 127.0.0.1:3982 … ssh-keyscan -p 3982 127.0.0.1 >> "…/kh-secret"'. The
  // setting promises exactly those three values stay out of the transcript.
  const server = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-lean-hostkey-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const knownHosts = path.join(home, 'kh-secret164')
  const tools = {}
  const ctx = { tools: { register: (def) => { tools[def.name] = def } }, effect: () => {}, get: () => undefined }
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    writeFileSync(knownHosts, '')
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
      box: { host: '127.0.0.1', port: server.port, user: 'testuser164', password: 'pw164', knownHosts },
    }), 'utf8')
    await apply(ctx, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, machineInventory: 'alias',
      reconnectCooldownMs: 0, connectTimeoutMs: 4000, commandTimeoutMs: 4000,
    })
    const text = String(await tools.ssh_doctor.execute({ machine: 'box' }, {})
      .then((r) => r.text, (err) => 'ERR: ' + err.message))
    assert.match(text, /Unknown host <host hidden>/, text)
    assert.doesNotMatch(text, /127\.0\.0\.1/, 'the host must be hidden: ' + text)
    assert.doesNotMatch(text, new RegExp('\\b' + server.port + '\\b'), 'the port must be hidden: ' + text)
    assert.doesNotMatch(text, /kh-secret164/, 'the known_hosts path must be hidden: ' + text)
    assert.match(text, /<path hidden>/, text)
    // The advice has to stay useful without the values.
    assert.match(text, /ssh-keyscan/, text)
    assert.match(text, /trustHostKey: true/, text)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await Promise.race([server.close(), new Promise((resolve) => setTimeout(resolve, 800))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('mode accepts the spellings people type and refuses the rest', async () => {
  // Measured: ' 644' and '0644 ' are trimmed, '0o644' is read as octal, '777'
  // means 0777, and 'abc' / '9' / '07777' / '0x1ff' are refused with a message that
  // names the accepted shape. Nothing is written when the mode is refused.
  srv.vfs.putDir('/modes')
  const written = async (name, mode) => run('ssh_write', { path: '/modes/' + name, content: 'x', mode })
  const modeOf = (name) => (srv.vfs.stat('/modes/' + name).mode & 0o7777).toString(8).padStart(4, '0')

  await written('trimmed', ' 644')
  assert.equal(modeOf('trimmed'), '0644', 'surrounding spaces are trimmed')
  await written('trailing', '0644 ')
  assert.equal(modeOf('trailing'), '0644')
  await written('prefixed', '0o600')
  assert.equal(modeOf('prefixed'), '0600')
  await written('three-digit', '777')
  assert.equal(modeOf('three-digit'), '0777')

  for (const bad of ['abc', '9', '07777', '0x1ff']) {
    await assert.rejects(() => written('bad-' + bad.replace(/\W/g, ''), bad),
      /mode must be octal digits like "600" or "0644"/)
    assert.equal(srv.vfs.getFile('/modes/bad-' + bad.replace(/\W/g, '')), undefined,
      'nothing may be written for a refused mode: ' + bad)
  }
})

test('exactly maxListEntries entries is not reported as truncated', async () => {
  // The off-by-one that matters: at cap-1, cap and cap+1 entries the reply must
  // show 2, 3 and 3 rows, and only the last one may mention anything hidden.
  // The fixture's own cap is 2000, so this runs its own plugin instance at 3.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-list-fit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const own = {}
  try {
    await apply(
      { tools: { register: (def) => { own[def.name] = def } }, effect: () => {}, get: () => undefined },
      {
        hostKeyPolicy: 'tofu', allowPlaintextPassword: true, maxListEntries: 3,
        reconnectCooldownMs: 0, connectTimeoutMs: 4000, commandTimeoutMs: 4000,
        machines: { box: machineFor('box', srv.port) },
      },
    )
    for (const count of [2, 3, 4]) {
      const dir = '/fit' + count
      srv.vfs.putDir(dir)
      for (let i = 0; i < count; i++) srv.vfs.putFile(dir + '/f' + i + '.txt', 'x')
      const text = String((await own.ssh_list.execute({ machine: 'box', path: dir }, {})).text)
      const rows = (text.match(/f\d\.txt/g) || []).length
      assert.equal(rows, Math.min(count, 3), 'row count for ' + count + ' entries: ' + text)
      if (count <= 3) assert.doesNotMatch(text, /more entries not shown/, 'nothing is hidden at ' + count + ': ' + text)
      else assert.match(text, /1 more entry not shown \(maxListEntries = 3\)/, text)
    }
  } finally {
    try { await own.ssh_close.execute({ force: true }, {}) } catch {}
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('the doctor keeps a trusted knownHosts path out of the reply in lean mode', async () => {
  // The failure path was fixed in 0.7.373; this is the success-only line
  // ('[ok] host key: SHA256:… (against <path>)'), reachable only when the key is
  // already trusted. Measured: it printed C:\…\kh-secret167 under
  // machineInventory: 'alias'.
  const server = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-doctor-kh-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const knownHosts = path.join(home, 'kh-secret167')
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    // The OpenSSH file the plugin verifies but never writes: fill it in by hand.
    const parsed = ssh2.utils.parseKey(testHostKey())
    writeFileSync(knownHosts, '[127.0.0.1]:' + server.port + ' ssh-rsa ' +
      parsed.getPublicSSH().toString('base64') + '\n', 'utf8')
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
      box: { host: '127.0.0.1', port: server.port, user: 'tester', password: 'test-pass', knownHosts },
    }), 'utf8')

    const lean = {}
    await apply({ tools: { register: (def) => { lean[def.name] = def } }, effect: () => {}, get: () => undefined }, {
      hostKeyPolicy: 'strict', allowPlaintextPassword: true, machineInventory: 'alias',
      reconnectCooldownMs: 0, connectTimeoutMs: 4000, commandTimeoutMs: 4000,
    })
    const text = String(await lean.ssh_doctor.execute({ machine: 'box' }, {})
      .then((r) => r.text, (err) => 'ERR: ' + err.message))
    assert.match(text, /\[ok\] host key: SHA256:\S+ \(against <path hidden>\)/, text)
    assert.doesNotMatch(text, /kh-secret167/, 'the path must not appear: ' + text)
    await lean.ssh_close.execute({ force: true }, {}).catch(() => {})

    const full = {}
    await apply({ tools: { register: (def) => { full[def.name] = def } }, effect: () => {}, get: () => undefined }, {
      hostKeyPolicy: 'strict', allowPlaintextPassword: true, machineInventory: 'full',
      reconnectCooldownMs: 0, connectTimeoutMs: 4000, commandTimeoutMs: 4000,
    })
    const shown = String((await full.ssh_doctor.execute({ machine: 'box' }, {})).text)
    assert.match(shown, /\(against .*kh-secret167\)/, 'full mode still names the file: ' + shown)
    await full.ssh_close.execute({ force: true }, {}).catch(() => {})
  } finally {
    await Promise.race([server.close(), new Promise((resolve) => setTimeout(resolve, 800))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('hostKeyPolicy off verifies nothing and records nothing', async () => {
  // 'off' accepts any key, so a fingerprint in the reply must never stand alone,
  // and the plugin must not write the key into its store: that would launder an
  // unverified key into a 'first contact: recorded' on the next connection.
  const server = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-off168-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  const ctx = { tools: { register: (def) => { tools[def.name] = def } }, effect: () => {}, get: () => undefined }
  try {
    await apply(ctx, {
      hostKeyPolicy: 'off', allowPlaintextPassword: true,
      reconnectCooldownMs: 0, connectTimeoutMs: 4000, commandTimeoutMs: 4000,
      machines: { box: machineFor('box', server.port) },
    })
    const text = String((await tools.ssh_connect.execute({ machine: 'box' }, {})).text)
    assert.match(text, /Host key: SHA256:/, text)
    assert.match(text, /WARNING: the host key policy in effect is "off"/, text)
    assert.equal(existsSync(path.join(home, 'dsh-ssh-safe', 'known_hosts.json')), false,
      'nothing may be recorded under hostKeyPolicy: off')

    const doctor = String((await tools.ssh_doctor.execute({ machine: 'box' }, {})).text)
    assert.match(doctor, /\[warn\] host key: NOT verified: hostKeyPolicy is "off"/, doctor)
    assert.doesNotMatch(doctor, /\[ok\] host key/, 'the doctor must not call it verified: ' + doctor)
    await tools.ssh_close.execute({ force: true }, {}).catch(() => {})
  } finally {
    await Promise.race([server.close(), new Promise((resolve) => setTimeout(resolve, 800))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('an unusable host-key store says which path, which code and which side failed', async () => {
  // A file where the state directory belongs makes every store write fail. The
  // message has to name the path and the errno, say the connection was refused, and
  // not blame the remote host; under machineInventory: 'alias' the path is hidden.
  // (The read branch is POSIX-only: Windows answers EEXIST from the write instead.)
  const server = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-store-fail-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  writeFileSync(path.join(home, 'dsh-ssh-safe'), 'not a directory', 'utf8')
  const text = async (tools, args) => String(await tools.ssh_connect.execute(args, {})
    .then((r) => r.text, (err) => 'ERR: ' + err.message))
  try {
    const lean = {}
    await apply({ tools: { register: (def) => { lean[def.name] = def } }, effect: () => {}, get: () => undefined }, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, machineInventory: 'alias',
      reconnectCooldownMs: 0, connectTimeoutMs: 4000, commandTimeoutMs: 4000,
      machines: { box: machineFor('box', server.port) },
    })
    const hidden = await text(lean, { machine: 'box' })
    assert.match(hidden, /could not be (read|written) \([A-Z]+\)/, hidden)
    assert.match(hidden, /The key could not be recorded, so the connection was refused/, hidden)
    assert.match(hidden, /filesystem problem on this machine/, 'it must not blame the remote host: ' + hidden)
    assert.doesNotMatch(hidden, /dsh-ssh-safe/, 'the path is hidden in lean mode: ' + hidden)
    assert.match(hidden, /<path hidden>/, hidden)
    await lean.ssh_close.execute({ force: true }, {}).catch(() => {})

    const full = {}
    await apply({ tools: { register: (def) => { full[def.name] = def } }, effect: () => {}, get: () => undefined }, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, machineInventory: 'full',
      reconnectCooldownMs: 0, connectTimeoutMs: 4000, commandTimeoutMs: 4000,
      machines: { box: machineFor('box', server.port) },
    })
    const shown = await text(full, { machine: 'box' })
    assert.match(shown, /the host key store .*known_hosts\.json could not be written \([A-Z]+\)/, shown)
    await full.ssh_close.execute({ force: true }, {}).catch(() => {})
  } finally {
    await Promise.race([server.close(), new Promise((resolve) => setTimeout(resolve, 800))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('a write through a symlinked directory says where the bytes went', async () => {
  // The file itself was not a link, so the existing note did not fire: writing
  // /link/a.txt through 'link -> /real' put the bytes in /real/a.txt while the reply
  // named only the path it was given. Only the immediate parent is checked.
  const server = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-parentlink-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  const ctx = { tools: { register: (def) => { tools[def.name] = def } }, effect: () => {}, get: () => undefined }
  try {
    await apply(ctx, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 4000, commandTimeoutMs: 4000,
      machines: { box: machineFor('box', server.port) },
    })
    server.vfs.putDir('/real')
    server.vfs.putLink('/link', '/real')
    const text = String((await tools.ssh_write.execute({ machine: 'box', path: '/link/a.txt', content: 'hello' }, {})).text)
    assert.match(text, /\[note\] the directory \/link is a symbolic link to \/real/, text)
    assert.match(text, /the file was written there \(\/real\/a\.txt\)/, text)
    assert.equal(server.vfs.stat('/real/a.txt').size, 5, 'the bytes land in the real directory')

    // An ordinary directory says nothing extra.
    const plain = String((await tools.ssh_write.execute({ machine: 'box', path: '/real/b.txt', content: 'x' }, {})).text)
    assert.doesNotMatch(plain, /symbolic link/, plain)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await Promise.race([server.close(), new Promise((resolve) => setTimeout(resolve, 800))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('the audit trail says when a write went through a directory link', async () => {
  // The record carried viaLinkDir from the start of 0.7.388, but the renderer only
  // printed the fields it knew: 'why did /etc change?' had no answer in the trail.
  const server = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-audit-linkdir-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  const ctx = { tools: { register: (def) => { tools[def.name] = def } }, effect: () => {}, get: () => undefined }
  try {
    await apply(ctx, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 4000, commandTimeoutMs: 4000, auditLog: true,
      machines: { box: machineFor('box', server.port) },
    })
    server.vfs.putDir('/real')
    server.vfs.putLink('/link', '/real')
    await tools.ssh_write.execute({ machine: 'box', path: '/link/a.txt', content: 'hi' }, {})
    const trail = String((await tools.ssh_audit.execute({ limit: 2 }, {})).text)
    assert.match(trail, /via dir link \/link -> \/real/, trail)
    // The same trail must not print a raw object or undefined for the new field.
    for (const bad of ['[object Object]', 'undefined', 'NaN']) {
      assert.doesNotMatch(trail, new RegExp(bad.replace(/[[\]]/g, '\\$&')), 'no ' + bad + ' in: ' + trail)
    }
    await tools.ssh_close.execute({ force: true }, {})
  } finally {
    await Promise.race([server.close(), new Promise((resolve) => setTimeout(resolve, 800))])
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})
