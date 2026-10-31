import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { SshPool } from '../src/pool.js'
import { startServer, machineFor } from './helpers/local-ssh-server.js'

// The read/write/list paths only ever ran against hand-written fakes, so a real
// SFTP conversation -- open, fstat, chunked reads, EOF, handles, attrs -- had
// never happened. This drives them against a small in-memory SFTP server.

let srv
let home
let pool

before(async () => {
  srv = await startServer()
  home = mkdtempSync(path.join(tmpdir(), 'dsh-sftp-live-'))
  // Directories a real server would already have; writing into a missing one
  // is refused, so the tests start from the same place a host does.
  for (const dir of ['/tmp', '/var', '/var/log', '/etc', '/srv', '/home']) srv.vfs.putDir(dir)
  pool = new SshPool({
    hostKeyPolicy: 'tofu',
    allowPlaintextPassword: true,
    connectTimeoutMs: 3000,
    sftpTimeoutMs: 5000,
    commandTimeoutMs: 5000,
    reconnectCooldownMs: 0,
    maxFileBytes: 1024 * 1024,
    machines: { t: machineFor('t', srv.port) },
  }, { dshHome: home })
})

after(async () => {
  await pool.closeAll({ force: true })
  await srv.close()
  rmSync(home, { recursive: true, force: true })
})

test('a file is read back with its byte count', async () => {
  srv.vfs.putFile('/etc/motd.txt', 'hello motd\n')
  const r = await pool.readFile('t', '/etc/motd.txt', {})
  assert.equal(r.content, 'hello motd\n')
  assert.equal(r.bytes, 11)
  assert.equal(r.truncated, false)
  assert.equal(r.path, '/etc/motd.txt')
})

test('a large file stops at maxBytes and says so', async () => {
  srv.vfs.putFile('/var/big.txt', 'x'.repeat(5000))
  const r = await pool.readFile('t', '/var/big.txt', { maxBytes: 100 })
  assert.equal(r.truncated, true)
  assert.ok(r.content.length <= 100, 'read ' + r.content.length)
  assert.equal(r.content, 'x'.repeat(r.content.length))
})

test('truncation does not split a multi-byte character', async () => {
  // Three bytes each; a 10-byte cap lands in the middle of the fourth.
  srv.vfs.putFile('/var/cjk.txt', '中'.repeat(20))
  const r = await pool.readFile('t', '/var/cjk.txt', { maxBytes: 10 })
  assert.equal(r.truncated, true)
  assert.ok(!r.content.includes('\uFFFD'), 'no replacement character: ' + JSON.stringify(r.content))
  assert.equal(r.content, '中'.repeat(r.content.length))
})

test('an empty file reads as empty, not as an error', async () => {
  srv.vfs.putFile('/var/empty.txt', '')
  const r = await pool.readFile('t', '/var/empty.txt', {})
  assert.equal(r.content, '')
  assert.equal(r.bytes, 0)
  assert.equal(r.truncated, false)
})

test('a missing file names the path', async () => {
  await assert.rejects(
    () => pool.readFile('t', '/var/nope.txt', {}),
    (err) => {
      assert.match(err.message, /no such file/i)
      assert.match(err.message, /\/var\/nope\.txt/)
      return true
    },
  )
})

test('reading a directory says to use ssh_list', async () => {
  srv.vfs.putDir('/var/log/app')
  await assert.rejects(() => pool.readFile('t', '/var/log/app', {}), /not a file.*ssh_list/)
})

test('a relative path is refused before any request', async () => {
  await assert.rejects(() => pool.readFile('t', 'etc/motd.txt', {}), /must be absolute/)
})

test('a written file comes back byte for byte', async () => {
  const result = await pool.writeFile('t', '/tmp/one.txt', 'written!')
  assert.equal(result.bytes, 8)
  assert.equal(srv.vfs.getFile('/tmp/one.txt').toString(), 'written!')
  const back = await pool.readFile('t', '/tmp/one.txt', {})
  assert.equal(back.content, 'written!')
})

test('overwriting a longer file truncates it', async () => {
  srv.vfs.putFile('/tmp/long.txt', 'a'.repeat(1000))
  await pool.writeFile('t', '/tmp/long.txt', 'short')
  assert.equal(srv.vfs.getFile('/tmp/long.txt').toString(), 'short')
})

test('createDirs builds the missing parents', async () => {
  const result = await pool.writeFile('t', '/srv/app/config/conf.yml', 'k: v\n', { createDirs: true })
  assert.equal(result.bytes, 5)
  assert.equal(srv.vfs.getFile('/srv/app/config/conf.yml').toString(), 'k: v\n')
})

test('writing over a directory says it is a directory', async () => {
  srv.vfs.putDir('/var/log/app')
  await assert.rejects(() => pool.writeFile('t', '/var/log/app', 'x'), /not a file.*it is a directory|is a directory/)
})

test('a directory lists names, sizes and kinds', async () => {
  srv.vfs.putDir('/srv/data')
  srv.vfs.putFile('/srv/data/a.txt', 'aaa')
  srv.vfs.putFile('/srv/data/b.bin', 'bb')
  srv.vfs.putDir('/srv/data/sub')
  const listing = await pool.list('t', '/srv/data', {})
  const byName = Object.fromEntries(listing.items.map((it) => [it.name, it]))
  assert.deepEqual(Object.keys(byName).sort(), ['a.txt', 'b.bin', 'sub'])
  assert.equal(byName['a.txt'].size, 3)
  assert.equal(byName['a.txt'].dir, false)
  assert.equal(byName['sub'].dir, true)
})

test('an empty directory lists nothing', async () => {
  srv.vfs.putDir('/srv/empty')
  const listing = await pool.list('t', '/srv/empty', {})
  assert.deepEqual(listing.items, [])
})

test('listing a file says to use ssh_read', async () => {
  srv.vfs.putFile('/srv/file.txt', 'x')
  await assert.rejects(() => pool.list('t', '/srv/file.txt', {}), /not a directory.*ssh_read/)
})

test('listing a missing directory names the path', async () => {
  await assert.rejects(() => pool.list('t', '/srv/missing', {}), /no such file/i)
})
test('a stalled read gives up at the deadline and the connection survives', async () => {
  srv.vfs.putFile('/var/stall.txt', 'x'.repeat(200000))
  srv.vfs.control.stallReads = true
  const started = Date.now()
  try {
    await assert.rejects(() => pool.readFile('t', '/var/stall.txt', { timeoutMs: 400 }), /did not complete within 400ms/)
    assert.ok(Date.now() - started < 3000, 'the deadline must fire promptly')
  } finally {
    srv.vfs.control.stallReads = false
  }
  // The session was destroyed on the way out; the next call must still work.
  const after = await pool.readFile('t', '/var/stall.txt', { maxBytes: 16 })
  assert.equal(after.content, 'x'.repeat(16))
})

test('a stalled write gives up at the deadline and the connection survives', async () => {
  srv.vfs.control.stallWrites = true
  const started = Date.now()
  try {
    await assert.rejects(
      () => pool.writeFile('t', '/tmp/stall.txt', 'y'.repeat(100000), { timeoutMs: 400 }),
      // The stream truncates on open, so the caller has to be told the file is
      // no longer what it was.
      /did not complete within 400ms.*the file was opened .* no data was sent/,
    )
    assert.ok(Date.now() - started < 3000, 'the deadline must fire promptly')
  } finally {
    srv.vfs.control.stallWrites = false
  }
  const result = await pool.writeFile('t', '/tmp/stall.txt', 'recovered')
  assert.equal(result.bytes, 9)
  assert.equal(srv.vfs.getFile('/tmp/stall.txt').toString(), 'recovered')
})

test('a five megabyte write arrives intact', async () => {
  const { createHash } = await import('node:crypto')
  const payload = Buffer.from('0123456789'.repeat(500000))
  const expected = createHash('sha256').update(payload).digest('hex')
  const result = await pool.writeFile('t', '/tmp/big.bin', payload, { timeoutMs: 20000 })
  assert.equal(result.bytes, 5000000)
  const stored = srv.vfs.getFile('/tmp/big.bin')
  assert.equal(stored.length, 5000000)
  assert.equal(createHash('sha256').update(stored).digest('hex'), expected)
})
test('a cancelled transfer stops at once instead of running to its deadline', async () => {
  // The harness aborts the call when the user stops the turn. A transfer that
  // ignored it kept the socket busy for its full deadline.
  const controller = new AbortController()
  srv.vfs.putFile('/var/cancel.txt', 'x'.repeat(1000))
  srv.vfs.control.stallReads = true
  const starting = pool.readFile('t', '/var/cancel.txt', { maxBytes: 64, signal: controller.signal })
  setTimeout(() => controller.abort(), 100)
  const started = Date.now()
  await assert.rejects(() => starting, /reading \/var\/cancel\.txt was cancelled/)
  assert.ok(Date.now() - started < 2000, 'cancellation must be prompt')
  srv.vfs.control.stallReads = false

  const writeController = new AbortController()
  srv.vfs.control.stallWrites = true
  const writing = pool.writeFile('t', '/tmp/cancel.txt', 'y'.repeat(100000), { timeoutMs: 20000, signal: writeController.signal })
  setTimeout(() => writeController.abort(), 100)
  await assert.rejects(() => writing, /writing \/tmp\/cancel\.txt was cancelled; the file was opened .* no data was sent/)
  srv.vfs.control.stallWrites = false

  const listController = new AbortController()
  srv.vfs.control.stallDirs = true
  const listing = pool.list('t', '/var', { signal: listController.signal })
  setTimeout(() => listController.abort(), 100)
  await assert.rejects(() => listing, /listing \/var was cancelled/)
  srv.vfs.control.stallDirs = false

  // The session was torn down each time; the pool must still work.
  srv.vfs.putFile('/var/after.txt', 'ok')
  const after = await pool.readFile('t', '/var/after.txt', { maxBytes: 16 })
  assert.equal(after.content, 'ok')
})
test('a write cancelled before it starts says the file was not touched', async () => {
  // The old message was 'the file may be truncated or partially written' for
  // every cancel, including one that never opened the file: the caller went
  // looking for damage that was not there.
  const controller = new AbortController()
  controller.abort()
  await assert.rejects(
    () => pool.writeFile('t', '/tmp/untouched.txt', 'x'.repeat(1000), { signal: controller.signal, createDirs: true }),
    /was cancelled; the file was not touched \(cancelled before it started\)/,
  )
  assert.equal(srv.vfs.getFile('/tmp/untouched.txt'), undefined, 'nothing may be created')
})
