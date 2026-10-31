import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { SshPool } from '../src/pool.js'
import { typeChar } from '../src/sftp.js'
import { formatListing } from '../src/format.js'
import { startServer, machineFor } from './helpers/local-ssh-server.js'

// A listing showed everything that is not a directory as '-', so a symlink and a
// FIFO looked like ordinary files -- and a socket, whose mode has the directory
// bit set, looked like a directory. Reading a FIFO then blocked until the
// deadline, which blamed the network.

let srv
let home
let pool

before(async () => {
  srv = await startServer()
  home = mkdtempSync(path.join(tmpdir(), 'dsh-special-'))
  srv.vfs.putDir('/tmp')
  pool = new SshPool({
    hostKeyPolicy: 'tofu',
    allowPlaintextPassword: true,
    connectTimeoutMs: 3000,
    sftpTimeoutMs: 800,
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

test('typeChar names every file kind the mode can describe', () => {
  assert.equal(typeChar(0o100644), '-')
  assert.equal(typeChar(0o040755), 'd')
  assert.equal(typeChar(0o120777), 'l')
  assert.equal(typeChar(0o010644), 'p')
  assert.equal(typeChar(0o140644), 's')
  assert.equal(typeChar(0o020644), 'c')
  assert.equal(typeChar(0o060644), 'b')
})

test('a listing distinguishes a link, a FIFO and a socket from a regular file', async () => {
  srv.vfs.putFile('/tmp/plain.txt', 'x')
  srv.vfs.putLink('/tmp/link.txt', '/tmp/plain.txt')
  srv.vfs.putSpecial('/tmp/pipe', 'p')
  srv.vfs.putSpecial('/tmp/sock', 's')

  const listing = await pool.list('t', '/tmp', {})
  const byName = Object.fromEntries(listing.items.map((it) => [it.name, it]))
  assert.equal(byName['plain.txt'].type, '-')
  assert.equal(byName['link.txt'].type, 'l', 'a symlink is a link, not a file')
  assert.equal(byName['pipe'].type, 'p')
  assert.equal(byName['sock'].type, 's')
  assert.equal(byName['sock'].dir, false, 'a socket is not a directory')

  const text = formatListing(listing)
  assert.match(text, /^l +0 +\S+Z +link\.txt$/m)
  assert.match(text, /^p +0 +\S+Z +pipe$/m)
  assert.match(text, /^s +0 +\S+Z +sock$/m)
})

test('reading a FIFO says it is a FIFO instead of blaming the network', async () => {
  srv.vfs.putSpecial('/tmp/blocking-pipe', 'p')
  await assert.rejects(
    () => pool.readFile('t', '/tmp/blocking-pipe', {}),
    (err) => {
      assert.match(err.message, /did not complete within 800ms/)
      assert.match(err.message, /is a named pipe \(FIFO\)/)
      assert.match(err.message, /blocks forever/)
      return true
    },
  )
})
test('a listing shows when each entry was last modified, to the second, in UTC', async () => {
  srv.vfs.putFile('/tmp/stamped.txt', 'x')
  const listing = await pool.list('t', '/tmp', {})
  const entry = listing.items.find((it) => it.name === 'stamped.txt')
  assert.ok(entry.mtime, 'a modification time is reported')
  assert.match(entry.mtime, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, entry.mtime)
  const text = formatListing(listing)
  const row = text.split('\n').find((line) => line.endsWith('stamped.txt'))
  assert.match(row, /^\S\s+\d+\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\s+stamped\.txt$/, row)
})

test('the rendered listing puts directories first, then names in order', async () => {
  srv.vfs.putDir('/tmp/aaa-dir')
  const text = formatListing(await pool.list('t', '/tmp', {}))
  const rows = text.split('\n').slice(1)
  const firstNonDir = rows.findIndex((row) => !row.startsWith('d'))
  assert.ok(firstNonDir > 0, 'a directory row comes first: ' + text)
  assert.equal(rows.slice(firstNonDir).some((row) => row.startsWith('d')), false, text)
  const names = rows.slice(firstNonDir).map((row) => row.split(/\s+/).pop())
  assert.deepEqual(names, names.slice().sort(), 'files are ordered by name')
})
test('a write blocked by a FIFO does not claim the file was truncated', async () => {
  // 'the file was opened (which truncates it) … its previous content is gone' is
  // true for a regular file and false for a FIFO: opening one blocks, and nothing
  // is truncated. The old sentence sent readers looking for damage that cannot
  // exist.
  srv.vfs.putSpecial('/tmp/wpipe', 'p')
  await assert.rejects(
    () => pool.writeFile('t', '/tmp/wpipe', 'x', {}),
    (err) => {
      assert.match(err.message, /a named pipe \(FIFO\)/)
      assert.doesNotMatch(err.message, /which truncates it/)
      assert.match(err.message, /opening it is the step that has not finished/)
      return true
    },
  )
})

test('a read or listing that times out says what to look at next', async () => {
  // The write path said 'the remote channel may have dropped'; read and listing
  // ended at 'did not complete within Nms' and left the reader guessing.
  const srv = await startServer()
  srv.vfs.putDir('/tmp')
  srv.vfs.putFile('/tmp/stall.txt', 'x'.repeat(100))
  srv.vfs.control.stallReads = true
  const pool = new SshPool({
    hostKeyPolicy: 'tofu', allowPlaintextPassword: true, connectTimeoutMs: 3000,
    sftpTimeoutMs: 400, reconnectCooldownMs: 0, maxFileBytes: 1024 * 1024,
    machines: { t: machineFor('t', srv.port) },
  }, { dshHome: mkdtempSync(path.join(tmpdir(), 'dsh-stall-')) })
  try {
    await assert.rejects(
      () => pool.readFile('t', '/tmp/stall.txt', {}),
      /did not complete within 400ms — the remote channel may have dropped, or the filesystem is not answering/,
    )
  } finally {
    await pool.closeAll({ force: true })
    await srv.close()
  }
})
