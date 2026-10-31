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
  assert.match(text, /^l +0 +link\.txt$/m)
  assert.match(text, /^p +0 +pipe$/m)
  assert.match(text, /^s +0 +sock$/m)
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
