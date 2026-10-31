import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { SshPool } from '../src/pool.js'
import { startServer, machineFor } from './helpers/local-ssh-server.js'

// The test server had no symlinks at all, so every link scenario was untestable:
// the plugin's only link-shaped behaviour is how it explains a link that leads
// nowhere. These drive it against a server that answers LSTAT/READLINK the way
// ssh2's client expects (ssh2 numbers READLINK 19, not 21).

let srv
let home
let pool

before(async () => {
  srv = await startServer()
  home = mkdtempSync(path.join(tmpdir(), 'dsh-symlink-'))
  for (const dir of ['/tmp', '/etc', '/home']) srv.vfs.putDir(dir)
  pool = new SshPool({
    hostKeyPolicy: 'tofu',
    allowPlaintextPassword: true,
    connectTimeoutMs: 3000,
    sftpTimeoutMs: 5000,
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

test('a read goes through a symlink to its target', async () => {
  srv.vfs.putFile('/etc/real.conf', 'listen 22')
  srv.vfs.putLink('/etc/link.conf', '/etc/real.conf')
  const result = await pool.readFile('t', '/etc/link.conf', {})
  assert.equal(result.content, 'listen 22')
})

test('a write through a symlink replaces the target, not the link', async () => {
  srv.vfs.putFile('/tmp/target.txt', 'old content')
  srv.vfs.putLink('/tmp/write-link.txt', '/tmp/target.txt')
  const result = await pool.writeFile('t', '/tmp/write-link.txt', 'new')
  assert.equal(result.bytes, 3)
  assert.equal(srv.vfs.getFile('/tmp/target.txt').toString(), 'new', 'the target is truncated and rewritten')
  assert.equal(srv.vfs.readLink('/tmp/write-link.txt'), '/tmp/target.txt', 'the link itself is untouched')
})

test('a dangling symlink says so instead of "no such file"', async () => {
  srv.vfs.putLink('/etc/dangling.conf', '/etc/vanished.conf')
  await assert.rejects(
    () => pool.readFile('t', '/etc/dangling.conf', {}),
    (err) => {
      assert.match(err.message, /no such file: \/etc\/dangling\.conf/)
      assert.match(err.message, /symbolic link to \/etc\/vanished\.conf/)
      assert.match(err.message, /the target does not exist/)
      return true
    },
  )
})

test('a symlink loop is named as a loop, not as a missing target', async () => {
  srv.vfs.putLink('/etc/loop-a', '/etc/loop-b')
  srv.vfs.putLink('/etc/loop-b', '/etc/loop-a')
  await assert.rejects(
    () => pool.readFile('t', '/etc/loop-a', {}),
    (err) => {
      assert.match(err.message, /symbolic link loop at \/etc\/loop-a/)
      assert.doesNotMatch(err.message, /target does not exist/)
      return true
    },
  )
})

test('a symlink to a directory is reported as a directory', async () => {
  srv.vfs.putDir('/tmp/real-dir')
  srv.vfs.putLink('/tmp/dir-link', '/tmp/real-dir')
  await assert.rejects(
    () => pool.readFile('t', '/tmp/dir-link', {}),
    /not a file: \/tmp\/dir-link \(it is a directory; use ssh_list\)/,
  )
  // ...and the listing goes through it.
  srv.vfs.putFile('/tmp/real-dir/inside.txt', 'x')
  const listed = await pool.list('t', '/tmp/dir-link', {})
  assert.ok(listed.items.some((entry) => entry.name === 'inside.txt'), JSON.stringify(listed.items))
})
