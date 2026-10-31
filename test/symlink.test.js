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
test('a write through a link reports where the content landed', async () => {
  // '/home/u/.ssh/config' that is a link to '/etc/ssh/ssh_config' writes into
  // /etc: the answer used to name only the path it was given.
  srv.vfs.putFile('/etc/ssh-config', 'old')
  srv.vfs.putLink('/tmp/ssh-config-link', '/etc/ssh-config')
  const result = await pool.writeFile('t', '/tmp/ssh-config-link', 'new')
  assert.equal(result.bytes, 3)
  assert.equal(result.linkTarget, '/etc/ssh-config')
  const plain = await pool.writeFile('t', '/tmp/plain-write.txt', 'x')
  assert.equal(plain.linkTarget, undefined, 'a normal write carries no link note')
})

test('a link chain longer than the server allows is not claimed to be a cycle', async () => {
  // ELOOP is what the server answers both for a real cycle and for a chain that
  // is longer than its limit, so the plugin must not assert 'the links point at
  // each other': a 40-link chain to a real file was reported as a cycle.
  srv.vfs.putDir('/links')
  srv.vfs.putFile('/links/real.txt', 'end of chain')
  srv.vfs.putLink('/links/a', '/links/b')
  srv.vfs.putLink('/links/b', '/links/a')
  for (let i = 0; i < 40; i++) srv.vfs.putLink('/links/chain' + i, '/links/chain' + (i + 1))
  srv.vfs.putFile('/links/chain40', 'end of chain')

  const cycle = await pool.readFile('t', '/links/a', {}).then(() => null, (err) => err)
  assert.ok(cycle instanceof Error, 'a cycle must reject')
  assert.match(cycle.message, /symbolic link loop at \/links\/a/)
  assert.match(cycle.message, /either the links point at each other or the chain is longer/)

  // The long chain answers the same way, and the wording covers both causes.
  const chain = await pool.readFile('t', '/links/chain0', {}).then(() => null, (err) => err)
  assert.ok(chain instanceof Error, 'an over-long chain must reject')
  assert.match(chain.message, /symbolic link loop at \/links\/chain0/)
  assert.match(chain.message, /either the links point at each other or the chain is longer/)

  // A one-hop link to a real file still resolves, so the change did not widen.
  const through = await pool.readFile('t', '/links/real.txt', {})
  assert.equal(through.content, 'end of chain')
})
