import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { SshPool } from '../src/pool.js'
import { startServer, machineFor } from './helpers/local-ssh-server.js'

// 'Permission denied: /root/x' names the path but not what to look at. The
// answer is always a mode or an owner, and which one depends on the operation.

let srv
let home
let pool

before(async () => {
  srv = await startServer()
  home = mkdtempSync(path.join(tmpdir(), 'dsh-perm-'))
  for (const dir of ['/tmp', '/etc', '/srv']) srv.vfs.putDir(dir)
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

test('a denied read, write and listing each say what to check', async () => {
  srv.vfs.putFile('/etc/secret.conf', 'x')
  srv.vfs.control.deny('/etc')

  await assert.rejects(
    () => pool.readFile('t', '/etc/secret.conf', {}),
    (err) => {
      assert.match(err.message, /Permission denied: \/etc\/secret\.conf/)
      assert.match(err.message, /may not read this file/)
      assert.match(err.message, /ls -l <path>/)
      return true
    },
  )

  await assert.rejects(
    () => pool.writeFile('t', '/etc/secret.conf', 'y'),
    (err) => {
      assert.match(err.message, /may not write there/)
      assert.match(err.message, /parent directory/)
      return true
    },
  )

  await assert.rejects(
    () => pool.list('t', '/etc', {}),
    (err) => {
      assert.match(err.message, /may not list this directory/)
      return true
    },
  )

  srv.vfs.control.undeny()
})

test('createDirs names the directory it could not create', async () => {
  srv.vfs.control.deny('/srv')
  await assert.rejects(
    () => pool.writeFile('t', '/srv/app/data/conf.yml', 'x', { createDirs: true }),
    (err) => {
      assert.match(err.message, /could not create remote directory \/srv/)
      assert.match(err.message, /Permission denied/)
      return true
    },
  )
  srv.vfs.control.undeny()
})

test('a file in the middle of the path is named, not left as a bare Failure', async () => {
  srv.vfs.putFile('/tmp/blocker', 'i am a file')
  await assert.rejects(
    () => pool.writeFile('t', '/tmp/blocker/sub/x.txt', 'x', { createDirs: true }),
    (err) => {
      assert.match(err.message, /\/tmp\/blocker already exists and is a file, not a directory/)
      return true
    },
  )
  // The file is untouched and no tree was built behind it.
  assert.equal(srv.vfs.getFile('/tmp/blocker').toString(), 'i am a file')
  assert.equal(srv.vfs.stat('/tmp/blocker/sub'), null)
})

test('createDirs builds the whole chain and writes the file', async () => {
  const result = await pool.writeFile('t', '/tmp/deep/a/b/c.txt', 'x', { createDirs: true })
  assert.equal(result.bytes, 1)
  for (const dir of ['/tmp/deep', '/tmp/deep/a', '/tmp/deep/a/b']) {
    assert.equal(srv.vfs.stat(dir)?.dir, true, dir)
  }
})
