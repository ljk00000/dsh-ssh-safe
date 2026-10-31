import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { startServer } from './helpers/local-ssh-server.js'
import { SshPool } from '../src/pool.js'

// '/tmp/afile.txt/sub' answered "no such file", which points at the wrong part of
// the path: the sub path is not what is missing, a component above it is a file.

const pool = (port) => new SshPool({
  hostKeyPolicy: 'tofu',
  allowPlaintextPassword: true,
  connectTimeoutMs: 4000,
  commandTimeoutMs: 4000,
  reconnectCooldownMs: 0,
  healthCheckIdleMs: 0,
  machines: { t: { host: '127.0.0.1', port, user: 'tester', password: 'test-pass' } },
}, { dshHome: mkdtempSync(path.join(tmpdir(), 'dsh-blocked-')) })

test('a file in the middle of a path is named instead of "no such file"', async () => {
  const srv = await startServer()
  srv.vfs.putFile('/tmp/afile.txt', 'x')
  const p = pool(srv.port)
  try {
    await assert.rejects(
      () => p.list('t', '/tmp/afile.txt/sub'),
      (err) => {
        assert.match(err.message, /cannot reach \/tmp\/afile\.txt\/sub/)
        assert.match(err.message, /\/tmp\/afile\.txt is a file, not a directory/)
        assert.doesNotMatch(err.message, /no such file/)
        return true
      },
    )
    // The same path through a read says it too.
    await assert.rejects(
      () => p.readFile('t', '/tmp/afile.txt/sub/file'),
      /\/tmp\/afile\.txt is a file, not a directory/,
    )
    // A path that is genuinely missing still says so, without a false lead.
    await assert.rejects(
      () => p.list('t', '/tmp/nowhere/at/all'),
      /no such file/,
    )
  } finally {
    // The pool keeps its connection live; srv.close() waits for it and the test
    // then hangs until the runner kills it.
    await p.closeAll({ force: true })
    await srv.close()
  }
})
