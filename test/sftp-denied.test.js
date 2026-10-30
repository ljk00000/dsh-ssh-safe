import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { apply } from '../src/index.js'
import { SshPool } from '../src/pool.js'
import { startServer, machineFor } from './helpers/local-ssh-server.js'

// A real sshd answers "Permission denied" for a path the login user may not
// touch, and that string is all the user gets to act on. These check it
// survives with the path attached instead of being swallowed.

async function withPool(server, fn) {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-denied-'))
  process.env.DSH_HOME = home
  const tools = {}
  await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 't',
    allowPlaintextPassword: true,
    hostKeyPolicy: 'tofu',
    healthCheckIdleMs: 0,
    machines: { t: machineFor('t', server.port) },
  })
  try {
    return await fn(tools)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    delete process.env.DSH_HOME
    rmSync(home, { recursive: true, force: true })
  }
}

test('a denied directory reports permission denied and the path', async () => {
  const srv = await startServer()
  srv.vfs.putDir('/private')
  srv.vfs.control.deny('/private')
  try {
    await withPool(srv, async (tools) => {
      await assert.rejects(
        () => tools.ssh_list.execute({ path: '/private' }, {}),
        (err) => {
          assert.match(err.message, /permission denied/i, err.message)
          assert.match(err.message, /\/private/, 'the path must be in the message')
          return true
        },
      )
    })
  } finally {
    await srv.close()
  }
})

test('a denied file reports permission denied for reads and writes', async () => {
  const srv = await startServer()
  srv.vfs.putFile('/var/secret.txt', 'x')
  srv.vfs.control.deny('/var/secret.txt')
  try {
    await withPool(srv, async (tools) => {
      await assert.rejects(
        () => tools.ssh_read.execute({ path: '/var/secret.txt' }, {}),
        /permission denied/i,
      )
      await assert.rejects(
        () => tools.ssh_write.execute({ path: '/var/secret.txt', content: 'y' }, {}),
        /permission denied/i,
      )
    })
  } finally {
    await srv.close()
  }
})
