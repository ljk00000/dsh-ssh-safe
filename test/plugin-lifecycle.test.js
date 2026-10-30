import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { apply } from '../src/index.js'
import { startServer, machineFor } from './helpers/local-ssh-server.js'

// DSH unloads a plugin through the disposer it registers with ctx.effect. If
// that disposer does not close the pooled sockets, reloading the plugin leaks
// one connection per machine for the life of the app.

test('unloading the plugin closes its connections', async () => {
  const srv = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-lifecycle-'))
  process.env.DSH_HOME = home
  const tools = {}
  const disposers = []
  const ctx = {
    tools: { register: (def) => { tools[def.name] = def } },
    effect: (factory) => {
      const dispose = typeof factory === 'function' ? factory() : undefined
      if (typeof dispose === 'function') disposers.push(dispose)
    },
    get: () => undefined,
  }

  try {
    await apply(ctx, {
      defaultMachine: 't', allowPlaintextPassword: true, hostKeyPolicy: 'tofu',
      healthCheckIdleMs: 0,
      machines: { t: machineFor('t', srv.port) },
    })
    assert.ok(disposers.length > 0, 'the plugin must register a disposer')

    const first = await tools.ssh_exec.execute({ command: 'echo one' }, {})
    assert.match(String(first.text), /ran: echo one/)
    assert.ok(srv.clientCount() >= 1, 'the exec should have opened a connection')

    for (const dispose of disposers) dispose()
    await new Promise((r) => setTimeout(r, 250))
    assert.equal(srv.clientCount(), 0, 'unload must leave no connection behind')

    const second = await tools.ssh_exec.execute({ command: 'echo two' }, {})
    assert.match(String(second.text), /ran: echo two/, 'the plugin must still work after a reload')
  } finally {
    for (const dispose of disposers) { try { dispose() } catch {} }
    await srv.close()
    delete process.env.DSH_HOME
    rmSync(home, { recursive: true, force: true })
  }
})
