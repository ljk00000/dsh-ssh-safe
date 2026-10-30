import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { apply } from '../src/index.js'
import { startServer, machineFor } from './helpers/local-ssh-server.js'

// A command whose channel dies before it reports an exit status must not look
// like a successful command that printed nothing.

test('ssh_exec says the output is partial when the connection dies mid-command', async () => {
  const srv = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-execdrop-'))
  process.env.DSH_HOME = home
  const tools = {}
  const ctx = {
    tools: { register: (def) => { tools[def.name] = def } },
    effect: () => {},
    get: () => undefined,
  }
  await apply(ctx, {
    defaultMachine: 'a', allowPlaintextPassword: true, hostKeyPolicy: 'tofu',
    healthCheckIdleMs: 0, maxConnections: 2,
    machines: {
      a: machineFor('a', srv.port),
      b: machineFor('b', srv.port),
      c: machineFor('c', srv.port),
    },
  })

  try {
    await tools.ssh_exec.execute({ command: 'echo warm' }, {})
    const running = tools.ssh_exec.execute({ command: 'sleep 3' }, {})
    await new Promise((r) => setTimeout(r, 200))
    await tools.ssh_exec.execute({ command: 'echo b', machine: 'b' }, {})
    await tools.ssh_exec.execute({ command: 'echo c', machine: 'c' }, {}) // evicts a

    const result = await Promise.race([running.then((r) => r), new Promise((r) => setTimeout(() => r('HUNG'), 5000))])
    assert.notEqual(result, 'HUNG', 'the call must settle')
    const text = String(result.text)
    assert.match(text, /connection closed before the command reported an exit status/, text)
    assert.match(text, /\[exit unknown\]/, text)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await srv.close()
    delete process.env.DSH_HOME
    rmSync(home, { recursive: true, force: true })
  }
})
