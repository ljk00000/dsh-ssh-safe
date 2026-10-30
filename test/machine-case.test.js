import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { apply } from '../src/index.js'
import { machineDefinition } from '../src/machines.js'
import { startServer, machineFor } from './helpers/local-ssh-server.js'

// Settings-form keys are typed by hand and keep their case. The alias that
// reaches the plugin is lower-cased first, so a case-sensitive lookup made
// 'BOX' invisible: ssh_machines listed "box" with no host, and every command
// said the machine was not configured.

test('a settings-form alias in any case is usable', async () => {
  const srv = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-case-'))
  process.env.DSH_HOME = home
  const tools = {}
  await apply({ tools: { register: (d) => { tools[d.name] = d } }, effect: () => {}, get: () => undefined }, {
    allowPlaintextPassword: true,
    hostKeyPolicy: 'tofu',
    healthCheckIdleMs: 0,
    machines: {
      BOX: machineFor('BOX', srv.port),
      mixedCase: machineFor('mixedCase', srv.port),
    },
  })
  try {
    for (const alias of ['box', 'BOX', 'Box']) {
      const result = await tools.ssh_exec.execute({ machine: alias, command: 'echo ' + alias }, {})
      assert.match(String(result.text), new RegExp('echo ' + alias), alias + ' must run')
    }
    const mixed = await tools.ssh_exec.execute({ machine: 'mixedcase', command: 'echo mixed' }, {})
    assert.match(String(mixed.text), /mixed/)

    const listed = String((await tools.ssh_machines.execute({}, {})).text)
    assert.match(listed, /box/, listed)
    assert.doesNotMatch(listed, /<no host>/, 'the listing must not show a hostless machine: ' + listed)
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    await srv.close()
    delete process.env.DSH_HOME
    rmSync(home, { recursive: true, force: true })
  }
})

test('the lookup is still own-property only', () => {
  // Nothing in the object's prototype chain may be read as a machine, and the
  // case-insensitive scan must not reach into it either.
  const machines = { real: { host: 'h', user: 'u' } }
  for (const alias of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
    assert.equal(machineDefinition(alias, { machines }).host, '', alias + ' must not resolve to a prototype member')
  }
  assert.equal(machineDefinition('real', { machines }).host, 'h')
  assert.equal(machineDefinition('REAL', { machines }).host, 'h', 'case-insensitive lookup still works')
})