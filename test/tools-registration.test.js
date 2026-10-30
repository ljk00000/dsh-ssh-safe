import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

// Registration is the seam that broke when the harness moved from
// `ctx.tools.defineTool` to `ctx.tools.register`. Nothing below calls a
// network or ssh2: the point is which entry point is used and what shape
// reaches it.

import { apply } from '../src/index.js'

function run(ctx) {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-reg-'))
  const saved = { ...process.env }
  process.env.DSH_HOME = home
  const restore = () => {
    for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key]
    Object.assign(process.env, saved)
    rmSync(home, { recursive: true, force: true })
  }
  return Promise.resolve(apply(ctx, {})).then(() => restore)
}

test('register receives a compiled definition (0.2.1+ path)', async () => {
  const seen = []
  await run({ tools: { register: (def) => { seen.push(def) } }, effect: () => {} })
  assert.equal(seen.length, 12, 'every tool must be registered through register()')
  for (const def of seen) {
    // The service rejects anything else with a TypeError, so asserting the
    // shape here is what stops a silent "did not activate" on the next bump.
    assert.equal(typeof def.name, 'string')
    assert.equal(def.parameters.type, 'object', def.name + ' parameters must be compiled JSON Schema')
    assert.ok(def.parameters.properties && typeof def.parameters.properties === 'object')
    assert.equal(typeof def.output.render, 'function', def.name + ' needs an output renderer')
    assert.ok(def.output.schema && def.output.schema.type === 'object')
    assert.equal(typeof def.execute, 'function')
  }
})

test('a registered tool still runs through the compiled definition', async () => {
  const tools = {}
  await run({ tools: { register: (def) => { tools[def.name] = def } }, effect: () => {} })
  const result = await tools.ssh_machines.execute({}, {})
  assert.match(String(result.text), /machine|DSH_SSH_/i)
})

test('an old harness that only exposes defineTool still registers', async () => {
  const legacy = []
  await run({ tools: { defineTool: (def) => { legacy.push(def) } }, effect: () => {} })
  assert.equal(legacy.length, 12)
  // The legacy method took the un-compiled definition: parameters are the
  // author property map, not { type: 'object', properties }.
  assert.equal(legacy[0].parameters.type, undefined)
})

test('a harness with neither entry point fails with a version-naming error', async () => {
  await assert.rejects(
    () => run({ tools: {}, effect: () => {} }),
    /neither ctx\.tools\.register|ctx\.tools\.defineTool/,
  )
})
