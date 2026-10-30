import { test } from 'node:test'
import assert from 'node:assert/strict'
import { apply, Config } from '../src/index.js'

// The enum schemas were added, but apply() built its config with
//   { ...Config(), ...(config || {}) }
// which spreads the defaults and then overwrites them with the user's values.
// The schemas therefore only ran when the DSH host called Config() itself --
// not on the path the plugin actually loads through.
//
// These tests pin the load-time behaviour: an invalid value must fail the load,
// not reach the running plugin.

const ctx = () => ({ tools: { defineTool: () => {} }, effect: () => {} })

test('apply rejects an invalid hostKeyPolicy', async () => {
  await assert.rejects(
    () => apply(ctx(), { hostKeyPolicy: 'typo-strict' }),
    (err) => {
      assert.match(err.message, /hostKeyPolicy/)
      assert.match(err.message, /strict/)
      return true
    }
  )
})

test('apply rejects an invalid execGuard', async () => {
  await assert.rejects(
    () => apply(ctx(), { execGuard: 'yes' }),
    (err) => {
      assert.match(err.message, /execGuard/)
      assert.match(err.message, /confirm/)
      return true
    }
  )
})

test('apply rejects an invalid machineInventory', async () => {
  await assert.rejects(
    () => apply(ctx(), { machineInventory: 'nope' }),
    (err) => { assert.match(err.message, /machineInventory/); return true }
  )
})

test('apply rejects a non-numeric maxConnections', async () => {
  await assert.rejects(
    () => apply(ctx(), { maxConnections: 'abc' }),
    (err) => { assert.match(err.message, /maxConnections/); return true }
  )
})

test('the error names the plugin and how to fix it', async () => {
  await assert.rejects(
    () => apply(ctx(), { execGuard: 'yes' }),
    (err) => {
      assert.match(err.message, /dsh-ssh-safe/)
      assert.match(err.message, /cordis\.patch\.yml/)
      return true
    }
  )
})

test('a valid config loads and the values are in effect', async () => {
  const tools = {}
  await apply(
    { tools: { defineTool: (d) => { tools[d.name] = d } }, effect: () => {} },
    { execGuard: 'confirm', maxConnections: 4, hostKeyPolicy: 'tofu' }
  )
  const text = String((await tools['ssh_config'].execute({})).text)
  assert.match(text, /"confirm"/)
  assert.match(text, /"tofu"/)
  assert.match(text, /maxConnections\s+4/)
})

test('no config at all still loads with the defaults', async () => {
  const tools = {}
  await apply({ tools: { defineTool: (d) => { tools[d.name] = d } }, effect: () => {} }, undefined)
  const text = String((await tools['ssh_config'].execute({})).text)
  assert.match(text, /"strict"/)
  assert.match(text, /"allow"/)
})

test('apply and Config agree on the effective values', async () => {
  const direct = Config({})
  const tools = {}
  await apply({ tools: { defineTool: (d) => { tools[d.name] = d } }, effect: () => {} }, {})
  const text = String((await tools['ssh_config'].execute({})).text)
  for (const key of ['hostKeyPolicy', 'execGuard', 'machineInventory']) {
    assert.match(text, new RegExp(key + '\\s+"' + direct[key] + '"'), key)
  }
})
test('a deny pattern that does not compile refuses to load', async () => {
  // checkCommand skips a pattern it cannot compile, so a typo here turned a
  // protection off while the setting still looked active in the config.
  await assert.rejects(
    () => apply(ctx(), { denyPatterns: ['ok-rule', 'dd if=.*('] }),
    (err) => {
      assert.match(err.message, /denyPatterns\[1\] is not a valid regular expression/)
      assert.match(err.message, /dd if=\.\*\(/)
      assert.match(err.message, /refuses to load/)
      return true
    },
  )
})

test('a valid custom deny pattern still loads', async () => {
  await assert.doesNotReject(() => apply(ctx(), { denyPatterns: ['\\bkillall\\b'] }))
})
