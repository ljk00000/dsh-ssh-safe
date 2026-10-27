import { test } from 'node:test'
import assert from 'node:assert/strict'
import { effectivePolicy } from '../src/pool.js'

// A per-machine setting must win in both directions. The previous
// implementation only honoured it when the value was 'tofu', so a machine
// could be neither tightened to 'strict' nor relaxed to 'off'.

test('a machine policy overrides the global one', () => {
  assert.equal(effectivePolicy('strict', 'off'), 'off')
  assert.equal(effectivePolicy('tofu', 'strict'), 'strict')
  assert.equal(effectivePolicy('off', 'strict'), 'strict', 'a machine may tighten')
  assert.equal(effectivePolicy('strict', 'tofu'), 'tofu')
})

test('the global policy applies when the machine has none', () => {
  assert.equal(effectivePolicy('tofu', ''), 'tofu')
  assert.equal(effectivePolicy('off', undefined), 'off')
  assert.equal(effectivePolicy('strict', null), 'strict')
})

test('an unrecognised machine value is ignored rather than passed through', () => {
  // A typo must not silently disable verification.
  assert.equal(effectivePolicy('strict', 'nonsense'), 'strict')
  assert.equal(effectivePolicy('strict', 'OFFF'), 'strict')
})

test('an out-of-range global value falls back to strict', () => {
  assert.equal(effectivePolicy('bogus', ''), 'strict')
  assert.equal(effectivePolicy(undefined, undefined), 'strict')
})

test('machine policy is case-insensitive', () => {
  assert.equal(effectivePolicy('strict', 'OFF'), 'off')
  assert.equal(effectivePolicy('off', 'Strict'), 'strict')
})
