import { test } from 'node:test'
import assert from 'node:assert/strict'

// These tests pin behaviour that was previously wrong. Each one failed against
// the first published implementation.

// ── 1. truncation must be reported whenever output was actually cut ──────
// The original push() compared against a recomputed post-append length, so a
// single oversized chunk was silently truncated with truncated === false.
import { OutputBudget, Utf8Collector } from '../src/buffer.js'

const acc = () => ({ text: '', truncated: false })

test('a single oversized chunk flips truncated', () => {
  const budget = new OutputBudget(10)
  const state = acc()
  budget.append(state, 'abcdefghijklmno')
  assert.equal(state.text, 'abcdefghij')
  assert.equal(state.truncated, true, 'the cut must be visible to the caller')
})

test('output exactly at the cap is not truncated', () => {
  const budget = new OutputBudget(10)
  const state = acc()
  budget.append(state, 'abcdefghij')
  assert.equal(state.text, 'abcdefghij')
  assert.equal(budget.truncated, false)
})

test('several chunks under the cap are not truncated', () => {
  const budget = new OutputBudget(10)
  const state = acc()
  budget.append(state, 'abcd')
  budget.append(state, 'efgh')
  assert.equal(state.text, 'abcdefgh')
  assert.equal(budget.truncated, false)
})

test('overflow on the second chunk flips truncated', () => {
  const budget = new OutputBudget(10)
  const state = acc()
  budget.append(state, 'abcdefgh')
  budget.append(state, 'ijklm')
  assert.equal(state.text, 'abcdefghij')
  assert.equal(budget.truncated, true)
})

// ── 2. multi-byte characters must not split on chunk boundaries ──────────
// ── 2. multi-byte characters must not split on chunk boundaries ──────────

test('a multi-byte character split across chunks survives intact', () => {
  const c = new Utf8Collector(1024)
  const buf = Buffer.from('中文测试', 'utf8')
  // Feed one byte at a time: every boundary is mid-character at some point.
  for (const b of buf) c.push(Buffer.from([b]))
  assert.equal(c.toString(), '中文测试', 'no U+FFFD replacement characters')
  assert.equal(c.truncated, false)
})

test('the byte cap never emits a half character', () => {
  const c = new Utf8Collector(4) // exactly one 3-byte char plus one byte
  c.push(Buffer.from('中文', 'utf8'))
  const out = c.toString()
  assert.ok(!out.includes('\uFFFD'), 'got: ' + JSON.stringify(out))
  assert.equal(c.truncated, true)
})

// ── 2b. stdout and stderr share one budget ──────────────────────────────

test('stdout and stderr together stay within one cap', () => {
  const budget = new OutputBudget(10)
  const out = { text: '', truncated: false }
  const err = { text: '', truncated: false }
  budget.append(out, 'abcdefgh')   // 8 of 10
  budget.append(err, 'ijklmno')    // only 2 fit
  assert.equal(out.text, 'abcdefgh')
  assert.equal(err.text, 'ij')
  assert.equal(budget.used, 10)
  assert.equal(budget.truncated, true)
  assert.equal(err.truncated, true, 'the stream that was cut says so')
})

test('a budget that is never exhausted reports nothing truncated', () => {
  const budget = new OutputBudget(100)
  const out = { text: '', truncated: false }
  budget.append(out, 'hello')
  assert.equal(budget.truncated, false)
  assert.equal(out.truncated, false)
})

// ── 3. exec output cap is in characters, so it must not depend on bytes ──
test('the character cap counts code points, not UTF-16 units', () => {
  const c = new Utf8Collector(1 << 20)
  c.push(Buffer.from('中文字', 'utf8'))
  assert.equal(c.toString(), '中文字')
})
