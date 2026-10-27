import { test } from 'node:test'
import assert from 'node:assert/strict'

// These tests pin behaviour that was previously wrong. Each one failed against
// the first published implementation.

// ── 1. truncation must be reported whenever output was actually cut ──────
// The old push() compared against a recomputed post-append length, so a single
// oversized chunk was silently truncated with truncated === false.
import { appendCapped } from '../src/buffer.js'

test('a single oversized chunk flips truncated', () => {
  const state = { text: '', truncated: false }
  appendCapped(state, 'abcdefghijklmno', 10)
  assert.equal(state.text, 'abcdefghij')
  assert.equal(state.truncated, true, 'the cut must be visible to the caller')
})

test('output exactly at the cap is not truncated', () => {
  const state = { text: '', truncated: false }
  appendCapped(state, 'abcdefghij', 10)
  assert.equal(state.text, 'abcdefghij')
  assert.equal(state.truncated, false)
})

test('several chunks under the cap are not truncated', () => {
  const state = { text: '', truncated: false }
  appendCapped(state, 'abcd', 10)
  appendCapped(state, 'efgh', 10)
  assert.equal(state.text, 'abcdefgh')
  assert.equal(state.truncated, false)
})

test('overflow on the second chunk flips truncated', () => {
  const state = { text: '', truncated: false }
  appendCapped(state, 'abcdefgh', 10)
  appendCapped(state, 'ijklm', 10)
  assert.equal(state.text, 'abcdefghij')
  assert.equal(state.truncated, true)
})

// ── 2. multi-byte characters must not split on chunk boundaries ──────────
import { Utf8Collector } from '../src/buffer.js'

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

// ── 3. exec output cap is in characters, so it must not depend on bytes ──
test('the character cap counts code points, not UTF-16 units', () => {
  const c = new Utf8Collector(1 << 20)
  c.push(Buffer.from('中文字', 'utf8'))
  assert.equal(c.toString(), '中文字')
})
