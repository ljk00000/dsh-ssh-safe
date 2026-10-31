// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe — output buffering helpers.
//
// Two bugs lived here before these helpers existed:
//   1. truncation was computed against a post-append length, so a single
//      oversized chunk was cut silently (truncated stayed false);
//   2. chunks were converted to strings independently, so a multi-byte UTF-8
//      character straddling a chunk boundary became U+FFFD replacement
//      characters — Chinese output was corrupted at random.
//
// Both are pinned by test/regression.test.js.

/**
 * A shared character budget across several capped accumulators.
 *
 * maxOutputChars is documented as the ceiling on collected output per call.
 * Two independent accumulators (stdout and stderr) each capped at that value
 * would let one call hold twice the advertised amount, so they share one budget.
 */
/**
 * Count characters the way a reader counts them.
 *
 * String#length counts UTF-16 units, so an emoji counts as two: '2976 more
 * characters were dropped' when 1488 emoji went missing is off by a factor of
 * two for exactly the characters that are hardest to eyeball.
 *
 * @param {string} text
 * @returns {number}
 */
export function countCodePoints(text) {
  const value = String(text ?? '')
  if (value.length === 0) return 0
  const surrogatePairs = value.match(/[\uD800-\uDBFF]/g)
  return value.length - (surrogatePairs ? surrogatePairs.length : 0)
}

export class OutputBudget {
  /** @param {number} cap total characters across every stream */
  constructor(cap) {
    this.cap = cap
    this.used = 0
    this.truncated = false
    // How much was thrown away. "output was truncated" without a number left
    // the caller guessing whether one character or a megabyte was lost.
    this.dropped = 0
  }

  /** Characters still available. */
  get remaining() { return Math.max(0, this.cap - this.used) }

  /**
   * Append to an accumulator, drawing from the shared budget.
   *
   * Returns the part that was kept, so a second consumer of the same stream
   * (the interleaving timeline exec() renders) can be bounded by the same
   * budget. It used to return the state object and the timeline was built from
   * the raw chunks, which is how maxOutputChars=4000 still produced a 337k
   * character result: the cap applied to the string nobody rendered.
   *
   * @param {{text: string, truncated: boolean}} state
   * @param {string} chunk
   * @returns {string} the accepted portion of chunk ('' once the budget is gone)
   */
  append(state, chunk) {
    const text = String(chunk ?? '')
    if (text.length === 0) return ''
    const room = this.remaining
    if (room <= 0) {
      state.truncated = true
      this.truncated = true
      this.dropped += countCodePoints(text)
      return ''
    }
    let take = text.length > room ? text.slice(0, room) : text
    // Never end on half of a surrogate pair. An unpaired surrogate survives
    // JSON.stringify (as \ud83d) but renders as a replacement character
    // downstream, and strict consumers reject it outright.
    if (take.length > 0 && take.length < text.length) {
      const last = take.charCodeAt(take.length - 1)
      if (last >= 0xd800 && last <= 0xdbff) take = take.slice(0, -1)
    }
    state.text += take
    this.used += take.length
    if (take.length < text.length) {
      state.truncated = true
      this.truncated = true
      this.dropped += countCodePoints(text.slice(take.length))
    }
    return take
  }
}

/**
 * Collect a UTF-8 byte stream without splitting characters.
 *
 * Bytes are buffered as one Buffer and only decoded at toString(), so a
 * character split across chunk boundaries is decoded once, whole.
 */
export class Utf8Collector {
  /** @param {number} maxBytes stop accepting bytes past this many */
  constructor(maxBytes = 1048576) {
    this.maxBytes = maxBytes
    /** @type {Buffer[]} */
    this.chunks = []
    this.size = 0
    this.truncated = false
  }

  /** @param {Buffer|Uint8Array} chunk */
  push(chunk) {
    if (!chunk || chunk.length === 0) return this
    const room = this.maxBytes - this.size
    if (room <= 0) {
      this.truncated = true
      return this
    }
    const view = chunk.length > room ? chunk.subarray(0, room) : chunk
    this.chunks.push(Buffer.isBuffer(view) ? view : Buffer.from(view))
    this.size += view.length
    if (view.length < chunk.length) this.truncated = true
    return this
  }

  /** Decode once, dropping any trailing incomplete character. */
  toString() {
    if (this.chunks.length === 0) return ''
    const buf = Buffer.concat(this.chunks, this.size)
    // A cap can land mid-character. node's decoder emits U+FFFD for the tail;
    // strip a single trailing replacement char when we truncated, so the
    // caller sees clean text instead of a corruption marker.
    const text = buf.toString('utf8')
    if (!this.truncated) return text
    return text.replace(/\uFFFD$/, '')
  }

  get bytes() { return this.size }
}
