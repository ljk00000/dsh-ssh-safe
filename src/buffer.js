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
 * Append text to a capped accumulator.
 * @param {{text: string, truncated: boolean}} state mutated in place
 * @param {string} chunk
 * @param {number} cap maximum number of UTF-16 units to keep
 */
export function appendCapped(state, chunk, cap) {
  const text = String(chunk ?? '')
  if (text.length === 0) return state
  const room = cap - state.text.length
  if (room <= 0) {
    state.truncated = true
    return state
  }
  if (text.length > room) {
    // Keep only what fits and say so. The old code decided this from a
    // recomputed length and therefore missed the single-chunk case.
    state.text += text.slice(0, room)
    state.truncated = true
    return state
  }
  state.text += text
  return state
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
