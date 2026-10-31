// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe — rendering helpers that do not need a connection.
//
// These lived inline in the tool bodies, where the only way to test them was to
// open an SSH session. A directory listing of 200k files produced a 20 MB tool
// result and there was no seam to pin the ceiling.

/**
 * Escape the control characters a filename may legally contain.
 *
 * A name with a newline in it used to split the rendered row in two, so one
 * entry looked like two and the second half looked like unlisted output.
 *
 * @param {unknown} name
 * @returns {string}
 */
function printable(name) {
  return String(name ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
    // C0, DEL, the C1 range (NEL, U+0085, breaks a row in some renderers), the
    // Unicode line/paragraph separators, and the bidi overrides — '‮txt.exe'
    // displays as 'exe.txt', which is a filename that lies about itself.
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, (c) => {
      const code = c.charCodeAt(0)
      return code <= 0xff
        ? '\\x' + code.toString(16).padStart(2, '0')
        : '\\u' + code.toString(16).padStart(4, '0')
    })
}

/**
 * The status line for one command result.
 *
 * A command killed by a signal has no exit code: ssh2 reports
 * `close(null, 'SIGKILL')`. Rendering that as `[exit unknown]` throws away the
 * one fact the caller needs, which is that the shell did not decide the status
 * — a signal did.
 *
 * @param {{code?: number|null, signal?: string|null}} result
 * @returns {string}
 */
export function exitLine(result) {
  const code = result ? result.code : null
  const signal = result ? result.signal : null
  if ((code === null || code === undefined) && typeof signal === 'string' && signal.length > 0) {
    return '[signal ' + signal + ']'
  }
  return '[exit ' + (code === null || code === undefined ? 'unknown' : code) + ']'
}

/**
 * '1 byte' / '2 bytes'. A written one-character file used to read
 * 'Wrote 1 bytes', which makes an otherwise careful message look careless.
 *
 * @param {number} count
 * @param {string} noun a noun with regular plural
 * @returns {string}
 */
export function plural(count, noun) {
  const n = Number(count) || 0
  return n + ' ' + noun + (n === 1 ? '' : 's')
}

/**
 * Render a directory listing.
 *
 * @param {{path: string, items: Array<{name: string, size: number, dir: boolean, type?: string, mtime?: string|null}>}} listing
 * @param {number} [limit] maximum rows; 0 or absent means no limit
 * @param {number} [offset] rows to skip after sorting, for paging
 * @returns {string}
 */
export function formatListing(listing, limit = 0, offset = 0) {
  const items = Array.isArray(listing?.items) ? listing.items : []
  const path = String(listing?.path || '.')
  if (items.length === 0) return '(empty directory: ' + path + ')'

  // Directories first, then by name. Sorting before the cap keeps the visible
  // rows stable instead of depending on readdir's order.
  const sorted = items.slice().sort((a, b) =>
    a.dir === b.dir ? String(a.name).localeCompare(String(b.name)) : a.dir ? -1 : 1)

  // Offset pages through a directory larger than the row cap. The cap is a
  // config value, so without this a caller could never reach entry 3001.
  const start = Math.max(0, Math.floor(Number(offset) || 0))
  const window = start > 0 ? sorted.slice(start) : sorted
  const max = Number(limit) > 0 ? Number(limit) : 0
  const shown = max > 0 ? window.slice(0, max) : window
  const omitted = window.length - shown.length

  const rows = shown.map((it) =>
    // The type character comes from the mode when the caller knows it: a symlink
    // or a FIFO shown as '-' looks like an ordinary file.
    (it.type || (it.dir ? 'd' : '-')) + ' ' + String(it.size).padStart(10) + '  ' + (it.mtime || '') + '  ' + printable(it.name))

  const head = start > 0 && sorted.length > start
    ? '… ' + start + ' entr' + (start === 1 ? 'y' : 'ies') + ' above not shown (offset = ' + start + ')\n'
    : ''
  const tail = omitted > 0
    ? '\n… ' + omitted + ' more entr' + (omitted === 1 ? 'y' : 'ies') + ' not shown (maxListEntries = ' + max +
      ') — pass offset: ' + (start + shown.length) + ' to continue'
    : ''
  // An offset past the end is not an error, but "(empty directory)" would be a
  // lie about a directory that has entries.
  if (start >= sorted.length && start > 0) {
    return path + '\n(offset ' + start + ' is past the last of ' + sorted.length + ' entries)'
  }

  return path + '\n' + head + rows.join('\n') + tail
}