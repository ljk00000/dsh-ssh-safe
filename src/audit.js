// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe — operation audit log.
//
// A plugin that advertises safety must be able to answer "what did the agent
// actually do on my server". Blocking patterns only describe what was
// prevented; this records what happened.
//
// What is recorded: timestamp, alias, operation, a one-line command summary,
// exit code, whether the guard refused it, and how long it took.
//
// What is deliberately NOT recorded: command output, file contents, any
// credential. An audit log that copies stdout would become a second, larger
// leak surface -- the opposite of the point.

import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from 'node:fs'
import path from 'node:path'

/** Default cap so a long-running session cannot fill the disk. */
const DEFAULT_MAX_BYTES = 4 * 1024 * 1024

/** How many rotated generations to keep beside the live log. */
const ROTATED_GENERATIONS = 4

/** Hard cap on any single string field in a record. */
const MAX_FIELD_CHARS = 300

/**
 * Bound a record's fields before it is written.
 *
 * The callers already summarise commands, but the log must not depend on that:
 * a caller that passed a raw 5,000 character command wrote a 5,102 byte line,
 * and rotation only looks at the file size *before* appending, so a handful of
 * such records lands past the cap. Non-string objects are replaced rather than
 * serialised, so nothing nested can grow a line either.
 *
 * @param {object} record
 * @returns {Record<string, unknown>}
 */
function clampRecord(record) {
  /** @type {Record<string, unknown>} */
  const out = {}
  for (const [key, value] of Object.entries(record && typeof record === 'object' ? record : {})) {
    if (value === undefined || typeof value === 'function') continue
    if (typeof value === 'string') {
      out[key] = value.length > MAX_FIELD_CHARS ? value.slice(0, MAX_FIELD_CHARS) + '…' : value
    } else if (value === null || typeof value === 'number' || typeof value === 'boolean') {
      out[key] = value
    } else {
      out[key] = '[object]'
    }
  }
  return out
}

/**
 * Trim a command to one readable line for the log.
 * Keeps the shape without the bulk: multi-line scripts collapse to their first
 * line plus a marker.
 */
export function summarize(command, maxLength = 200) {
  const raw = String(command ?? '')
  const firstLine = raw.split(/\r?\n/)[0].trim()
  const multi = raw.includes('\n')
  let text = firstLine
  if (text.length > maxLength) {
    text = text.slice(0, maxLength)
    // Do not cut a surrogate pair in half: the record is NDJSON, and a lone
    // half renders as a replacement character in every reader.
    if (/[\uD800-\uDBFF]$/.test(text)) text = text.slice(0, -1)
    text += '…'
  }
  if (multi) text += ' [+' + (raw.split(/\r?\n/).length - 1) + ' more lines]'
  return text
}

export class AuditLog {
  /**
   * @param {string} directory directory the log file lives in
   * @param {{enabled?: boolean, maxBytes?: number}} [options]
   */
  constructor(directory, options = {}) {
    this.enabled = options.enabled !== false
    this.maxBytes = Number(options.maxBytes) || DEFAULT_MAX_BYTES
    this.file = path.join(directory, 'audit.ndjson')
    this.failures = 0
  }

  /**
   * Append one record. Never throws: auditing must not break an operation.
   * @param {object} record
   */
  write(record) {
    if (!this.enabled) return
    try {
      mkdirSync(path.dirname(this.file), { recursive: true })
      this.#rotateIfNeeded()
      const line = JSON.stringify({
        ...clampRecord(record),
        // Authoritative: a record must not be able to rewrite its timestamp.
        at: new Date().toISOString(),
      })
      appendFileSync(this.file, line + '\n', { encoding: 'utf8' })
      // After the write: the file must exist before its mode can be set.
      this.#ensurePrivate()
    } catch {
      // A read-only home directory, a full disk, a permission change: none of
      // these should turn a successful command into a failure.
      this.failures += 1
    }
  }

  /**
   * Keep the log readable only by its owner.
   *
   * The file records hosts, commands and file paths. The default mode is 0644,
   * which means every other account on the machine can read it -- not acceptable
   * for a plugin whose selling point is that it keeps secrets out of the way.
   * Windows has no POSIX mode, so the call is a no-op there.
   */
  #ensurePrivate() {
    try {
      if (process.platform === 'win32') return
      if (!existsSync(this.file)) return
      chmodSync(this.file, 0o600)
    } catch {
      // A filesystem without POSIX modes (or a permission change) must not turn
      // a successful command into a failure.
      this.failures += 1
    }
  }

  /** Rotate when the file exceeds the cap, keeping ROTATED_GENERATIONS generations. */
  #rotateIfNeeded() {
    let size = 0
    try { size = statSync(this.file).size } catch { return }
    if (size < this.maxBytes) return
    try {
      // Shift the generations up, dropping the oldest one. Overwriting .1
      // silently lost records, and recent() could not read them back.
      for (let g = ROTATED_GENERATIONS - 1; g >= 1; g--) {
        const from = this.file + '.' + g
        const to = this.file + '.' + (g + 1)
        if (!existsSync(from)) continue
        try { renameSync(from, to) } catch { /* keep going */ }
      }
      renameSync(this.file, this.file + '.1')
    } catch { /* keep appending if it fails */ }
  }

  /**
   * Read the most recent records, newest last.
   * @param {number} limit
   */
  recent(limit = 50) {
    try {
      // Oldest generation first, so the newest records end up last.
      const all = []
      // Oldest generation first, newest last, so the records read in the order
      // they were written.
      const names = []
      for (let g = ROTATED_GENERATIONS; g >= 1; g--) names.push(this.file + '.' + g)
      names.push(this.file)
      for (const name of names) {
        try {
          for (const line of readFileSync(name, 'utf8').split('\n')) {
            if (line) all.push(line)
          }
        } catch { /* that generation may not exist */ }
      }
      // A negative limit used to mean 'drop the first N': slice(-(-5)) is
      // slice(5), so recent(-5) returned everything except the oldest five.
      const take = Number.isFinite(Number(limit)) ? Math.max(1, Math.floor(Number(limit))) : 50
      return all.slice(-take).map((line) => {
        try {
          const parsed = JSON.parse(line)
          // A log line is a record or nothing. 'null', a bare number or an array
          // parses fine and then breaks the renderer: a single such line in
          // audit.ndjson took ssh_audit down with a TypeError.
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed
          return { malformed: true, line: line.slice(0, 120) }
        } catch {
          return { malformed: true, line: line.slice(0, 120) }
        }
      })
    } catch {
      return []
    }
  }
}
