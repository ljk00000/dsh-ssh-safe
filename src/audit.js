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

import { appendFileSync, mkdirSync, readFileSync, renameSync, statSync } from 'node:fs'
import path from 'node:path'

/** Default cap so a long-running session cannot fill the disk. */
const DEFAULT_MAX_BYTES = 4 * 1024 * 1024

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
  if (text.length > maxLength) text = text.slice(0, maxLength) + '…'
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
        at: new Date().toISOString(),
        ...record,
      })
      appendFileSync(this.file, line + '\n', { encoding: 'utf8' })
    } catch {
      // A read-only home directory, a full disk, a permission change: none of
      // these should turn a successful command into a failure.
      this.failures += 1
    }
  }

  /** Rotate to .1 when the file exceeds the cap, keeping one previous file. */
  #rotateIfNeeded() {
    let size = 0
    try { size = statSync(this.file).size } catch { return }
    if (size < this.maxBytes) return
    try { renameSync(this.file, this.file + '.1') } catch { /* keep appending if it fails */ }
  }

  /**
   * Read the most recent records, newest last.
   * @param {number} limit
   */
  recent(limit = 50) {
    try {
      const text = readFileSync(this.file, 'utf8')
      const lines = text.split('\n').filter(Boolean)
      return lines.slice(-limit).map((line) => {
        try { return JSON.parse(line) } catch { return { malformed: true, line: line.slice(0, 120) } }
      })
    } catch {
      return []
    }
  }
}
