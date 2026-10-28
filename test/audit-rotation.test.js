import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, statSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { AuditLog } from '../src/audit.js'

// The log rotated by overwriting .1, and recent() only read the live file, so
// records older than the last rotation were unreachable through the tool --
// exactly the window that matters after an incident.

const dir = () => mkdtempSync(path.join(tmpdir(), 'dsh-audit-'))

test('records survive a rotation', () => {
  const d = dir()
  try {
    const log = new AuditLog(d, { enabled: true, maxBytes: 150 })
    for (const c of ['one','two','three','four','five','six','seven','eight','nine','ten']) {
      log.write({ kind: 'exec', machine: 'a', command: c })
    }
    const recs = log.recent(100)
    assert.equal(recs.length, 10, 'every record must still be readable')
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('records read back in the order they were written', () => {
  const d = dir()
  try {
    const log = new AuditLog(d, { enabled: true, maxBytes: 150 })
    const names = ['one','two','three','four','five','six','seven','eight','nine','ten']
    for (const c of names) log.write({ kind: 'exec', machine: 'a', command: c })
    const recs = log.recent(100)
    assert.deepEqual(recs.map((r) => r.command), names)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('the rotated generations are kept on disk', () => {
  const d = dir()
  try {
    const log = new AuditLog(d, { enabled: true, maxBytes: 150 })
    for (const c of ['one','two','three','four','five','six','seven','eight','nine','ten']) {
      log.write({ kind: 'exec', machine: 'a', command: c })
    }
    const files = readdirSync(d)
    assert.ok(files.includes('audit.ndjson.1'), 'the previous generation is kept')
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('the log file is readable only by its owner where POSIX modes apply', () => {
  const d = dir()
  try {
    const log = new AuditLog(d, { enabled: true })
    log.write({ kind: 'exec', machine: 'a', command: 'ls' })
    const mode = statSync(path.join(d, 'audit.ndjson')).mode & 0o777
    if (process.platform === 'win32') {
      // Windows has no POSIX mode; the chmod is skipped by design.
      assert.ok(true)
    } else {
      assert.equal(mode, 0o600, 'expected 0600, got ' + mode.toString(8))
    }
  } finally { rmSync(d, { recursive: true, force: true }) }
})
