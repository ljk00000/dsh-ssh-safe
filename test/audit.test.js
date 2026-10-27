import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { AuditLog, summarize } from '../src/audit.js'

function dir() { return mkdtempSync(path.join(tmpdir(), 'dsh-ssh-audit-')) }

test('summarize keeps one line and marks the rest', () => {
  assert.equal(summarize('ls -la'), 'ls -la')
  assert.match(summarize('line1\nline2\nline3'), /line1 \[\+2 more lines\]/)
})

test('summarize truncates a long command', () => {
  const long = 'a'.repeat(400)
  const out = summarize(long, 50)
  assert.ok(out.length <= 51, 'got ' + out.length)
  assert.match(out, /…$/)
})

test('a record is appended as one JSON line', () => {
  const d = dir()
  try {
    const audit = new AuditLog(d, { enabled: true })
    audit.write({ kind: 'exec', machine: 'prod', command: 'ls', outcome: 'ok', exitCode: 0 })
    const text = readFileSync(path.join(d, 'audit.ndjson'), 'utf8')
    const lines = text.split('\n').filter(Boolean)
    assert.equal(lines.length, 1)
    const record = JSON.parse(lines[0])
    assert.equal(record.kind, 'exec')
    assert.equal(record.machine, 'prod')
    assert.ok(record.at, 'a timestamp is always recorded')
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('a disabled log writes nothing', () => {
  const d = dir()
  try {
    const audit = new AuditLog(d, { enabled: false })
    audit.write({ kind: 'exec' })
    assert.equal(existsSync(path.join(d, 'audit.ndjson')), false)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('a write failure does not throw', () => {
  const audit = new AuditLog('\\\\?\\invalid\\path', { enabled: true })
  assert.doesNotThrow(() => audit.write({ kind: 'exec' }))
  assert.equal(audit.failures, 1, 'the failure is counted, not raised')
})

test('recent returns the newest records last', () => {
  const d = dir()
  try {
    const audit = new AuditLog(d, { enabled: true })
    for (let i = 1; i <= 5; i++) audit.write({ kind: 'exec', command: 'c' + i })
    const records = audit.recent(3)
    assert.equal(records.length, 3)
    assert.deepEqual(records.map((r) => r.command), ['c3', 'c4', 'c5'])
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('the log rotates instead of growing without bound', () => {
  const d = dir()
  try {
    const audit = new AuditLog(d, { enabled: true, maxBytes: 400 })
    for (let i = 0; i < 50; i++) audit.write({ kind: 'exec', command: 'command-number-' + i })
    assert.ok(existsSync(path.join(d, 'audit.ndjson.1')), 'the previous file was kept')
    const size = readFileSync(path.join(d, 'audit.ndjson'), 'utf8').length
    assert.ok(size <= 400, 'the live file respects the cap, got ' + size)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('a malformed line is reported rather than thrown', () => {
  const d = dir()
  try {
    const audit = new AuditLog(d, { enabled: true })
    audit.write({ kind: 'exec', command: 'good' })
    writeFileSync(path.join(d, 'audit.ndjson'), 'not json\n', { flag: 'a' })
    const records = audit.recent(10)
    assert.ok(records.some((r) => r.malformed === true))
  } finally { rmSync(d, { recursive: true, force: true }) }
})
