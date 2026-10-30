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
  const base = mkdtempSync(path.join(tmpdir(), 'dsh-audit-fail-'))
  try {
    // A path inside an existing file fails with ENOTDIR on every platform.
    // The previous version used a Windows-only invalid path, which Linux
    // accepted as an ordinary directory name -- so the write succeeded and the
    // assertion failed only on CI.
    const blocker = path.join(base, 'a-file')
    writeFileSync(blocker, 'x')
    const audit = new AuditLog(path.join(blocker, 'sub'), { enabled: true })
    assert.doesNotThrow(() => audit.write({ kind: 'exec' }))
    assert.equal(audit.failures, 1, 'the failure is counted, not raised')
  } finally {
    rmSync(base, { recursive: true, force: true })
  }
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
test('the log recovers when the file or its directory is deleted', () => {
  const d = dir()
  try {
    const log = new AuditLog(d)
    log.write({ kind: 'exec', machine: 't', command: 'one' })
    const file = path.join(d, 'audit.ndjson')
    rmSync(file, { force: true })
    log.write({ kind: 'exec', machine: 't', command: 'two' })
    assert.equal(existsSync(file), true, 'the file must come back')
    assert.match(readFileSync(file, 'utf8'), /two/)

    rmSync(d, { recursive: true, force: true })
    log.write({ kind: 'exec', machine: 't', command: 'three' })
    assert.equal(existsSync(file), true, 'the directory must come back')
    assert.match(readFileSync(file, 'utf8'), /three/)
    assert.equal(log.failures, 0, 'recovering is not a failure')
  } finally { rmSync(d, { recursive: true, force: true }) }
})
test('a line that parses to a non-object is reported, not passed on', () => {
  // JSON.parse('null') succeeds. Handing the null to a renderer made ssh_audit
  // throw a TypeError and take the whole review down with it.
  const d = dir()
  try {
    const audit = new AuditLog(d, { enabled: true })
    audit.write({ kind: 'exec', machine: 't', command: 'good' })
    writeFileSync(path.join(d, 'audit.ndjson'), ['null', '42', '"text"', '[1,2]', ''].join('\n') + '\n', { flag: 'a' })
    const records = audit.recent(10)
    const objects = records.filter((r) => r && typeof r === 'object' && !r.malformed)
    assert.equal(objects.length, 1, 'the real record survives: ' + JSON.stringify(records))
    assert.equal(objects[0].command, 'good')
    const malformed = records.filter((r) => r && r.malformed === true)
    assert.equal(malformed.length, 4, 'null, number, string and array are all unreadable')
    for (const record of malformed) assert.equal(typeof record.line, 'string')
  } finally { rmSync(d, { recursive: true, force: true }) }
})
test('summarize does not cut a multi-byte character in half', () => {
  // The record is NDJSON; a lone surrogate renders as a replacement character
  // in every reader, and the command column is the one people scan.
  const text = summarize('a'.repeat(199) + '🙂' + 'tail', 200)
  assert.equal(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(text), false, 'lone surrogate: ' + JSON.stringify(text.slice(-4)))
  assert.ok(text.endsWith('…'))
})

test('a negative limit is not a request to drop the oldest records', () => {
  // slice(-(-5)) is slice(5): recent(-5) used to return everything but the five
  // oldest. The tool clamps its argument, but the log must not depend on that.
  const dir = mkdtempSync(path.join(tmpdir(), 'dsh-aud-'))
  try {
    const log = new AuditLog(dir, { enabled: true })
    for (let i = 0; i < 10; i++) log.write({ kind: 'exec', command: 'c' + i })
    assert.equal(log.recent(-5).length, 1)
    assert.equal(log.recent(0).length, 1)
    assert.equal(log.recent(3).length, 3)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
