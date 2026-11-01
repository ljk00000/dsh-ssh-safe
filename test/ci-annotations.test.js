import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// The script turns a TAP log into GitHub annotations so a failing run page names
// the test. It never had a test of its own, and two of its three silent failures
// lived here: a UTF-16 log (a PowerShell redirect) matched no line at all, and a
// Windows location -- where TAP escapes the backslashes -- lost the file= link.

const here = path.dirname(fileURLToPath(import.meta.url))
const script = path.join(here, '..', 'scripts', 'ci-annotations.mjs')

const run = (file) => spawnSync(process.execPath, [script, file], { encoding: 'utf8', timeout: 20000 })

const tapWithOneFailure = [
  'TAP version 13',
  'ok 1 - a passing test',
  'not ok 2 - the broken one',
  '  ---',
  '  duration_ms: 12.3',
  "  location: 'C:\\\\repo\\\\test\\\\tools.test.js:42:1'",
  "  error: 'expected 2 to equal 3'",
  '  ...',
  '1..2',
].join('\n')

test('a UTF-8 log becomes one annotation per failing test', () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-ann-'))
  try {
    const file = path.join(home, 'tap.txt')
    writeFileSync(file, tapWithOneFailure, 'utf8')
    const out = run(file)
    assert.equal(out.status, 0, out.stderr)
    assert.match(out.stdout, /::error file=test\/tools\.test\.js::failing test: the broken one — expected 2 to equal 3/)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('a UTF-16 log (PowerShell redirect) is read, not reported as empty', () => {
  // `node --test --test-reporter=tap > log.txt` in PowerShell writes UTF-16LE.
  // The old reader saw NUL bytes, matched nothing, and said 'the test run failed
  // but no "not ok" line was captured' about a log that named the test on line 3.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-ann-utf16-'))
  try {
    const file = path.join(home, 'tap16.txt')
    writeFileSync(file, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(tapWithOneFailure, 'utf16le')]))
    const out = run(file)
    assert.equal(out.status, 0, out.stderr)
    assert.match(out.stdout, /::error file=test\/tools\.test\.js::failing test: the broken one/)
    assert.doesNotMatch(out.stdout, /no "not ok" line was captured/)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('a log with no failing test says so', () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-ann-ok-'))
  try {
    const file = path.join(home, 'ok.txt')
    writeFileSync(file, 'TAP version 13\nok 1 - fine\n1..1\n', 'utf8')
    const out = run(file)
    assert.match(out.stdout, /no "not ok" line was captured/)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('a missing log is reported by name', () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-ann-missing-'))
  try {
    const out = run(path.join(home, 'not-there.txt'))
    assert.match(out.stdout, /::error::ci-annotations: .*not-there\.txt/)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('the 25-annotation cap says how many actually failed, and stays quiet at 25', () => {
  // The warning fired on the 25th annotation with 'more than 25 tests failed', even
  // when exactly 25 had failed and nothing was withheld.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-ann-cap-'))
  const build = (count) => {
    const lines = ['TAP version 13']
    for (let i = 1; i <= count; i++) {
      lines.push('not ok ' + i + ' - failure ' + i)
      lines.push("  error: 'boom ' + i")
    }
    lines.push('1..' + count)
    return lines.join('\n')
  }
  try {
    const many = path.join(home, 'many.txt')
    writeFileSync(many, build(30), 'utf8')
    const out = run(many)
    const errors = out.stdout.split('\n').filter((l) => l.startsWith('::error::'))
    assert.equal(errors.length, 25, 'at most 25 annotations: ' + errors.length)
    assert.match(out.stdout, /::warning::30 tests failed; only the first 25 are annotated here/)

    const exact = path.join(home, 'exact.txt')
    writeFileSync(exact, build(25), 'utf8')
    const exactOut = run(exact)
    assert.equal(exactOut.stdout.split('\n').filter((l) => l.startsWith('::error::')).length, 25)
    assert.doesNotMatch(exactOut.stdout, /::warning::/, 'nothing was withheld, so no warning: ' + exactOut.stdout)
  } finally { rmSync(home, { recursive: true, force: true }) }
})
