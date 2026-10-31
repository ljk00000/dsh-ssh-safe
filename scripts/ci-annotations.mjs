// Turn a TAP test log into GitHub Actions annotations.
//
// Why this exists: the job log needs repository admin rights to download, so a
// failing CI run only ever said "Process completed with exit code 1". An
// annotation is readable by anyone, and it can carry the failing test name and
// the assertion message -- which is the whole diagnosis.
//
// Usage: node scripts/ci-annotations.mjs test-output.txt

import { readFileSync } from 'node:fs'

const ESCAPE = (text) => String(text)
  .replace(/%/g, '%25')
  .replace(/\r/g, '%0D')
  .replace(/\n/g, '%0A')

const file = process.argv[2]
if (!file) {
  console.log('::error::ci-annotations: no log file given')
  process.exit(0)
}

let text = ''
try {
  text = readFileSync(file, 'utf8')
} catch (err) {
  console.log('::error::ci-annotations: ' + ESCAPE(err.message))
  process.exit(0)
}

// A log written by PowerShell may start with a byte-order mark, which would
  // make the first "not ok" line unmatchable.
const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/)
let reported = 0
for (let i = 0; i < lines.length; i++) {
  const start = /^not ok \d+ - (.*)$/.exec(lines[i])
  if (!start) continue
  const name = start[1]
  let detail = ''
  let location = ''
  for (let j = i + 1; j < Math.min(i + 25, lines.length); j++) {
    const line = lines[j]
    if (/^ok \d+/.test(line) || /^not ok \d+/.test(line)) break
    const error = /^\s{2}error:\s*(.*)$/.exec(line)
    if (error && !detail) {
      detail = error[1]
      // "error: |-" is a YAML block: the message itself is on the next lines.
      if (detail === '|-' || detail === '|') {
        detail = ''
        for (let k = j + 1; k < Math.min(j + 8, lines.length); k++) {
          const body = lines[k]
          if (/^\s{2}[a-zA-Z]+:/.test(body)) break
          if (body.trim()) { detail = body.trim(); break }
        }
      }
    }
    const loc = /^\s{2}location:\s*'(.*)'$/.exec(line)
    if (loc && !location) location = loc[1]
  }
  const where = /test[\\/]([^\\/]+\.test\.js)/.exec(location)
  const attribute = where ? ' file=test/' + where[1] : ''
  const message = ESCAPE('failing test: ' + name + (detail ? ' — ' + detail.replace(/^'|'$/g, '') : ''))
  console.log('::error' + attribute + '::' + message)
  reported += 1
  if (reported >= 25) {
    console.log('::warning::more than 25 tests failed; further names are in the log')
    break
  }
}
if (reported === 0) {
  console.log('::error::the test run failed but no "not ok" line was captured')
}
