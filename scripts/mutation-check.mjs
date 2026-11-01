#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe — mutation check.
//
// A test that passes is not the same as a test that would fail if the code were
// wrong. This applies one edit to a source file, runs a test file, and restores the
// file: the mutation is CAUGHT when the run fails, which is the only evidence that
// the test measures the behaviour it names.
//
// Two ways to get a false answer, both seen while checking this suite:
//   - a mutation that does not change behaviour ('max = -1' where the code only
//     tests 'max > 0') still passes, which says nothing about the test;
//   - 'node --test --test-name-pattern' with a pattern that matches nothing exits 0
//     and prints the file as one passing test, which looks like a caught mutation.
// The second is why this script greps the TAP output instead of trusting the exit
// code, and why it refuses a mutation that leaves the file unchanged.
//
// Usage: node scripts/mutation-check.mjs --file src/format.js \
//          --before "const shown = max > 0 ? window.slice(0, max) : window" \
//          --after "const shown = max === 0 ? [] : window.slice(0, max)" \
//          --test test/tools-live.test.js
//
//
// Checks that were run against this suite and are worth repeating after a refactor
// (each one was CAUGHT, which is the point — a mutation that is not caught means the
// test does not measure what it names):
//
//   node scripts/mutation-check.mjs --file src/hostkey.js \
//     --before "    else if (marker === 'cert-authority') certAuthorities.push({ hostField, keyType })" \
//     --after  "    else if (marker === 'cert-authority') { /* dropped */ }" \
//     --test test/openssh-known-hosts.test.js          # 0.7.409 — the CA-only file says why
//
//   node scripts/mutation-check.mjs --file src/index.js \
//     --before "        recordWorkspace('ok')" --after "        void 0" \
//     --test test/tools.test.js                        # 0.7.411 — ssh_workspace is audited
//
//   node scripts/mutation-check.mjs --file src/format.js \
//     --before "const shown = max > 0 ? window.slice(0, max) : window" \
//     --after  "const shown = max === 0 ? [] : window.slice(0, max)" \
//     --test test/tools-live.test.js                   # 0.7.416 — maxListEntries: 0 is unlimited
//
//   node scripts/mutation-check.mjs --file scripts/gui.mjs \
//     --before "    allowPlaintextPassword: settingsAllowPlaintext()," \
//     --after  "    allowPlaintextPassword: false," \
//     --test test/gui.test.js                          # 0.7.406 — the page reads the setting
//
// If this run is killed (a timeout, Ctrl-C on the wrapper, a machine that goes
// away), the file may be left mutated: 'git checkout -- <file>' restores it, and
// the header of the run says which file was being edited.
//
// Exit 0 = caught (or skipped because the anchor was missing), 1 = not caught.
import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'

const args = {}
const argv = process.argv.slice(2)
for (let i = 0; i < argv.length; i += 2) {
  const key = argv[i]
  if (!key || !key.startsWith('--')) {
    console.error('Unknown argument: ' + key + '. Use --file, --before, --after, --test.')
    process.exit(2)
  }
  args[key.slice(2)] = argv[i + 1]
}
for (const required of ['file', 'before', 'after', 'test']) {
  if (typeof args[required] !== 'string' || args[required] === '') {
    console.error('--' + required + ' is required.')
    process.exit(2)
  }
}
const target = path.resolve(args.file)
const original = readFileSync(target, 'utf8')
if (args.before === args.after) {
  console.error('--before and --after are identical: that mutation cannot change behaviour.')
  process.exit(2)
}
if (!original.includes(args.before)) {
  console.error('The --before text is not in ' + args.file + ', so nothing was changed.')
  console.error('A mutation that does not apply is not evidence — check the anchor.')
  process.exit(2)
}

let caught = false
let output = ''
// finally covers the normal paths; this covers a throw from outside the try and a
// process.exit() further down. A SIGKILL cannot be caught — see the header.
process.on('exit', () => {
  try { if (readFileSync(target, 'utf8') !== original) writeFileSync(target, original) } catch { /* nothing left to do */ }
})
try {
  writeFileSync(target, original.replace(args.before, args.after))
  try {
    output = execFileSync(process.execPath, ['--test', '--test-reporter=tap', '--test-timeout=180000', args.test], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 600000,
    })
  } catch (err) {
    output = String((err && err.stdout) || '') + String((err && err.stderr) || '')
  }
  // The exit status is not enough: a pattern that matches nothing also exits 0.
  caught = /^not ok \d+/m.test(output) || /^ℹ fail [1-9]/m.test(output) || /^# fail [1-9]/m.test(output)
} finally {
  writeFileSync(target, original)
}

const failing = (output.match(/^not ok \d+ - (.+)$/gm) || []).slice(0, 5).map((line) => line.replace(/^not ok \d+ - /, ''))
if (caught) {
  console.log('CAUGHT — the edited code fails ' + args.test + ':')
  for (const name of failing) console.log('  ' + name)
  process.exit(0)
}
console.log('NOT CAUGHT — the suite still passes with the behaviour changed.')
console.log('Either the mutation does not change behaviour, or no test measures it.')
process.exit(1)