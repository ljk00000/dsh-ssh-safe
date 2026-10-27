import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkCommand, normalizeCommand, canonicalizeRm } from '../src/guard.js'

// The reference patterns shipped as the Config default.
const PATTERNS = [
  'rm\\s+-rf\\s+/(?:\\s|$)',
  '\\bmkfs\\.',
  '\\bdd\\s+if=.*\\bof=/dev/[sn]',
  ':\\(\\)\\s*\\{\\s*:\\|:\\s*&\\s*\\};:',
  '\\b(?:shutdown|reboot|halt|poweroff)\\b',
]

const blocked = (cmd) => checkCommand(cmd, PATTERNS).blocked

test('normalizeCommand collapses whitespace and strips quotes', () => {
  assert.equal(normalizeCommand('rm   -rf\t/'), 'rm -rf /')
  assert.equal(normalizeCommand("rm -rf '/'"), 'rm -rf /')
  assert.equal(normalizeCommand('/bin/rm -rf /'), 'rm -rf /')
})

test('canonicalizeRm unifies flag spelling', () => {
  assert.match(canonicalizeRm('rm -fr /'), /rm -rf \//)
  assert.match(canonicalizeRm('rm --recursive --force /'), /rm -rf \//)
  assert.match(canonicalizeRm('rm -r -f /'), /rm -rf \//)
})

test('catastrophic deletions are refused in every spelling', () => {
  for (const cmd of [
    'rm -rf /',
    'rm -fr /',
    'rm --recursive --force /',
    'rm  -rf  /',
    '/bin/rm -rf /',
    'sudo /bin/rm -rf /',
  ]) {
    assert.equal(blocked(cmd), true, 'should refuse: ' + cmd)
  }
})

test('a shell wrapper does not hide the command', () => {
  for (const cmd of [
    "bash -c 'rm -rf /'",
    'sh -c "rm -rf /"',
    "eval 'rm -rf /'",
    "env bash -c 'rm -rf /'",
  ]) {
    assert.equal(blocked(cmd), true, 'should refuse: ' + cmd)
  }
})

test('filesystem-destroying tools are refused', () => {
  assert.equal(blocked('mkfs.ext4 /dev/sda1'), true)
  assert.equal(blocked('dd if=/dev/zero of=/dev/sda'), true)
  assert.equal(blocked('shutdown -h now'), true)
  assert.equal(blocked('reboot'), true)
})

test('ordinary work is allowed', () => {
  for (const cmd of [
    'rm -rf /home/user/build',
    'rm -rf ./build',
    'rm file.txt',
    'systemctl restart nginx',
    'git status',
    'cat /etc/hosts',
    'python train.py --epochs 10',
    "bash -c 'ls -la'",
  ]) {
    assert.equal(blocked(cmd), false, 'should allow: ' + cmd)
  }
})

test('the refusal names the pattern so it can be tuned', () => {
  const r = checkCommand('rm -rf /', PATTERNS)
  assert.equal(r.blocked, true)
  assert.ok(r.pattern && r.pattern.length > 0)
})

test('an empty pattern list blocks nothing', () => {
  assert.equal(checkCommand('rm -rf /', []).blocked, false)
})
