import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkCommand, normalizeCommand, canonicalizeRm, DEFAULT_DENY_RULES } from '../src/guard.js'

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
test('quoting the target does not launder the command', () => {
  // Blanking quoted text for reading commands must not become a bypass: the
  // dangerous part of these sits outside the quotes.
  for (const cmd of [
    'rm -rf "/"',
    "rm -rf '/'",
    'sudo rm -rf "/"',
    'sh -c "rm -rf /"',
    "sh -c 'rm -rf /'",
    "sudo sh -c 'rm -rf /'",
    "xargs sh -c 'rm -rf /'",
    "find . -exec sh -c 'rm -rf /' \\;",
    'echo "rm -rf /" | bash',
  ]) {
    assert.equal(blocked(cmd), true, 'should refuse: ' + cmd)
  }
})

test('reading or printing the text is not the command', () => {
  // 'grep "rm -rf /" notes.md' was refused, and a rail that blocks searching
  // for a dangerous string is one the user turns off.
  const full = [
    '(?:^|[\\s;&|()])rm\\s+-[rf]{1,2}\\s+/+(?:\\*|\\.{1,2})?(?:\\s|$|[)])',
    '\\b(?:shutdown|reboot|halt|poweroff)\\b',
  ]
  for (const cmd of [
    "grep 'rm -rf /' notes.md",
    "egrep -c 'reboot' /var/log/syslog",
    "git commit -m \"guard: stop refusing rm -rf / mentions\"",
    "echo 'shutdown -h now' >> todo.txt",
    "man rm",
  ]) {
    assert.equal(checkCommand(cmd, full).blocked, false, 'should allow: ' + cmd)
  }
  // The unquoted part is still checked.
  assert.equal(checkCommand('grep x notes.md && rm -rf /', full).blocked, true)
})

test('every flag spelling of rm on / is caught, and ordinary paths are not', () => {
  // Measured slipping through before: 'rm --recursive --force /' and
  // 'rm -rf -- /'. Both delete the root, and the rule's own description promises
  // the spellings are covered.
  const patterns = DEFAULT_DENY_RULES.map((rule) => rule.pattern)
  for (const command of [
    'rm -rf /',
    'rm -fr /',
    'rm -Rf /',
    'rm -r -f /',
    'rm --recursive --force /',
    'rm -rf -- /',
    'rm -rf /*',
    'rm -rf /.',
    'rm -rf //',
  ]) {
    assert.equal(checkCommand(command, patterns).blocked, true, command)
  }

  // A seatbelt that blocks ordinary work gets switched off, which protects
  // nothing: these must stay allowed.
  for (const command of [
    'rm -rf /tmp/build',
    'rm -rf ./build',
    'rm -i file.txt',
    'rm -v /tmp/x',
    'rm file.txt',
  ]) {
    assert.equal(checkCommand(command, patterns).blocked, false, command)
  }
})

test('dd argument order and mke2fs are the same commands', () => {
  // Both were measured slipping through: 'dd of=/dev/sda if=/dev/zero' needed
  // if= first to match, and mke2fs is mkfs for ext2/3/4 under its own name.
  const patterns = DEFAULT_DENY_RULES.map((rule) => rule.pattern)
  for (const command of [
    'dd if=/dev/zero of=/dev/sda bs=1M',
    'dd of=/dev/sda if=/dev/zero bs=1M',
    'dd if=/dev/urandom of=/dev/nvme0n1',
    'mkfs.ext4 /dev/sda1',
    'mkfs -t ext4 /dev/sda1',
    'mke2fs /dev/sda1',
    'mke2fs -F /dev/sda1',
  ]) {
    assert.equal(checkCommand(command, patterns).blocked, true, command)
  }

  // A file is not a device: building a filesystem in an image is ordinary work.
  for (const command of [
    'dd if=/dev/zero of=./disk.img bs=1M count=10',
    'dd if=/dev/sda of=backup.img',
    'mkfs.ext4 ./disk.img',
    'mke2fs -F ./disk.img',
  ]) {
    assert.equal(checkCommand(command, patterns).blocked, false, command)
  }
})

test('a named fork bomb is caught and an ordinary function is not', () => {
  const patterns = DEFAULT_DENY_RULES.map((rule) => rule.pattern)
  for (const command of ['bomb(){ bomb|bomb& };bomb', 'f() { f & }; f', 'x(){ x | x; }']) {
    assert.equal(checkCommand(command, patterns).blocked, true, command)
  }
  for (const command of [
    'retry() { retry_once || true; }',
    'log(){ echo "$*" | tee -a log; }',
    'greet() { echo hi; }',
  ]) {
    assert.equal(checkCommand(command, patterns).blocked, false, command)
  }
})
