import { test } from 'node:test'
import { createHash } from 'node:crypto'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, statSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { checkHostKey, checkOpenSshHostKey, fingerprint, keyId, storePath, fingerprintsEqual } from '../src/hostkey.js'

const keyA = Buffer.from('key-A')
const keyB = Buffer.from('key-B')

function freshHome() {
  return mkdtempSync(path.join(tmpdir(), 'dsh-ssh-safe-'))
}

test('fingerprint is stable and ssh-shaped', () => {
  assert.match(fingerprint(keyA), /^SHA256:[A-Za-z0-9+/]+$/)
  assert.equal(fingerprint(keyA), fingerprint(keyA))
  assert.notEqual(fingerprint(keyA), fingerprint(keyB))
})

test('keyId joins host and port', () => {
  assert.equal(keyId('h', 22), 'h:22')
})

test('strict refuses an unknown host', () => {
  const home = freshHome()
  try {
    const v = checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'strict' })
    assert.equal(v.ok, false)
    assert.equal(v.firstSeen, true)
    assert.match(v.reason, /Unknown host/)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('trustHostKey accepts first contact and records it', () => {
  const home = freshHome()
  try {
    const first = checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'strict', trustHostKey: true })
    assert.equal(first.ok, true)
    assert.equal(first.firstSeen, true)

    const second = checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'strict' })
    assert.equal(second.ok, true, 'a recorded host passes without trustHostKey')
    assert.equal(second.firstSeen, false)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('a changed host key is always fatal, even with trustHostKey', () => {
  const home = freshHome()
  try {
    checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'strict', trustHostKey: true })
    const v = checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyB, policy: 'strict', trustHostKey: true })
    assert.equal(v.ok, false, 'trustHostKey must not override a changed key')
    assert.match(v.reason, /HOST KEY CHANGED/)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('tofu records on first contact without an explicit flag', () => {
  const home = freshHome()
  try {
    const v = checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'tofu' })
    assert.equal(v.ok, true)
    assert.equal(v.firstSeen, true)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('policy off accepts anything but still reports the fingerprint', () => {
  const home = freshHome()
  try {
    const v = checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyB, policy: 'off' })
    assert.equal(v.ok, true)
    assert.match(v.fp, /^SHA256:/)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('fingerprint comparison is constant-time and length-safe', () => {
  assert.equal(fingerprintsEqual('SHA256:abc', 'SHA256:abc'), true)
  assert.equal(fingerprintsEqual('SHA256:abc', 'SHA256:abd'), false)
  assert.equal(fingerprintsEqual('SHA256:abc', 'SHA256:ab'), false, 'length mismatch is not an error')
  assert.equal(fingerprintsEqual('', ''), true)
  assert.equal(fingerprintsEqual(null, null), true)
})

test('two hosts recorded in sequence both survive', () => {
  const home = freshHome()
  try {
    checkHostKey({ dshHome: home, host: 'one', port: 22, keyBlob: keyA, policy: 'tofu' })
    checkHostKey({ dshHome: home, host: 'two', port: 22, keyBlob: keyB, policy: 'tofu' })
    const store = JSON.parse(readFileSync(storePath(home), 'utf8'))
    assert.ok(store.hosts['one:22'], 'the first host was not lost')
    assert.ok(store.hosts['two:22'], 'the second host was recorded')
    assert.equal(Object.keys(store.hosts).length, 2)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('a store write leaves no temporary file behind', () => {
  const home = freshHome()
  try {
    checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'tofu' })
    const dir = path.dirname(storePath(home))
    const strays = readdirSync(dir).filter((f) => f.includes('.tmp-'))
    assert.deepEqual(strays, [], 'the atomic write must rename, not leave temp files')
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('the store is written with restrictive permissions', () => {
  const home = freshHome()
  try {
    checkHostKey({ dshHome: home, host: 'h', port: 22, keyBlob: keyA, policy: 'tofu' })
    const mode = statSync(storePath(home)).mode & 0o777
    // Windows ignores POSIX bits; only assert on POSIX platforms.
    if (process.platform !== 'win32') assert.equal(mode, 0o600)
  } finally { rmSync(home, { recursive: true, force: true }) }
})
test('a recorded entry without a fingerprint is not reported as a changed key', async () => {
  // is documented: an unreadable file means 'unknown'. An entry that exists but
  // holds no fingerprint is a corrupt record, not evidence of interception --
  // 'HOST KEY CHANGED' is the one alarm that has to keep its meaning.
  const dir = mkdtempSync(path.join(tmpdir(), 'dsh-hk-'))
  const file = path.join(dir, 'known_hosts.json')
  for (const entry of ['garbage', { firstSeenAt: 'x' }, { fingerprint: 12345 }]) {
    writeFileSync(file, JSON.stringify({ version: 1, hosts: { ['h.example:22']: entry } }))
    const verdict = checkHostKey({
      dshHome: dir, host: 'h.example', port: 22, keyBlob: keyA,
      policy: 'strict', trustHostKey: false, knownHostsFile: file,
    })
    assert.equal(verdict.ok, false, 'a corrupt record must still refuse')
    assert.doesNotMatch(verdict.reason, /HOST KEY CHANGED/)
    assert.match(verdict.reason, /Host key verification failed/)
    assert.match(verdict.reason, /no usable fingerprint/)
  }
})
test('the OpenSSH store advice matches whether the file exists', () => {
  // 'Unknown host' with a custom knownHosts path is usually a typo, and the
  // message recommended appending to a directory that does not exist — a command
  // that fails exactly where it is offered.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-store-'))
  try {
    const missing = path.join(home, 'nope', 'known_hosts')
    const absent = checkOpenSshHostKey({
      text: '', file: missing, host: 'h', port: 22, keyBlob: Buffer.from('k'),
      policy: 'tofu', trustHostKey: false, fp: 'SHA256:x',
    })
    assert.equal(absent.ok, false)
    assert.match(absent.reason, /neither does the directory/)
    assert.match(absent.reason, /create the directory first/)

    // The directory exists but the file does not: the append will create it.
    const dirOnly = path.join(home, 'known_hosts')
    const half = checkOpenSshHostKey({
      text: '', file: dirOnly, host: 'h', port: 22, keyBlob: Buffer.from('k'),
      policy: 'tofu', trustHostKey: false, fp: 'SHA256:x',
    })
    assert.match(half.reason, /The file does not exist yet/)
    assert.doesNotMatch(half.reason, /neither does the directory/)

    // An existing, empty store needs no extra sentence.
    mkdirSync(path.dirname(dirOnly), { recursive: true })
    writeFileSync(dirOnly, '')
    const present = checkOpenSshHostKey({
      text: '', file: dirOnly, host: 'h', port: 22, keyBlob: Buffer.from('k'),
      policy: 'tofu', trustHostKey: false, fp: 'SHA256:x',
    })
    assert.doesNotMatch(present.reason, /does not exist/)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('a negated host pattern takes the whole known_hosts entry out of play', () => {
  // '*.example.com,!bad.example.com' covered bad.example.com: the negation was
  // ignored, so a key the user explicitly excluded was accepted.
  const blob = Buffer.from('the-presented-key-material-0123456789abcdef')
  const base64 = blob.toString('base64')
  const fp = 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')
  const check = (text, host) => checkOpenSshHostKey({
    text, file: '<f>', host, port: 22, keyBlob: blob, policy: 'strict', trustHostKey: false, fp,
  })

  assert.equal(check('*.example.com ssh-ed25519 ' + base64, 'bad.example.com').ok, true)
  assert.equal(check('*.example.com,!bad.example.com ssh-ed25519 ' + base64, 'bad.example.com').ok, false,
    'the negated host must not be covered')
  assert.equal(check('*.example.com,!other.example.com ssh-ed25519 ' + base64, 'bad.example.com').ok, true,
    'an unrelated negation must not clear the entry')
  assert.equal(check('bad.example.com,!bad.example.com ssh-ed25519 ' + base64, 'bad.example.com').ok, false)
})

test('an IPv6 host is bracketed in messages but stored the same way as before', () => {
  // '::1:22' reads as host '::1' port 22 or host '::' port 1:22. Bracketing only
  // the label matters: changing the stored key would orphan every recorded IPv6
  // fingerprint, and an orphaned record means the next key is silently trusted.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-v6msg-'))
  const blob = Buffer.from('ipv6-message-format-0123456789')
  const fp = 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')
  const first = checkHostKey({ dshHome: home, host: '::1', port: 22, keyBlob: blob, policy: 'tofu', trustHostKey: false, fp })
  assert.equal(first.ok, true)
  // The record lives under the old key, so existing stores keep working.
  const stored = JSON.parse(readFileSync(storePath(home), 'utf8'))
  assert.deepEqual(Object.keys(stored.hosts), ['::1:22'])
  // A repeat lookup finds it.
  assert.equal(checkHostKey({ dshHome: home, host: '::1', port: 22, keyBlob: blob, policy: 'tofu', trustHostKey: false, fp }).ok, true)
  // A different key names the host unambiguously.
  const changed = checkHostKey({
    dshHome: home, host: '::1', port: 22, keyBlob: Buffer.from('other'), policy: 'tofu', trustHostKey: false, fp: 'SHA256:other',
  })
  assert.equal(changed.ok, false)
  assert.match(changed.reason, /HOST KEY CHANGED for \[::1\]:22/)
  // An unknown port is spelled the same way.
  const unknown = checkHostKey({
    dshHome: home, host: '::1', port: 2222, keyBlob: blob, policy: 'strict', trustHostKey: false, fp,
  })
  assert.match(unknown.reason, /Unknown host \[::1\]:2222/)
  // IPv4 is unchanged.
  const v4 = checkHostKey({ dshHome: home, host: '10.0.0.1', port: 22, keyBlob: blob, policy: 'strict', trustHostKey: false, fp })
  assert.match(v4.reason, /Unknown host 10\.0\.0\.1:22/)
})

test('a known_hosts file in no recognisable format says so, not a JSON error', () => {
  // It fell through to the plugin's JSON store parser, so pointing knownHosts at a
  // corrupt file answered with a JSON syntax error.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-khfmt-'))
  const blob = Buffer.from('known-hosts-format-test-0123456789')
  const fp = 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')
  const file = path.join(home, 'known_hosts')
  writeFileSync(file, '# comment\ngarbage not a known_hosts line\n', 'utf8')
  const out = checkHostKey({
    dshHome: home, host: 'h', port: 22, keyBlob: blob, policy: 'tofu', trustHostKey: false,
    knownHostsFile: file, fp,
  })
  assert.equal(out.ok, false)
  assert.match(out.reason, /is not in a format this plugin can verify/)
  assert.match(out.reason, /first entry: "garbage not a known_hosts line"/)
  assert.doesNotMatch(out.reason, /JSON/, 'the setting names a known_hosts file, not a JSON store')
  // An empty file is still a legitimate first contact.
  writeFileSync(file, '', 'utf8')
  const empty = checkHostKey({
    dshHome: home, host: 'h', port: 22, keyBlob: blob, policy: 'tofu', trustHostKey: true,
    knownHostsFile: file, fp,
  })
  assert.equal(empty.ok, true)
})

test('a broken trust record says what is wrong with it, in words', () => {
  // The reason printed the JavaScript type: '(undefined)' and '(object)' describe
  // nothing a user can act on, and a missing field is fixed differently from an
  // empty one.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-fpstate-'))
  const blob = Buffer.from('fingerprint-state-key-0123456789')
  const fp = 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')
  const dir = path.join(home, 'dsh-ssh-safe')
  mkdirSync(dir, { recursive: true })
  const store = path.join(dir, 'known_hosts.json')
  const cases = [
    [{ firstSeenAt: 'x' }, /the field is missing/],
    [{ fingerprint: null }, /it is null/],
    [{ fingerprint: '' }, /it is empty/],
    [{ fingerprint: 42 }, /it is a number/],
    [{ fingerprint: {} }, /it is a object/],
  ]
  for (const [entry, expected] of cases) {
    writeFileSync(store, JSON.stringify({ version: 1, hosts: { 'h.example:22': entry } }), 'utf8')
    const verdict = checkHostKey({
      dshHome: home, host: 'h.example', port: 22, keyBlob: blob, policy: 'tofu', trustHostKey: false, fp,
    })
    assert.equal(verdict.ok, false)
    assert.match(verdict.reason, expected, verdict.reason)
    assert.match(verdict.reason, /no usable fingerprint/)
  }
  rmSync(home, { recursive: true, force: true })
})

test('a known_hosts file with no entries is unknown, not a broken format', () => {
  // 'touch ~/.ssh/known_hosts' is the normal way to start one. A comment-only or
  // empty file used to be refused as 'not in a format this plugin can verify',
  // quoting an empty first entry.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-khempty-'))
  const blob = Buffer.from('known-hosts-empty-key-0123456789')
  const file = path.join(home, 'known_hosts')
  for (const content of ['', '# a comment\n', '\n\n  \n']) {
    writeFileSync(file, content, 'utf8')
    const verdict = checkHostKey({
      dshHome: home, host: 'h.example', port: 22, keyBlob: blob, policy: 'tofu',
      trustHostKey: false, knownHostsFile: file,
    })
    assert.equal(verdict.ok, false)
    assert.match(verdict.reason, /Unknown host h\.example:22/, JSON.stringify(content))
    assert.doesNotMatch(verdict.reason, /not in a format this plugin can verify/)
    // The file exists, so it must not be described as missing either.
    assert.doesNotMatch(verdict.reason, /The file does not exist/)
  }
  // Real garbage still gets the format refusal.
  writeFileSync(file, 'this is not a known_hosts entry\n', 'utf8')
  const garbage = checkHostKey({
    dshHome: home, host: 'h.example', port: 22, keyBlob: blob, policy: 'tofu',
    trustHostKey: false, knownHostsFile: file,
  })
  assert.match(garbage.reason, /not in a format this plugin can verify/)
  rmSync(home, { recursive: true, force: true })
})


test('the strict unknown-host advice fits a knownHosts path that cannot be written', () => {
  // Under the default strict policy a mistyped knownHosts path is the commonest
  // way to reach 'Unknown host', and the advice told the caller to append into a
  // directory that does not exist -- a command that fails where it is offered.
  const home2 = mkdtempSync(path.join(tmpdir(), 'dsh-khdir-'))
  const dir = path.join(home2, 'sub')
  mkdirSync(dir, { recursive: true })
  const missingFile = path.join(dir, 'kh')
  const missingDir = path.join(dir, 'nope', 'kh')
  const blob = Buffer.from('not a real key')
  const call = (file) => checkHostKey({
    dshHome: home2, host: 'h.example', port: 2222, keyBlob: blob,
    policy: 'strict', trustHostKey: false, knownHostsFile: file,
  })
  try {
    const fileNote = call(missingFile).reason
    assert.match(fileNote, /The file does not exist yet/)
    assert.doesNotMatch(fileNote, /create the directory first/)
    const dirNote = call(missingDir).reason
    assert.match(dirNote, /neither does the directory/)
    assert.match(dirNote, /create the directory first \(mkdir -p /)
  } finally { rmSync(home2, { recursive: true, force: true }) }
})

test('a plain known_hosts entry covers port 22 and no other port', () => {
  // OpenSSH looks up '[host]:port' off port 22, so a plain entry does not cover a
  // custom port. Accepting it anyway extended trust from one port to all of them,
  // and disagreed with this plugin's own store, which keys records by host:port.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-khport-'))
  const blob = Buffer.from('known-hosts-port-key-0123456789')
  const file = path.join(home, 'known_hosts')
  writeFileSync(file, 'h.example ssh-ed25519 ' + blob.toString('base64') + '\n', 'utf8')
  const check = (port) => checkHostKey({
    dshHome: home, host: 'h.example', port, keyBlob: blob, policy: 'tofu',
    trustHostKey: false, knownHostsFile: file,
  })
  assert.equal(check(22).ok, true, 'port 22 is what the plain entry covers')
  const custom = check(2222)
  assert.equal(custom.ok, false)
  assert.match(custom.reason, /Unknown host h\.example:2222/)
  // And the bracketed form covers exactly its own port.
  writeFileSync(file, '[h.example]:2222 ssh-ed25519 ' + blob.toString('base64') + '\n', 'utf8')
  assert.equal(check(2222).ok, true)
  assert.equal(check(22).ok, false)
  rmSync(home, { recursive: true, force: true })
})
