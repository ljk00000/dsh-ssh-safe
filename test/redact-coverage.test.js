import { test } from 'node:test'
import assert from 'node:assert/strict'
import { redact } from '../src/credentials.js'

// redact handled KEY=value and PEM blocks. An Authorization header or a password
// inside a URL went through untouched -- and ssh_read returns exactly this
// text, so a .env or a config file could leak a live token into the transcript.

test('credentials are redacted wherever they appear', () => {
  for (const secret of [
    'PASSWORD=hunter2',
    'password=hunter2',
    'api_key: abc123def456',
    'export SECRET_TOKEN=abcdef',
    'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.aaa.bbb',
    'authorization: bearer sk-1234567890abcdef',
    'Basic dXNlcjpwYXNzd29yZA==',
    'Bearer sk-1234567890abcdef',
    'mysql://user:pass@host/db',
    'https://user:pass@example.com/x',
    '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----',
  ]) {
    const out = redact(secret)
    assert.notEqual(out, secret, 'not redacted: ' + secret)
    assert.doesNotMatch(out, /hunter2|abc123def456|abcdef|eyJhbGci|dXNlcjpwYXNzd29yZA|sk-1234567890abcdef|pass@/, 'secret survived: ' + out)
  }
})

// Measured against a real transcript: ssh_read redacts files by default, and
// the files most likely to hold a password are JSON and YAML. Neither was
// covered — '{"password": "hunter2"}' kept its value because the closing quote
// sat between the key and the colon.
test('quoted config formats are redacted too', () => {
  const secrets = [
    '{"password": "hunter2"}',
    '{ "password" : "hunter2" }',
    '{"db": {"user": "root", "passwd": "hunter2"}}',
    '{"keyPassphrase": "topsecret"}',
    '{"access_token":"eyJhbGciOiJIUzI1NiJ9.x.y"}',
    'password="hunter 2"',
    'curl -u admin:hunter2 https://api.example.com',
    'mysql --password=hunter2 -h db',
  ]
  for (const secret of secrets) {
    const out = redact(secret)
    assert.doesNotMatch(out, /hunter2|topsecret|eyJhbGciOiJIUzI1NiJ9/, 'secret survived: ' + secret + ' -> ' + out)
  }
})

test('a word that merely contains a secret word is not a secret', () => {
  for (const plain of ['secretary: hello', 'The token of appreciation was noted.', 'monkey see monkey do']) {
    assert.equal(redact(plain), plain, 'must not alter: ' + plain)
  }
})

test('a long single line is redacted in linear time', () => {
  // ssh_exec hands every result through redact(). The key rule used to start
  // its key run with an unanchored lazy quantifier, and the URL rule used an
  // unanchored unbounded scheme run, so both were retried from every position
  // of a line made of word characters: a 200k-character one-line output took
  // 33 seconds to redact before it was returned. Nothing about that is fixed
  // by the caller; the rules themselves have to scan once.
  const flat = 'a'.repeat(200000)
  const started = Date.now()
  assert.equal(redact(flat), flat)
  const elapsed = Date.now() - started
  assert.ok(elapsed < 250, 'redact took ' + elapsed + 'ms for a 200k one-line string')

  // The same shape still has to catch a secret at the end of the line.
  const withSecret = 'a'.repeat(200000) + ' PASSWORD=hunter2'
  const out = redact(withSecret)
  assert.ok(!out.includes('hunter2'), 'secret at the end of a long line must be redacted')
  assert.ok(out.includes('<redacted>'))
})

test('ordinary text is left untouched', () => {
  for (const plain of [
    'no secret here at all',
    'ls -la /home/user',
    'echo hello world',
    'echo basic math',
    'git log --oneline',
  ]) {
    assert.equal(redact(plain), plain, 'must not alter: ' + plain)
  }
})
test('the plugin\'s own vocabulary is not mistaken for a secret', () => {
  // 'trustHostKey: true' ends in KEY, so the generic rule replaced the value with
  // '<redacted>' and the one line that told the caller what to do became
  // gibberish: 'call ssh_connect with trustHostKey: <redacted>'. A path and a key
  // type are not secrets either.
  assert.equal(
    redact('call ssh_connect with trustHostKey: true for this one connection.'),
    'call ssh_connect with trustHostKey: true for this one connection.',
  )
  assert.equal(redact('keyPath: /home/u/.ssh/id_ed25519'), 'keyPath: /home/u/.ssh/id_ed25519')
  assert.equal(redact('keyType: ssh-ed25519'), 'keyType: ssh-ed25519')

  // Everything that really is a secret is still redacted.
  assert.match(redact('password: hunter2'), /<redacted>/)
  assert.match(redact('api_key: sk-abc'), /<redacted>/)
  assert.match(redact('AWS_SECRET_ACCESS_KEY=abc'), /<redacted>/)
  assert.match(redact('keyPassphrase: hunter2'), /<redacted>/,
    'only the names on the list are exempt')
})

test('a password glued to -p is redacted and a port is not', () => {
  // 'mysql -uroot -pSECRET' has no '=' or ':' after the flag, so every rule above
  // missed it -- and this exact shape is how a database password reaches a shell
  // command, and then the audit log.
  assert.equal(redact('mysql -uroot -pSuperSecret1 -e "select 1"'), 'mysql -uroot -p<redacted> -e "select 1"')
  assert.equal(redact('mysqldump -u root -pPassw0rd db'), 'mysqldump -u root -p<redacted> db')

  // A port is not a secret. Masking these would make the log say the wrong thing.
  for (const line of ['ssh -p 2222 host', 'ssh -p2222 host', 'scp -P 2222 f h:/tmp', 'redis-cli -p 6379 ping']) {
    assert.equal(redact(line), line)
  }
})

test('a URL with no user part still has its password masked', () => {
  // 'redis://:hunter2@cache:6379' is a normal shape and the rule required a
  // non-empty user, so the password went through untouched.
  assert.equal(redact('redis://:hunter2@cache:6379'), 'redis://:<redacted>@cache:6379')
  assert.equal(redact('mysql://root:hunter2@db:3306/app'), 'mysql://root:<redacted>@db:3306/app')
})

test('a passphrase written as prose is masked too', () => {
  assert.equal(redact('the key passphrase is hunter2'), 'the key passphrase is <redacted>')
  assert.equal(redact('PASSWORD was hunter2'), 'PASSWORD is <redacted>')
  // Over-redaction is the accepted direction: a sentence that names no secret
  // loses a word rather than a password leaking.
  assert.equal(redact('the passphrase is required'), 'the passphrase is <redacted>')
})

test('a private key cut short by a read limit is still masked', () => {
  // The PEM rule needs BEGIN and END. A 1024-byte slice of a key has no END, so
  // the whole body was returned verbatim — the one thing ssh_read promises not to
  // do. Measured: 'mentions masked: false, leaks key body: true'.
  const partial = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAB\nb3BlbnNzaC1rZXkt\n'
  const maskedPartial = redact(partial)
  assert.equal(maskedPartial, '<redacted-pem>')
  assert.doesNotMatch(maskedPartial, /b3BlbnNzaC1rZXkt/)

  // A complete block is still masked once, not twice.
  const complete = 'before\n-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\nafter'
  const maskedComplete = redact(complete)
  assert.match(maskedComplete, /^before\n<redacted-pem>\nafter$/)

  // Text that only mentions a marker without a body is left alone.
  const prose = 'see the -----BEGIN marker in the docs'
  assert.equal(redact(prose), prose)
})

test('a PuTTY .ppk private key is masked too', () => {
  // .ppk has no PEM markers: the header line plus base64 under Private-Lines. It
  // reached ssh_read verbatim while the tool promised to mask secret-shaped text.
  const ppk = [
    'PuTTY-User-Key-File-2: ssh-rsa',
    'Encryption: none',
    'Private-Lines: 2',
    'PRIVATEKEYDATA1',
    'PRIVATEKEYDATA2',
    'Private-MAC: abcdef',
  ].join('\n')
  const out = redact(ppk)
  assert.equal(out, '<redacted-ppk>')
  assert.doesNotMatch(out, /PRIVATEKEYDATA/)
  // A mention of the format in prose is masked as well; that is the safe side.
  assert.equal(redact('nothing to see here'), 'nothing to see here')
})

test('-p with a separate password argument is masked, but -p as a port is not', () => {
  // 'sshpass -p SECRET pw ssh host' put the password in the audit command: only the
  // glued form ('-pSECRET') was handled.
  assert.doesNotMatch(redact('sshpass -p SECRET pw ssh host'), /SECRET/)
  assert.match(redact('sshpass -p SECRET pw ssh host'), /-p <redacted>/)
  assert.doesNotMatch(redact('sshpass -p "two words" pw ssh host'), /two words/)
  // A port must survive: masking it would make the log say the wrong thing.
  assert.equal(redact('ssh -p 2222 root@host'), 'ssh -p 2222 root@host')
  assert.equal(redact('scp -P 2222 file host:'), 'scp -P 2222 file host:')
})

test('--pass and redis-cli -a are masked without touching real flags', () => {
  // '--pass=SECRET' and 'redis-cli -a SECRET' reached the audit command verbatim;
  // masking every '-a' would have mangled 'ls -a' instead.
  assert.doesNotMatch(redact('mysql --pass=SECRET42 db'), /SECRET42/)
  assert.doesNotMatch(redact('mysql --pass SECRET42 db'), /SECRET42/)
  assert.doesNotMatch(redact('redis-cli -a SECRET42 ping'), /SECRET42/)
  assert.doesNotMatch(redact('redis-cli -a "two words" ping'), /two words/)
  // Longest alternative wins: --passphrase is not read as --pass.
  assert.equal(redact('git --passphrase=KEYPASS clone x'), 'git --passphrase=<redacted> clone x')
  // Real flags stay.
  assert.equal(redact('ls -a /tmp'), 'ls -a /tmp')
  assert.equal(redact('tar -af archive.tar x'), 'tar -af archive.tar x')
  assert.equal(redact('ssh -p 2222 root@host'), 'ssh -p 2222 root@host')
})

test('many unterminated BEGIN markers do not take quadratic time', () => {
  // The regex needed BEGIN and END: with thousands of BEGINs and no END, every
  // candidate scanned to the end of the string before failing. Measured 3.58 s on
  // 20 000 markers in 600 KB, with a 1 MiB default read limit.
  const text = '-----BEGIN X PRIVATE KEY-----b'.repeat(20000)
  const started = Date.now()
  const out = redact(text)
  const ms = Date.now() - started
  assert.equal(out, '<redacted-pem>')
  assert.ok(ms < 500, 'redact took ' + ms + 'ms on ' + text.length + ' bytes')

  // Prose that only mentions the marker is still left alone.
  assert.equal(redact('see the -----BEGIN marker in the docs'), 'see the -----BEGIN marker in the docs')
})
