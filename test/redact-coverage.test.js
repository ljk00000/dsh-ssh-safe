import { test } from 'node:test'
import assert from 'node:assert/strict'
import { redact } from '../src/credentials.js'
import { normalizeRemotePath } from '../src/remote-path.js'
import { printable } from '../src/format.js'

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
  assert.equal(redact('PASSWORD was hunter2'), 'PASSWORD was <redacted>')
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


test('a password piped into sudo is masked', () => {
  // 'echo pass | sudo -S cmd' is how sudo is fed non-interactively. The secret
  // sits on the left of the pipe, so the flag rules never saw it: measured
  // 'echo hunter2 | sudo -S id' reaching audit.ndjson verbatim.
  for (const [input, secret] of [
    ["echo 'hunter2' | sudo -S apt-get update", 'hunter2'],
    ['echo hunter2 | sudo -S id', 'hunter2'],
    ["printf '%s\\n' 'hunter2' | sudo -S id", 'hunter2'],
    ['echo hunter2 | doas -S id', 'hunter2'],
    ['echo hunter2 | passwd --stdin root', 'hunter2'],
  ]) {
    const out = redact(input)
    assert.ok(!out.includes(secret), input + ' -> ' + out)
    assert.match(out, /<redacted>/, input)
  }
  // A filename on the left is not a secret, and the audit line stays useful.
  assert.equal(redact('cat /var/log/syslog | sudo -S tee /tmp/x'),
    'cat /var/log/syslog | sudo -S tee /tmp/x')
  assert.equal(redact('echo hi | sudo tee f'), 'echo hi | sudo tee f')
})


test('MYSQL_PWD and openssl -pass are masked', () => {
  // MYSQL_PWD is a password variable whose name ends in PWD, which the key rule
  // did not know; and the glued -p rule read openssl's -pass as -p + 'ass',
  // masking the flag while leaving 'pass:hunter2' in the log.
  assert.equal(redact('MYSQL_PWD=hunter2 mysql -u root'), 'MYSQL_PWD=<redacted> mysql -u root')
  assert.equal(redact('openssl enc -aes-256 -pass pass:hunter2 -in a'),
    'openssl enc -aes-256 -pass <redacted> -in a')
  assert.equal(redact('openssl enc -pass file:/root/.pw -in a'),
    'openssl enc -pass <redacted> -in a')
  // Ports and ordinary flags still read as they are.
  for (const unchanged of ['ssh -p 2222 host', 'scp -P 2222 file host:', 'psql -p 5432 db', 'ls -la']) {
    assert.equal(redact(unchanged), unchanged)
  }
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

test('PASS=, openssl -k and mysqladmin -w are masked, and their look-alikes are not', () => {
  // Measured against the audit log: 'PASS=…', 'SSHPASS=…' (the variable sshpass
  // itself reads), 'openssl enc -k SECRET' and 'mysqladmin -w SECRET' were all
  // written verbatim, because PASS was not in the name list and -k/-w were not
  // recognised flags.
  assert.equal(redact('PASS=hunter2 cmd'), 'PASS=<redacted> cmd')
  assert.equal(redact('DB_PASS=hunter2 psql'), 'DB_PASS=<redacted> psql')
  assert.equal(redact('SSHPASS=hunter2 sshpass -e ssh h'), 'SSHPASS=<redacted> sshpass -e ssh h')
  assert.equal(redact('openssl enc -k hunter2 -d'), 'openssl enc -k <redacted> -d')
  assert.equal(redact('mysqladmin -u root -w hunter2 status'), 'mysqladmin -u root -w <redacted> status')

  // The look-alikes stay readable: a field spec, a keep-old-files flag, a word
  // match, a no-prompt flag and a filename are not secrets.
  for (const text of ['sort -k 2 file', 'tar -k -xf a.tar', 'grep -w foo bar.txt',
    'psql -w -c "select 1"', 'openssl enc -kfile x -d', 'PWD=/home/u cmd', 'PASSFILE=/tmp/f cmd']) {
    assert.equal(redact(text), text, text + ' must not be rewritten')
  }
})

test('quoted flag values, --pw and single-dash -password are masked without mangling', () => {
  // '--password "two words"' masked the first word and left the second, which is
  // the half that matters. '--pw'/'--passw' were not recognised, and '--password'
  // written with one dash was read by the glued -p rule as '-p assword': the flag
  // name was masked and the secret survived.
  assert.equal(redact('tool --password "alpha beta"'), 'tool --password <redacted>')
  assert.equal(redact('tool --token "alpha beta"'), 'tool --token <redacted>')
  assert.equal(redact('tool --pw hunter2'), 'tool --pw <redacted>')
  assert.equal(redact('tool --passw hunter2'), 'tool --passw <redacted>')
  assert.equal(redact('tool -password hunter2'), 'tool -password <redacted>')
  assert.equal(redact('tool -passphrase=hunter2'), 'tool -passphrase=<redacted>')
  // A flag that only ends its argument there is untouched.
  assert.equal(redact('docker login --password-stdin'), 'docker login --password-stdin')
  assert.equal(redact('mysql -p 2222'), 'mysql -p 2222')
  assert.equal(redact('ssh -p2222 host'), 'ssh -p2222 host')
})

test('a flag whose name names a secret is masked, and a path or type is not', () => {
  // A generated matrix of flag spellings found --api-key, --apikey, --api_key, --key,
  // --private-key, --secret-key and --access-token leaking with a space separator:
  // the = form was caught by the KEY=value rule, the space form by nothing.
  assert.equal(redact('tool --api-key hunter2'), 'tool --api-key <redacted>')
  assert.equal(redact('tool --apikey hunter2'), 'tool --apikey <redacted>')
  assert.equal(redact('tool --api_key hunter2'), 'tool --api_key <redacted>')
  assert.equal(redact('tool --private-key hunter2'), 'tool --private-key <redacted>')
  assert.equal(redact('tool --secret-key hunter2'), 'tool --secret-key <redacted>')
  assert.equal(redact('tool --access-token hunter2'), 'tool --access-token <redacted>')
  // A value that names a file, a type or a store is not the secret itself.
  for (const text of ['tool --password-file /tmp/pw', 'tool --token-type rsa', 'tool --key-type ed25519',
    'tool --secret-store vault', 'tool --token-name ci']) {
    assert.equal(redact(text), text, text + ' must not be rewritten')
  }
  // Quoted values are one value here too.
  assert.equal(redact('tool --api-key "two words"'), 'tool --api-key <redacted>')
})

test('a quoted value after -p= or -pass is masked whole', () => {
  assert.equal(redact('tool -p="two words"'), 'tool -p<redacted>')
  assert.equal(redact('tool -pass "two words"'), 'tool -pass <redacted>')
  // A port stays a port.
  assert.equal(redact('ssh -p 2222 host'), 'ssh -p 2222 host')
  assert.equal(redact('ssh -p2222 host'), 'ssh -p2222 host')
})

test('a YAML value runs to the end of the line and a Dockerfile ENV is masked', () => {
  // 'password: two words' kept the second word: the env rule stopped at the first
  // space, which is right for KEY=value and wrong for YAML.
  assert.equal(redact('password: my secret phrase'), 'password: <redacted>')
  assert.equal(redact('db:\n  password: hunter2\n  host: h'), 'db:\n  password: <redacted>\n  host: h')
  // A JSON line keeps the fields after the secret.
  assert.equal(redact('{"user":"u","password":"hunter2","host":"h"}'),
    '{"user":"u","password":<redacted>,"host":"h"}')
  // Dockerfile ENV has no separator at all.
  assert.equal(redact('ENV API_TOKEN hunter2'), 'ENV API_TOKEN <redacted>')
  assert.equal(redact('ENV API_TOKEN=hunter2'), 'ENV API_TOKEN=<redacted>')
})

test('the extra env names are masked and their look-alikes are not', () => {
  // A generated matrix of 117 name/separator pairs leaked CREDENTIAL, AUTH, BEARER,
  // COOKIE and DB_PWD (PWD itself is the working directory).
  for (const name of ['CREDENTIAL', 'AUTH', 'BEARER', 'COOKIE', 'DB_PWD', 'CLIENT_SECRET']) {
    assert.equal(redact(name + '=hunter2'), name + '=<redacted>', name)
  }
  // Paths and names that merely contain a word stay readable.
  for (const text of ['GOOGLE_APPLICATION_CREDENTIALS=/tmp/creds.json', 'PASSFILE=/tmp/pw',
    'KEY_PATH=/home/u/.ssh/id_ed25519', 'PWD=/home/u', 'OLDPWD=/tmp', 'AUTHORS=me',
    'TOKENIZER=bert', 'KEYBOARD_LAYOUT=us']) {
    assert.equal(redact(text), text, text + ' must not be rewritten')
  }
})

test('~/.netrc and ~/.pgpass secrets are masked', () => {
  // These two files put the secret where no key or flag reaches it: netrc uses a
  // bare 'password <value>' line and pgpass has no key name at all.
  assert.equal(redact('machine db.example.com\n  login admin\n  password hunter2\n'),
    'machine db.example.com\n  login admin\n  password <redacted>\n')
  assert.equal(redact('default\n  login u\n  password hunter2'), 'default\n  login u\n  password <redacted>')
  assert.equal(redact('db.example.com:5432:mydb:user:hunter2'), 'db.example.com:5432:mydb:user:<redacted>')
  assert.equal(redact('*:*:*:postgres:hunter2'), '*:*:*:postgres:<redacted>')
  assert.equal(redact('[::1]:5432:db:u:hunter2'), '[::1]:5432:db:u:<redacted>')
  // Log lines, a boolean sshd setting and a five-field sentence stay readable.
  for (const text of ['10:30:45:abc:def', 'a:b:c:d:e:f:g', 'PasswordAuthentication yes',
    'host:port:db:user:pass answer?']) {
    assert.equal(redact(text), text, text + ' must not be rewritten')
  }
})

test('a file whose name ends in a space can be read, written and listed', () => {
  // raw.trim() treated the trailing space as paste noise, so a POSIX name ending in
  // one was unreachable: ssh_list showed 'name ', ssh_read answered
  // 'no such file: /d/name', and ssh_write created a different file than asked.
  assert.equal(normalizeRemotePath('/d/name '), '/d/name ')
  assert.equal(normalizeRemotePath('/d/w '), '/d/w ')
  // CR/LF/TAB pasted from a terminal are still dropped, and a blank path is refused.
  assert.equal(normalizeRemotePath('/d/name\n'), '/d/name')
  assert.equal(normalizeRemotePath('\t/d/name\r\n'), '/d/name')
  assert.throws(() => normalizeRemotePath('   '), /path is blank/)
  assert.throws(() => normalizeRemotePath('\n\t'), /path is blank/)
  // The row must show the space, or 'no such file: /d/name' is a lie about what
  // exists on the host.
  assert.equal(printable('/d/name '), '"/d/name "')
  assert.equal(printable('/d/name'), '/d/name')
  assert.equal(printable(' /d/name'), '" /d/name"')
  assert.equal(printable('a b'), 'a b')
})

test('a password inside a URL, a connection string or an auth header is masked', async () => {
  // The bare-value rules cannot know that DATABASE_URL=xyz is a secret, but the
  // shapes that carry one are known: user:pass@host, Password= in a connection
  // string, and the token after Bearer/Basic. All three were unmasked before.
  const { redact } = await import('../src/credentials.js')
  const cases = [
    ['postgres://user:hunter2@db.example:5432/app', 'postgres://user:<redacted>@db.example:5432/app'],
    ['mysql://root:sw0rdfish@localhost/app', 'mysql://root:<redacted>@localhost/app'],
    ['redis://:letmein@cache.example:6379/0', 'redis://:<redacted>@cache.example:6379/0'],
    // The value runs to the end of the line on purpose: a password may itself
    // contain ';', so stopping at the separator would mask only its first part.
    // The cost is that the fields after the password disappear with it — the
    // documented side to err on.
    ['Server=x;User Id=sa;Password=t0psecret;', 'Server=x;User Id=sa;Password=<redacted>'],
    // The whole value after the colon goes: the scheme word is not worth risking
    // a rule that keeps part of a token. (The AUTH_HEADER=name form keeps
    // 'Bearer' because the mask starts at the value, not at the keyword.)
    ['Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.x.y', 'Authorization: <redacted>'],
  ]
  for (const [input, expected] of cases) {
    assert.equal(String(redact(input)), expected, input)
  }
  // The URL path must survive: masking the whole line made the output useless.
  assert.doesNotMatch(String(redact('postgres://user:hunter2@db.example:5432/app')), /hunter2/)
})

test('redaction keeps the verb, and the plugin\'s own warnings survive it', () => {
  // The prose rule printed 'IS <redacted>' for both tenses, so 'the password was
  // hunter2' came back as 'the password is <redacted>'.
  assert.equal(redact('the password was hunter2'), 'the password was <redacted>')
  assert.equal(redact('the password is hunter2'), 'the password is <redacted>')

  // The same rule ate the first word after the verb in the plugin's own
  // diagnostics: 'the stored password is not DPAPI output' became 'the stored
  // password is <redacted> a DPAPI blob', which reads as the opposite. Every
  // message the plugin writes must survive the masker it applies to its replies.
  const diagnostics = [
    'the stored password does not look like DPAPI output; re-run scripts/set-password.mjs on this account',
    'the stored key passphrase does not look like DPAPI output; re-run scripts/set-password.mjs on this account',
    'the settings-form password — set, but ignored because allowPlaintextPassword is off',
    'a session password came with this call, but a stored credential was used instead (session passwords are the last resort).',
    'Passing a password in conversation is disabled for this profile — set allowSessionPassword to true in the plugin config to allow it.',
  ]
  for (const message of diagnostics) {
    assert.equal(redact(message), message, 'the masker rewrote the plugin\'s own sentence: ' + redact(message))
  }
})
