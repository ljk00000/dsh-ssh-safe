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
