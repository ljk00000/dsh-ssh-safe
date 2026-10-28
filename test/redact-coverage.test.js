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
