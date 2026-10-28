import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { decryptDpapi, dpapiAvailable, encryptDpapi, forgetDecrypted } from '../src/dpapi.js'
import { credentialFor, credentialsPath } from '../src/machines.js'

// A password has to live somewhere between connections. DPAPI is the option that
// stores ciphertext bound to the Windows account, so a copy of the file on
// another machine -- or another user on this one -- decrypts to nothing.
//
// The alternative the plugin used to offer, a readable password in a JSON file,
// is now refused by default; that behaviour is covered in machines.test.js.

const skip = dpapiAvailable() ? false : 'DPAPI is a Windows feature'

test('a password survives the round trip', { skip }, () => {
  const secret = 'p@ss word-with $pecial & chars! 中文'
  const cipher = encryptDpapi(secret)
  assert.match(cipher, /^[0-9a-f]+$/i, 'the stored form is hex, not the password')
  assert.doesNotMatch(cipher, /p@ss/, 'the ciphertext does not contain the secret')
  forgetDecrypted()
  assert.equal(decryptDpapi(cipher), secret)
})

test('decryption is cached in memory, and a different ciphertext misses it', { skip }, () => {
  const one = encryptDpapi('alpha')
  const two = encryptDpapi('beta')
  forgetDecrypted()
  assert.equal(decryptDpapi(one), 'alpha')
  assert.equal(decryptDpapi(two), 'beta', 'the cache is keyed by ciphertext')
  assert.equal(decryptDpapi(one), 'alpha')
})

test('a modified payload is rejected instead of decrypting to a wrong password', { skip }, () => {
  // DPAPI carries an HMAC. Flipping a byte anywhere in the protected region must
  // fail rather than yield a different password that would be sent to the server.
  const cipher = encryptDpapi('secret')
  for (const offset of [80, Math.floor(cipher.length / 2), cipher.length - 10, cipher.length - 1]) {
    forgetDecrypted()
    const flipped = cipher[offset] === 'a' ? 'b' : 'a'
    const tampered = cipher.slice(0, offset) + flipped + cipher.slice(offset + 1)
    assert.throws(() => decryptDpapi(tampered), 'offset ' + offset + ' must be rejected')
  }
})

test('a change outside the protected region cannot alter the password', { skip }, () => {
  // The blob has a header area DPAPI ignores. Editing it must not change what
  // comes out: the failure mode to rule out is a silent wrong password.
  const cipher = encryptDpapi('unchanged')
  forgetDecrypted()
  const at = 20
  const flipped = cipher[at] === 'a' ? 'b' : 'a'
  const tampered = cipher.slice(0, at) + flipped + cipher.slice(at + 1)
  assert.equal(decryptDpapi(tampered), 'unchanged')
})

test('a stored DPAPI password is the preferred source', { skip }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dsh-dpapi-'))
  try {
    mkdirSync(path.join(dir, 'dsh-ssh-safe'), { recursive: true })
    const cipher = encryptDpapi('encrypted-one')
    writeFileSync(credentialsPath(dir), JSON.stringify({ prod: { passwordDpapi: cipher } }), 'utf8')

    // An environment password is present as well; the encrypted file wins.
    process.env.DSH_SSH_PROD_HOST = 'h'
    process.env.DSH_SSH_PROD_USER = 'u'
    process.env.DSH_SSH_PROD_PASSWORD = 'from-env'
    forgetDecrypted()

    const auth = credentialFor('prod', {
      machines: { prod: { host: 'h', user: 'u' } },
      dshHome: dir,
    })
    assert.equal(auth.kind, 'file-dpapi')
    assert.equal(auth.password, 'encrypted-one')
  } finally {
    delete process.env.DSH_SSH_PROD_HOST
    delete process.env.DSH_SSH_PROD_USER
    delete process.env.DSH_SSH_PROD_PASSWORD
    rmSync(dir, { recursive: true, force: true })
  }
})

test('the file on disk never contains the password in readable form', { skip }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dsh-dpapi-'))
  try {
    mkdirSync(path.join(dir, 'dsh-ssh-safe'), { recursive: true })
    const secret = 'must-not-appear-on-disk'
    writeFileSync(credentialsPath(dir), JSON.stringify({
      prod: { passwordDpapi: encryptDpapi(secret) },
    }), 'utf8')
    const body = readFileSync(credentialsPath(dir), 'utf8')
    assert.doesNotMatch(body, /must-not-appear-on-disk/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('an undecryptable blob degrades with an explanation', { skip }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dsh-dpapi-'))
  try {
    mkdirSync(path.join(dir, 'dsh-ssh-safe'), { recursive: true })
    // Ciphertext from some other account or machine.
    writeFileSync(credentialsPath(dir), JSON.stringify({
      prod: { passwordDpapi: 'deadbeef'.repeat(20) },
    }), 'utf8')
    const auth = credentialFor('prod', {
      machines: { prod: { host: 'h', user: 'u', keyPath: '~/.ssh/id_k' } },
      dshHome: dir,
    })
    assert.match(auth.kind, /-key$/, 'a usable key still wins')
    assert.match(auth.warnings.join(' '), /could not be decrypted/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
