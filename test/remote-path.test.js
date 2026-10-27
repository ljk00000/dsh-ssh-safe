import { test } from 'node:test'
import assert from 'node:assert/strict'
import { normalizeRemotePath, RemotePathError } from '../src/remote-path.js'

test('an absolute path passes through unchanged', () => {
  assert.equal(normalizeRemotePath('/home/user/file.txt'), '/home/user/file.txt')
})

test('duplicate slashes are collapsed', () => {
  assert.equal(normalizeRemotePath('/home//user///file'), '/home/user/file')
})

test('dot segments are resolved', () => {
  assert.equal(normalizeRemotePath('/home/user/./file'), '/home/user/file')
  assert.equal(normalizeRemotePath('/home/user/sub/../file'), '/home/user/file')
})

test('a tilde is refused, because SFTP would create a file literally named ~', () => {
  assert.throws(() => normalizeRemotePath('~/file.txt'), RemotePathError)
  assert.throws(() => normalizeRemotePath('~'), RemotePathError)
})

test('a relative path is refused unless explicitly allowed', () => {
  assert.throws(() => normalizeRemotePath('file.txt'), RemotePathError)
  assert.equal(normalizeRemotePath('file.txt', { allowRelative: true }), 'file.txt')
  assert.equal(normalizeRemotePath('.', { allowRelative: true }), '.')
})

test('empty and blank paths are refused', () => {
  assert.throws(() => normalizeRemotePath(''), RemotePathError)
  assert.throws(() => normalizeRemotePath('   '), RemotePathError)
  assert.throws(() => normalizeRemotePath(null), RemotePathError)
})

test('a NUL byte is refused', () => {
  assert.throws(() => normalizeRemotePath('/tmp/a\u0000b'), RemotePathError)
})

test('a trailing slash is dropped so two spellings compare equal', () => {
  assert.equal(normalizeRemotePath('/home/user/'), '/home/user')
  assert.equal(normalizeRemotePath('/home/user/./'), '/home/user')
  assert.equal(normalizeRemotePath('/home//user//'), '/home/user')
  assert.equal(normalizeRemotePath('/home/user'), '/home/user')
})

test('the root is not reduced to an empty string', () => {
  assert.equal(normalizeRemotePath('/'), '/')
})

test('the error names the problem so the caller can fix it', () => {
  try {
    normalizeRemotePath('~/x')
    assert.fail('should have thrown')
  } catch (err) {
    assert.match(err.message, /does not expand/)
    assert.equal(err.name, 'RemotePathError')
  }
})
