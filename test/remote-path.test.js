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
test('a relative path with .. is refused even when relatives are allowed', () => {
  // SFTP resolves it against the login directory, which this plugin does not
  // know; a '..' there can escape wherever the caller expected to be.
  assert.throws(() => normalizeRemotePath('./a/../a', { allowRelative: true }), /cannot contain "\.\."/)
  assert.throws(() => normalizeRemotePath('..', { allowRelative: true }), /cannot contain "\.\."/)
  assert.throws(() => normalizeRemotePath('a/../../b', { allowRelative: true }), /remote base directory is not known/)
})

test('a relative path without .. is accepted when relatives are allowed', () => {
  assert.equal(normalizeRemotePath('logs/app.log', { allowRelative: true }), 'logs/app.log')
  assert.equal(normalizeRemotePath('.', { allowRelative: true }), '.')
})
test('a trailing slash names a directory, so a file operation refuses it', () => {
  // Dropping the slash turned '/etc/passwd/' into a valid file path and
  // OVERWROTE the file: measured, ssh_write('/etc/passwd/', 'x') replaced its
  // content, while a real sshd answers ENOTDIR for the trailing-slash form.
  assert.throws(
    () => normalizeRemotePath('/etc/passwd/', { file: true }),
    (err) => {
      assert.ok(err instanceof RemotePathError)
      assert.match(err.message, /names a directory, not a file/)
      assert.match(err.message, /drop the trailing slash to use \/etc\/passwd;/)
      return true
    },
  )
  // Without the option (a listing) the slash is just a spelling of the same
  // directory and is dropped.
  assert.equal(normalizeRemotePath('/tmp/', { allowRelative: true }), '/tmp')
  assert.equal(normalizeRemotePath('/'), '/')
})
