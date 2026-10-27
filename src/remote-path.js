// dsh-ssh-safe — remote path handling.
//
// SFTP receives raw strings and has no shell to expand anything: a leading ~
// is a literal filename, and multiple slashes confuse some servers. Normalising
// here keeps writeFile/readFile/list consistent.

import { posix } from 'node:path'

export class RemotePathError extends Error {
  constructor(message) {
    super(message)
    this.name = 'RemotePathError'
  }
}

/**
 * Normalise a path for SFTP.
 *
 * - collapses duplicate slashes and resolves '.' / '..'
 * - refuses an empty path
 * - refuses a '～' prefix: SFTP will not expand it, so failing loudly beats
 *   silently creating a file literally named '~'
 * - refuses NUL bytes (they truncate C strings inside the SFTP layer)
 *
 * @param {string} input
 * @param {{allowRelative?: boolean}} [options]
 * @returns {string}
 */
export function normalizeRemotePath(input, options = {}) {
  const raw = String(input ?? '')
  if (raw.length === 0) throw new RemotePathError('path is empty')
  if (raw.includes('\u0000')) throw new RemotePathError('path contains a NUL byte')

  const trimmed = raw.trim()
  if (trimmed.length === 0) throw new RemotePathError('path is blank')

  if (trimmed === '~' || trimmed.startsWith('~/')) {
    throw new RemotePathError(
      'SFTP does not expand "~" — use an absolute path such as /home/user/... ' +
      '(received: ' + trimmed + ')'
    )
  }

  const allowRelative = options.allowRelative === true
  if (!trimmed.startsWith('/') && !allowRelative) {
    throw new RemotePathError(
      'path must be absolute on the remote host (received: ' + trimmed + ')'
    )
  }

  // posix.normalize preserves a leading slash and resolves ./.., but it also
  // preserves a trailing slash ('/a/b/' stays '/a/b/'). Two spellings of the
  // same directory must compare equal, so the trailing slash is dropped except
  // for the root itself.
  let normalized = posix.normalize(trimmed)
  if (normalized.length > 1 && normalized.endsWith('/')) normalized = normalized.replace(/\/+$/, '')
  if (normalized === '' || normalized === '.') {
    if (allowRelative) return '.'
    throw new RemotePathError('path resolves to an empty location: ' + trimmed)
  }
  return normalized
}
