// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe — SFTP transfer operations.
//
// These three lived inside SshPool, which had grown to ~700 lines mixing
// connection lifecycle, authentication, output buffering, transfers and
// eviction. Splitting them keeps each file to one concern; the pool keeps only
// what it needs: an sftp session and a caller-supplied deadline.
//
// Every operation here has the same shape: open the session, settle exactly
// once against a deadline, and detach listeners so a late event cannot resolve
// twice. ssh2 can fail without emitting either 'error' or 'close', so the
// deadline is the only reliable backstop.

import { printable } from './format.js'
import { Utf8Collector } from './buffer.js'
import { normalizeRemotePath } from './remote-path.js'
import { redact } from './credentials.js'

/** Open an SFTP session or reject. */
function openSftp(client) {
  return new Promise((resolve, reject) => {
    try {
      client.sftp((err, sftp) => {
        if (err) reject(new Error(redact(err.message)))
        else resolve(sftp)
      })
    } catch (err) {
      reject(new Error(redact(err && err.message ? err.message : String(err))))
    }
  })
}

/**
 * Close an SFTP session.
 *
 * Every transfer opens its own session, and sshd counts sessions per
 * connection (MaxSessions, 10 by default). Leaving them open leaked one channel
 * per operation until the server answered "(SSH) Channel open failure: open
 * failed" — reproducible after about ten reads. Ending the session in the
 * settle path is what keeps a long session usable.
 */
function closeSftp(sftp) {
  try { sftp.end() } catch { /* already gone */ }
}

/**
 * Wire a caller's AbortSignal to a settle() callback.
 *
 * The harness aborts exec.signal when the user stops the turn; a cooperative
 * tool must stop its work, not just stop waiting for it. Returns the listener so
 * settle() can detach it.
 *
 * @param {AbortSignal|undefined} signal
 * @param {string|(() => string)} message text, or a function for text that is only known later
 * @param {(error: Error) => void} settle
 * @returns {(() => void)|null}
 */
function onAbort(signal, message, settle) {
  if (!signal) return null
  // The message may be a function evaluated at abort time: what a write has done
  // to the remote file is only known once it starts.
  const describe = typeof message === 'function' ? message : () => message
  if (signal.aborted) {
    settle(new Error(describe() + ' (cancelled before it started)'))
    return null
  }
  const listener = () => settle(new Error(describe()))
  try { signal.addEventListener('abort', listener, { once: true }) } catch { return null }
  return listener
}

/** Detach a listener installed by onAbort(). */
function clearAbort(signal, listener) {
  if (!listener || !signal) return
  try { signal.removeEventListener('abort', listener) } catch {}
}

/**
 * Wrap an sftp error with the remote path it refers to.
 *
 * "No such file" alone gives the caller nothing to act on; the path is what
 * makes it diagnosable. The errno code is preserved so callers can still tell
 * ENOENT from EACCES.
 */
function remoteError(err, target, operation) {
  const message = redact(err && err.message ? err.message : String(err))
  // A relative path is resolved by sshd against the login user's home
  // directory, not against anything the caller passed earlier. Saying so turns
  // a bare "No such file: tmp/x" into something the caller can act on.
  const relative = typeof target === 'string' && target.length > 0 && !target.startsWith('/')
  const denied = /permission denied|EACCES/i.test(message)
  const hints = []
  if (relative && /no such file|not found|does not exist/i.test(message)) {
    hints.push("relative to the login user's home directory — pass an absolute path to be exact")
  }
  // 'Permission denied: /root/x' says what failed but not what to look at: the
  // answer is always a mode or an owner, and which one depends on the operation.
  if (denied) {
    if (operation === 'write') {
      hints.push('the account may not write there — check the owner and mode of the parent directory (ls -ld <dir>), or choose a path it owns')
    } else if (operation === 'read') {
      hints.push('the account may not read this file — check its owner and mode (ls -l <path>)')
    } else if (operation === 'list') {
      hints.push('the account may not list this directory — check its owner and mode (ls -ld <path>)')
    } else {
      hints.push('the account may not touch this path — check its owner and mode (ls -ld <parent>)')
    }
  }
  const hint = hints.length > 0 ? ' (' + hints.join('; ') + ')' : ''
  const wrapped = /** @type {Error & {code?: unknown}} */ (new Error(message + ': ' + printable(target) + hint))
  const code = /** @type {{code?: unknown}} */ (err || {}).code
  if (code !== undefined) wrapped.code = code
  return wrapped
}

/**
 * Say which kind of path was handed to the wrong operation.
 *
 * OpenSSH answers "Failure" for reading a directory and "No such file" for
 * readdir on a regular file; neither names the actual problem, so the caller
 * reads it as a bug in the plugin. One stat on the error path is enough to
 * report "it is a directory" or "it is a file".
 *
 * @param {any} sftp session
 * @param {string} target normalised remote path
 * @param {'file'|'dir'} expected what the operation needed
 * @returns {Promise<Error|null>} a better error, or null to keep the original
 */
async function kindMismatch(sftp, target, expected) {
  if (typeof sftp.stat !== 'function') return null
  let attrs
  try {
    attrs = await callSftp(sftp, 'stat', target)
  } catch (statError) {
    // The path is gone -- but a path that is a symlink to nothing is a different
    // situation from a path that never existed, and only LSTAT can tell. The
    // server's answer for both is "No such file", which leaves the caller
    // wondering why the file they just created is not there.
    const dangling = await danglingLink(sftp, target, statError)
    if (dangling) return dangling
    // '/tmp/afile.txt/sub' fails with "no such file", but the sub path is not
    // what is missing: a component above it is a file. One stat per component,
    // only on the error path.
    return await blockedByFile(sftp, target)
  }
  if (!attrs || typeof attrs.isDirectory !== 'function') return null
  const isDir = attrs.isDirectory()
  if (expected === 'file' && isDir) {
    const e = /** @type {Error & {code?: string}} */ (new Error('not a file: ' + printable(target) + ' (it is a directory; use ssh_list)'))
    e.code = 'EISDIR'
    return e
  }
  if (expected === 'dir' && !isDir) {
    const e = /** @type {Error & {code?: string}} */ (new Error('not a directory: ' + printable(target) + ' (it is a file; use ssh_read)'))
    e.code = 'ENOTDIR'
    return e
  }
  return null
}

/**
 * Find a component above the target that is a file.
 *
 * '/tmp/afile.txt/sub' cannot exist, and the server says "No such file" for the
 * whole path -- true, and it points at the wrong part of it. One stat per
 * component, only on the error path.
 *
 * @param {any} sftp session
 * @param {string} target normalised remote path
 * @returns {Promise<Error|null>}
 */
async function blockedByFile(sftp, target) {
  const parts = String(target).split('/').filter(Boolean)
  let prefix = ''
  for (let i = 0; i < parts.length - 1; i++) {
    prefix += '/' + parts[i]
    let attrs
    try {
      attrs = await callSftp(sftp, 'stat', prefix)
    } catch {
      // A missing component above is the ordinary "no such file"; only a file in
      // the way needs a different sentence.
      return null
    }
    if (attrs && typeof attrs.isDirectory === 'function' && !attrs.isDirectory()) {
      return new Error(
        'cannot reach ' + printable(target) + ': ' + printable(prefix) + ' is a file, not a directory'
      )
    }
  }
  return null
}

/**
 * Explain a path that is a symlink whose target does not exist.
 *
 * @param {any} sftp
 * @param {string} target
 * @param {any} original the stat/read error to keep when this is not a link
 * @returns {Promise<Error|null>} null to keep the original error
 */
async function danglingLink(sftp, target, original) {
  if (typeof sftp.lstat !== 'function') return null
  let attrs
  try { attrs = await callSftp(sftp, 'lstat', target) } catch { return null }
  if (!attrs || typeof attrs.isSymbolicLink !== 'function' || !attrs.isSymbolicLink()) return null
  // A cycle is a link that IS there, pointing at another that points back: it is
  // not a missing target, and 'the target does not exist' sends the user looking
  // for a file that was never the problem.
  const originalMessage = String(original && original.message || '')
  if (/too many levels|ELOOP/i.test(originalMessage)) {
    return new Error(
      'symbolic link loop at ' + printable(target) + ' — the links point at each other, so there is no ' +
      'file behind them; replace or remove one of the links'
    )
  }
  let points = ''
  if (typeof sftp.readlink === 'function') {
    try { points = String(await callSftp(sftp, 'readlink', target)) } catch { /* the link may be gone again */ }
  }
  return new Error(
    'no such file: ' + printable(target) + ' — that path is a symbolic link' +
    (points ? ' to ' + points : '') +
    ', but the target does not exist'
  )
}

/**
 * Whether decoded text looks like a binary file rather than text.
 *
 * A NUL cannot appear in UTF-8 text at all, and a heavy share of replacement
 * characters means the bytes were not UTF-8. Both were previously rendered as
 * ordinary content.
 *
 * @param {string} text
 * @returns {{binary: boolean, invalidBytes: number}}
 */
export function looksBinary(text) {
  const value = String(text || '')
  if (value.length === 0) return { binary: false, invalidBytes: 0 }
  const invalidBytes = (value.match(/\uFFFD/g) || []).length
  const nul = value.includes('\u0000')
  // 2% is comfortably above the rate a stray replacement character reaches in
  // text that is merely mangled in one place. The floor of 2 made a tiny file
  // look like text ('A<FFFD><FFFD>B' is 50% invalid), so files shorter than 10
  // characters are judged by their bytes: one invalid byte there is a binary
  // header, not a typo in a sentence.
  const tiny = value.length < 10
  const binary = nul || (tiny && invalidBytes > 0) ||
    invalidBytes > Math.max(2, value.length * 0.02)
  return { binary, invalidBytes }
}

/**
 * The character `ls -l` puts in the first column, from the file's mode.
 *
 * @param {number} mode
 * @returns {string}
 */
export function typeChar(mode) {
  const bits = Number(mode) & 0o170000
  if (bits === 0o040000) return 'd'
  if (bits === 0o120000) return 'l'
  if (bits === 0o010000) return 'p'
  if (bits === 0o140000) return 's'
  if (bits === 0o020000) return 'c'
  if (bits === 0o060000) return 'b'
  return '-'
}

/**
 * Name a path that is not a regular file, for a timeout that it caused.
 *
 * @param {any} sftp
 * @param {string} target
 * @param {'read'|'write'} operation
 * @returns {Promise<string>} '' when the path is an ordinary file
 */
async function specialFileNote(sftp, target, operation) {
  // Never let the diagnostic outlive the timeout it decorates: after a forced
  // close the session is gone, stat never answers, and awaiting it here kept
  // the whole read pending forever (measured: still pending 12s after a 3s
  // timeout).
  const note = await Promise.race([
    probeSpecialFile(sftp, target, operation),
    new Promise((resolve) => {
      const timer = setTimeout(() => resolve(''), 250)
      if (typeof timer.unref === 'function') timer.unref()
    }),
  ])
  return note
}

/** The unbounded probe behind specialFileNote. */
async function probeSpecialFile(sftp, target, operation) {
  if (typeof sftp.stat !== 'function') return ''
  let attrs
  try { attrs = await callSftp(sftp, 'stat', target) } catch { return '' }
  if (!attrs || typeof attrs.mode !== 'number') return ''
  const kind = typeChar(attrs.mode)
  const names = {
    p: 'a named pipe (FIFO)',
    s: 'a socket',
    c: 'a character device',
    b: 'a block device',
    d: 'a directory',
    l: 'a symbolic link',
  }
  const name = names[kind]
  if (!name) return ''
  const why = kind === 'p'
    ? (operation === 'read'
      ? ' — a FIFO has no end until something writes to it, so reading it blocks forever'
      : ' — a FIFO blocks until something reads from it')
    : ' — only regular files can be read or written this way'
  return ' — ' + printable(target) + ' is ' + name + why
}

/** Promisify an ssh2 sftp method's node-style callback. */
function callSftp(sftp, method, ...args) {
  return new Promise((resolve, reject) => {
    try {
      sftp[method](...args, (err, value) => (err ? reject(err) : resolve(value)))
    } catch (err) {
      reject(err)
    }
  })
}

/** Parent directory of a remote path, using '/' only. */
function dirnameOf(target) {
  const path = String(target || '')
  const idx = path.lastIndexOf('/')
  if (idx < 0) return ''
  if (idx === 0) return '/'
  return path.slice(0, idx)
}

/**
 * Create every missing component of a remote directory.
 *
 * ssh_write could only write into a directory that already existed, and the
 * failure surfaced as a bare "No such file" with no path and no remedy — which
 * reads like a bug in the plugin rather than a missing directory. Creating the
 * parents is opt-in (createDirs: true) so a typo in the path does not silently
 * build a tree of empty directories.
 */
async function ensureRemoteDir(sftp, dir) {
  const path = String(dir || '')
  if (!path || path === '/' || path === '.') return
  const absolute = path.startsWith('/')
  const parts = path.split('/').filter((part) => part && part !== '.')
  let current = ''
  for (const part of parts) {
    current += '/' + part
    // A relative path must stay relative: sshd resolves it against the login
    // directory, and an accidental leading slash would target the root instead.
    const probe = absolute ? current : current.slice(1)
    try {
      const attrs = await callSftp(sftp, 'stat', probe)
      // A path that exists as a FILE is not a directory to walk through. The
      // mkdir below would fail with the server's bare "Failure", which says
      // nothing about the real problem: one component of the path is a file.
      if (attrs && typeof attrs.isDirectory === 'function' && !attrs.isDirectory()) {
        throw new Error(
          'cannot create the parent directories of this path: ' + probe +
          ' already exists and is a file, not a directory'
        )
      }
      continue
    } catch (err) {
      if (/already exists and is a file/.test(String(err && err.message))) throw err
      /* missing: create it */
    }
    try {
      await callSftp(sftp, 'mkdir', probe)
    } catch (err) {
      // A concurrent writer may have won the race; that is success, not failure.
      try {
        await callSftp(sftp, 'stat', probe)
      } catch {
        throw new Error('could not create remote directory ' + probe + ': ' + redact(err && err.message ? err.message : String(err)))
      }
    }
  }
}

/**
 * Read a remote file as UTF-8, capped at `maxBytes`.
 *
 * Bytes are collected before decoding so a multi-byte character split across
 * chunk boundaries is not corrupted.
 *
 * @param {any} client
 * @param {string} remotePath
 * @param {{maxBytes?: number, timeoutMs: number, signal?: AbortSignal}} options
 * @returns {Promise<{content: string, truncated: boolean, bytes: number, path: string, binary?: boolean, invalidBytes?: number}>}
 */
export async function readRemoteFile(client, remotePath, { maxBytes, timeoutMs, signal }) {
  const target = normalizeRemotePath(remotePath, { file: true })
  const sftp = await openSftp(client)
  return await new Promise((resolve, reject) => {
    const collector = new Utf8Collector(maxBytes)
    let settled = false
    let timer = null
    let stream = null
    let abortListener = null

    const settle = (result, error) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      clearAbort(signal, abortListener)
      abortListener = null
      if (stream) {
        // Detach the data handler, then leave exactly one 'error' listener
        // behind. Destroying the stream and closing the SFTP session makes
        // ssh2 fail any request still in flight ("No response from server")
        // and emit it on the stream; with no listener that becomes an
        // unhandled 'error' event, which takes the whole process down --
        // observed while reading a file that did not exist.
        try { stream.removeAllListeners('data') } catch {}
        try { stream.removeAllListeners('error'); stream.on('error', () => {}) } catch {}
        try { stream.destroy() } catch {}
      }
      setImmediate(() => closeSftp(sftp))
      if (error) reject(error)
      else resolve(result)
    }

    timer = setTimeout(async () => {
      if (settled) return
      // A read that never returns is usually a FIFO: a real server blocks on the
      // open until something writes, and the deadline message then blames the
      // network. One stat after the timeout (not before, so ordinary reads pay
      // nothing) names the real cause.
      const detail = await specialFileNote(sftp, target, 'read')
      if (settled) return
      // The same fallback the write path has: a bare 'did not complete' says
      // nothing about what to look at next.
      settle(null, new Error('reading ' + printable(target) + ' did not complete within ' + timeoutMs + 'ms' +
        (detail || ' — the remote channel may have dropped, or the filesystem is not answering')))
    }, timeoutMs)
    abortListener = onAbort(signal, 'reading ' + printable(target) + ' was cancelled', (error) => settle(null, error))

    try {
      stream = sftp.createReadStream(target)
    } catch (err) {
      return kindMismatch(sftp, target, 'file').then(
        (better) => settle(null, better || remoteError(err, target, 'read')),
        () => settle(null, remoteError(err, target, 'read')),
      )
    }

    // Once the stream has failed, 'close' still fires without an error, and it
    // used to win the race against the asynchronous explanation below: the read
    // resolved with empty content for a path that is a directory. A pending
    // explanation now suppresses the success path.
    let explain = null
    const finish = () => {
      if (explain) return
      const content = collector.toString()
      settle({
        content,
        truncated: collector.truncated,
        bytes: collector.bytes,
        path: target,
        // Decoding is always UTF-8. A PNG, a gzip stream or a Latin-1 log comes
        // back as replacement characters and NULs, which then go into the
        // transcript as if they were the file's text. Detecting it here is what
        // lets the tool say so.
        ...looksBinary(content),
      })
    }

    stream.on('data', (chunk) => {
      collector.push(chunk)
      if (collector.truncated) finish()
    })
    const fail = (e) => {
      if (explain) return
      explain = kindMismatch(sftp, target, 'file').then(
        (better) => settle(null, better || remoteError(e, target, 'read')),
        () => settle(null, remoteError(e, target, 'read')),
      )
    }
    stream.on('error', fail)
    stream.on('end', finish)
    stream.on('close', finish)
  })
}

/**
 * Write UTF-8 text to a remote file.
 *
 * A stalled write stream is the case that used to hang forever: ssh2 can fail
 * without emitting 'error' or 'close'.
 *
 * @param {any} client
 * @param {string} remotePath
 * @param {string|Buffer} content
 * @param {{timeoutMs: number, createDirs?: boolean, signal?: AbortSignal, mode?: number}} options
 * @returns {Promise<{bytes: number, path: string, linkTarget?: string, mode?: number, modeRequested?: number}>}
 *   `linkTarget` is set when the path was a symlink (where the bytes went);
 *   `mode` is the permission bits the file ended up with
 */
export async function writeRemoteFile(client, remotePath, content, { timeoutMs = 30000, createDirs = false, signal, mode } = /** @type {any} */ ({})) {
  const target = normalizeRemotePath(remotePath, { file: true })
  const payload = Buffer.isBuffer(content) ? content : Buffer.from(String(content ?? ''), 'utf8')
  const sftp = await openSftp(client)
  if (createDirs) await ensureRemoteDir(sftp, dirnameOf(target))

  return await new Promise((resolve, reject) => {
    let settled = false
    let timer = null
    let stream = null
    let abortListener = null

    const settle = (result, error) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      clearAbort(signal, abortListener)
      abortListener = null
      if (stream && error) {
        // Same hazard as in readRemoteFile: a pending request fails when the
        // session closes, and an event with no listener kills the process.
        try { stream.removeAllListeners('close'); stream.removeAllListeners('finish') } catch {}
        try { stream.removeAllListeners('error'); stream.on('error', () => {}) } catch {}
        try { stream.destroy() } catch {}
      }
      setImmediate(() => closeSftp(sftp))
      if (error) reject(error)
      else resolve(result)
    }

    // What the remote file looks like right now. "may be truncated or partially
    // written" was printed even when the write never opened the file: a cancel
    // before the first byte sent the caller looking for damage that was not
    // there. Once the stream exists the file HAS been truncated by the open, and
    // the byte count is the only thing that says how much is missing.
    // 'special': a FIFO or socket is not truncated by an open — the open is what
    // blocks — so claiming "its previous content is gone" there describes damage
    // that cannot have happened.
    const writeState = (special = false) => {
      if (!stream) return 'the file was not touched'
      const wrote = Number(stream.bytesWritten) || 0
      if (special) {
        return wrote === 0
          ? 'no data was sent: opening it is the step that has not finished'
          : 'sent ' + wrote + ' byte' + (wrote === 1 ? '' : 's') + ' before it stopped'
      }
      if (wrote === 0) return 'the file was opened (which truncates it) but no data was sent, so its previous content is gone'
      return 'sent ' + wrote + ' byte' + (wrote === 1 ? '' : 's') + ' before it stopped; the file is partial'
    }
    timer = setTimeout(async () => {
      if (settled) return
      const detail = await specialFileNote(sftp, target, 'write')
      if (settled) return
      settle(null, new Error(
        'writing ' + printable(target) + ' did not complete within ' + timeoutMs + 'ms' +
        (detail || ' — the remote channel may have dropped') + '; ' + writeState(Boolean(detail))
      ))
    }, timeoutMs)
    // A function, not a string: the state is composed when the abort happens.
    abortListener = onAbort(signal, () => 'writing ' + printable(target) + ' was cancelled; ' + writeState(),
      (error) => settle(null, error))

    const requestedMode = mode
    try {
      // mode is only applied when the file is created; an existing file keeps
      // its permissions, which is what chmod-less writing should do.
      stream = sftp.createWriteStream(target, mode === undefined ? undefined : { mode })
    } catch (err) {
      return kindMismatch(sftp, target, 'file').then(
        (better) => settle(null, better || remoteError(err, target, 'write')),
        () => settle(null, remoteError(err, target, 'write')),
      )
    }

    // Same race as in readRemoteFile: a failed write still emits 'close', so
    // the success path has to stand down while the error is being explained.
    let explain = null
    let finishing = false
    const done = async () => {
      if (explain || finishing) return
      finishing = true
      // Writing through a symlink puts the bytes somewhere else: '/home/u/.ssh/
      // config' that is a link to '/etc/ssh/ssh_config' writes into /etc. The
      // result used to say only the path it was given, so the caller never
      // learned where the content actually landed.
      let linkTarget
      let mode
      try {
        if (typeof sftp.lstat === 'function') {
          let attrs = await callSftp(sftp, 'lstat', target)
          if (attrs && typeof attrs.isSymbolicLink === 'function' && attrs.isSymbolicLink() &&
            typeof sftp.readlink === 'function') {
            linkTarget = String(await callSftp(sftp, 'readlink', target))
            // A link's own mode is 0777 on a real server and says nothing about the
            // file the bytes landed in: stat() the target when there is a link.
            try {
              const real = await callSftp(sftp, 'stat', target)
              if (real && typeof real.mode === 'number') attrs = real
            } catch { /* the target may be gone; keep the link's attrs */ }
          }
          // The permissions the file ended up with are not the ones asked for on
          // every server (umask applies), and they decide who can read the file
          // just written.
          // 0o7777, not 0o777: a server that honours a setuid or sticky bit
          // recorded it, and masking it away reported a file that is not the one
          // on disk.
          if (attrs && typeof attrs.mode === 'number') mode = attrs.mode & 0o7777
        }
      } catch { /* the link may be gone again; the write itself succeeded */ }
      if (explain) return
      // The caller asked for a mode and the file already existed: report both, so
      // the tool can say the mode was not applied instead of leaving the caller
      // with an executable script that is not executable.
      // (the local 'mode' above shadows the parameter, so the requested value
      // is the one captured before the write started)
      settle({ bytes: payload.length, path: target, linkTarget, mode, modeRequested: requestedMode })
    }
    stream.on('error', (e) => {
      if (explain) return
      // The stream truncates on open, so a write that fails part-way leaves less
      // than the caller asked for. Saying so is the difference between "retry"
      // and "someone deleted half this file".
      const note = (err) => {
        // Only when bytes actually went out. An open failure (missing parent, a
        // path that is not a file) wrote nothing, and claiming a truncated file
        // sends the caller looking for damage that is not there.
        const wrote = Number(stream && stream.bytesWritten) > 0
        if (wrote && err && typeof err.message === 'string' && !/partially written/.test(err.message)) {
          err.message += ' — the file may be truncated or partially written'
        }
        return err
      }
      explain = kindMismatch(sftp, target, 'file').then(
        (better) => settle(null, better || note(remoteError(e, target, 'write'))),
        () => settle(null, note(remoteError(e, target, 'write'))),
      )
    })
    stream.on('close', done)
    stream.on('finish', done)
    try { stream.end(payload) } catch (err) {
      settle(null, remoteError(err, target, 'write'))
    }
  })
}

/**
 * List a remote directory.
 *
 * @param {any} client
 * @param {string} remotePath
 * @param {{timeoutMs: number, signal?: AbortSignal}} options
 * @returns {Promise<{path: string, items: Array<{name: string, size: number, dir: boolean, mtime: string|null}>}>}
 */
/**
 * Turn SFTP readdir entries into listing rows.
 *
 * `.` and `..` are dropped: OpenSSH reports them, ssh2 passes them through,
 * and the rows are noise next to real names (the loopback test server never
 * emits them, so nothing caught this).
 *
 * @param {Array<{filename: string, attrs: {size?: number, mode?: number, mtime?: number}}>} items
 * @returns {Array<{name: string, size?: number, dir: boolean, type: string, mtime: string|null}>}
 */
export function listingEntries(items) {
  return items
    .filter((it) => it.filename !== '.' && it.filename !== '..')
    .map((it) => ({
      name: it.filename,
      size: it.attrs.size,
      // Compare the whole type field: a socket is 0o140000, which also has the
      // 0o040000 directory bit set, so a bit test called sockets dirs.
      dir: (Number(it.attrs.mode) & 0o170000) === 0o040000,
      // A symlink, a FIFO and a socket are not regular files, and a listing that
      // shows all three as '-' invites reading a FIFO, which blocks.
      type: typeChar(it.attrs.mode),
      // SFTP reports whole seconds, so the milliseconds are always .000 and only
      // make the column wider.
      mtime: it.attrs.mtime
        ? new Date(it.attrs.mtime * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
        : null,
    }))
}

export async function listRemoteDir(client, remotePath, { timeoutMs, signal }) {
  const target = normalizeRemotePath(remotePath || '.', { allowRelative: true })
  const sftp = await openSftp(client)

  return await new Promise((resolve, reject) => {
    let settled = false
    let abortListener = null
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      closeSftp(sftp)
      reject(new Error(redact('listing ' + printable(target) + ' did not complete within ' + timeoutMs + 'ms' +
        ' — the remote channel may have dropped, or the filesystem is not answering')))
    }, timeoutMs)

    const settle = (result, error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      clearAbort(signal, abortListener)
      abortListener = null
      closeSftp(sftp)
      if (error) reject(error)
      else resolve(result)
    }

    abortListener = onAbort(signal, 'listing ' + printable(target) + ' was cancelled', (error) => settle(null, error))
    try {
      sftp.readdir(target, (err, items) => {
        if (err) {
          // readdir on a regular file fails with the server's ENOENT text,
          // which reads as "the path does not exist" for a path that does.
          return kindMismatch(sftp, target, 'dir').then(
            (better) => settle(null, better || remoteError(err, target, 'list')),
            () => settle(null, remoteError(err, target, 'list')),
          )
        }
        settle({ path: target, items: listingEntries(items) })
      })
    } catch (err) {
      settle(null, new Error(redact(err && err.message ? err.message : String(err))))
    }
  })
}