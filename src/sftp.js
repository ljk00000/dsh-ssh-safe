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
 * Wrap an sftp error with the remote path it refers to.
 *
 * "No such file" alone gives the caller nothing to act on; the path is what
 * makes it diagnosable. The errno code is preserved so callers can still tell
 * ENOENT from EACCES.
 */
function remoteError(err, target) {
  const message = redact(err && err.message ? err.message : String(err))
  const wrapped = /** @type {Error & {code?: unknown}} */ (new Error(message + ': ' + target))
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
  try { attrs = await callSftp(sftp, 'stat', target) } catch { return null }
  if (!attrs || typeof attrs.isDirectory !== 'function') return null
  const isDir = attrs.isDirectory()
  if (expected === 'file' && isDir) {
    const e = /** @type {Error & {code?: string}} */ (new Error('not a file: ' + target + ' (it is a directory; use ssh_list)'))
    e.code = 'EISDIR'
    return e
  }
  if (expected === 'dir' && !isDir) {
    const e = /** @type {Error & {code?: string}} */ (new Error('not a directory: ' + target + ' (it is a file; use ssh_read)'))
    e.code = 'ENOTDIR'
    return e
  }
  return null
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
  let current = absolute ? '' : ''
  for (const part of parts) {
    current += (absolute ? '/' : '/') + part
    const probe = absolute ? current : current.replace(/^\//, '')
    try {
      await callSftp(sftp, 'stat', probe)
      continue
    } catch { /* missing: create it */ }
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
 * @param {{maxBytes?: number, timeoutMs: number}} options
 * @returns {Promise<{content: string, truncated: boolean, bytes: number, path: string}>}
 */
export async function readRemoteFile(client, remotePath, { maxBytes, timeoutMs }) {
  const target = normalizeRemotePath(remotePath)
  const sftp = await openSftp(client)
  return await new Promise((resolve, reject) => {
    const collector = new Utf8Collector(maxBytes)
    let settled = false
    let timer = null
    let stream = null

    const settle = (result, error) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
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

    timer = setTimeout(() => {
      settle(null, new Error('reading ' + target + ' did not complete within ' + timeoutMs + 'ms'))
    }, timeoutMs)

    try {
      stream = sftp.createReadStream(target)
    } catch (err) {
      return kindMismatch(sftp, target, 'file').then(
        (better) => settle(null, better || remoteError(err, target)),
        () => settle(null, remoteError(err, target)),
      )
    }

    // Once the stream has failed, 'close' still fires without an error, and it
    // used to win the race against the asynchronous explanation below: the read
    // resolved with empty content for a path that is a directory. A pending
    // explanation now suppresses the success path.
    let explain = null
    const finish = () => {
      if (explain) return
      settle({
        content: collector.toString(),
        truncated: collector.truncated,
        bytes: collector.bytes,
        path: target,
      })
    }

    stream.on('data', (chunk) => {
      collector.push(chunk)
      if (collector.truncated) finish()
    })
    const fail = (e) => {
      if (explain) return
      explain = kindMismatch(sftp, target, 'file').then(
        (better) => settle(null, better || remoteError(e, target)),
        () => settle(null, remoteError(e, target)),
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
 * @param {{timeoutMs: number, createDirs?: boolean}} options
 * @returns {Promise<{bytes: number, path: string}>}
 */
export async function writeRemoteFile(client, remotePath, content, { timeoutMs = 30000, createDirs = false } = /** @type {any} */ ({})) {
  const target = normalizeRemotePath(remotePath)
  const payload = Buffer.isBuffer(content) ? content : Buffer.from(String(content ?? ''), 'utf8')
  const sftp = await openSftp(client)
  if (createDirs) await ensureRemoteDir(sftp, dirnameOf(target))

  return await new Promise((resolve, reject) => {
    let settled = false
    let timer = null
    let stream = null

    const settle = (result, error) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
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

    timer = setTimeout(() => {
      settle(null, new Error(
        'writing ' + target + ' did not complete within ' + timeoutMs + 'ms' +
        ' — the remote channel may have dropped'
      ))
    }, timeoutMs)

    try {
      stream = sftp.createWriteStream(target)
    } catch (err) {
      return kindMismatch(sftp, target, 'file').then(
        (better) => settle(null, better || remoteError(err, target)),
        () => settle(null, remoteError(err, target)),
      )
    }

    // Same race as in readRemoteFile: a failed write still emits 'close', so
    // the success path has to stand down while the error is being explained.
    let explain = null
    const done = () => {
      if (explain) return
      settle({ bytes: payload.length, path: target })
    }
    stream.on('error', (e) => {
      if (explain) return
      explain = kindMismatch(sftp, target, 'file').then(
        (better) => settle(null, better || remoteError(e, target)),
        () => settle(null, remoteError(e, target)),
      )
    })
    stream.on('close', done)
    stream.on('finish', done)
    try { stream.end(payload) } catch (err) {
      settle(null, remoteError(err, target))
    }
  })
}

/**
 * List a remote directory.
 *
 * @param {any} client
 * @param {string} remotePath
 * @param {{timeoutMs: number}} options
 * @returns {Promise<{path: string, items: Array<{name: string, size: number, dir: boolean, mtime: string|null}>}>}
 */
export async function listRemoteDir(client, remotePath, { timeoutMs }) {
  const target = normalizeRemotePath(remotePath || '.', { allowRelative: true })
  const sftp = await openSftp(client)

  return await new Promise((resolve, reject) => {
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      closeSftp(sftp)
      reject(new Error(redact('listing ' + target + ' did not complete within ' + timeoutMs + 'ms')))
    }, timeoutMs)

    const settle = (result, error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      closeSftp(sftp)
      if (error) reject(error)
      else resolve(result)
    }

    try {
      sftp.readdir(target, (err, items) => {
        if (err) {
          // readdir on a regular file fails with the server's ENOENT text,
          // which reads as "the path does not exist" for a path that does.
          return kindMismatch(sftp, target, 'dir').then(
            (better) => settle(null, better || remoteError(err, target)),
            () => settle(null, remoteError(err, target)),
          )
        }
        settle({
          path: target,
          items: items.map((it) => ({
            name: it.filename,
            size: it.attrs.size,
            dir: (it.attrs.mode & 0o040000) !== 0,
            mtime: it.attrs.mtime ? new Date(it.attrs.mtime * 1000).toISOString() : null,
          })),
        })
      })
    } catch (err) {
      settle(null, new Error(redact(err && err.message ? err.message : String(err))))
    }
  })
}
