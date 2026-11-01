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

import { posix } from 'node:path'
import { printable, printableText } from './format.js'
import { Utf8Collector } from './buffer.js'
import { normalizeRemotePath } from './remote-path.js'
import { redact } from './credentials.js'

/** Open an SFTP session or reject. */
function openSftp(client) {
  return new Promise((resolve, reject) => {
    // ssh2 answers "Unable to start subsystem: sftp", which names neither the
    // machine nor what to do: three of the four file tools need this subsystem,
    // and a server with Subsystem sftp commented out answers exactly that.
    const explain = (message) => {
      const text = redact(String(message || ''))
      if (/subsystem/i.test(text)) {
        return new Error(
          'the server did not start the SFTP subsystem (' + text + '); ssh_read, ssh_list and ' +
          'ssh_write need it — check that sshd_config has Subsystem sftp enabled and that no ' +
          'ForceCommand or chroot rule blocks it'
        )
      }
      return new Error(text)
    }
    try {
      client.sftp((err, sftp) => {
        if (err) reject(explain(err.message))
        else resolve(sftp)
      })
    } catch (err) {
      reject(explain(err && err.message ? err.message : String(err)))
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
  const listener = () => {
    // The pool aborts with a reason when the cause is known ("the connection was
    // closed with force: true"); the harness aborts without one.
    const reason = signal.reason
    // A dropped connection is not a cancellation: "reading /x was cancelled (the
    // connection dropped)" blamed an action nobody took.
    if (reason === 'the connection dropped') {
      settle(new Error(describe().replace(' was cancelled', ' did not finish') + ' — ' + reason))
      return
    }
    settle(new Error(describe() + (typeof reason === 'string' && reason ? ' (' + reason + ')' : '')))
  }
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
  // The server writes this text: ssh2 puts the message from its SFTP STATUS
  // packet straight into err.message, so a host (or something pretending to be
  // one) controls those bytes. Escaped, and redacted first, like everything
  // else that leaves this plugin.
  const message = printableText(redact(err && err.message ? err.message : String(err)))
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
      hints.push('the account may not read this file — check the owner and mode of the file and of the directories above it (ls -l <path>, ls -ld <dir>)')
    } else if (operation === 'list') {
      hints.push('the account may not list this directory — check its owner and mode, and the search permission on the directories above it (ls -ld <path>)')
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
    } catch (err) {
      const why = String(err && err.message ? err.message : err)
      // A missing component above is the ordinary "no such file". A component
      // that is a symlink loop answers exactly the same thing for the whole
      // path, so reading /w/loop/x.txt said only "no such file: /w/loop/x.txt"
      // while /w/loop itself was explained properly.
      if (/too many levels|ELOOP/i.test(why)) {
        return new Error(
          'cannot reach ' + printable(target) + ': ' + printable(prefix) + ' is a symbolic link loop ' +
          '(the links point at each other), so nothing below it can be reached; replace or remove ' +
          'one of the links'
        )
      }
      if (typeof sftp.lstat === 'function') {
        try {
          const linkAttrs = await callSftp(sftp, 'lstat', prefix)
          if (linkAttrs && typeof linkAttrs.isSymbolicLink === 'function' && linkAttrs.isSymbolicLink()) {
            let points = ''
            try { points = String(await callSftp(sftp, 'readlink', prefix)) } catch { /* gone again */ }
            return new Error(
              'cannot reach ' + printable(target) + ': ' + printable(prefix) + ' is a symbolic link' +
              (points ? ' to ' + points : '') + ', and that target does not exist'
            )
          }
        } catch { /* the component is gone again */ }
      }
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
      // ELOOP is also what a chain longer than the server's limit answers, so the
      // message must not claim a cycle it cannot see: a 40-link chain to a real file
      // was reported as 'the links point at each other', which is false.
      'symbolic link loop at ' + printable(target) + ' — either the links point at each other or the ' +
      'chain is longer than the server allows, so there is no file behind them; replace or remove one ' +
      'of the links'
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
      const why = String(err && err.message ? err.message : err)
      // Only ENOENT means 'missing'. A component that exists but cannot be
      // walked through was treated as missing too, so a symlink loop turned into
      // 'could not create remote directory /w/loop: already exists' — true, and
      // useless: the directory never had to be created.
      if (/too many levels|ELOOP/i.test(why)) {
        throw new Error(
          'cannot create the parent directories of this path: ' + probe + ' is a symbolic link ' +
          'loop (the links point at each other, or the chain is longer than the server allows), so ' +
          'nothing can be created through it; replace or remove one of the links'
        )
      }
      // A component that is a symlink answering "No such file" is not missing:
      // it points at something that cannot be reached, and mkdir on it produced
      // "could not create remote directory /w/gone/a: not a directory" — a
      // sentence about a different path than the one that is broken.
      if (typeof sftp.lstat === 'function') {
        let linkAttrs = null
        try { linkAttrs = await callSftp(sftp, 'lstat', probe) } catch { /* gone again */ }
        if (linkAttrs && typeof linkAttrs.isSymbolicLink === 'function' && linkAttrs.isSymbolicLink()) {
          let points = ''
          try { points = String(await callSftp(sftp, 'readlink', probe)) } catch { /* gone again */ }
          throw new Error(
            'cannot create the parent directories of this path: ' + probe + ' is a symbolic link' +
            (points ? ' to ' + points : '') + ', and that target cannot be reached; fix that link first'
          )
        }
      }
      // Everything else keeps the old path (try mkdir, then report what the server
      // said): a denied directory is not a loop, and "could not create … Permission
      // denied" is the message the permission test pins.
      /* missing or unclear: try to create it */
    }
    try {
      await callSftp(sftp, 'mkdir', probe)
    } catch (err) {
      // A concurrent writer may have won the race; that is success, not failure.
      try {
        await callSftp(sftp, 'stat', probe)
      } catch {
        throw new Error('could not create remote directory ' + printable(probe) + ': ' +
          printableText(redact(err && err.message ? err.message : String(err))))
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

/** The most ancestors one write inspects for a link (one lstat each). */
const ANCESTOR_LINK_HOPS = 8

/**
 * Find the closest ancestor directory of `target` that is a symlink.
 *
 * A write names a path; the bytes land wherever the server's link traversal puts
 * them, which for '/a/b/c.txt' can be a link at '/a', not only at '/a/b'. Walking
 * from the closest ancestor upward means the first hit is the one that decides
 * the destination; the rest of the path is appended to its final target.
 *
 * @param {any} sftp session
 * @param {string} target the path that was written
 * @returns {Promise<{path: string, target: string, landedAt: string}|null>}
 */
async function findLinkedAncestor(sftp, target) {
  if (typeof sftp.lstat !== 'function' || typeof sftp.readlink !== 'function') return null
  const parts = posix.normalize(target).split('/').filter(Boolean)
  if (parts.length < 2) return null
  const file = parts.pop()
  const from = Math.max(1, parts.length - ANCESTOR_LINK_HOPS + 1)
  for (let depth = parts.length; depth >= from; depth -= 1) {
    const dir = '/' + parts.slice(0, depth).join('/')
    let attrs = null
    try { attrs = await callSftp(sftp, 'lstat', dir) } catch { return null }
    if (!attrs || typeof attrs.isSymbolicLink !== 'function' || !attrs.isSymbolicLink()) continue
    let raw
    try { raw = String(await callSftp(sftp, 'readlink', dir)) } catch { return null }
    const firstHop = posix.normalize(raw.startsWith('/') ? raw : posix.join(posix.dirname(dir), raw))
    const targetDir = (await followLinkChain(sftp, dir, firstHop)) || firstHop
    const below = parts.slice(depth).concat([file]).join('/')
    return {
      path: dir,
      target: targetDir,
      landedAt: posix.normalize(targetDir + '/' + below),
    }
  }
  return null
}

/** The most link targets one listing resolves (one readlink each). */
const LINK_TARGET_LIMIT = 40

/** How far a symlink chain is followed before it is treated as a loop. */
const LINK_CHAIN_HOPS = 12

/**
 * Resolve a symlink chain to the path the bytes actually reach.
 *
 * readlink answers one hop. A relative target ("../x") is resolved against the
 * directory of the link, the way the server resolves it.
 *
 * @param {any} sftp session
 * @param {string} link the path that resolved to `first`
 * @param {string} first the immediate target
 * @returns {Promise<string|undefined>} the final target, or undefined when `first` is it
 */
async function followLinkChain(sftp, link, first) {
  if (typeof sftp.lstat !== 'function' || typeof sftp.readlink !== 'function') return undefined
  let current = first
  let base = link
  for (let hop = 0; hop < LINK_CHAIN_HOPS; hop += 1) {
    const absolute = current.startsWith('/') ? current : posix.join(posix.dirname(base), current)
    const resolved = posix.normalize(absolute)
    let attrs = null
    try { attrs = await callSftp(sftp, 'lstat', resolved) } catch { return undefined }
    if (!attrs || typeof attrs.isSymbolicLink !== 'function' || !attrs.isSymbolicLink()) {
      return resolved === first ? undefined : resolved
    }
    base = resolved
    try { current = String(await callSftp(sftp, 'readlink', resolved)) } catch { return undefined }
  }
  return undefined
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
 * @returns {Promise<{bytes: number, path: string, linkTarget?: string, linkFinalTarget?: string, parentLink?: {path: string, target: string, landedAt: string}|null, mode?: number, modeRequested?: number}>}
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
      // 'its previous content is gone' was printed for a file that never existed,
      // which describes damage to nothing. Naming the state that is true either
      // way avoids both the false alarm and an extra round trip to find out.
      if (wrote === 0) return 'the file was opened (which truncates it) but no data was sent, so it is empty now' +
        ' (if it existed before, that content is gone)'
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
      let linkFinalTarget
      let parentLink
      let mode
      try {
        if (typeof sftp.lstat === 'function') {
          let attrs = await callSftp(sftp, 'lstat', target)
          if (attrs && typeof attrs.isSymbolicLink === 'function' && attrs.isSymbolicLink() &&
            typeof sftp.readlink === 'function') {
            const linkRaw = String(await callSftp(sftp, 'readlink', target))
            // A relative target ("real.txt") means "next to the link", so report the
            // path it actually names: the note said "a symbolic link to real.txt",
            // which reads as a file somewhere else entirely.
            linkTarget = posix.normalize(linkRaw.startsWith('/')
              ? linkRaw
              : posix.join(posix.dirname(target), linkRaw))
            // The bytes travel the whole chain, but readlink names only the first
            // hop: writing to /d/hop1 (→ /d/link-file → /d/target.txt) reported
            // "the content was written there" about a path that is itself a link.
            // Follow the chain and record where it ends.
            linkFinalTarget = await followLinkChain(sftp, target, linkTarget)
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
          // The file itself was not a link: a DIRECTORY on its way may be. Writing
          // '/home/u/live/app.conf' through 'live -> /etc/app' put the bytes in
          // /etc/app/app.conf while the reply named only the path it was given, and
          // a link further up ('/home -> /srv/home') was not looked at either.
          if (!linkTarget && typeof sftp.lstat === 'function') {
            parentLink = await findLinkedAncestor(sftp, target)
          }
        }
      } catch { /* the link may be gone again; the write itself succeeded */ }
      if (explain) return
      // The caller asked for a mode and the file already existed: report both, so
      // the tool can say the mode was not applied instead of leaving the caller
      // with an executable script that is not executable.
      // (the local 'mode' above shadows the parameter, so the requested value
      // is the one captured before the write started)
      settle({ bytes: payload.length, path: target, linkTarget, linkFinalTarget, parentLink, mode, modeRequested: requestedMode })
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
 * @returns {Promise<{path: string, items: Array<{name: string, size?: number, dir: boolean, type?: string, mtime: string|null, linkTarget?: string}>, viaLink?: {path: string, target: string}|null}>}
 */
/**
 * Turn SFTP readdir entries into listing rows.
 *
 * `.` and `..` are dropped: OpenSSH reports them, ssh2 passes them through,
 * and the rows are noise next to real names (the loopback test server never
 * emits them, so nothing caught this).
 *
 * @param {Array<{filename: string, linkTarget?: string, attrs: {size?: number, mode?: number, mtime?: number}}>} items
 * @returns {Array<{name: string, size?: number, dir: boolean, type: string, mtime: string|null, linkTarget?: string}>}
 */
export function listingEntries(items) {
  // A server that answers readdir with something that is not a list used to reach
  // the caller as 'items.filter is not a function: /tmp/x' — a JavaScript
  // internal on a defensive path, naming nothing the reader can act on.
  if (!Array.isArray(items)) {
    // 'a object' was the first version of this sentence: pick the article.
    const shape = items === null ? 'null'
      : typeof items === 'object' ? 'an object'
      : typeof items === 'string' ? 'a string'
      : String(typeof items) === 'number' ? 'a number'
      : 'a ' + typeof items
    throw new Error('the server sent ' + shape + ' where a list of directory entries belongs')
  }
  return items
    // An entry without a name cannot be a row, and an entry without attrs is a
    // server that sent SSH_FXP_NAME without them: reading it as an empty object
    // keeps the rest of the listing instead of throwing on the first bad entry.
    .filter((it) => it && typeof it.filename === 'string' && it.filename !== '.' && it.filename !== '..')
    .map((it) => {
      const attrs = it.attrs && typeof it.attrs === 'object' ? it.attrs : {}
      return {
        name: it.filename,
        // A size that is not a number is unknown, not zero: formatListing prints
        // it as a dash rather than inventing a byte count.
        size: Number.isFinite(attrs.size) ? attrs.size : undefined,
        // Compare the whole type field: a socket is 0o140000, which also has the
        // 0o040000 directory bit set, so a bit test called sockets dirs.
        dir: (Number(attrs.mode) & 0o170000) === 0o040000,
        // A symlink, a FIFO and a socket are not regular files, and a listing that
        // shows all three as '-' invites reading a FIFO, which blocks.
        type: typeChar(attrs.mode),
        // A row that says 'l' but not where it points hides the one thing a link
        // listing exists to show: ls -l prints ' -> target' for the same reason.
        ...(it.linkTarget ? { linkTarget: it.linkTarget } : {}),
        // SFTP reports whole seconds, so the milliseconds are always .000 and only
        // make the column wider. A server can report a time no Date can represent
        // (or something that is not a number): toISOString() then throws "Invalid
        // time value" and the whole listing fails with no path and no filename.
        mtime: isoSeconds(attrs.mtime),
      }
    })
}
/**
 * The ISO stamp for a whole-second epoch, or null when it cannot be one.
 *
 * new Date(1e20 * 1000).toISOString() throws RangeError, so one unusable
 * timestamp took down the entire listing.
 *
 * @param {unknown} seconds
 * @returns {string|null}
 */
function isoSeconds(seconds) {
  const n = Number(seconds)
  if (!Number.isFinite(n) || n <= 0) return null
  const at = new Date(n * 1000)
  if (Number.isNaN(at.getTime())) return null
  return at.toISOString().replace(/\.\d{3}Z$/, 'Z')
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
      sftp.readdir(target, async (err, items) => {
        if (err) {
          // readdir on a regular file fails with the server's ENOENT text,
          // which reads as "the path does not exist" for a path that does.
          return kindMismatch(sftp, target, 'dir').then(
            (better) => settle(null, better || remoteError(err, target, 'list')),
            () => settle(null, remoteError(err, target, 'list')),
          )
        }
        // One readlink per link row, capped: a directory of 10,000 links must not
        // turn a listing into 10,000 round trips.
        try {
          const rows = listingEntries(items)
          const links = rows.filter((row) => row.type === 'l').slice(0, LINK_TARGET_LIMIT)
          if (links.length > 0 && typeof sftp.readlink === 'function') {
            await Promise.all(links.map(async (row) => {
              try {
                const raw = String(await new Promise((resolve, reject) => sftp.readlink(posix.join(target, row.name), (err, value) => (err ? reject(err) : resolve(value)))))
                row.linkTarget = raw
              } catch { /* a link that vanished keeps its row without a target */ }
            }))
          }
          // 'ls /link' prints the link; readdir follows it and lists the target's
        // contents. Saying which directory the rows came from keeps the header from
        // implying that a link to /etc is a directory of its own.
        let viaLink = null
        try {
          if (typeof sftp.lstat === 'function' && typeof sftp.readlink === 'function') {
            const attrs = await callSftp(sftp, 'lstat', target)
            if (attrs && typeof attrs.isSymbolicLink === 'function' && attrs.isSymbolicLink()) {
              const raw = String(await callSftp(sftp, 'readlink', target))
              const firstHop = posix.normalize(raw.startsWith('/')
                ? raw
                : posix.join(posix.dirname(target), raw))
              viaLink = { path: target, target: (await followLinkChain(sftp, target, firstHop)) || firstHop }
            }
          }
        } catch { /* the link may be gone; the rows are still the answer */ }
        settle({ path: target, items: rows, viaLink })
        } catch (err) {
          // An async callback that rejects would leave the promise hanging: the
          // caller then waits for the listing timeout instead of hearing the reason.
          settle(null, remoteError(err, target, 'list'))
        }
      })
    } catch (err) {
      settle(null, new Error(printableText(redact(err && err.message ? err.message : String(err)))))
    }
  })
}