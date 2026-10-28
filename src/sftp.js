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
 * Read a remote file as UTF-8, capped at `maxBytes`.
 *
 * Bytes are collected before decoding so a multi-byte character split across
 * chunk boundaries is not corrupted.
 *
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
        try { stream.removeAllListeners('data'); stream.removeAllListeners('error') } catch {}
        try { stream.destroy() } catch {}
      }
      if (error) reject(error)
      else resolve(result)
    }

    timer = setTimeout(() => {
      settle(null, new Error('reading ' + target + ' did not complete within ' + timeoutMs + 'ms'))
    }, timeoutMs)

    try {
      stream = sftp.createReadStream(target)
    } catch (err) {
      return settle(null, new Error(redact(err && err.message ? err.message : String(err))))
    }

    const finish = () => settle({
      content: collector.toString(),
      truncated: collector.truncated,
      bytes: collector.bytes,
      path: target,
    })

    stream.on('data', (chunk) => {
      collector.push(chunk)
      if (collector.truncated) finish()
    })
    stream.on('error', (e) => settle(null, new Error(redact(e.message))))
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
 * @returns {Promise<{bytes: number, path: string}>}
 */
export async function writeRemoteFile(client, remotePath, content, { timeoutMs }) {
  const target = normalizeRemotePath(remotePath)
  const payload = Buffer.isBuffer(content) ? content : Buffer.from(String(content ?? ''), 'utf8')
  const sftp = await openSftp(client)

  return await new Promise((resolve, reject) => {
    let settled = false
    let timer = null
    let stream = null

    const settle = (result, error) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      if (stream && error) {
        try { stream.removeAllListeners('error'); stream.removeAllListeners('close'); stream.removeAllListeners('finish') } catch {}
        try { stream.destroy() } catch {}
      }
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
      return settle(null, new Error(redact(err && err.message ? err.message : String(err))))
    }

    const done = () => settle({ bytes: payload.length, path: target })
    stream.on('error', (e) => settle(null, new Error(redact(e.message))))
    stream.on('close', done)
    stream.on('finish', done)
    try { stream.end(payload) } catch (err) {
      settle(null, new Error(redact(err && err.message ? err.message : String(err))))
    }
  })
}

/**
 * List a remote directory.
 *
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
      reject(new Error(redact('listing ' + target + ' did not complete within ' + timeoutMs + 'ms')))
    }, timeoutMs)

    const settle = (result, error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error) reject(error)
      else resolve(result)
    }

    try {
      sftp.readdir(target, (err, items) => {
        if (err) return settle(null, new Error(redact(err.message)))
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
