// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Cross-process lock for the credential and host-key stores.
//
// The lock is a sibling file created with O_EXCL. Its existence is the lock;
// the JSON body only records the owner so a dead process can be reported. A
// stale lock (an old mtime, or a PID that no longer exists) is broken instead
// of waiting forever, but only after the normal acquisition window has failed.

import { closeSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'

const DEFAULT_WAIT_MS = 4000
const DEFAULT_POLL_MS = 25
const STALE_MS = 30_000

export class StoreLockTimeout extends Error {
  constructor(file) {
    super('Timed out waiting for the credential store lock: ' + file + '.lock')
    this.name = 'StoreLockTimeout'
    this.code = 'ESTORELOCK'
  }
}

function lockPath(file) {
  return String(file) + '.lock'
}

function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    // EPERM means the process exists but belongs to another user.
    return Boolean(err && err.code === 'EPERM')
  }
}

function isStale(file) {
  try {
    const stat = statSync(file)
    if (Date.now() - stat.mtimeMs > STALE_MS) return true
  } catch {
    return true
  }
  try {
    const body = JSON.parse(readFileSync(file, 'utf8'))
    return !pidAlive(Number(body && body.pid))
  } catch {
    // An unreadable lock body is not evidence that its owner is alive.
    return true
  }
}

function tryCreate(file) {
  const target = lockPath(file)
  try {
    mkdirSync(path.dirname(target), { recursive: true })
    const fd = openSync(target, 'wx', 0o600)
    try {
      writeFileSync(fd, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }) + '\n')
    } finally {
      closeSync(fd)
    }
    return true
  } catch (err) {
    if (err && err.code === 'EEXIST') return false
    throw err
  }
}

/**
 * Acquire the store lock. Returns { path, timedOut, release }.
 * A timed-out lock has a no-op release; it is never treated as held.
 */
export function acquireStoreLock(file, options = {}) {
  const waitMs = Number.isFinite(options.waitMs) ? Math.max(0, Number(options.waitMs)) : DEFAULT_WAIT_MS
  const pollMs = Number.isFinite(options.pollMs) ? Math.max(5, Number(options.pollMs)) : DEFAULT_POLL_MS
  const target = lockPath(file)
  const deadline = Date.now() + waitMs
  while (true) {
    if (tryCreate(file)) {
      let released = false
      return {
        path: target,
        timedOut: false,
        release() {
          if (released) return
          released = true
          try { rmSync(target, { force: true }) } catch { /* best effort */ }
        },
      }
    }
    if (existsSync(target) && isStale(target)) {
      try { rmSync(target, { force: true }) } catch { /* another process may have won */ }
      // Whether or not the removal worked, this pass must not bypass the deadline.
      // An unremovable stale lock — a non-empty directory at the lock path, or a file
      // another process keeps open on Windows — spun here forever: `continue` skipped
      // both the deadline check and the wait, so the caller hung at 100% CPU and even a
      // setTimeout guard in the same process could not run.
      if (Date.now() >= deadline) return { path: target, timedOut: true, release() {} }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, pollMs)
      continue
    }
    if (Date.now() >= deadline) {
      return { path: target, timedOut: true, release() {} }
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, pollMs)
  }
}

/**
 * Run fn while holding the lock, and always release it afterwards.
 *
 * An async fn keeps the lock until its promise settles. The finally-based version
 * released it as soon as fn() returned its promise, so a second writer could enter
 * while the first one was still awaiting — the lock looked held and was not.
 */
export function withStoreLock(file, fn, options = {}) {
  const lock = acquireStoreLock(file, options)
  if (lock.timedOut) throw new StoreLockTimeout(file)
  let result
  try {
    result = fn()
  } catch (err) {
    lock.release()
    throw err
  }
  if (result && typeof result.then === 'function') {
    return result.then(
      (value) => { lock.release(); return value },
      (err) => { lock.release(); throw err },
    )
  }
  lock.release()
  return result
}
