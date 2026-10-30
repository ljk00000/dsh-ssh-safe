// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe -- at-rest protection for passwords.
//
// A password has to live somewhere between connections. The options are:
//
//   plaintext in a file   readable by anything that can read the file, and by
//                         anything that copies it: backups, sync folders,
//                         a screenshot, a zip sent to a colleague.
//   Windows DPAPI         ciphertext, tied to the Windows account that wrote it.
//                         Another user on the same machine, or the same file on
//                         another machine, decrypts to nothing.
//   memory only           nothing on disk at all; lost when the process exits.
//
// This module implements the middle option, and the plugin keeps the last one
// available through environment variables.
//
// How it works: DPAPI is reached through PowerShell's ConvertFrom-SecureString,
// which is DPAPI-backed, so no native module is needed. The secret travels over
// stdin, never on a command line, and the plaintext only ever exists in this
// process's memory.

import { spawnSync } from 'node:child_process'

/** PowerShell's DPAPI round trip is available on Windows only. */
export function dpapiAvailable() {
  return process.platform === 'win32'
}

// The interpreter that ships with Windows. pwsh is preferred when present, but
// powershell.exe is the one that is always there.
function shell() {
  const probe = spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', 'exit 0'], {
    encoding: 'utf8',
    timeout: 10000,
  })
  return probe.status === 0 ? 'pwsh' : 'powershell.exe'
}

let cachedShell = ''

function runShell(args, input, timeoutMs) {
  if (!cachedShell) cachedShell = shell()
  const result = spawnSync(cachedShell, ['-NoProfile', '-NonInteractive', '-Command', args], {
    input,
    encoding: 'utf8',
    timeout: timeoutMs,
    windowsHide: true,
  })
  if (result.error) throw new Error('could not run ' + cachedShell + ': ' + result.error.message)
  if (result.status !== 0) {
    throw new Error((cachedShell + ' failed: ' + String(result.stderr || '').trim()).slice(0, 300))
  }
  return String(result.stdout || '')
}

/**
 * Encrypt a password for the current Windows user.
 *
 * @param {string} plain
 * @returns {string} DPAPI ciphertext, hex encoded
 */
export function encryptDpapi(plain) {
  if (!dpapiAvailable()) throw new Error('DPAPI is available on Windows only')
  const text = String(plain ?? '')
  if (!text) throw new Error('nothing to encrypt')
  // The secret arrives on stdin so it never appears in a process command line,
  // where any local user could read it from the process table.
  const out = runShell(
    '$s = [Console]::In.ReadToEnd(); ' +
    '$sec = ConvertTo-SecureString -String $s -AsPlainText -Force; ' +
    'ConvertFrom-SecureString -SecureString $sec',
    text,
    20000
  )
  const hex = out.trim()
  if (!/^[0-9a-f]{40,}$/i.test(hex)) throw new Error('unexpected DPAPI output')
  return hex
}

// Decrypted values are kept in memory, keyed by ciphertext, so repeated
// connections do not pay for a PowerShell start each time. A rotated password
// produces different ciphertext, so the old entry is simply never hit again.
const memory = new Map()

/**
 * Decrypt DPAPI ciphertext written by encryptDpapi, on the same account.
 *
 * @param {string} cipher hex ciphertext
 * @returns {string} the password
 */
export function decryptDpapi(cipher) {
  if (!dpapiAvailable()) throw new Error('DPAPI is available only on Windows')
  const key = String(cipher ?? '').trim()
  if (!key) throw new Error('no ciphertext')
  if (memory.has(key)) return memory.get(key)
  const out = runShell(
    '$hex = [Console]::In.ReadToEnd().Trim(); ' +
    '$sec = ConvertTo-SecureString -String $hex; ' +
    '$b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec); ' +
    'try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } ' +
    'finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }',
    key,
    20000
  )
  // The shell adds a trailing newline; the password itself may contain spaces
  // but not a trailing newline, because it arrived the same way.
  const plain = out.replace(/\r?\n$/, '')
  if (!plain) throw new Error('DPAPI decryption produced nothing')
  memory.set(key, plain)
  return plain
}

/** Forget cached plaintext. Used by tests. */
export function forgetDecrypted() {
  memory.clear()
}
