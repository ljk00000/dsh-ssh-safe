#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// dsh-ssh-safe -- store an SSH password without it landing in a transcript.
//
// Why this exists: putting a password in the settings form writes it to the DSH
// config file in plain text, and passing one to a tool puts it in the
// conversation. Neither is what you want for a value that rotates.
//
// The credential file is read fresh on every connection, so a rotation takes
// effect on the next command with no restart.
//
// Usage:
//   node scripts/set-password.mjs --alias gpu
//   node scripts/set-password.mjs --alias gpu --host gpu.example.com --port 2222 --user root
//   node scripts/set-password.mjs --alias prod --key-path ~/.ssh/id_ed25519 --key-passphrase
//
// The password is stored Windows-DPAPI encrypted: the file holds ciphertext that
// only this Windows account can open. --plaintext writes it readable, which is
// refused by the plugin unless allowPlaintextPassword is set.
//
// --password exists for automation. On a terminal, omit it: the prompt does not
// echo, and the value stays out of your shell history.

import { spawnSync } from 'node:child_process'
import { encryptDpapi, dpapiAvailable } from '../src/dpapi.js'
import { chmodSync, existsSync, statSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { acquireStoreLock } from './lib/store-lock.mjs'
import { homedir } from 'node:os'
import path from 'node:path'
import process from 'node:process'

function parseArgs(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]
    if (!token.startsWith('--')) continue
    const key = token.slice(2)
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) {
      out[key] = true
    } else {
      out[key] = next
      i++
    }
  }
  return out
}

/** Read a line without echoing it. Falls back to a normal read when not a TTY. */
function readSecret(question) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin
    if (!stdin.isTTY) {
      let data = ''
      stdin.setEncoding('utf8')
      stdin.on('data', (chunk) => { data += chunk })
      stdin.on('end', () => resolve(data.split(/\r?\n/)[0] || ''))
      stdin.on('error', reject)
      return
    }
    process.stdout.write(question)
    stdin.setRawMode(true)
    stdin.resume()
    stdin.setEncoding('utf8')
    let value = ''
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode(false)
          stdin.pause()
          stdin.removeListener('data', onData)
          process.stdout.write('\n')
          resolve(value)
          return
        }
        if (ch === '\u0003') {
          stdin.setRawMode(false)
          process.stdout.write('\n')
          process.exit(130)
        }
        if (ch === '\u007f' || ch === '\b') {
          value = value.slice(0, -1)
          continue
        }
        // Do not echo: the whole point of this prompt.
        value += ch
      }
    }
    stdin.on('data', onData)
  })
}

const args = parseArgs(process.argv.slice(2))

// Same rule as the GUI and the tools, enforced the same way: refuse an alias
// that contains anything else. Stripping used to store the password under a
// different name than the one 'ssh_exec --machine prod/x' looks up, so it was
// written and then never found -- and the user was told it had been stored.
// Keep this in step with every option the body reads (grep for "args[" / "args.").
const KNOWN_OPTIONS = ['alias', 'host', 'port', 'user', 'key-path', 'key-passphrase', 'password',
  'plaintext', 'clear-password', 'clear-key-passphrase', 'dsh-home', 'help']
for (const key of Object.keys(args)) {
  if (!KNOWN_OPTIONS.includes(key)) {
    console.error('Unknown option --' + key + '. Accepted: ' + KNOWN_OPTIONS.map((o) => '--' + o).join(', '))
    process.exit(2)
  }
}
const rawAlias = String(args.alias || '').trim().toLowerCase()
const alias = rawAlias
if (rawAlias && !/^[a-z0-9._-]+$/.test(rawAlias)) {
  console.error('Alias "' + String(args.alias) + '" contains characters an alias cannot have.')
  console.error('Use a-z, 0-9, dot, underscore or hyphen -- the name is not rewritten for you,')
  console.error('because the password would then be stored under a name nothing looks up.')
  process.exit(2)
}
// Names that collide with Object.prototype. stderr used to say 'Stored for
// "__proto__"' and exit 0 while writing nothing at all: store["__proto__"] =
// entry sets the prototype instead of a key, so JSON.stringify dropped it. The
// page has refused these three names for a while; the CLI now agrees.
const reserved = ['__proto__', 'prototype', 'constructor']
if (reserved.includes(alias)) {
  console.error('Alias "' + alias + '" collides with a built-in JavaScript property, so it cannot be stored.')
  console.error('Pick another name -- nothing was written and the file is unchanged.')
  process.exit(2)
}
if (!alias) {
  console.error('Usage: node scripts/set-password.mjs --alias <name> [--host h] [--port p] [--user u]')
  console.error('                                              [--key-path p] [--key-passphrase]')
  console.error('                                              [--password p] [--plaintext] [--clear-password]')
  console.error('                                              [--clear-key-passphrase]')
  process.exit(2)
}

// Pure argument checks run before anything touches the filesystem: a refused
// command used to leave an empty dsh-ssh-safe directory behind, because the
// read-modify-write section (and the mkdir it needs) came first.
if (args.port !== undefined) {
  const port = Number(args.port)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error('--port must be an integer between 1 and 65535 (received ' + JSON.stringify(args.port) + ')')
    process.exit(2)
  }
}
if (args['clear-password'] === true && args.password !== undefined) {
  console.error('--clear-password removes the stored password, so it cannot be combined with --password.')
  console.error('Run the clear on its own, then store the new password with a second command.')
  process.exit(2)
}
if (args['clear-password'] === true && args.plaintext !== undefined) {
  console.error('--plaintext only applies when storing a password; drop it when clearing.')
  process.exit(2)
}
if (args['clear-key-passphrase'] === true && args['key-passphrase'] !== undefined) {
  console.error('--clear-key-passphrase removes the stored passphrase, so it cannot be combined with --key-passphrase.')
  console.error("Run the clear on its own, then store the new passphrase with a second command.")
  process.exit(2)
}
if (args['clear-key-passphrase'] === true && args.plaintext !== undefined) {
  console.error('--plaintext only applies when storing a secret; drop it when clearing.')
  process.exit(2)
}

/**
 * Rename over the credential file, retrying while Windows says it is busy.
 *
 * The plugin may hold the file open while reading it, and Windows refuses a rename
 * over a file another handle has open (EPERM) -- the settings page learned this the
 * hard way and retries the same way.
 */
function renameWithRetry(from, to) {
  const retryable = new Set(['EPERM', 'EBUSY', 'EACCES'])
  let last = null
  for (let attempt = 1; attempt <= 6; attempt++) {
    try {
      renameSync(from, to)
      return
    } catch (err) {
      last = err
      if (!retryable.has(String(err && err.code))) throw err
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 15 * attempt)
    }
  }
  throw new Error('could not replace ' + to + ' after 6 attempts (' + String(last && last.code) + ')')
}

/**
 * Write the store, or explain why nothing was written and exit 2.
 *
 * Three commands write this file (store, clear password, clear passphrase) and
 * the failure text has to be the same three times: one implementation, so the
 * wording cannot drift between them.
 *
 * @param {Record<string, any>} next the whole store to persist
 */
function persist(next) {
  try {
    mkdirSync(dir, { recursive: true })
    // Write beside the file and rename over it. An in-place write truncates
    // first, so the plugin -- which re-reads this file on every connection, from
    // another process -- could read an empty file and answer "no credentials"
    // while this command reported success. Measured: one read in 185k landed in
    // that window before this change.
    const tmp = file + '.tmp-' + process.pid
    writeFileSync(tmp, JSON.stringify(next, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 })
    try {
      renameWithRetry(tmp, file)
    } catch (err) {
      try { rmSync(tmp, { force: true }) } catch { /* nothing left to do */ }
      throw err
    }
  } catch (err) {
    const code = err && err.code
    if ((code === 'EEXIST' || code === 'ENOTDIR') && existsSync(dir) && statSync(dir).isFile()) {
      console.error('Cannot write ' + file + ': ' + dir + ' is a file, not a directory.')
      console.error('Remove or rename that file, then run this again. Nothing was written.')
    } else {
      console.error('Cannot write ' + file + ' (' + (code || (err && err.message) || 'unknown error') + ').')
      console.error('Nothing was written. Fix the path or its permissions, then run this again.')
    }
    process.exit(2)
  }
}

const dshHome = String(args['dsh-home'] || process.env.DSH_HOME || path.join(homedir(), '.dsh'))
const dir = path.join(dshHome, 'dsh-ssh-safe')
const file = path.join(dir, 'credentials.json')

// Read-modify-write across processes: the page may be saving another machine at
// the same moment, and whichever wrote last used to win silently (measured 2 lost
// saves in 40 concurrent trials). The lock is released on every exit path by the
// hook below; a process killed outright leaves it behind only until it goes stale.
try {
  mkdirSync(dir, { recursive: true })
} catch { /* persist() reports the real error when it writes */ }
let lock = { release() { /* nothing was taken */ }, timedOut: false }
try {
  lock = acquireStoreLock(file)
  process.on('exit', () => lock.release())
} catch {
  // An unusable directory must reach persist(), which names the reason. Failing
  // here with a raw ENOENT from the lock file would hide that message.
}
if (lock.timedOut) {
  console.error('WARNING: another process held the credential-file lock for several seconds;')
  console.error('this run continued without it, so a save it made at the same moment may be lost.')
}

// Read-modify-write so other machines survive.
//
// A file that cannot be read is NOT replaced. It used to warn and overwrite, which
// threw away every other machine's entry in a store whose whole point is holding
// them -- and a truncated or BOM-prefixed file is usually repairable. The GUI was
// fixed to refuse for the same reason; this follows it.
let store = {}
if (existsSync(file)) {
  let text
  try {
    text = readFileSync(file, 'utf8')
  } catch (err) {
    console.error('Existing credentials.json could not be read, so nothing was written:')
    console.error('  ' + file)
    console.error('  ' + (err && err.message ? err.message : String(err)))
    process.exit(2)
  }
  let parsed
  try {
    // Notepad saves 'UTF-8 with BOM', and JSON.parse rejects it: the store then
    // read as corrupt when it had only been opened and saved.
    parsed = JSON.parse(text.replace(/^\uFEFF/, ''))
  } catch (err) {
    console.error('Existing credentials.json could not be parsed, so nothing was written:')
    console.error('  ' + file)
    console.error('  ' + String(err && err.message ? err.message : err).slice(0, 160))
    console.error('The other machines are still in that file: repair it, or move it aside, then run this again.')
    process.exit(2)
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    // '[{...}]' was accepted as an object, then store[alias] = entry added a
    // property JSON.stringify drops from an array: the file stayed '[]' while
    // this script printed 'Stored for ...'.
    console.error('Existing credentials.json is not an object of machines (it holds ' +
      (Array.isArray(parsed) ? 'an array' : JSON.stringify(parsed === null ? null : typeof parsed)) +
      '), so nothing was written:')
    console.error('  ' + file)
    console.error('Fix or move that file aside, then run this again.')
    process.exit(2)
  }
  store = parsed
}

const entry = { ...(store[alias] && typeof store[alias] === 'object' ? store[alias] : {}) }
// '--host "   "' stored an empty string: not wrong, but it printed "host" with
// nothing after it and looked like a setting had been saved.
if (args.host && String(args.host).trim()) entry.host = String(args.host).trim()
// Already validated above, before anything touched the filesystem.
if (args.port !== undefined) entry.port = Number(args.port)
if (args.user && String(args.user).trim()) entry.user = String(args.user).trim()
if (args['key-path'] && String(args['key-path']).trim()) entry.keyPath = String(args['key-path']).trim()

// --key-passphrase with no value means "prompt for it".
const passphraseInput = typeof args['key-passphrase'] === 'string'
  ? args['key-passphrase']
  : args['key-passphrase'] === true
    ? await readSecret('Key passphrase for "' + alias + '" (input hidden): ')
    : undefined
if (passphraseInput !== undefined) {
  // A passphrase protects a key the same way a password protects an account, and it
  // used to be written in plaintext while the password beside it was DPAPI
  // encrypted -- the file said "<set, NOT encrypted -- avoid>" and stored it anyway.
  if (args.plaintext === true || !dpapiAvailable()) {
    entry.keyPassphrase = passphraseInput
    delete entry.keyPassphraseDpapi
  } else {
    entry.keyPassphraseDpapi = encryptDpapi(passphraseInput)
    delete entry.keyPassphrase
  }
}

// Removing a stored password had no path at all: the page ignores an empty
// password (saving without one means "leave it alone"), and this script had no
// flag for it. The only way to revoke a DPAPI blob was to delete the machine or
// edit credentials.json by hand.
if (args['clear-password'] === true) {
  // Contradictory flags were rejected above, before the store was touched.
  const had = Boolean(entry.password || entry.passwordDpapi)
  delete entry.password
  delete entry.passwordDpapi
  if (!had) {
    console.error('No stored password for "' + alias + '" — nothing to clear.')
    console.error('Other fields in that entry were left untouched.')
    process.exit(2)
  }
  // An entry that held only the password is now empty: leaving "alias": {}
  // behind would show up as a machine with no host.
  if (Object.keys(entry).length === 0) delete store[alias]
  else store[alias] = entry
  persist(store)
  console.log('Cleared the stored password for "' + alias + '".')
  console.log('Set DSH_SSH_' + alias.toUpperCase() + '_PASSWORD, or store a key with --key-path, to' +
    ' authenticate this machine again.')
  process.exit(0)
}

// The password could be cleared and the passphrase could not: revoking a stored
// passphrase meant editing credentials.json by hand, and a rotated key left the
// old passphrase behind with nothing that said so.
if (args['clear-key-passphrase'] === true) {
  // Contradictory flags were rejected above, before the store was touched.
  const had = Boolean(entry.keyPassphrase || entry.keyPassphraseDpapi)
  delete entry.keyPassphrase
  delete entry.keyPassphraseDpapi
  if (!had) {
    console.error('No stored key passphrase for "' + alias + '" — nothing to clear.')
    console.error('Other fields in that entry were left untouched.')
    process.exit(2)
  }
  if (Object.keys(entry).length === 0) delete store[alias]
  else store[alias] = entry
  persist(store)
  console.log('Cleared the stored key passphrase for "' + alias + '".')
  console.log('If the key is still protected, the next connection will say so; store the new' +
    ' passphrase with --key-passphrase.')
  process.exit(0)
}

let secret = typeof args.password === 'string' ? args.password : undefined
if (secret === undefined && (args.password === true || args.password === undefined)) {
  const typed = await readSecret('Password for "' + alias + '" (input hidden): ')
  if (typed) secret = typed
}

if (secret) {
  if (args.plaintext === true) {
    // Kept for the rare case where something else must read the file. The plugin
    // refuses it by default; say so rather than leaving a surprise.
    entry.password = secret
    delete entry.passwordDpapi
    console.warn('')
    console.warn('WARNING: --plaintext stores the password in readable form.')
    console.warn('The plugin ignores it unless allowPlaintextPassword is true.')
  } else if (!dpapiAvailable()) {
    console.error('DPAPI encryption is available on Windows only.')
    console.error('Store nothing instead: set DSH_SSH_' + alias.toUpperCase() + '_PASSWORD in the environment')
    console.error('that launches DeepSeek Harness, which keeps the secret in memory.')
    process.exit(2)
  } else {
    entry.passwordDpapi = encryptDpapi(secret)
    delete entry.password
  }
}

if (Object.keys(entry).length === 0) {
  console.error('Nothing to store. Pass --password, or --key-path with --key-passphrase.')
  process.exit(2)
}

store[alias] = entry
// A file where the directory belongs used to crash with a raw stack trace:
// 'Error: EEXIST: file already exists, mkdir …' and nothing about what was
// written. Nothing is written in that case, and saying so is the whole message.
persist(store)

// On Windows an ACL is the equivalent of a file mode, and unlike chmod it is
// enforced there.
if (process.platform === 'win32') {
  const me = process.env.USERDOMAIN && process.env.USERNAME
    ? process.env.USERDOMAIN + '\\' + process.env.USERNAME
    : process.env.USERNAME
  const acl = spawnSync('icacls', [file, '/inheritance:r', '/grant:r', me + ':(R,W)', '/grant:r', 'SYSTEM:(R,W)'], { encoding: 'utf8' })
  if (acl.status !== 0) {
    console.warn('Could not tighten the ACL; check the file permissions yourself: ' + file)
  }
} else {
  try { chmodSync(file, 0o600) } catch { /* best effort */ }
}

console.log('')
console.log('Stored for "' + alias + '":')
for (const key of ['host', 'port', 'user', 'keyPath', 'keyPassphrase', 'keyPassphraseDpapi', 'passwordDpapi', 'password']) {
  if (entry[key] === undefined) continue
  const shown = key === 'password' || key === 'keyPassphrase'
    ? '<set, NOT encrypted -- avoid>'
    : key === 'passwordDpapi' || key === 'keyPassphraseDpapi'
      ? '<encrypted with DPAPI, ' + String(entry[key]).length + ' chars>'
      : entry[key]
  // keyPassphraseDpapi is 19 characters; padEnd(14) glued it to its value.
  console.log('  ' + key.padEnd(20) + shown)
}
console.log('')
console.log('File: ' + file)
console.log('The plugin re-reads it on every connection; no restart needed.')
console.log('Check with: ssh_credentials')
