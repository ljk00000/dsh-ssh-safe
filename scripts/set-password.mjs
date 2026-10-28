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
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
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
const alias = String(args.alias || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '')
if (!alias) {
  console.error('Usage: node scripts/set-password.mjs --alias <name> [--host h] [--port p] [--user u]')
  console.error('                                              [--key-path p] [--key-passphrase]')
  process.exit(2)
}

const dshHome = String(args['dsh-home'] || process.env.DSH_HOME || path.join(homedir(), '.dsh'))
const dir = path.join(dshHome, 'dsh-ssh-safe')
const file = path.join(dir, 'credentials.json')

// Read-modify-write so other machines survive.
let store = {}
if (existsSync(file)) {
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8'))
    if (parsed && typeof parsed === 'object') store = parsed
  } catch (err) {
    console.warn('Existing credentials.json could not be parsed and will be replaced: ' + err.message)
  }
}

const entry = { ...(store[alias] && typeof store[alias] === 'object' ? store[alias] : {}) }
if (args.host) entry.host = String(args.host)
if (args.port) entry.port = Number(args.port)
if (args.user) entry.user = String(args.user)
if (args['key-path']) entry.keyPath = String(args['key-path'])

// --key-passphrase with no value means "prompt for it".
if (typeof args['key-passphrase'] === 'string') {
  entry.keyPassphrase = args['key-passphrase']
} else if (args['key-passphrase'] === true) {
  entry.keyPassphrase = await readSecret('Key passphrase for "' + alias + '" (input hidden): ')
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
mkdirSync(dir, { recursive: true })
writeFileSync(file, JSON.stringify(store, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 })

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
for (const key of ['host', 'port', 'user', 'keyPath', 'keyPassphrase', 'passwordDpapi', 'password']) {
  if (entry[key] === undefined) continue
  const shown = key === 'password' || key === 'keyPassphrase'
    ? '<set, NOT encrypted -- avoid>'
    : key === 'passwordDpapi'
      ? '<encrypted with DPAPI, ' + String(entry[key]).length + ' chars>'
      : entry[key]
  console.log('  ' + key.padEnd(14) + shown)
}
console.log('')
console.log('File: ' + file)
console.log('The plugin re-reads it on every connection; no restart needed.')
console.log('Check with: ssh_credentials')
