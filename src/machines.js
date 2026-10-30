// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe -- machine definitions and credential resolution.
//
// Three places can define a machine, because they solve different problems:
//
//   config   the DSH settings form. Best for fields that rarely change: host,
//            port, user, key path, host-key policy.
//   file     <DSH_HOME>/dsh-ssh-safe/credentials.json, mode 0600. Read on every
//            connection and re-read when its mtime changes, so a rotated
//            password takes effect on the next command with no restart.
//   env      DSH_SSH_<ALIAS>_*. Best for CI and for keeping secrets off disk.
//
// Precedence, highest first: config, then file, then env. An empty value never
// wins, so a settings form left blank does not shadow an environment variable.
//
// SECURITY: nothing here writes a secret anywhere, and every shape it returns is
// safe to print. Use credentialState() for diagnostics -- it reports which
// source is in play without revealing the value.

import { readFileSync } from 'node:fs'
import path from 'node:path'
import { agentSocket, machineFromEnv } from './credentials.js'
import { decryptDpapi } from './dpapi.js'

/** Where the hot-reloadable credential file lives. */
export function credentialsPath(dshHome) {
  return path.join(dshHome, 'dsh-ssh-safe', 'credentials.json')
}

/** The file's expected shape, shown in error messages and in the docs. */
export function credentialsTemplate() {
  return [
    '{',
    '  "gpu": { "password": "..." },',
    '  "prod": { "keyPath": "~/.ssh/id_ed25519", "keyPassphrase": "..." }',
    '}',
  ].join('\n')
}

/**
 * Read the credential file.
 *
 * Never throws: a missing, unreadable or malformed file means "no file", and the
 * other sources still work.
 *
 * @param {string} dshHome
 * @returns {Record<string, object>} alias -> entry
 */
export function loadCredentialFile(dshHome) {
  // '' means the file is disabled (useCredentialFile: false). Joining it would
  // read 'dsh-ssh-safe/credentials.json' relative to the process working
  // directory -- a file the plugin was told to ignore, in a place nobody chose.
  if (!dshHome) return {}
  const file = credentialsPath(dshHome)
  let text
  try {
    // Read on every call. An mtime cache was tried and could miss a rotation
    // that landed in the same millisecond, which is exactly the "change the
    // password and retry" case this file exists for. The file is a few hundred
    // bytes; the read costs nothing next to the TCP handshake.
    text = readFileSync(file, 'utf8')
  } catch {
    return {}
  }
  try {
    const parsed = JSON.parse(text)
    const data = {}
    // A JSON array is an object to typeof, and its indices became machines:
    // '[{"host":...}]' produced a machine named "0" that looked connectable.
    // The file is a map from alias to entry; anything else is not this format.
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      for (const [alias, entry] of Object.entries(parsed)) {
        if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
          data[String(alias).toLowerCase()] = entry
        }
      }
    }
    return data
  } catch {
    // A truncated file or a stray comma must not break every connection.
    return {}
  }
}

/**
 * Read an own property and nothing from the prototype chain.
 *
 * 'machines.constructor' and 'credentials.__proto__' are not machines: a plain
 * [] lookup returns Object.prototype for the former and runs the prototype
 * setter for the latter, so an alias that collides with them would read
 * invented fields instead of "not configured".
 *
 * @param {unknown} object
 * @param {string} key
 * @returns {Record<string, any>}
 */
function ownEntry(object, key) {
  if (!object || typeof object !== 'object') return {}
  const direct = String(key)
  const has = (name) => Object.hasOwn(object, name)
  // Settings-form keys are typed by hand and keep their case ('Prod',
  // 'mixedCase'). The alias is lower-cased before it reaches this lookup, so a
  // case-sensitive read made such a machine "not configured" while ssh_machines
  // still listed it with no host at all.
  let name = direct
  if (!has(name)) {
    const wanted = direct.toLowerCase()
    const match = Object.keys(object).find((candidate) => candidate.toLowerCase() === wanted)
    if (match === undefined) return {}
    name = match
  }
  const value = /** @type {Record<string, any>} */ (object)[name]
  return value && typeof value === 'object' ? value : {}
}

/** True when a value counts as present. 0 and false do. */
function filled(value) {
  return value !== undefined && value !== null && value !== ''
}

/**
 * First source that actually has a value.
 * @param {Array<[string, unknown]>} candidates
 * @returns {{value: unknown, source: string}}
 */
function firstSet(candidates) {
  for (const [source, value] of candidates) {
    if (filled(value)) return { value, source }
  }
  return { value: '', source: 'none' }
}

/**
 * Merge the three sources into one machine definition.
 *
 * @param {string} alias
 * @param {{machines?: Record<string, object>, dshHome?: string}} [options]
 */
export function machineDefinition(alias, { machines = {}, dshHome = '' } = {}) {
  const env = machineFromEnv(alias)
  // Own properties only. 'machines.constructor' and 'credentials.__proto__' are
  // not machines: a plain [] lookup returns Object.prototype for the former and
  // the prototype setter for the latter, so an alias that collides with them
  // would read invented fields instead of "not configured".
  const cfg = ownEntry(machines, alias)
  const file = ownEntry(loadCredentialFile(dshHome), alias)

  const host = firstSet([['config', cfg.host], ['env', env.host], ['file', file.host]])
  const user = firstSet([
    ['config', cfg.user], ['env', env.username], ['file', file.user], ['file', file.username],
  ])
  const keyPath = firstSet([['config', cfg.keyPath], ['env', env.keyPath], ['file', file.keyPath]])
  const keyPassphrase = firstSet([
    ['config', cfg.keyPassphrase], ['env', env.keyPassphrase], ['file', file.keyPassphrase],
  ])
  const policy = firstSet([
    ['config', cfg.hostKeyPolicy], ['env', env.hostKeyPolicy], ['file', file.hostKeyPolicy],
  ])
  const knownHosts = firstSet([
    ['config', cfg.knownHosts], ['env', env.knownHosts], ['file', file.knownHosts],
  ])
  // A password is resolved by credentialFor(), because the value may need
  // decrypting and plaintext may be refused. Here we only record the source.
  const passwordSource = filled(cfg.password)
    ? 'config'
    : filled(file.passwordDpapi)
      ? 'file-dpapi'
      : filled(file.password)
        ? 'file-plaintext'
        : filled(env.password)
          ? 'env'
          : 'none'

  // 22 is the default, so an explicit 22 is indistinguishable from "not set".
  // The port simply stays 22, which is the same outcome.
  const port = firstSet([
    ['config', cfg.port], ['file', file.port], ['env', env.port !== 22 ? env.port : ''],
  ])
  // Only the settings form is schema-validated. The credential file is raw JSON
  // and the environment is a string, so port 99999 or -1 reached net.connect and
  // came back as "Port should be >= 0 and < 65536. Received type number (99999)"
  // with no machine, no source and nothing to fix. Keep the value, report it.
  const configured = filled(port.value)
  const portNumber = Number(port.value)
  const portValid = !configured ||
    (Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= 65535)
  const portProblem = portValid ? '' :
    'port ' + JSON.stringify(port.value) + ' from the ' + port.source +
    ' is not an integer between 1 and 65535'

  return {
    alias,
    // Whitespace is never part of a host, a user name or a path: every write
    // path (page, set-password) trims these, so a value with spaces came from a
    // hand-edited file or a pasted environment variable. Trimming here keeps the
    // value that is used identical to the value that is displayed.
    host: String(host.value || '').trim(),
    // Number('') is 0, which is not "unset": an unset port must stay 22.
    port: configured && portValid && Number.isInteger(portNumber) ? portNumber : 22,
    /** The value as configured, so a listing can show what is actually there. */
    portRaw: filled(port.value) ? port.value : '',
    portProblem,
    username: String(user.value || '').trim(),
    // Never carries plaintext: a DPAPI entry has to be decrypted on demand.
    password: '',
    keyPath: String(keyPath.value || '').trim(),
    keyPassphrase: String(keyPassphrase.value || ''),
    // Empty means "inherit the global policy". A previous version defaulted to
    // 'strict' here, which made the global setting unreachable.
    hostKeyPolicy: String(policy.value || ''),
    knownHosts: String(knownHosts.value || ''),
    /** Env var names that were found, for diagnostics. Never values. */
    present: env.present,
    /** Which source supplied each field. Never contains a value. */
    sources: {
      host: host.source,
      port: port.source,
      user: user.source,
      password: passwordSource,
      keyPath: keyPath.source,
      keyPassphrase: keyPassphrase.source,
      hostKeyPolicy: policy.source,
      knownHosts: knownHosts.source,
    },
  }
}

/**
 * Assemble the auth object for ssh2.
 *
 * Order: an encrypted file secret, then a plaintext one the caller allowed, then
 * the environment, then a session password, then the agent.
 *
 * A plaintext password is REFUSED by default. Storing one defeats the point of
 * this plugin: it is readable by anything that can read the file, and travels
 * with the file into backups and screenshots. The refusal is a warning plus a
 * fallthrough rather than a hard error, so a machine that also has a usable key
 * keeps working.
 *
 * @param {string} alias
 * @param {{machines?: Record<string, object>, dshHome?: string, sessionPassword?: string,
 *   allowSessionPassword?: boolean, useAgent?: boolean, allowPlaintextPassword?: boolean}} [options]
 */
export function credentialFor(alias, {
  machines = {},
  dshHome = '',
  sessionPassword,
  allowSessionPassword,
  useAgent,
  allowPlaintextPassword = false,
} = {}) {
  const m = machineDefinition(alias, { machines, dshHome })
  const cfg = ownEntry(machines, alias)
  const env = machineFromEnv(alias)
  const file = dshHome ? ownEntry(loadCredentialFile(dshHome), alias) : {}
  /** @type {string[]} */
  const warnings = []

  // A session password is the LAST resort: the settings form, the credential
  // file and the environment all win. Supplying one while a stored credential
  // exists therefore has no effect, which reads as "my new password worked"
  // when it was never tried. Say so instead of letting the caller believe it.
  const sessionOffered = allowSessionPassword === true && filled(sessionPassword)
  const warnShadowedSession = () => {
    if (!sessionOffered) return
    warnings.push(
      'a session password was supplied, but a stored credential was used instead ' +
      '(session passwords are the last resort). Update or remove the stored credential ' +
      'to use the one supplied with this call.'
    )
  }

  // 1. settings form (plaintext in the DSH config file)
  if (filled(cfg.password)) {
    if (allowPlaintextPassword) {
      warnShadowedSession()
      return { kind: 'config-password', password: String(cfg.password), machine: m, warnings }
    }
    warnings.push(
      'the settings form holds a plaintext password; it was ignored. ' +
      'Use the credential file (DPAPI encrypted) or an environment variable.'
    )
  }

  // 2. encrypted secret in the credential file
  if (filled(file.passwordDpapi)) {
    try {
      warnShadowedSession()
      return { kind: 'file-dpapi', password: decryptDpapi(file.passwordDpapi), machine: m, warnings }
    } catch (err) {
      // A blob written by another Windows account, or a corrupted one, cannot be
      // opened here. Fall through rather than failing to a dead end.
      warnings.push(
        'the stored password could not be decrypted (' +
        String(err && err.message ? err.message : err).slice(0, 120) +
        '). Re-run scripts/set-password.mjs on this machine and account.'
      )
    }
  }

  // 3. plaintext secret in the credential file
  if (filled(file.password)) {
    if (allowPlaintextPassword) {
      warnShadowedSession()
      return { kind: 'file-password', password: String(file.password), machine: m, warnings }
    }
    warnings.push(
      'credentials.json holds a plaintext password; it was ignored. ' +
      'Re-run scripts/set-password.mjs, which stores it DPAPI encrypted.'
    )
  }

  // 4. environment: memory only, nothing written
  if (filled(env.password)) {
    warnShadowedSession()
    return { kind: 'env-password', password: env.password, machine: m, warnings }
  }

  // 5. key file
  if (m.keyPath) {
    warnShadowedSession()
    return {
      kind: m.sources.keyPath + '-key',
      keyPath: m.keyPath,
      passphrase: m.keyPassphrase,
      machine: m,
      warnings,
    }
  }

  // 6. a password passed for this call only
  if (allowSessionPassword && typeof sessionPassword === 'string' && sessionPassword.length > 0) {
    return { kind: 'session-password', password: sessionPassword, machine: m, warnings }
  }

  // 7. agent: no secret reaches this plugin at all
  if (useAgent !== false) {
    const sock = agentSocket()
    if (sock) return { kind: 'agent', agent: sock, machine: m, warnings }
  }

  return { kind: 'none', machine: m, warnings }
}

/**
 * Diagnostic view of a machine's credentials. Safe to print: it reports which
 * source is in play and never the value.
 *
 * @param {string} alias
 * @param {{machines?: Record<string, object>, dshHome?: string}} [options]
 */
export function credentialState(alias, { machines = {}, dshHome = '' } = {}) {
  const m = machineDefinition(alias, { machines, dshHome })
  return {
    alias,
    host: m.host,
    port: m.port,
    username: m.username,
    passwordSource: m.sources.password,
    keyPathSource: m.sources.keyPath,
    keyPath: m.keyPath,
    hostKeyPolicy: m.hostKeyPolicy || '(global)',
    configured: Boolean(m.host && m.username),
    sources: m.sources,
  }
}

/** All aliases any source knows about, sorted. */
export function knownAliases({ machines = {}, dshHome = '', env = process.env } = {}) {
  const set = new Set()
  for (const key of Object.keys(machines || {})) set.add(String(key).toLowerCase())
  for (const key of Object.keys(loadCredentialFile(dshHome) || {})) set.add(String(key).toLowerCase())
  for (const key of Object.keys(env || {})) {
    const match = /^DSH_SSH_(.+)_HOST$/.exec(key)
    if (match && env[key]) set.add(match[1].toLowerCase())
  }
  set.delete('')
  return [...set].sort()
}
