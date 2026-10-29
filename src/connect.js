// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe — one place that turns a resolved credential into ssh2 options.
//
// This exists because the mapping was written twice: once in the pool and once
// in the settings page's test button. Both named credential kinds explicitly,
// and the pool's copy silently dropped the kinds that came from the settings
// form and the credential file, so a stored password connected with no
// authentication at all. The page kept working, which is exactly what a second
// copy buys you: one path correct and one path wrong, and no test able to tell.
//
// Keying on the resolved VALUE rather than on the kind means a new source
// becomes usable here the moment credentialFor() learns to produce it.

import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'

/** Expand a leading ~ so key paths written by hand work. */
export function expandHome(p) {
  const s = String(p || '')
  if (!s.startsWith('~')) return s
  return s.replace(/^~(?=[/\\]|$)/, homedir())
}

/**
 * Build the ssh2 options for one machine and one resolved credential.
 *
 * @param {{host: string, port?: number, username: string}} machine
 * @param {{password?: string, keyPath?: string, passphrase?: string, agent?: string}} auth
 * @param {{readyTimeout?: number, keepaliveInterval?: number, keepaliveCountMax?: number}} [timing]
 * @returns {Record<string, unknown>}
 */
export function connectOptions(machine, auth, timing = {}) {
  /** @type {Record<string, unknown>} */
  const options = {
    host: machine.host,
    port: machine.port || 22,
    username: machine.username,
    readyTimeout: timing.readyTimeout ?? 15000,
    keepaliveInterval: timing.keepaliveInterval ?? 20000,
    keepaliveCountMax: timing.keepaliveCountMax ?? 3,
  }

  if (auth.keyPath) {
    options.privateKey = readFileSync(expandHome(auth.keyPath))
    if (auth.passphrase) options.passphrase = auth.passphrase
  } else if (auth.password) {
    options.password = auth.password
  } else if (auth.agent) {
    // The agent holds the key; ssh2 asks it to sign and we never see it.
    options.agent = auth.agent
  }

  return options
}
