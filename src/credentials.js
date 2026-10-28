// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe — credential resolution.
//
// SECURITY CONTRACT (read before changing this file):
//   1. Passwords and key passphrases come from ENVIRONMENT VARIABLES by default.
//      They are read at call time and never written to disk, config, or logs.
//   2. A password supplied through a tool argument is accepted ONLY when the
//      profile sets allowSessionPassword: true. That value lives in memory for
//      the duration of the call and is never persisted.
//   3. Nothing here is ever included in an error message, a tool result, or a
//      system prompt. Every function returns a redacted shape instead.
//   4. This module performs no network I/O of its own.

/** Environment variable names, per machine alias. */
export function envNames(alias) {
  const A = String(alias || '').toUpperCase().replace(/[^A-Z0-9]/g, '_');
  return {
    host: `DSH_SSH_${A}_HOST`,
    port: `DSH_SSH_${A}_PORT`,
    user: `DSH_SSH_${A}_USER`,
    password: `DSH_SSH_${A}_PASSWORD`,
    keyPath: `DSH_SSH_${A}_KEY_PATH`,
    keyPassphrase: `DSH_SSH_${A}_KEY_PASSPHRASE`,
    hostKeyPolicy: `DSH_SSH_${A}_HOST_KEY_POLICY`,
    knownHosts: `DSH_SSH_${A}_KNOWN_HOSTS`,
  }
}

const readEnv = (name) => {
  const v = process.env[name]
  return typeof v === 'string' && v.length > 0 ? v : ''
}

/**
 * Resolve a machine definition from the environment.
 * Returns only the fields that are actually present; never throws.
 */
export function machineFromEnv(alias, env = process.env) {
  const names = envNames(alias)
  const get = (n) => {
    const v = env?.[n]
    return typeof v === 'string' && v.length > 0 ? v : ''
  }
  return {
    alias,
    host: get(names.host),
    port: get(names.port) ? Number(get(names.port)) : 22,
    username: get(names.user),
    password: get(names.password),
    keyPath: get(names.keyPath),
    keyPassphrase: get(names.keyPassphrase),
    // Empty, not 'strict': effectivePolicy(global, machine) lets the machine
    // win when it holds a valid value, so defaulting here made the global
    // hostKeyPolicy setting unreachable.
    hostKeyPolicy: get(names.hostKeyPolicy),
    knownHosts: get(names.knownHosts),
    /** Names of the env vars that were found, for diagnostics. Never values. */
    present: Object.entries(names)
      .filter(([k]) => get(names[k]))
      .map(([k]) => names[k]),
  }
}

/** Which env var names a machine would need, for actionable error text. */
export function expectedEnv(alias) {
  const n = envNames(alias)
  return {
    required: [n.host, n.user],
    auth: [n.password + '  (or)  ' + n.keyPath],
    optional: [n.port, n.keyPassphrase, n.hostKeyPolicy, n.knownHosts],
  }
}

/**
 * Assemble the auth object for ssh2 connect().
 * sessionPassword is used only when explicitly permitted by config.
 */
/**
 * Whether an SSH agent is reachable.
 *
 * An agent is the safest credential source: the private key stays in the agent
 * and this plugin only ever holds a signature. It is checked after an explicit
 * password/key but before falling back to a session password.
 */
export function agentSocket(env = process.env) {
  const sock = env.SSH_AUTH_SOCK
  return typeof sock === 'string' && sock.length > 0 ? sock : ''
}

/**
 * @param {string} alias
 * @param {{sessionPassword?: string, allowSessionPassword?: boolean, useAgent?: boolean}} [options]
 */
export function resolveAuth(alias, { sessionPassword, allowSessionPassword, useAgent } = {}) {
  const m = machineFromEnv(alias)
  if (m.password) return { kind: 'env-password', password: m.password, machine: m }
  if (m.keyPath) return { kind: 'env-key', keyPath: m.keyPath, passphrase: m.keyPassphrase, machine: m }
  if (allowSessionPassword && typeof sessionPassword === 'string' && sessionPassword.length > 0) {
    return { kind: 'session-password', password: sessionPassword, machine: m }
  }
  // Agent last: it needs no secret from us at all.
  if (useAgent !== false) {
    const sock = agentSocket()
    if (sock) return { kind: 'agent', agent: sock, machine: m }
  }
  return { kind: 'none', machine: m }
}

const SECRET_ENV = /(PASSWORD|PASSPHRASE|SECRET|TOKEN|PRIVATE)/i

/** Replace anything that looks like a secret before it can reach a message. */
export function redact(text) {
  let s = String(text ?? '')
  if (!s) return s
  // env-var style assignments
  s = s.replace(/\b([A-Z0-9_]*(?:PASSWORD|PASSPHRASE|SECRET|TOKEN|KEY)[A-Z0-9_]*)\s*[=:]\s*\S+/gi, '$1=<redacted>')
  // PEM blocks
  s = s.replace(/-----BEGIN [\s\S]*?-----END [^-]*-----/g, '<redacted-pem>')
  // HTTP authorization headers. 'Authorization: Bearer <token>' and
  // 'Basic <base64>' are how an API key usually reaches a config file, and
  // they are not KEY=value so the rule above missed them.
  s = s.replace(/\b(authorization|proxy-authorization)\s*:\s*(basic|bearer|token)\s+\S+/gi,
    '$1: <redacted>')
  // 'Basic <base64>' / 'Bearer <token>' on their own line, without a header
  // name. The token is consumed greedily so trailing '=' padding is included.
  s = s.replace(/\b(basic|bearer)\s+([A-Za-z0-9+/=._~-]{8,})/gi, '$1 <redacted>')
  // Credentials inside a URL: scheme://user:password@host.
  s = s.replace(/([a-z][a-z0-9+.-]*:\/\/)([^\s:@/]+):([^\s@/]+)@/gi, '$1$2:<redacted>@')
  // bare long secrets are left alone on purpose: guessing wrong shreds output.
  return s
}

/** Redact an object's secret-looking keys, one level deep and in arrays. */
export function redactObject(value) {
  if (Array.isArray(value)) return value.map(redactObject)
  if (value && typeof value === 'object') {
    const out = {}
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_ENV.test(k) ? '<redacted>' : redactObject(v)
    }
    return out
  }
  if (typeof value === 'string') return redact(value)
  return value
}
