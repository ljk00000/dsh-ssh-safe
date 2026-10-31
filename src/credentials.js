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
//   5. Resolution itself lives in machines.js (credentialFor). An older
//      resolveAuth() here read the environment only, was used by nothing but
//      its own tests, and made the tests look like coverage of a path the
//      product never took.

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
 * Names that end a secret. Anchored at the end on purpose: 'secretary: hello'
 * is prose, while 'client_secret: x' and 'AWS_SECRET_ACCESS_KEY=...' are not.
 * A prefix is allowed because real variable names carry one.
 */

/**
 * Key names that end like a secret but never hold one.
 *
 * The generic rule matches any identifier ending in KEY, which is what makes it
 * catch 'api_key: ...' without a list. These are the plugin's own vocabulary: a
 * boolean and a path, neither of which can leak a credential.
 */
const NEVER_SECRET = new Set(['trusthostkey', 'keypath', 'keytype'])

/** Replace anything that looks like a secret before it can reach a message. */
export function redact(text) {
  let s = String(text ?? '')
  if (!s) return s
  // One pass for .env, YAML, TOML, INI and JSON.
  //
  // The JSON case was the gap: '{"password": "hunter2"}' did not match, because
  // the closing quote sat between the key and the colon. A quoted key, a quoted
  // value and a value containing spaces are all common in the config files this
  // redaction exists to protect.
  // The key run is anchored on a non-word character (or the start of the
  // text), which is what keeps this linear: without the anchor the lazy
  // [A-Za-z0-9_]*? was retried at every position of a long run of word
  // characters, and a 200k-character single-line output took 33 seconds to
  // redact. See the timing test in test/redact-coverage.test.js.
  s = s.replace(
    /(^|[^\w])(["']?)([A-Za-z0-9_]*?(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|KEY))\2(\s*[=:]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,}]+)/gi,
    (match, lead, quote, key, separator) => {
      // 'trustHostKey: true' is an instruction, not a secret: it ends in KEY like
      // every password field does, and replacing its value with '<redacted>'
      // turned the one line that tells the caller what to do into gibberish.
      if (NEVER_SECRET.has(String(key).toLowerCase())) return match
      return lead + quote + key + quote + separator + '<redacted>'
    },
  )
  // 'curl -u user:password' and '--user=user:password' carry the secret after a
  // flag rather than after '=' or ':', so the rule above misses them.
  // No \b in front of a flag: '-' is not a word character, so a boundary can
  // never sit between the space and the dash. That was why 'curl -u a:b' kept
  // leaking after the rule was added.
  s = s.replace(/(^|[\s"'])(-u|--user)(\s+|=)([^\s:@]+):(\S+)/g, '$1$2$3$4:<redacted>')
  // 'mysql -uroot -pSECRET' / 'mysqldump -pSECRET db': the password is glued to
  // the flag, so no '=' or ':' appears and every rule above misses it. Only the
  // glued form is handled: 'ssh -p 2222 host' and '-p22' keep the flag as a
  // port, because masking a port would make the log say the wrong thing.
  s = s.replace(/(^|\s)(-p)([^\s-]\S*)/g, (match, lead, flag, value) =>
    /^\d+$/.test(value) ? match : lead + flag + '<redacted>')
  // '--password secret' and '--token=secret'.
  s = s.replace(/(^|[\s"'])(--?(?:password|passwd|passphrase|token|secret))(\s+|=)(\S+)/gi, '$1$2$3<redacted>')
  // PEM blocks
  s = s.replace(/-----BEGIN [\s\S]*?-----END [^-]*-----/g, '<redacted-pem>')
  // A key whose END marker is beyond a read limit has none: the rule above needs
  // both markers, so a 1024-byte slice of a private key was returned verbatim —
  // exactly the material ssh_read promises to mask. Mask from BEGIN to the end.
  s = s.replace(/-----BEGIN [A-Z0-9 ]+-----([\s\S]*)$/, (match, rest) =>
    /-----END [^-]*-----/.test(rest) ? match : '<redacted-pem>')
  // HTTP authorization headers. 'Authorization: Bearer <token>' and
  // 'Basic <base64>' are how an API key usually reaches a config file, and
  // they are not KEY=value so the rule above missed them.
  s = s.replace(/\b(authorization|proxy-authorization)\s*:\s*(basic|bearer|token)\s+\S+/gi,
    '$1: <redacted>')
  // 'Basic <base64>' / 'Bearer <token>' on their own line, without a header
  // name. The token is consumed greedily so trailing '=' padding is included.
  s = s.replace(/\b(basic|bearer)\s+([A-Za-z0-9+/=._~-]{8,})/gi, '$1 <redacted>')
  // Credentials inside a URL: scheme://user:password@host.
  // Anchored and bounded for the same reason as the key rule: an unbounded
  // [a-z0-9+.-]* scheme run was retried from every position of a long line.
  // The user part may be EMPTY: 'redis://:hunter2@cache:6379' is a normal
  // Redis URL and it carried the password through this rule untouched.
  s = s.replace(/(^|[^\w])([a-z][a-z0-9+.-]{0,31}:\/\/)([^\s:@/]*):([^\s@/]+)@/gi, '$1$2$3:<redacted>@')
  // Prose, as in a note or a shell comment: 'the key passphrase is hunter2'.
  // A sentence that ends in a non-secret ('the passphrase is required') is
  // over-redacted rather than leaked; that is the right way to be wrong.
  s = s.replace(/\b(passphrase|passwd|password|pwd)\s+(?:is|was)\s+(\S+)/gi, '$1 is <redacted>')
  // bare long secrets are left alone on purpose: guessing wrong shreds output.
  return s
}
