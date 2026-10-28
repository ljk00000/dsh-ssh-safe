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
const PIPE_EXECUTORS = ['bash', 'sh', 'zsh', 'dash', 'ksh', 'python', 'python3', 'perl', 'ruby', 'node', 'eval', 'source']

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
    const recursive = /(?:^|\s)(?:--recursive|-r|-R)(?=\s|$)/.test(args) || /-[a-zA-Z]*[rR]/.test(args)
    const force = /(?:^|\s)--force(?=\s|$)/.test(args) || /-[a-zA-Z]*f/.test(args)
    const targets = args
      .replace(/--recursive|--force|--verbose/g, ' ')
      .replace(/-[a-zA-Z]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
    const flags = (recursive ? 'r' : '') + (force ? 'f' : '')
    return ' rm -' + flags + ' ' + targets
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
    const head = right.split(/\s+/)[0].replace(/^[\w./-]*\//, '')
    if (PIPE_EXECUTORS.includes(head)) {
      return { found: true, executor: head, source: segments[i - 1].trim() }
    }
  }
  return { found: false }
}

export function checkCommand(command, patterns, options = {}) {
  const list = Array.isArray(patterns) ? patterns : []
  if (list.length === 0) return { blocked: false }

  const raw = String(command ?? '')
  const normalized = normalizeCommand(raw)
  const canonical = canonicalizeRm(normalized)

  for (const candidate of new Set([raw, normalized, canonical])) {
    for (const pattern of list) {
      let re
      try { re = new RegExp(pattern) } catch { continue }
      if (re.test(candidate)) return { blocked: true, reason: 'matches deny pattern', pattern }
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

  const wrapper = findWrapper(normalized)
  if (wrapper) {
    const inner = extractWrapped(normalized, wrapper)
    if (inner && inner !== normalized) {
      const nested = checkCommand(inner, list, options)
      if (nested.blocked) {
        return { blocked: true, reason: 'inside ' + wrapper, pattern: nested.pattern }
      }
    }
  }

  return { blocked: false }
}
