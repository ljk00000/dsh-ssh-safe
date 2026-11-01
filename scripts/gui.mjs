#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// dsh-ssh-safe -- on-demand local page for machines and credentials.
//
// Why a separate process instead of a long-running server inside the plugin:
//
//   * the plugin stays a pure tool provider with no listening socket, which is
//     what "no cloud, no ports" promised;
//   * the page exists only while this command runs;
//   * closing it (or 10 idle minutes) ends the process.
//
// Security shape:
//   * binds 127.0.0.1 only, on a random port;
//   * every request needs a token minted at startup, so another local process
//     or a stray browser tab cannot drive it;
//   * passwords travel from the browser to this process and are immediately
//     DPAPI encrypted -- they are never written in readable form, never logged,
//     and never returned by any endpoint;
//   * no external assets: the page is one local file, no CDN, no telemetry.
//
// Usage:
//   node scripts/gui.mjs [--dsh-home DIR] [--profile DIR] [--port N] [--no-open] [--idle-ms N]

import { spawn , spawnSync } from 'node:child_process'
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { createServer } from 'node:http'
import { createRequire } from 'node:module'
import { networkInterfaces } from 'node:os'
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { acquireStoreLock } from './lib/store-lock.mjs'
import net from 'node:net'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import { connectOptions } from '../src/connect.js'
import { checkHostKey } from '../src/hostkey.js'
import { expandHome } from '../src/pool.js'
import { dpapiAvailable, encryptDpapi } from '../src/dpapi.js'
import { credentialFor, credentialState, credentialsPath, machineDefinition } from '../src/machines.js'
import { envNames } from '../src/credentials.js'

const here = path.dirname(fileURLToPath(import.meta.url))

function parseArgs(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]
    if (!token.startsWith('--')) continue
    const key = token.slice(2)
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) out[key] = true
    else { out[key] = next; i++ }
  }
  return out
}

const args = parseArgs(process.argv.slice(2))
// The tools refuse an argument they do not declare, because a misspelled one is
// silently ignored and looks like it worked. This script accepted any --key the
// same way: `--proflie desktop` started against the default profile without a
// word, and every save then edited a credential file the user had not named.
const ACCEPTED_OPTIONS = ['dsh-home', 'profile', 'port', 'idle-ms', 'no-open']
// One constant, so the --help text cannot drift from the timeout the page uses.
const DEFAULT_IDLE_MS = 10 * 60 * 1000
// --help is not 'an option the script does not know': it is the one every CLI is
// expected to answer. Refusing it with the accepted list (0.7.337) sent the reader
// looking for a typo in a word they spelled correctly.
if (args.help === true) {
  console.log([
    'Usage: node scripts/gui.mjs [options]',
    '',
    '  --dsh-home DIR   DSH home directory (default: $DSH_HOME or ~/.dsh)',
    '  --profile DIR    profile directory (default: <dsh-home>/profiles/desktop)',
    '  --port N         listen port; 0 picks a free one (default: 0)',
    '  --idle-ms N      exit after N ms with no page open (default: ' + DEFAULT_IDLE_MS + ')',
    '  --no-open        do not open a browser',
    '  --help           show this text and exit',
    '',
    'The page holds no credential of its own: every request needs the token printed at startup.',
  ].join('\n'))
  process.exit(0)
}
const unknownOptions = Object.keys(args).filter((key) => !ACCEPTED_OPTIONS.includes(key))
if (unknownOptions.length > 0) {
  console.error('Unknown option(s): ' + unknownOptions.map((key) => '--' + key).join(', ') +
    '. Accepted: ' + ACCEPTED_OPTIONS.map((key) => '--' + key).join(', '))
  process.exit(2)
}
const dshHome = path.resolve(String(args['dsh-home'] || process.env.DSH_HOME || path.join(process.env.USERPROFILE || process.env.HOME || '.', '.dsh')))
const profileDir = path.resolve(String(args.profile || path.join(dshHome, 'profiles', 'desktop')))
// Both of these used to go straight into Number(): --port abc reached
// server.listen(NaN) and died with a RangeError stack trace, and --idle-ms abc
// became NaN, which setTimeout treats as 0, so the page exited at once while the
// banner promised 'NaN 秒'. The tools validate their inputs; so should the CLI.
const rawPort = args.port
if (typeof rawPort === 'boolean') {
  console.error('--port needs a value: --port 8787 (or --port 0 for a free one).')
  process.exit(2)
}
const port = rawPort === undefined ? 0 : Number(rawPort)
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  console.error('--port must be an integer between 0 and 65535 (0 picks a free port); received ' + JSON.stringify(rawPort))
  process.exit(2)
}
const rawIdle = args['idle-ms']
if (typeof rawIdle === 'boolean') {
  console.error('--idle-ms needs a value in milliseconds, e.g. --idle-ms 600000.')
  process.exit(2)
}
const idleMs = rawIdle === undefined ? DEFAULT_IDLE_MS : Number(rawIdle)
if (!Number.isFinite(idleMs) || Math.floor(idleMs) !== idleMs || idleMs < 1000) {
  // 0 is not 'never': setTimeout(fn, 0) fires at once, which is the opposite of
  // what anyone typing it means. Say that instead of exiting immediately.
  console.error('--idle-ms must be a whole number of milliseconds, at least 1000; received ' + JSON.stringify(rawIdle))
  console.error('The page exits after that much inactivity. 0 would exit at once, not never.')
  process.exit(2)
}
const credFile = credentialsPath(dshHome)

/**
 * Machines defined in the DSH settings form.
 *
 * They live in the profile's cordis.patch.yml, which is a YAML array of loader
 * entries. Parsing it with a regex is not lovely, but the alternative is pulling
 * a YAML dependency into a plugin whose selling point is that it has none. The
 * shapes handled are the ones DSH writes: an entry per plugin, config below it,
 * machines as a mapping of alias to flat key/value pairs.
 *
 * Any failure means "no settings-form machines" -- the page still works off the
 * credential file and the environment.
 */
function pluginBlock() {
  const file = path.join(profileDir, 'cordis.patch.yml')
  let text
  try { text = readFileSync(file, 'utf8') } catch { return null }
  const lines = text.split(/\r?\n/)
  // 'id: dsh-ssh-safe   # comment' and a quoted id are both valid YAML; the exact
  // match used to make the whole plugin entry invisible, so the page showed no
  // machines for a file DSH reads fine.
  const idLine = /^\s*-\s*id:\s*["']?dsh-ssh-safe["']?\s*(?:#.*)?$/
  const start = lines.findIndex((line) => idLine.test(line))
  if (start < 0) return null
  const entryIndent = (lines[start].match(/^\s*/) || [''])[0].length

  let end = lines.length
  for (let i = start + 1; i < lines.length; i++) {
    const indent = (lines[i].match(/^\s*/) || [''])[0].length
    if (indent === entryIndent && /^\s*-\s*id:/.test(lines[i])) { end = i; break }
  }
  return lines.slice(start, end)
}

/**
 * Whether the profile still lets the plugin read its credential file.
 *
 * The test button mimics a real connection, so it has to make the same choice
 * the plugin does: with useCredentialFile off, the file's password, host, port
 * and user are all out of play, and a "connection ok" here would be a lie.
 */
/**
 * The global hostKeyPolicy from the settings file, since machineDefinition only
 * carries the per-machine override.
 */
/**
 * How many `- id: dsh-ssh-safe` entries the profile has.
 *
 * Two entries are ambiguous: DSH may take the last and this page reads the first,
 * so the count decides whether the page can trust what it shows.
 *
 * @returns {number}
 */
function pluginEntryCount() {
  const file = path.join(profileDir, 'cordis.patch.yml')
  let text
  try { text = readFileSync(file, 'utf8') } catch { return 0 }
  const idLine = /^\s*-\s*id:\s*["']?dsh-ssh-safe["']?\s*(?:#.*)?$/
  return text.split(/\r?\n/).filter((line) => idLine.test(line)).length
}
/**
 * The indentation of the plugin config keys inside the entry.
 *
 * machines.<alias>.hostKeyPolicy is a per-machine override, and the regex readers
 * below accept any leading whitespace: one machine with `hostKeyPolicy: off` then
 * became the GLOBAL policy for every machine, so the page reported "[ok] 主机密钥"
 * for a host the plugin would refuse.
 *
 * @param {string[]|null} block
 * @returns {number} -1 when it cannot be determined
 */
function configIndent(block) {
  if (!block) return -1
  const configAt = block.findIndex((line) => /^\s*config\s*:\s*(#.*)?$/.test(line))
  if (configAt < 0) return -1
  const base = (block[configAt].match(/^\s*/) || [''])[0].length
  for (let i = configAt + 1; i < block.length; i++) {
    const line = block[i]
    if (!line.trim() || /^\s*#/.test(line)) continue
    const indent = (line.match(/^\s*/) || [''])[0].length
    return indent > base ? indent : -1
  }
  return -1
}

/** Whether a line is a config-level key (not one nested inside a machine). */
function atConfigIndent(block, line) {
  const indent = configIndent(block)
  if (indent < 0) return true
  return ((line.match(/^\s*/) || [''])[0].length) === indent
}
function settingsHostKeyPolicy() {
  const block = pluginBlock()
  if (!block) return 'strict'
  for (const line of block) {
    if (!atConfigIndent(block, line)) continue
    const match = line.match(/^\s*hostKeyPolicy:\s*['"]?(strict|tofu|off)['"]?\s*(?:#.*)?$/)
    if (match) return match[1]
  }
  return 'strict'
}

/**
 * The plugin's connectTimeoutMs, so the test button gives up when the plugin
 * would. The hardcoded 15s disagreed with a raised setting: a 60s link was
 * reported FAIL while ssh_connect was still dialling, and a lowered one made
 * the page wait four times longer than the tool.
 */
function settingsConnectTimeoutMs() {
  const block = pluginBlock()
  if (!block) return 15000
  for (const line of block) {
    if (!atConfigIndent(block, line)) continue
    const match = line.match(/^\s*connectTimeoutMs:\s*(\d+)\s*(?:#.*)?$/)
    if (match) {
      // The HTTP request waits on this, so keep it finite: ten minutes.
      const value = Number(match[1])
      if (Number.isFinite(value) && value >= 1000) return Math.min(value, 600000)
    }
  }
  return 15000
}

function settingsUseCredentialFile() {
  const block = pluginBlock()
  if (!block) return true
  for (const line of block) {
    if (!atConfigIndent(block, line)) continue
    const match = line.match(/^\s*useCredentialFile:\s*(true|false)\s*(?:#.*)?$/)
    if (match) return match[1] === 'true'
  }
  return true
}

/**
 * Read one YAML scalar the way the plugin's parser will.
 *
 * 'host: "10.0.0.5"   # quoted' used to arrive as '10.0.0.5"   # quoted': the
 * leading quote was stripped, the trailing one and the comment were kept. The
 * page then showed -- and tested -- a host the plugin would never use.
 *
 * @param {string} raw
 * @returns {string}
 */
function parseScalar(raw) {
  const text = String(raw).trim()
  if (!text) return ''
  const quote = text[0]
  if (quote === '"' || quote === "'") {
    let out = ''
    for (let i = 1; i < text.length; i++) {
      const ch = text[i]
      if (quote === '"' && ch === '\\' && i + 1 < text.length) { out += text[i + 1]; i++; continue }
      if (ch === quote) {
        // A single-quoted YAML string escapes a quote by doubling it.
        if (quote === "'" && text[i + 1] === "'") { out += "'"; i++; continue }
        return out
      }
      out += ch
    }
    return out
  }
  // Unquoted: a comment starts at '#' only after whitespace.
  const comment = text.search(/\s#/)
  return (comment >= 0 ? text.slice(0, comment) : text).trim()
}

/**
 * The settings-form machines, in block style, whatever indentation was used.
 *
 * This used to assume the exact shape DSH writes: aliases two spaces under
 * `machines:` and fields below them. Four-space indentation, a quoted alias, an
 * alias with a trailing comment, or flow style all produced an EMPTY list, so the
 * page showed no machines while the plugin connected to them fine.
 *
 * @returns {{machines: Record<string, Record<string, unknown>>, problem: string}}
 */
function machinesBlock() {
  const empty = { machines: {}, problem: '' }
  const block = pluginBlock()
  if (!block) return empty
  const at = block.findIndex((line) => /^\s*machines\s*:\s*(#.*)?$/.test(line))
  if (at < 0) {
    const inline = block.find((line) => /^\s*machines\s*:\s*\S/.test(line))
    if (inline) {
      return {
        machines: {},
        problem: 'the settings form writes machines on one line (`machines: { … }`), which this page cannot edit; use the tools or edit cordis.patch.yml directly',
      }
    }
    return empty
  }
  const machinesIndent = (block[at].match(/^\s*/) || [''])[0].length

  const machines = {}
  let current = ''
  let childIndent = -1
  let problem = ''
  for (let i = at + 1; i < block.length; i++) {
    const line = block[i]
    if (!line.trim() || /^\s*#/.test(line)) continue
    const indent = (line.match(/^\s*/) || [''])[0].length
    if (indent <= machinesIndent) break
    // The first child line decides the alias column, instead of assuming two
    // spaces: the old rule matched only the exact shape DSH writes.
    if (childIndent < 0) childIndent = indent
    const pair = /^\s*(?:"([^"]*)"|'([^']*)'|([\w.-]+))\s*:\s*(.*)$/.exec(line)
    if (!pair) continue
    const key = pair[1] ?? pair[2] ?? pair[3]
    const rest = String(pair[4] || '')
    // 'gpu:   # the lab box' is an alias with a comment, not a machine defined
    // on one line: the leading '#' has to be stripped before the emptiness test.
    const bare = rest.trim()
    const valueText = bare.startsWith('#') ? '' : bare.replace(/\s+#.*$/, '').trim()
    if (indent === childIndent) {
      if (valueText === '' || valueText === '{}') {
        current = key.toLowerCase()
        machines[current] = {}
        continue
      }
      // `gpu: { host: 10.0.0.1 }` -- flow style one level down. A plain scalar
      // (`plain: 'just a string'`) is not that shape, and the message used to name
      // `{ … }` for it, describing a block that is not in the file.
      const shape = valueText.startsWith('{') ? 'on one line (`' + key + ': { … }`)'
        : 'as a single value (`' + key + ': ' + valueText.slice(0, 40) + '`), not a block of fields'
      problem = problem || 'a machine is written ' + shape + ', which this page cannot edit; use the tools or edit cordis.patch.yml directly'
      current = ''
      continue
    }
    if (indent > childIndent && current) {
      let value = parseScalar(rest)
      if (value === '' || value === 'null' || value === '~') continue
      if (/^\d+$/.test(value)) value = Number(value)
      if (value === 'true') value = true
      if (value === 'false') value = false
      machines[current][key] = value
    }
  }
  // The plugin's schema requires text for these, and a number or a boolean there
  // stops the whole plugin from loading. The page used to render `host: 123` as the
  // string "123" and say nothing, so it looked like a machine that works.
  const TEXT_FIELDS = new Set(['host', 'user', 'keyPath', 'password', 'keyPassphrase', 'hostKeyPolicy', 'knownHosts'])
  const wrong = []
  for (const [alias, fields] of Object.entries(machines)) {
    for (const [field, value] of Object.entries(fields)) {
      if (!TEXT_FIELDS.has(field) || typeof value === 'string') continue
      wrong.push(alias + '.' + field + ' is ' + (typeof value) + ' (' + JSON.stringify(value) + ')')
    }
  }
  if (wrong.length > 0) {
    problem = problem || 'the plugin refuses to load this machines block: ' + wrong.join(', ') +
      ' — host, user and the other text fields must be quoted text in cordis.patch.yml'
  }
  if (pluginEntryCount() > 1) {
    problem = problem || 'this profile has more than one plugin entry for dsh-ssh-safe; this page reads'
      + ' the first one, so what it shows (and saves) may not be what is in effect. Remove the duplicate'
  }
  return { machines, problem }
}

function settingsMachines() {
  return machinesBlock().machines
}
/** Load ssh2 from the profile, so the test button can make a real connection. */
function loadSsh2() {
  const candidates = [profileDir, process.cwd(), here]
  for (const dir of candidates) {
    try {
      return createRequire(path.join(dir, 'noop.js'))('ssh2')
    } catch { /* next */ }
  }
  return null
}

/**
 * Normalise an alias, or explain why it cannot be used.
 *
 * This used to strip forbidden characters silently, so "prod/x" was stored as
 * "prodx" and "a b" as "ab". The page then listed a machine the caller never
 * typed, and `machine: "prod/x"` answered "not configured". set-password already
 * refuses such aliases; the page now agrees with it instead of rewriting.
 *
 * @param {unknown} value
 * @returns {{alias: string} | {error: string}}
 */
function parseAlias(value) {
  const raw = String(value ?? '').trim()
  if (!raw) return { error: '别名不能为空' }
  const alias = raw.toLowerCase()
  if (!/^[a-z0-9._-]+$/.test(alias)) {
    // "字母" is not what is checked: ü, ö and Cyrillic letters are letters and are
    // refused, so a reader could not see why their alias failed.
    return { error: '别名只能用 a-z 的英文字母、数字、点、下划线、连字符（收到 ' + JSON.stringify(raw) + '）' }
  }
  return { alias }
}

/**
 * How long the page stays open, in words.
 *
 * Math.round(idleMs / 60000) printed '0 分钟' for anything under thirty seconds,
 * so --idle-ms 1500 said the page would exit after '0 minutes' and then did.
 */
function idleWords(ms) {
  const minutes = Math.round(ms / 60000)
  if (minutes >= 1) return minutes + ' 分钟'
  return (Math.round(ms / 100) / 10) + ' 秒'
}

/**
 * Names that collide with Object.prototype.
 *
 * Saving an alias of '__proto__' used to answer {"ok":true} and write nothing:
 * 'store["__proto__"] = entry' assigns the prototype instead of a key, so the
 * entry vanished while the page said it had been saved.
 */
const RESERVED_ALIASES = new Set(['__proto__', 'prototype', 'constructor'])
const filled = (v) => v !== undefined && v !== null && v !== ''

function readStore() {
  try {
    const parsed = JSON.parse(readFileSync(credFile, 'utf8'))
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch { return {} }
}

/**
 * Why the credential file cannot be read, or '' when it is fine.
 *
 * readStore() answers {} for a file it cannot parse, and a save then wrote that
 * single entry over the whole file: one missing comma cost the user every machine
 * in it, with no warning. Saving and deleting now refuse while the file is broken.
 *
 * @returns {string}
 */
function storeProblem() {
  let text
  try { text = readFileSync(credFile, 'utf8') } catch (err) {
    return err && err.code === 'ENOENT' ? '' : ('无法读取 ' + credFile + '：' + (err && err.message))
  }
  try {
    const parsed = JSON.parse(text)
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return ''
    return credFile + ' 的内容不是 JSON 对象（收到 ' + (Array.isArray(parsed) ? 'array' : typeof parsed) + '）'
  } catch (err) {
    return credFile + ' 现在无法解析（' + (err && err.message) + '）'
  }
}

/** Block this event loop for a moment (there is no sync sleep in Node). */
function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
}

/**
 * Rename over the credential file, retrying while Windows says it is busy.
 *
 * On Windows a rename fails with EPERM when any other handle has the target open:
 * an antivirus scan, a sync client, or the icacls call this page itself starts after
 * each write. Measured: one save/delete cycle in forty answered 500 with
 * "EPERM: operation not permitted, rename ...", and the page then showed both
 * machines because the delete had not happened.
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
      sleepSync(15 * attempt)
    }
  }
  throw new Error('could not replace ' + path.basename(to) + ' after 6 attempts (' +
    String(last && last.code) + '): another program is holding the file open — an' +
    ' antivirus, a sync client, or a concurrent writer. Try again.')
}

/**
 * Remove temp files a crashed save left behind.
 *
 * writeStore() writes credentials.json.tmp-<pid> and renames it over the real
 * file. A crash in that window leaves the temp file in the profile directory with
 * every password still in it, at a path nothing ever mentioned — and on Windows the
 * ACL restriction is applied to credentials.json only, so the leftover keeps the
 * inherited ACLs the real file was hardened against.
 *
 * A live save holds its temp file for milliseconds, so anything older than
 * STALE_TMP_MS belongs to a writer that is gone.
 */
const STALE_TMP_MS = 10 * 60 * 1000
function sweepStaleTemps(now = Date.now()) {
  const removed = []
  let names = []
  try { names = readdirSync(path.dirname(credFile)) } catch { return removed }
  const base = path.basename(credFile)
  const pattern = new RegExp('^' + base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\.tmp-\\d+$')
  for (const name of names) {
    if (!pattern.test(name)) continue
    const full = path.join(path.dirname(credFile), name)
    try {
      const age = now - statSync(full).mtimeMs
      if (age < STALE_TMP_MS) continue
      rmSync(full, { force: true })
      removed.push(name)
    } catch { /* a temp file that vanished or cannot be read is not fatal */ }
  }
  return removed
}

function writeStore(store) {
  mkdirSync(path.dirname(credFile), { recursive: true })
  sweepStaleTemps()
  // Write beside the file and rename over it.
  //
  // The plugin reads this file on every connection, from another process. An
  // in-place write truncates first, so a connection that lands in that window
  // reads an empty file, falls back to "no machines" and fails with "not
  // configured" -- while the page says the save succeeded.
  const text = JSON.stringify(store, null, 2) + '\n'
  const tmp = credFile + '.tmp-' + process.pid
  writeFileSync(tmp, text, { encoding: 'utf8', mode: 0o600 })
  try {
    renameWithRetry(tmp, credFile)
  } catch (err) {
    try { rmSync(tmp, { force: true }) } catch { /* nothing left to do */ }
    throw err
  }
  if (process.platform === 'win32') {
    const me = process.env.USERDOMAIN && process.env.USERNAME
      ? process.env.USERDOMAIN + '\\' + process.env.USERNAME
      : process.env.USERNAME
    try {
      // Synchronously: the asynchronous version could still hold the file when the
      // next save tried to rename over it (that was the EPERM above).
      spawnSync('icacls', [credFile, '/inheritance:r', '/grant:r', me + ':(R,W)', '/grant:r', 'SYSTEM:(R,W)'],
        { windowsHide: true, stdio: 'ignore', timeout: 15000 })
    } catch { /* best effort */ }
  } else {
    try { chmodSync(credFile, 0o600) } catch { /* best effort */ }
  }
}

function envAliases() {
  const out = []
  for (const key of Object.keys(process.env)) {
    const m = /^DSH_SSH_(.+)_HOST$/.exec(key)
    if (m && process.env[key]) out.push(m[1].toLowerCase())
  }
  return [...new Set(out)].sort()
}

function state() {
  const parsed = machinesBlock()
  const settings = parsed.machines
  // With the credential file turned off the plugin never reads it, so listing
  // its machines here would present machines that cannot connect -- and the
  // test button would say so, contradicting the list right above it.
  const fileEnabled = settingsUseCredentialFile()
  const readHome = fileEnabled ? dshHome : ''
  const fromDisk = fileEnabled ? Object.keys(readStore()) : []
  const aliases = [...new Set([...fromDisk, ...Object.keys(settings), ...envAliases()])].sort()
  const machines = aliases.map((alias) => {
    const m = machineDefinition(alias, { machines: settings, dshHome: readHome })
    return {
      alias,
      host: m.host,
      port: m.port,
      username: m.username,
      keyPath: m.keyPath,
      passwordSource: m.sources.password,
      // The passphrase gets the same treatment as the password: the page offers
      // 清除 only where this file actually holds one.
      keyPassphraseSource: m.sources.keyPassphrase,
      hostKeyPolicy: m.hostKeyPolicy || '(global)',
      fromSettings: Boolean(settings[alias] && (settings[alias].host || settings[alias].user)),
      inCredentialFile: fromDisk.includes(alias),
      // A settings-form port that cannot be dialled was shown as the 22
      // fallback, so the page looked configured while the real call would fail
      // on that value.
      portProblem: m.portProblem || '',
      portRaw: m.portProblem ? String(m.portRaw ?? '') : '',
    }
  })
  return {
    credentialFile: credFile,
    fileEnabled,
    dpapi: dpapiAvailable(),
    envAliases: envAliases(),
    machines,
    // A settings file this page could not read is said out loud: showing no
    // machines is indistinguishable from having none.
    machinesProblem: parsed.problem,
  }
}

// ---- connection test -------------------------------------------------------

/**
 * Explain a refused command channel in the page's own words.
 *
 * ssh2 prints "(SSH) Channel open failure: " with an empty reason, which names the
 * stage but not the cause: sshd answers that when the connection is at
 * MaxSessions, or when the account may not open a shell.
 *
 * @param {unknown} message
 * @returns {string}
 */
/**
 * Say what is wrong with the credential in words the reader can act on.
 *
 * @param {unknown} err the error connectOptions() threw
 * @returns {string}
 */
function explainCredentialError(err) {
  const message = String((err && err.message) || err || '')
  const pathMatch = message.match(/\s(C:\S+|\/\S+)/)
  // 'cannot read the private key C:/x: ENOENT' ends the path with the colon that
  // separates the sentence, and it reached the reader as part of the name.
  const shown = pathMatch ? pathMatch[1].replace(/[:，,.;]+$/, '') : ''
  if (/EISDIR|is a directory/i.test(message)) {
    return 'keyPath 指向的是目录，不是私钥文件' + (shown ? '：' + shown : '') +
      '——请填私钥本身（例如 ~/.ssh/id_ed25519），不要填 ~/.ssh'
  }
  if (/ENOENT|cannot read the private key/i.test(message)) {
    return '找不到私钥文件' + (shown ? '：' + shown : '') +
      '——检查 keyPath 的拼写，或改用 ~/.ssh/ 下的私钥'
  }
  if (/passphrase/i.test(message)) {
    return '私钥有口令保护：在设置里填 keyPassphrase（或环境变量 DSH_SSH_<别名>_KEY_PASSPHRASE）'
  }
  if (/Unsupported key format|Malformed OpenSSH private key/i.test(message)) {
    return '私钥格式无法解析' + (shown ? '：' + shown : '') +
      '——只支持 OpenSSH/PEM 私钥，PuTTY 的 .ppk 需要先转换'
  }
  return '凭据无法使用：' + message.slice(0, 160)
}
function channelFailureNote(message) {
  const text = String(message ?? '')
  if (/Channel open failure/i.test(text)) {
    return '服务器拒绝再开一个会话通道（通常是会话上限 MaxSessions，默认 10；' +
      '或该账号不允许开 shell）——本页的连接已断开，正式使用时关掉那台主机上的其它会话，' +
      '或在 sshd_config 里提高上限'
  }
  if (/Administratively prohibited/i.test(text)) {
    return '服务器禁止开 shell（sshd_config 的 PermitTTY / ForceCommand，或账号被限制）'
  }
  return text.slice(0, 160)
}
function tcpProbe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port })
    const done = (ok, detail) => { try { socket.destroy() } catch {} ; resolve({ ok, detail }) }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => done(true, 'port ' + port + ' accepts connections'))
    socket.once('timeout', () => done(false, 'no answer within ' + timeoutMs + 'ms'))
    socket.once('error', (err) => done(false, (err && err.code) || 'connect failed'))
  })
}

/**
 * A real connection: TCP, host key, authentication, then one command.
 *
 * The host key is reported but NOT recorded. A test must not move the trust
 * state; that is what ssh_connect with trustHostKey is for.
 */
async function testConnection(alias) {
  const settings = settingsMachines()
  // The plugin would ignore the credential file entirely when the profile turns
  // it off; testing with it anyway would report a connection the plugin cannot
  // make.
  const fileEnabled = settingsUseCredentialFile()
  const credentialHome = fileEnabled ? dshHome : ''
  const m = machineDefinition(alias, { machines: settings, dshHome: credentialHome })
  const lines = []
  const say = (stage, verdict, detail) =>
    lines.push('[' + verdict + '] ' + stage + (detail ? ': ' + detail : ''))
  const finish = (ok) => ({ ok, lines })
    // Absent stages read like passed stages: a run that stopped at 凭据 printed no
    // 主机密钥 or 认证 line at all. Every early return now says that it stopped.
    const stopped = (why) => {
      lines.push('', '已停止：' + why + '，后面的检查没有进行。')
      return finish(false)
    }
  if (!fileEnabled) {
    say('凭据文件', 'warn', '设置里 useCredentialFile 为 false，本页保存的密码/主机不会被插件读取')
  }

  // An alias nothing defines used to answer "缺少主机或用户", which blames the
  // form for a machine that does not exist: the page cannot say "add a host" for
  // something it has never heard of.
  const known = state().machines.some((machine) => machine.alias === alias)
  if (!known) {
    say('配置', 'FAIL', '没有名为 "' + alias + '" 的机器：设置界面、凭据文件和环境变量里都没有它')
    return stopped('没有这台机器')
  }
  if (!m.host || !m.username) {
    say('配置', 'FAIL', '缺少主机或用户，请在上方填写后保存')
    return stopped('缺少主机或用户')
  }
  if (m.portProblem) {
    // Report the value the plugin will use for the connection, which is not the
    // one in the settings form: a '[ok] 配置' line here claims a working setup.
    say('配置', 'FAIL', '端口无效：' + m.portProblem + '（设置界面里写的是 ' + String(m.portRaw ?? '') + '）— 正式连接会失败')
    say('配置', 'FAIL', '端口无效：' + m.portProblem + '（设置界面里写的是 ' + String(m.portRaw ?? '') + '）— 正式连接会失败')
    return stopped('端口无效')
  }
  say('配置', 'ok', m.username + '@' + m.host + ':' + m.port)

  const connectTimeoutMs = settingsConnectTimeoutMs()
  const tcp = await tcpProbe(m.host, m.port, connectTimeoutMs)
  // The errno alone sent the reader to the wrong place: ECONNREFUSED means the
  // host answered and nothing is listening on that port, while the stop line said
  // 主机不可达. The tool version has carried this advice for a while; the page,
  // which is the least technical surface, had none.
  const tcpHint = /ECONNREFUSED/.test(String(tcp.detail))
    ? '端口上没有服务在监听（sshd 未运行、端口写错，或服务器只监听别的地址）'
    : /ENOTFOUND|EAI_AGAIN|EAI_FAIL/.test(String(tcp.detail))
      ? '主机名解析不了（检查拼写、DNS，或改用 IP）'
      : /ETIMEDOUT|no answer/.test(String(tcp.detail))
        ? '连接超时：可能被防火墙丢弃，或主机不在线'
        : /ECONNRESET|EPIPE/.test(String(tcp.detail))
          ? '连接被对方关闭：那个端口可能不是 sshd'
          : ''
  say('TCP', tcp.ok ? 'ok' : 'FAIL', tcp.detail + (tcpHint ? ' —— ' + tcpHint : ''))
  if (!tcp.ok) {
    lines.push('', '已停止：TCP 没有连通，无法测试认证（原因见上面的 TCP 一行）。')
    return finish(false)
  }

  const ssh2 = loadSsh2()
  if (!ssh2) {
    return stopped('缺少 ssh2 模块')
  }

  // One resolver, shared with the plugin: the page must not disagree with the
  // plugin about which credential source wins.
  const auth = credentialFor(alias, { machines: settings, dshHome: credentialHome, useAgent: false })
  for (const warning of auth.warnings || []) say('凭据', 'warn', warning)

  return await new Promise((resolve) => {
    const client = new ssh2.Client()
    let fingerprint = ''
    // A host-key mismatch does not end the attempt (proving the credential works
    // is useful), but it must not leave the verdict green: the plugin refuses
    // that connection a second later.
    let mismatched = false
    let settled = false
    const done = (ok) => {
      if (settled) return
      settled = true
      try { client.end() } catch {}
      resolve(finish(ok && !mismatched))
    }
    const timer = setTimeout(() => {
      // A little past the dial timeout, so a handshake that is merely slow is
      // reported by ssh2 (which knows why) rather than by this watchdog.
      say('认证', 'FAIL', '在 ' + Math.round(connectTimeoutMs / 1000) + ' 秒内没有完成握手')
      done(false)
    }, connectTimeoutMs + 5000)

    client.on('ready', () => {
      const source = String(auth.kind || 'none').replace(/-password$|-key$/, '')
      say('认证', 'ok', source === 'none' ? '已认证' : '已认证（凭据来源：' + source + '）')
      client.exec('echo dsh-gui-ok', (err, stream) => {
        if (err) {
          clearTimeout(timer)
          // '(SSH) Channel open failure: ' with nothing after the colon names the
          // stage but not why. The tool layer has explained MaxSessions since 0.7.245;
          // the page, the least technical surface, printed the raw text.
          say('命令通道', 'FAIL', channelFailureNote(err.message))
          return done(false)
        }
        let out = ''
        stream.on('data', (chunk) => { out += chunk.toString('utf8') })
        stream.stderr.on('data', () => {})
        stream.on('close', () => {
          clearTimeout(timer)
          const replied = out.includes('dsh-gui-ok')
          say('命令通道', replied ? 'ok' : 'FAIL', replied ? 'echo 返回正常' : '没有收到预期输出')
          done(replied)
        })
      })
    })

    client.on('error', (err) => {
      clearTimeout(timer)
      const message = String((err && err.message) || err)
      if (/authentication/i.test(message)) {
        say('认证', 'FAIL', message.slice(0, 160))
        lines.push('', '提示：密码是否正确？如果服务器只允许密钥，请把公钥加入 ~/.ssh/authorized_keys。')
      } else {
        say('连接', 'FAIL', message.slice(0, 160))
      }
      done(false)
    })

    // Same mapping the pool uses, so the page and ssh_exec cannot disagree
    // about which credential is in play. (They did: the page authenticated and
    // the pool sent nothing at all.)
    let config
    try {
      config = connectOptions(m, auth, { readyTimeout: connectTimeoutMs, keepaliveInterval: 0 })
    } catch (err) {
      clearTimeout(timer)
      say('凭据', 'FAIL', explainCredentialError(err))
      lines.push('', '已停止：凭据不能用，后面的检查没有进行。')
      return done(false)
    }
    if (!config.password && !config.privateKey && !config.agent) {
      clearTimeout(timer)
      say('凭据', 'FAIL', '没有可用的密码或私钥，请在上方填写密码后保存')
      lines.push('', '已停止：凭据不能用，后面的检查没有进行。')
      return done(false)
    }
    config.hostVerifier = (key) => {
      // Report, do not record: a test must not change the trust state. It must
      // still TELL the truth about what the plugin will do with this key -- a
      // page that prints "[ok] 主机密钥" for a changed key says the opposite of
      // what ssh_connect will do a second later.
      try {
        fingerprint = 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/, '')
        const policy = m.hostKeyPolicy || settingsHostKeyPolicy()
        const verdict = checkHostKey({
          dshHome: credentialHome,
          host: m.host,
          port: m.port,
          keyBlob: key,
          policy,
          trustHostKey: false,
          knownHostsFile: m.knownHosts ? expandHome(m.knownHosts) : '',
        })
        if (policy === 'off') {
          // checkHostKey returns ok for 'off' WITHOUT checking anything: '已记录，
          // 校验通过' said the opposite of what the setting does.
          say('主机密钥', 'warn', fingerprint + ' — hostKeyPolicy 为 "off"：本页与插件都不校验主机密钥')
        } else if (verdict.ok) {
          say('主机密钥', 'ok', fingerprint + '（已记录，校验通过；本页不修改记录）')
        } else if (/^HOST KEY CHANGED/.test(String(verdict.reason))) {
          mismatched = true
          // The page knows the presented fingerprint but not the recorded one, which
          // is the fact the reader needs to compare (and to paste into the ticket).
          // The remedy is one command, and the page used to name neither.
          const recorded = (String(verdict.reason).match(/(?:records|recorded)\s+(SHA256:[A-Za-z0-9+/=]+)/) || [])[1]
          say('主机密钥', 'FAIL', fingerprint + ' 与记录的不一致' +
            (recorded ? '（记录的是 ' + recorded + '）' : '') +
            '，正式连接会被拒绝（可能是重装，也可能是中间人）。确认新指纹无误后，' +
            '删掉 known_hosts 里这一行（ssh-keygen -R <主机>）再重试')
        } else {
          say('主机密钥', 'warn', fingerprint + ' 还没有记录，正式连接会被拒绝，除非用 ssh_connect trustHostKey: true（本页不记录）')
        }
      } catch { /* a diagnostics page must not break the connection it reports on */ }
      return true
    }

    try { client.connect(config) } catch (err) {
      clearTimeout(timer)
      say('连接', 'FAIL', String(err.message).slice(0, 120))
      done(false)
    }
  })
}

// ---- server ----------------------------------------------------------------

// A cryptographic source, not Math.random(): this token is the only thing
// standing between another local process and the saved credentials.
const token = randomToken()
function randomToken() {
  return randomBytes(24).toString('hex')
}

function sendJson(res, status, body) {
  const text = JSON.stringify(body)
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  res.end(text)
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = ''
    let tooLarge = false
    req.on('data', (chunk) => {
      if (tooLarge) return
      data += chunk
      if (data.length > 64 * 1024) {
        // 413, not 500: the caller sent too much, the server did nothing wrong.
        //
        // destroy() here destroyed the socket BEFORE the 413 could be written,
        // so the caller saw a dropped connection ("other side closed") instead
        // of the reason. Stop accumulating and let the response go out; the rest
        // of the body is drained by the request itself.
        tooLarge = true
        data = ''
        const error = new Error('body too large')
        error.statusCode = 413
        reject(error)
      }
    })
    req.on('end', () => {
      if (!data) return resolve({})
      let parsed
      try { parsed = JSON.parse(data) } catch {
        const error = new Error('invalid JSON')
        error.statusCode = 400
        reject(error)
        return
      }
      // null is valid JSON, and reading .alias from it threw: the caller got a
      // 500 carrying "Cannot read properties of null (reading 'alias')" for a
      // request the server could have refused in one sentence.
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        const error = new Error('body must be a JSON object')
        error.statusCode = 400
        reject(error)
        return
      }
      resolve(parsed)
    })
    req.on('error', reject)
  })
}

let idleTimer
function touch() {
  clearTimeout(idleTimer)
  idleTimer = setTimeout(() => {
    console.log('')
    console.log('闲置 ' + idleWords(idleMs) + '，已退出。')
    process.exit(0)
  }, idleMs)
  idleTimer.unref()
}

/**
 * Constant-time token comparison.
 *
 * '===' on a secret leaks its length and prefix through timing; the token is
 * the only thing between another local process and the saved credentials, so
 * it is worth comparing the way the cryptography library does.
 */
function tokenMatches(candidate) {
  if (typeof candidate !== 'string') return false
  const given = Buffer.from(candidate)
  const expected = Buffer.from(token)
  if (given.length !== expected.length) return false
  return timingSafeEqual(given, expected)
}

/** API calls must carry the token in the header. */
const authorized = (req) => tokenMatches(req.headers['x-gui-token'])

/**
 * The page itself may be opened with ?t=... -- that is the URL printed at
 * startup. The query form is NOT accepted by the API: a URL pasted into a chat
 * or a browser history should not hand over write access to the credential file.
 */
const pageAuthorized = (req, url) => authorized(req) || tokenMatches(url.searchParams.get('t'))

/** The endpoints that rewrite credentials.json: each one needs the store lock. */
const WRITE_ENDPOINTS = new Set(['/api/save', '/api/delete', '/api/clear-password', '/api/clear-key-passphrase'])

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1')

  // Belt and braces: only answer a Host that points at this machine.
  if (!/^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/.test(String(req.headers.host || ''))) {
    res.writeHead(421)
    return res.end('misdirected request')
  }

  // Declared outside the try: a const inside it is invisible to the finally.
  let lock = null
  let lockWarning = ''
  try {
    if (req.method === 'GET' && url.pathname === '/') {
      if (!pageAuthorized(req, url)) {
        res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' })
        return res.end('forbidden: open the URL printed by the command')
      }
      const html = readFileSync(path.join(here, 'gui.html'), 'utf8')
        .replace('__TOKEN__', token)
        .replace(/__IDLE__/g, idleWords(idleMs))
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      return res.end(html)
    }

    if (!authorized(req)) return sendJson(res, 403, { error: 'forbidden' })
    // Only an authenticated request keeps the page alive; a scanner that probes
    // the port must not be able to postpone the idle exit.
    touch()
    const body = req.method === 'POST' ? await readBody(req) : {}
    // Four endpoints rewrite credentials.json; they read, mutate and write, and a
    // second page instance doing the same at the same moment silently lost one of
    // the two saves. Hold a cross-process lock for the whole request.
    const writeApi = req.method === 'POST' && WRITE_ENDPOINTS.has(url.pathname)
    if (writeApi) {
      // The directory may not exist on the first save; the lock lives in it, and a
      // failure here must not turn a save that writeStore() can still explain into a
      // bare 500.
      try {
        mkdirSync(path.dirname(credFile), { recursive: true })
        lock = acquireStoreLock(credFile)
      } catch {
        lock = null
      }
      // The page has to know too: its reply said 'saved' while another writer may have
      // been holding the file. The console line never reaches the person looking at the
      // form.
      if (lock && lock.timedOut) {
        lockWarning = '另一个进程长时间持有凭据文件锁，本次保存没有加锁：对方同时保存的修改可能被覆盖。'
        console.log('  ' + lockWarning)
      } else if (!lock) {
        lockWarning = '无法创建凭据文件锁（目录或权限问题），本次保存没有加锁：并发保存可能互相覆盖。'
      }
    }

    if (req.method === 'GET' && url.pathname === '/api/state') {
      return sendJson(res, 200, { ...state(), fileProblem: storeProblem() })
    }

    if (req.method === 'POST' && url.pathname === '/api/save') {
      const parsedAlias = parseAlias(body.alias)
      if (parsedAlias.error) return sendJson(res, 400, { error: parsedAlias.error })
      const alias = parsedAlias.alias
      if (RESERVED_ALIASES.has(alias)) {
        return sendJson(res, 400, { error: '别名 "' + alias + '" 与 JavaScript 内置属性冲突，无法保存，请换一个名字' })
      }
      const problem = storeProblem()
      if (problem) {
        return sendJson(res, 409, { error: problem + '——为避免把它整个覆盖掉，本页不会写入。请先修正语法，或把文件移走再回来。' })
      }
      const store = readStore()
      const entry = { ...(store[alias] && typeof store[alias] === 'object' ? store[alias] : {}) }
      const warnings = []
      if (!settingsUseCredentialFile()) {
        warnings.push('设置里 useCredentialFile 为 false：本页保存的内容插件不会读取，请在设置里改为 true 或改用环境变量')
      }

      // Every field must be text. String({a:1}) is '[object Object]', and that
      // was written to the file as the host name -- the plugin then dialled a
      // machine called [object Object]. Same for a boolean port: Number(true)
      // is 1, a valid port, so it saved silently as port 1.
      for (const field of ['host', 'user', 'keyPath', 'password']) {
        const value = body[field]
        if (value === undefined || value === null || value === '') continue
        if (typeof value !== 'string') {
          return sendJson(res, 400, { error: field + ' 必须是字符串（收到 ' + (Array.isArray(value) ? 'array' : typeof value) + '）' })
        }
      }
      if (body.port !== undefined && body.port !== null && body.port !== '') {
        if (typeof body.port !== 'string' && typeof body.port !== 'number') {
          return sendJson(res, 400, { error: '端口必须是 1-65535 的整数（收到 ' + (Array.isArray(body.port) ? 'array' : typeof body.port) + '）' })
        }
      }

      if (filled(body.host)) entry.host = String(body.host).trim()
      // 0 means 'not set' in the plugin (the settings form uses it that way since
      // 0.7.332), so refusing it here quoted a rule the plugin does not have: a
      // caller normalising 'no port' to 0 was rejected while the same 0 in the
      // settings form simply falls back to 22.
      const portAsked = filled(body.port) && Number(body.port) !== 0
      if (portAsked) {
        const port = Number(body.port)
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          return sendJson(res, 400, { error: '端口必须是 1-65535 的整数' })
        }
        entry.port = port
      }
      if (filled(body.user)) entry.user = String(body.user).trim()
      if (filled(body.keyPath)) entry.keyPath = String(body.keyPath).trim()

      if (filled(body.password)) {
        if (!dpapiAvailable()) {
          return sendJson(res, 400, { error: '当前平台没有 DPAPI，请改用环境变量' })
        }
        entry.passwordDpapi = encryptDpapi(String(body.password))
        delete entry.password
      }

      // The settings form outranks this file for host/port/user. Say so rather
      // than let an edit look saved and then lose.
      const settings = settingsMachines()
      const fromSettings = settings[alias] || {}
      if (fromSettings.host && filled(body.host) && String(body.host).trim() !== String(fromSettings.host)) {
        warnings.push('该别名的 host 在 DSH 设置界面里定义，优先于本页；要改 host 请改设置')
      }
      if (fromSettings.user && filled(body.user) && String(body.user).trim() !== String(fromSettings.user)) {
        warnings.push('该别名的 user 在 DSH 设置界面里定义，优先于本页')
      }
      // The comment above says host/port/user, and the port was missing: a saved
      // 2222 lost to the settings 2200 without a word.
      if (fromSettings.port && filled(body.port) && Number(body.port) !== Number(fromSettings.port)) {
        warnings.push('该别名的 port 在 DSH 设置界面里定义，优先于本页；要改 port 请改设置')
      }

      store[alias] = entry
      writeStore(store)
      if (lockWarning) warnings.push(lockWarning)
      return sendJson(res, 200, { ok: true, warnings })
    }

    if (req.method === 'POST' && url.pathname === '/api/delete') {
      // Same rule as save: stripping "gpu/1" to "gpu1" deleted a different
      // machine's credentials, and testing it reported on that other machine.
      const parsedAlias = parseAlias(body.alias)
      if (parsedAlias.error) return sendJson(res, 400, { error: parsedAlias.error })
      const alias = parsedAlias.alias
      const problem = storeProblem()
      if (problem) {
        return sendJson(res, 409, { error: problem + '——为避免把它整个覆盖掉，本页不会写入。请先修正语法，或把文件移走再回来。' })
      }
      const store = readStore()
      const removed = Boolean(store[alias])
      if (removed) {
        delete store[alias]
        writeStore(store)
      }
      // A machine defined in the settings form is not in this file, so the row
      // stayed on the page after "已删除". Say which source still defines it.
      const warnings = []
      const settings = settingsMachines()[alias]
      if (settings && (settings.host || settings.user)) {
        warnings.push(removed
          ? '已删除凭据文件里的记录；该别名在 DSH 设置界面里也有定义，仍然可用，要移除请改设置'
          : '凭据文件里没有该别名的记录；它来自 DSH 设置界面，要从这里移除请改设置')
      }
      // Environment variables are a third source, and the row stays on the page
      // after a delete for the same reason: deleting from the file cannot remove
      // something the file never held.
      if (envAliases().includes(alias)) {
        warnings.push(removed
          ? '已删除凭据文件里的记录；该别名也由环境变量提供（' + envNames(alias).host + ' 一类），仍然可用'
          : '凭据文件里没有该别名的记录；它来自环境变量（' + envNames(alias).host + ' 一类），本页删不掉，要移除请改启动环境')
      }
      if (!removed && !warnings.length) {
        warnings.push('凭据文件里没有该别名的记录，没有可删除的内容')
      }
      if (lockWarning) warnings.push(lockWarning)
      return sendJson(res, 200, { ok: true, removed, warnings })
    }

    if (req.method === 'POST' && url.pathname === '/api/clear-password') {
      // The page could store a password but never remove one: saving without a
      // password means "leave it alone", so a stored DPAPI blob could only be
      // revoked through the CLI or by editing the file.
      const parsedAlias = parseAlias(body.alias)
      if (parsedAlias.error) return sendJson(res, 400, { error: parsedAlias.error })
      const alias = parsedAlias.alias
      const problem = storeProblem()
      if (problem) {
        return sendJson(res, 409, { error: problem + '——为避免把它整个覆盖掉，本页不会写入。请先修正语法，或把文件移走再回来。' })
      }
      const store = readStore()
      const entry = store[alias] && typeof store[alias] === 'object' ? store[alias] : null
      const warnings = []
      if (!entry || (!entry.password && !entry.passwordDpapi)) {
        // Not an error: the row may get its password from the environment or the
        // settings form, which this file cannot remove.
        const envs = envAliases()
        if (envs.includes(alias)) {
          warnings.push('凭据文件里没有该别名的密码；它来自环境变量（' + envNames(alias).password + ' 一类），要移除请改启动环境')
        }
        return sendJson(res, 200, { ok: true, cleared: false, warnings: warnings.length ? warnings : ['凭据文件里没有该别名的已存密码'] })
      }
      delete entry.password
      delete entry.passwordDpapi
      let removedEntry = false
      if (Object.keys(entry).length === 0) {
        delete store[alias]
        removedEntry = true
      } else {
        store[alias] = entry
      }
      writeStore(store)
      const settings = settingsMachines()[alias]
      if (settings && (settings.password || settings.privateKey)) {
        warnings.push('已清除凭据文件里的密码；该别名在 DSH 设置界面里也提供了凭据，仍然可用，要移除请改设置')
      }
      if (lockWarning) warnings.push(lockWarning)
      return sendJson(res, 200, { ok: true, cleared: true, removedEntry, warnings })
    }

    if (req.method === 'POST' && url.pathname === '/api/clear-key-passphrase') {
      // --clear-key-passphrase existed in the CLI and not on the page, so a
      // passphrase stored from the page could only be revoked from a terminal.
      const parsedAlias = parseAlias(body.alias)
      if (parsedAlias.error) return sendJson(res, 400, { error: parsedAlias.error })
      const alias = parsedAlias.alias
      const problem = storeProblem()
      if (problem) {
        return sendJson(res, 409, { error: problem + '——为避免把它整个覆盖掉，本页不会写入。请先修正语法，或把文件移走再回来。' })
      }
      const store = readStore()
      const entry = store[alias] && typeof store[alias] === 'object' ? store[alias] : null
      if (!entry || (!entry.keyPassphrase && !entry.keyPassphraseDpapi)) {
        return sendJson(res, 200, { ok: true, cleared: false, warnings: ['凭据文件里没有该别名的已存口令'] })
      }
      delete entry.keyPassphrase
      delete entry.keyPassphraseDpapi
      let removedEntry = false
      if (Object.keys(entry).length === 0) {
        delete store[alias]
        removedEntry = true
      } else {
        store[alias] = entry
      }
      writeStore(store)
      const warnings = []
      if (removedEntry) warnings.push('该条目只剩口令，已一并删除')
      if (lockWarning) warnings.push(lockWarning)
      return sendJson(res, 200, { ok: true, cleared: true, removedEntry, warnings })
    }

    if (req.method === 'POST' && url.pathname === '/api/test') {
      const parsedAlias = parseAlias(body.alias)
      if (parsedAlias.error) return sendJson(res, 400, { error: parsedAlias.error })
      const alias = parsedAlias.alias
      if (RESERVED_ALIASES.has(alias)) {
        return sendJson(res, 400, { error: '别名 "' + alias + '" 与 JavaScript 内置属性冲突，请换一个名字' })
      }
      return sendJson(res, 200, await testConnection(alias))
    }

    if (req.method === 'POST' && url.pathname === '/api/shutdown') {
      sendJson(res, 200, { ok: true })
      setTimeout(() => process.exit(0), 120)
      return
    }

    sendJson(res, 404, { error: 'not found' })
  } catch (err) {
    // A malformed request is the caller's mistake (400/413); anything else is
    // this server's (500). Both still answer, so the page can show why.
    const status = err && Number.isInteger(err.statusCode) ? err.statusCode : 500
    sendJson(res, status, { error: String((err && err.message) || err).slice(0, 200) })
  } finally {
    // Released on every path, including the early returns and a thrown error.
    if (lock) lock.release()
  }
})

// A crashed save may have left credentials.json.tmp-<pid> behind with every
// password in it. Sweep here, after the constants it uses are initialised: running
// it beside credFile hit the temporal dead zone of STALE_TMP_MS and the error was
// swallowed by the per-file try/catch.
const sweptTemps = sweepStaleTemps()

server.listen(port, '127.0.0.1', () => {
  const actual = server.address().port
  const url = 'http://127.0.0.1:' + actual + '/?t=' + token
  touch()
  console.log('')
  console.log('  dsh-ssh-safe 机器与凭据')
  console.log('  ' + url)
  console.log('')
  console.log('  凭据文件: ' + credFile)
  if (sweptTemps.length > 0) {
    console.log('  已清理上次写入残留的临时文件: ' + sweptTemps.join(', '))
  }
  console.log('  DPAPI 加密: ' + (dpapiAvailable() ? '可用' : '不可用（请改用环境变量）'))
  console.log('  关闭页面即退出；闲置 ' + idleWords(idleMs) + '也会退出。')
  console.log('')
  if (!args['no-open']) {
    const opener = process.platform === 'win32'
      ? ['cmd', ['/c', 'start', '', url]]
      : process.platform === 'darwin'
        ? ['open', [url]]
        : ['xdg-open', [url]]
    try { spawn(opener[0], opener[1], { detached: true, stdio: 'ignore', windowsHide: true }).unref() } catch { /* print only */ }
  }
})

server.on('error', (err) => {
  // A taken port is the one startup failure the user can fix in a second, and the
  // raw errno ('listen EADDRINUSE: address already in use') says nothing about how.
  const code = err && err.code
  if (code === 'EADDRINUSE') {
    console.error('无法启动: 端口 127.0.0.1:' + port + ' 已被占用。换一个 --port，或把 --port 设为 0 让系统挑空闲端口。')
    process.exit(1)
  }
  if (code === 'EACCES') {
    console.error('无法启动: 没有权限监听端口 127.0.0.1:' + port + '（1024 以下的端口通常需要管理员）。换一个 1024 以上的端口。')
    process.exit(1)
  }
  console.error('无法启动: ' + err.message)
  process.exit(1)
})
