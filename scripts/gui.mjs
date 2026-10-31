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
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import { connectOptions } from '../src/connect.js'
import { checkHostKey } from '../src/hostkey.js'
import { expandHome } from '../src/pool.js'
import { dpapiAvailable, encryptDpapi } from '../src/dpapi.js'
import { credentialFor, credentialState, credentialsPath, machineDefinition } from '../src/machines.js'

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
const dshHome = path.resolve(String(args['dsh-home'] || process.env.DSH_HOME || path.join(process.env.USERPROFILE || process.env.HOME || '.', '.dsh')))
const profileDir = path.resolve(String(args.profile || path.join(dshHome, 'profiles', 'desktop')))
const idleMs = Number(args['idle-ms'] || 10 * 60 * 1000)
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
  const start = lines.findIndex((line) => /^\s*-\s*id:\s*dsh-ssh-safe\s*$/.test(line))
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
function settingsHostKeyPolicy() {
  const block = pluginBlock()
  if (!block) return 'strict'
  for (const line of block) {
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

function settingsMachines() {
  const block = pluginBlock()
  if (!block) return {}
  const machinesAt = block.findIndex((line) => /^\s*machines:\s*$/.test(line))
  if (machinesAt < 0) return {}
  const machinesIndent = (block[machinesAt].match(/^\s*/) || [''])[0].length

  const machines = {}
  let current = ''
  for (let i = machinesAt + 1; i < block.length; i++) {
    const line = block[i]
    if (!line.trim() || /^\s*#/.test(line)) continue
    const indent = (line.match(/^\s*/) || [''])[0].length
    if (indent <= machinesIndent) break

    const alias = line.match(/^\s*([\w.-]+):\s*$/)
    if (alias && indent === machinesIndent + 2) {
      current = alias[1].toLowerCase()
      machines[current] = {}
      continue
    }
    const pair = line.match(/^\s*([\w.-]+):\s*(.*)$/)
    if (pair && current && indent > machinesIndent + 2) {
      let value = parseScalar(pair[2])
      if (value === '' || value === 'null' || value === '~') continue
      if (/^\d+$/.test(value)) value = Number(value)
      if (value === 'true') value = true
      if (value === 'false') value = false
      machines[current][pair[1]] = value
    }
  }
  return machines
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
    return { error: '别名只能用字母、数字、点、下划线、连字符（收到 ' + JSON.stringify(raw) + '）' }
  }
  return { alias }
}

/** The alias a request refers to, normalised the same way. */
const aliasOf = (value) => String(value || '').trim().toLowerCase().replace(/[^a-z0-9._-]/g, '')

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

function writeStore(store) {
  mkdirSync(path.dirname(credFile), { recursive: true })
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
  const settings = settingsMachines()
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
  }
}

// ---- connection test -------------------------------------------------------

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
  if (!fileEnabled) {
    say('凭据文件', 'warn', '设置里 useCredentialFile 为 false，本页保存的密码/主机不会被插件读取')
  }

  if (!m.host || !m.username) {
    say('配置', 'FAIL', '缺少主机或用户，请在上方填写后保存')
    return finish(false)
  }
  if (m.portProblem) {
    // Report the value the plugin will use for the connection, which is not the
    // one in the settings form: a '[ok] 配置' line here claims a working setup.
    say('配置', 'FAIL', '端口无效：' + m.portProblem + '（设置界面里写的是 ' + String(m.portRaw ?? '') + '）— 正式连接会失败')
    return finish(false)
  }
  say('配置', 'ok', m.username + '@' + m.host + ':' + m.port)

  const connectTimeoutMs = settingsConnectTimeoutMs()
  const tcp = await tcpProbe(m.host, m.port, connectTimeoutMs)
  say('TCP', tcp.ok ? 'ok' : 'FAIL', tcp.detail)
  if (!tcp.ok) {
    lines.push('', '已停止：主机不可达，无法测试认证。')
    return finish(false)
  }

  const ssh2 = loadSsh2()
  if (!ssh2) {
    say('认证', 'FAIL', '找不到 ssh2 模块，无法做完整测试（请先安装插件依赖）')
    return finish(false)
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
          say('命令通道', 'FAIL', err.message.slice(0, 120))
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
      say('凭据', 'FAIL', '私钥读取失败：' + String(err.message).slice(0, 100))
      return done(false)
    }
    if (!config.password && !config.privateKey && !config.agent) {
      clearTimeout(timer)
      say('凭据', 'FAIL', '没有可用的密码或私钥，请在上方填写密码后保存')
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
        if (verdict.ok) {
          say('主机密钥', 'ok', fingerprint + '（已记录，校验通过；本页不修改记录）')
        } else if (/^HOST KEY CHANGED/.test(String(verdict.reason))) {
          mismatched = true
          say('主机密钥', 'FAIL', fingerprint + ' 与记录的指纹不一致，正式连接会被拒绝（可能是重装，也可能是中间人）')
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
      try { resolve(JSON.parse(data)) } catch {
        const error = new Error('invalid JSON')
        error.statusCode = 400
        reject(error)
      }
    })
    req.on('error', reject)
  })
}

let idleTimer
function touch() {
  clearTimeout(idleTimer)
  idleTimer = setTimeout(() => {
    console.log('')
    console.log('闲置 ' + Math.round(idleMs / 60000) + ' 分钟，已退出。')
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

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1')

  // Belt and braces: only answer a Host that points at this machine.
  if (!/^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/.test(String(req.headers.host || ''))) {
    res.writeHead(421)
    return res.end('misdirected request')
  }

  try {
    if (req.method === 'GET' && url.pathname === '/') {
      if (!pageAuthorized(req, url)) {
        res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' })
        return res.end('forbidden: open the URL printed by the command')
      }
      const html = readFileSync(path.join(here, 'gui.html'), 'utf8')
        .replace('__TOKEN__', token)
        .replace(/__IDLE__/g, String(Math.round(idleMs / 60000)))
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      return res.end(html)
    }

    if (!authorized(req)) return sendJson(res, 403, { error: 'forbidden' })
    // Only an authenticated request keeps the page alive; a scanner that probes
    // the port must not be able to postpone the idle exit.
    touch()
    const body = req.method === 'POST' ? await readBody(req) : {}

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
      if (filled(body.port)) {
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
      return sendJson(res, 200, { ok: true, warnings })
    }

    if (req.method === 'POST' && url.pathname === '/api/delete') {
      const alias = aliasOf(body.alias)
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
      if (!removed && !warnings.length) {
        warnings.push('凭据文件里没有该别名的记录，没有可删除的内容')
      }
      return sendJson(res, 200, { ok: true, removed, warnings })
    }

    if (req.method === 'POST' && url.pathname === '/api/test') {
      const alias = aliasOf(body.alias)
      if (!alias) return sendJson(res, 400, { error: '别名不能为空' })
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
  }
})

const port = Number(args.port || 0)
server.listen(port, '127.0.0.1', () => {
  const actual = server.address().port
  const url = 'http://127.0.0.1:' + actual + '/?t=' + token
  touch()
  console.log('')
  console.log('  dsh-ssh-safe 机器与凭据')
  console.log('  ' + url)
  console.log('')
  console.log('  凭据文件: ' + credFile)
  console.log('  DPAPI 加密: ' + (dpapiAvailable() ? '可用' : '不可用（请改用环境变量）'))
  console.log('  关闭页面即退出；闲置 ' + Math.round(idleMs / 60000) + ' 分钟也会退出。')
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
  console.error('无法启动: ' + err.message)
  process.exit(1)
})
