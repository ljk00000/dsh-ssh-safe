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

import { spawn } from 'node:child_process'
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { createServer } from 'node:http'
import { createRequire } from 'node:module'
import { networkInterfaces } from 'node:os'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import { connectOptions } from '../src/connect.js'
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
function settingsMachines() {
  const file = path.join(profileDir, 'cordis.patch.yml')
  let text
  try { text = readFileSync(file, 'utf8') } catch { return {} }
  const lines = text.split(/\r?\n/)
  const start = lines.findIndex((line) => /^\s*-\s*id:\s*dsh-ssh-safe\s*$/.test(line))
  if (start < 0) return {}
  const entryIndent = (lines[start].match(/^\s*/) || [''])[0].length

  let end = lines.length
  for (let i = start + 1; i < lines.length; i++) {
    const indent = (lines[i].match(/^\s*/) || [''])[0].length
    if (indent === entryIndent && /^\s*-\s*id:/.test(lines[i])) { end = i; break }
  }

  const block = lines.slice(start, end)
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
      let value = pair[2].trim()
      if (value === '' || value === 'null' || value === '~') continue
      value = value.replace(/^["']|["']$/g, '')
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

function writeStore(store) {
  mkdirSync(path.dirname(credFile), { recursive: true })
  writeFileSync(credFile, JSON.stringify(store, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 })
  if (process.platform === 'win32') {
    const me = process.env.USERDOMAIN && process.env.USERNAME
      ? process.env.USERDOMAIN + '\\' + process.env.USERNAME
      : process.env.USERNAME
    try {
      spawn('icacls', [credFile, '/inheritance:r', '/grant:r', me + ':(R,W)', '/grant:r', 'SYSTEM:(R,W)'],
        { windowsHide: true, stdio: 'ignore' })
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
  const fromDisk = Object.keys(readStore())
  const aliases = [...new Set([...fromDisk, ...Object.keys(settings), ...envAliases()])].sort()
  const machines = aliases.map((alias) => {
    const m = machineDefinition(alias, { machines: settings, dshHome })
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
    }
  })
  return {
    credentialFile: credFile,
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
  const m = machineDefinition(alias, { machines: settings, dshHome })
  const lines = []
  const say = (stage, verdict, detail) =>
    lines.push('[' + verdict + '] ' + stage + (detail ? ': ' + detail : ''))
  const finish = (ok) => ({ ok, lines })

  if (!m.host || !m.username) {
    say('配置', 'FAIL', '缺少主机或用户，请在上方填写后保存')
    return finish(false)
  }
  say('配置', 'ok', m.username + '@' + m.host + ':' + m.port)

  const tcp = await tcpProbe(m.host, m.port, 8000)
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
  const auth = credentialFor(alias, { machines: settings, dshHome, useAgent: false })
  for (const warning of auth.warnings || []) say('凭据', 'warn', warning)

  return await new Promise((resolve) => {
    const client = new ssh2.Client()
    let fingerprint = ''
    let settled = false
    const done = (ok) => {
      if (settled) return
      settled = true
      try { client.end() } catch {}
      resolve(finish(ok))
    }
    const timer = setTimeout(() => {
      say('认证', 'FAIL', '在 20 秒内没有完成握手')
      done(false)
    }, 20000)

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
      config = connectOptions(m, auth, { readyTimeout: 15000, keepaliveInterval: 0 })
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
      // Report, do not record: a test must not change the trust state.
      try {
        fingerprint = 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/, '')
        say('主机密钥', 'ok', fingerprint + '（仅报告，未记录；正式连接用 ssh_connect）')
      } catch { /* ignore */ }
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
    req.on('data', (chunk) => {
      data += chunk
      if (data.length > 64 * 1024) { reject(new Error('body too large')); req.destroy() }
    })
    req.on('end', () => {
      if (!data) return resolve({})
      try { resolve(JSON.parse(data)) } catch { reject(new Error('invalid JSON')) }
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
      return sendJson(res, 200, state())
    }

    if (req.method === 'POST' && url.pathname === '/api/save') {
      const alias = aliasOf(body.alias)
      if (!alias) return sendJson(res, 400, { error: '别名不能为空' })
      if (RESERVED_ALIASES.has(alias)) {
        return sendJson(res, 400, { error: '别名 "' + alias + '" 与 JavaScript 内置属性冲突，无法保存，请换一个名字' })
      }
      const store = readStore()
      const entry = { ...(store[alias] && typeof store[alias] === 'object' ? store[alias] : {}) }
      const warnings = []

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

      store[alias] = entry
      writeStore(store)
      return sendJson(res, 200, { ok: true, warnings })
    }

    if (req.method === 'POST' && url.pathname === '/api/delete') {
      const alias = aliasOf(body.alias)
      const store = readStore()
      if (store[alias]) {
        delete store[alias]
        writeStore(store)
      }
      return sendJson(res, 200, { ok: true })
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
    sendJson(res, 500, { error: String((err && err.message) || err).slice(0, 200) })
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
