import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { request as httpRequest } from 'node:http'
import { startServer } from './helpers/local-ssh-server.js'
import { mkdirSync, writeFileSync, utimesSync } from 'node:fs'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { dpapiAvailable } from '../src/dpapi.js'
import { SshPool } from '../src/pool.js'
import { machineFor, alternateHostKey, testHostKey, testKeyPair } from './helpers/local-ssh-server.js'

// The page is a separate process on purpose: the plugin keeps no listening
// socket. These tests drive the real server, so they cover the parts that matter
// beyond the UI: the token check, that a saved password never comes back out of
// any endpoint, and that a test-connection failure is reported instead of thrown.

const here = path.dirname(fileURLToPath(import.meta.url))
const script = path.join(here, '..', 'scripts', 'gui.mjs')

/**
 * Ports undici (and therefore fetch) refuses to connect to, from the Fetch spec's
 * "bad port" list. The server asks for port 0, so the OS can hand out one of
 * these: fetch then fails with "bad port" and the test looks like a server bug.
 * Only the ephemeral-range entries matter, but the whole list is cheap.
 */
const BAD_PORTS = new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102, 103, 104,
  109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515,
  526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049,
  3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080,
])

/** Start the server, wait for the URL it prints, hand back the token. */
function start(home, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, '--no-open', '--port', '0',
      '--dsh-home', home, '--idle-ms', String(options.idleMs || 60000)], { stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    const timer = setTimeout(() => {
      child.kill()
      reject(new Error('server did not print a URL in time'))
    }, 15000)
    child.stdout.on('data', (chunk) => {
      out += chunk.toString('utf8')
      const match = out.match(/http:\/\/127\.0\.0\.1:(\d+)\/\?t=([0-9a-f]+)/)
      if (match) {
        clearTimeout(timer)
        if (BAD_PORTS.has(Number(match[1]))) {
          // Retry on another port rather than failing a test the code did not
          // break: the OS handed out one fetch refuses to talk to.
          child.kill()
          resolve(start(home, options))
          return
        }
        resolve({ child, base: 'http://127.0.0.1:' + match[1], token: match[2], output: () => out })
      }
    })
    child.stderr.on('data', (chunk) => { out += chunk.toString('utf8') })
    child.on('exit', (code) => {
      if (code !== 0) {
        clearTimeout(timer)
        reject(new Error('server exited ' + code + ': ' + out.slice(0, 400)))
      }
    })
  })
}

const call = async (base, token, route, body) => {
  const res = await fetch(base + route, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'content-type': 'application/json', 'x-gui-token': token },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() }
}

test('the page is served only with the token', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    const noToken = await fetch(base + '/')
    assert.equal(noToken.status, 403, 'a bare URL must be refused')

    const withToken = await fetch(base + '/?t=' + token)
    assert.equal(withToken.status, 200)
    const html = await withToken.text()
    assert.match(html, /dsh-ssh-safe/)
    assert.doesNotMatch(html, /__TOKEN__/, 'the placeholder is replaced')
    assert.match(html, /DPAPI/, 'the page explains how passwords are stored')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a query-string token opens the page but not the API', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    // The startup URL is a ?t= link. It must keep working for the page itself,
    // and must not become a way to call the API -- a URL that ends up in a chat
    // log or browser history should not carry write access to the credentials.
    const page = await fetch(base + '/?t=' + token)
    assert.equal(page.status, 200)

    const state = await fetch(base + '/api/state?t=' + token)
    assert.equal(state.status, 403, 'the API must require the header')

    const save = await fetch(base + '/api/save?t=' + token, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ alias: 'x', host: 'h', user: 'u' }),
    })
    assert.equal(save.status, 403)
    assert.equal(existsSync(path.join(home, 'dsh-ssh-safe', 'credentials.json')), false)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('an API call without the token is refused', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base } = await start(home)
  try {
    const res = await fetch(base + '/api/state')
    assert.equal(res.status, 403)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('state starts empty and names the credential file', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    const s = await call(base, token, '/api/state')
    assert.equal(s.status, 200)
    assert.deepEqual(s.body.machines, [])
    assert.match(s.body.credentialFile, /credentials\.json$/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a saved machine shows up without its password', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    const saved = await call(base, token, '/api/save', {
      alias: 'gpu', host: 'h.example.com', port: '2222', user: 'root',
    })
    assert.equal(saved.status, 200)

    const s = await call(base, token, '/api/state')
    const machine = s.body.machines.find((m) => m.alias === 'gpu')
    assert.ok(machine, 'the machine is listed')
    assert.equal(machine.host, 'h.example.com')
    assert.equal(machine.port, 2222)
    assert.equal(machine.username, 'root')
    // No endpoint may echo a secret; there is none yet, and none may appear later.
    assert.doesNotMatch(JSON.stringify(s.body), /passwordDpapi/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})


test('a credential file that does not parse is reported and never overwritten', async () => {
  // readStore() answers {} for a file it cannot parse, and a save then wrote the
  // page's single entry over the whole file: one missing comma cost every machine
  // in it, silently.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const dir = path.join(home, 'dsh-ssh-safe')
  mkdirSync(dir, { recursive: true })
  const file = path.join(dir, 'credentials.json')
  const broken = '{ this is not json with machines: { keep: { host: "keep.example" } }'
  writeFileSync(file, broken, 'utf8')
  const { child, base, token } = await start(home)
  try {
    const state = await call(base, token, '/api/state')
    assert.equal(state.status, 200, 'the page still loads')
    assert.match(String(state.body.fileProblem), /无法解析/, 'the state names the problem')
    const saved = await call(base, token, '/api/save', {
      alias: 'new', host: 'h.example', user: 'u', password: 'p',
    })
    assert.equal(saved.status, 409, 'the save is refused')
    assert.match(String(saved.body.error), /不会写入/)
    assert.equal(readFileSync(file, 'utf8'), broken, 'the file is untouched, byte for byte')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a slack credential file still saves and keeps its other entries', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const dir = path.join(home, 'dsh-ssh-safe')
  mkdirSync(dir, { recursive: true })
  const file = path.join(dir, 'credentials.json')
  writeFileSync(file, JSON.stringify({ keep: { host: 'keep.example', user: 'k' } }, null, 2), 'utf8')
  const { child, base, token } = await start(home)
  try {
    const saved = await call(base, token, '/api/save', {
      alias: 'new', host: 'h.example', user: 'u', password: 'p',
    })
    assert.equal(saved.status, 200)
    const after = JSON.parse(readFileSync(file, 'utf8'))
    assert.deepEqual(Object.keys(after).sort(), ['keep', 'new'])
    assert.equal(after.keep.host, 'keep.example')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a password is stored encrypted and never returned', { skip: dpapiAvailable() ? false : 'DPAPI is a Windows feature' }, async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    const secret = 'gui-secret-value'
    const saved = await call(base, token, '/api/save', {
      alias: 'gpu', host: 'h', user: 'u', password: secret,
    })
    assert.equal(saved.status, 200)
    assert.doesNotMatch(JSON.stringify(saved.body), new RegExp(secret))

    const file = path.join(home, 'dsh-ssh-safe', 'credentials.json')
    const raw = readFileSync(file, 'utf8')
    assert.doesNotMatch(raw, new RegExp(secret), 'the password is not on disk in readable form')
    assert.match(raw, /passwordDpapi/)

    const s = await call(base, token, '/api/state')
    const machine = s.body.machines.find((m) => m.alias === 'gpu')
    assert.equal(machine.passwordSource, 'file-dpapi')
    assert.doesNotMatch(JSON.stringify(s.body), new RegExp(secret), 'state never carries the value')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('an unreachable host is reported, not thrown', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    await call(base, token, '/api/save', { alias: 'dead', host: '127.0.0.1', port: '1', user: 'u' })
    const r = await call(base, token, '/api/test', { alias: 'dead' })
    assert.equal(r.status, 200, 'the endpoint answers even when the connection fails')
    assert.equal(r.body.ok, false)
    const text = r.body.lines.join('\n')
    assert.match(text, /\[FAIL\] TCP/)
    assert.match(text, /已停止/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('port 0 means "not set" here too, as it does in the plugin', async () => {
  // The page rejected 0 with '端口必须是 1-65535 的整数', a rule the plugin does not
  // have: the settings form uses 0 for 'unset' and the resolver falls back to 22.
  // A caller normalising 'no port' to 0 was refused while the same 0 in the form
  // worked.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-port0-'))
  const { child, base, token } = await start(home)
  try {
    const zero = await call(base, token, '/api/save', { alias: 'zero', host: 'h', port: 0, user: 'u' })
    assert.equal(zero.status, 200)
    const text = await call(base, token, '/api/save', { alias: 'text', host: 'h', port: '0', user: 'u' })
    assert.equal(text.status, 200)
    const saved = JSON.parse(readFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), 'utf8'))
    assert.equal('port' in saved.zero, false, 'port 0 must not be written as a port: ' + JSON.stringify(saved.zero))
    assert.equal('port' in saved.text, false, 'port "0" must not be written either')
    // A real value is still validated.
    const tooBig = await call(base, token, '/api/save', { alias: 'big', host: 'h', port: 70000, user: 'u' })
    assert.equal(tooBig.status, 400)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a bad port is rejected before anything is written', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    const r = await call(base, token, '/api/save', { alias: 'x', host: 'h', port: '99999', user: 'u' })
    assert.equal(r.status, 400)
    assert.equal(existsSync(path.join(home, 'dsh-ssh-safe', 'credentials.json')), false)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('delete removes the entry and keeps the others', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    await call(base, token, '/api/save', { alias: 'a', host: 'h', user: 'u' })
    await call(base, token, '/api/save', { alias: 'b', host: 'h', user: 'u' })
    await call(base, token, '/api/delete', { alias: 'a' })
    const s = await call(base, token, '/api/state')
    assert.deepEqual(s.body.machines.map((m) => m.alias), ['b'])
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('shutdown ends the process', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token, output } = await start(home)
  const exited = new Promise((resolve) => child.on('exit', resolve))
  try {
    await call(base, token, '/api/shutdown', {})
    const code = await Promise.race([
      exited,
      new Promise((resolve) => setTimeout(() => resolve('timeout'), 10000)),
    ])
    assert.equal(code, 0, 'it exits cleanly; output: ' + output().slice(0, 300))
  } finally {
    try { child.kill() } catch {}
    rmSync(home, { recursive: true, force: true })
  }
})

test('an alias that collides with Object.prototype is refused, not silently dropped', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    for (const alias of ['__proto__', 'constructor', 'prototype']) {
      const res = await call(base, token, '/api/save', { alias, host: 'h.example', user: 'u' })
      assert.equal(res.status, 400, alias + ' must be refused')
    }
    const state = await call(base, token, '/api/state')
    assert.deepEqual(state.body.machines, [], 'nothing was saved')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})
test('a request for another Host is refused', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    // fetch() overwrites Host from the URL, so this needs the raw http client.
    const status = await new Promise((resolve, reject) => {
      const req = httpRequest({
        host: '127.0.0.1',
        port: Number(new URL(base).port),
        path: '/api/state',
        headers: { host: 'evil.example', 'x-gui-token': token },
      }, (res) => { res.resume(); resolve(res.statusCode) })
      req.on('error', reject)
      req.end()
    })
    assert.equal(status, 421, 'a Host header that is not this machine must be refused')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('saving a machine stores the password encrypted, never in plaintext', { skip: dpapiAvailable() ? false : 'DPAPI is a Windows feature' }, async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    const saved = await call(base, token, '/api/save', {
      alias: 'box', host: '10.0.0.9', port: 2222, user: 'root', password: 'plain-text-secret',
    })
    assert.equal(saved.status, 200, JSON.stringify(saved.body))
    assert.equal(saved.body.ok, true)

    const file = path.join(home, 'dsh-ssh-safe', 'credentials.json')
    const raw = readFileSync(file, 'utf8')
    assert.match(raw, /passwordDpapi/)
    assert.ok(!raw.includes('plain-text-secret'), 'the password must not be stored in plaintext')

    const state = await call(base, token, '/api/state')
    const box = state.body.machines.find((m) => m.alias === 'box')
    assert.ok(box, 'the machine should be listed')
    assert.equal(box.passwordSource, 'file-dpapi')
    assert.ok(!JSON.stringify(state.body).includes('plain-text-secret'), 'state must not carry the password')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('save validates the alias and the port', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    assert.equal((await call(base, token, '/api/save', { alias: '', host: 'h' })).status, 400)
    assert.equal((await call(base, token, '/api/save', { alias: '__proto__', host: 'h' })).status, 400)
    assert.equal((await call(base, token, '/api/save', { alias: 'p', host: 'h', port: 70000 })).status, 400)
    assert.equal((await call(base, token, '/api/save', { alias: 'p', host: 'h', port: 'abc' })).status, 400)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('delete removes an entry and state follows', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    await call(base, token, '/api/save', { alias: 'gone', host: '10.0.0.10' })
    const before = await call(base, token, '/api/state')
    assert.ok(before.body.machines.some((m) => m.alias === 'gone'))

    const deleted = await call(base, token, '/api/delete', { alias: 'gone' })
    assert.equal(deleted.status, 200)
    const after = await call(base, token, '/api/state')
    assert.ok(!after.body.machines.some((m) => m.alias === 'gone'))
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('unknown routes are 404 and malformed bodies are 400', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    assert.equal((await call(base, token, '/api/nope')).status, 404)
    const bad = await fetch(base + '/api/save', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-gui-token': token },
      body: '{not json',
    })
    assert.equal(bad.status, 400, 'a malformed body is the caller error')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})
test('two saves at the same time both survive', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    // save is read-modify-write over the credential file. Two requests can
    // interleave between the read and the write, and the second one would
    // overwrite the first entry if the handler is not serialised.
    const [one, two] = await Promise.all([
      call(base, token, '/api/save', { alias: 'alpha', host: '10.0.0.1', user: 'u' }),
      call(base, token, '/api/save', { alias: 'beta', host: '10.0.0.2', user: 'u' }),
    ])
    assert.equal(one.status, 200)
    assert.equal(two.status, 200)
    const raw = readFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), 'utf8')
    const store = JSON.parse(raw)
    assert.ok(store.alpha, 'alpha missing, keys: ' + JSON.stringify(Object.keys(store)))
    assert.ok(store.beta, 'beta missing, keys: ' + JSON.stringify(Object.keys(store)))
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})
test('an oversized body is refused with 413', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    const res = await fetch(base + '/api/save', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-gui-token': token },
      body: JSON.stringify({ alias: 'big', host: 'h', user: 'u', padding: 'x'.repeat(80 * 1024) }),
    }).catch(() => null)
    // The server destroys the socket once the cap is crossed, so the client may
    // see a reset instead of a response; either way nothing may be written.
    if (res) assert.equal(res.status, 413)
    assert.ok(!existsSync(path.join(home, 'dsh-ssh-safe', 'credentials.json')), 'nothing may be stored')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})
test('the test button walks every stage against a reachable server', { skip: dpapiAvailable() ? false : 'DPAPI is a Windows feature' }, async () => {
  const srv = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    const saved = await call(base, token, '/api/save', {
      alias: 'live', host: '127.0.0.1', port: srv.port, user: 'tester', password: 'test-pass',
    })
    assert.equal(saved.status, 200, JSON.stringify(saved.body))

    const tested = await call(base, token, '/api/test', { alias: 'live' })
    assert.equal(tested.status, 200)
    const text = tested.body.lines.join('\n')
    assert.equal(tested.body.ok, true, text)
    assert.match(text, /\[ok\] 配置/)
    assert.match(text, /\[ok\] TCP/)
    assert.match(text, /\[ok\] 认证/)
    assert.match(text, /\[ok\] 命令通道/)
    assert.match(text, /SHA256:/)
    // The page must state the truth about what the plugin will do with this key:
    // an unknown host is refused by ssh_connect, so it is a warning here, not an
    // "ok" that contradicts the next real call.
    assert.match(text, /\[warn\] 主机密钥/, text)
    assert.match(text, /本页不记录/, 'a test must not change the trust state')
    assert.equal(existsSync(path.join(home, 'dsh-ssh-safe', 'known_hosts.json')), false,
      'the test button wrote a trust record')
  } finally {
    child.kill()
    await srv.close()
    rmSync(home, { recursive: true, force: true })
  }
})

test('the test button reports an unreachable host instead of hanging', { skip: dpapiAvailable() ? false : 'DPAPI is a Windows feature' }, async () => {
  const dead = await startServer()
  const port = dead.port
  await dead.close()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    await call(base, token, '/api/save', { alias: 'gone', host: '127.0.0.1', port, user: 'tester', password: 'pw' })
    const tested = await call(base, token, '/api/test', { alias: 'gone' })
    assert.equal(tested.body.ok, false)
    const text = tested.body.lines.join('\n')
    assert.match(text, /\[FAIL\] TCP/, text)
    assert.match(text, /已停止/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})
test('an unauthenticated probe does not keep the page alive', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base } = await start(home, { idleMs: 1200 })
  const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)))
  try {
    // A scanner hitting the port must not be able to postpone the idle exit.
    await new Promise((r) => setTimeout(r, 400))
    await fetch(base + '/').catch(() => {})
    const code = await Promise.race([exited, new Promise((r) => setTimeout(() => r('timeout'), 5000))])
    assert.equal(code, 0, 'the page should still have exited on its own')
  } finally {
    try { child.kill() } catch {}
    rmSync(home, { recursive: true, force: true })
  }
})

test('an authenticated call keeps the page alive', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home, { idleMs: 1200 })
  const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)))
  try {
    // Touch it twice inside the window; the second call happens after the
    // original deadline, so only the first one can have extended it.
    await new Promise((r) => setTimeout(r, 500))
    await call(base, token, '/api/state')
    await new Promise((r) => setTimeout(r, 900))
    await call(base, token, '/api/state')
    const early = await Promise.race([exited, new Promise((r) => setTimeout(() => r('alive'), 300))])
    assert.equal(early, 'alive', 'the page must still be running after the touches')
  } finally {
    try { child.kill() } catch {}
    rmSync(home, { recursive: true, force: true })
  }
})
test('machines from the settings form are listed and outrank the file', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    hostKeyPolicy: tofu',
    '    machines:',
    '      formbox:',
    '        host: 10.1.2.3',
    '        port: 2200',
    '        user: root',
    '      emptybox:',
    '        host: ""',
    '- id: some-other-plugin',
    '  config: {}',
  ].join('\n'))
  const { child, base, token } = await start(home)
  try {
    const state = await call(base, token, '/api/state')
    const box = state.body.machines.find((m) => m.alias === 'formbox')
    assert.ok(box, 'settings machines must be listed: ' + JSON.stringify(state.body.machines))
    assert.equal(box.host, '10.1.2.3')
    assert.equal(box.port, 2200)
    assert.equal(box.username, 'root')
    assert.equal(box.fromSettings, true)
    const empty = state.body.machines.find((m) => m.alias === 'emptybox')
    assert.equal(empty.host, '', 'an empty host stays empty rather than becoming a string')

    // Saving a different host must warn that the settings form wins.
    const saved = await call(base, token, '/api/save', { alias: 'formbox', host: '10.9.9.9', user: 'admin' })
    assert.equal(saved.status, 200)
    assert.ok(saved.body.warnings.some((w) => w.includes('设置界面')), JSON.stringify(saved.body))
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a settings file with no plugin entry is simply ignored', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), '- id: unrelated\n  config: {}\n')
  const { child, base, token } = await start(home)
  try {
    const state = await call(base, token, '/api/state')
    assert.deepEqual(state.body.machines, [])
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('the test button gives up when connectTimeoutMs says so', async () => {
  // The page dialled with a hardcoded 15s readyTimeout, so a profile that sets
  // connectTimeoutMs: 3000 still made the caller wait 15 197 ms -- five times
  // longer than ssh_exec would. Measured before/after on the same black-hole port.
  const net = await import('node:net')
  const sockets = []
  const blackhole = net.createServer((socket) => { sockets.push(socket) })
  await new Promise((resolve) => blackhole.listen(0, '127.0.0.1', resolve))
  const port = /** @type {any} */ (blackhole.address()).port
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    connectTimeoutMs: 1200',
    '    allowPlaintextPassword: true',
  ].join('\n'))
  const { child, base, token } = await start(home)
  try {
    await call(base, token, '/api/save', { alias: 'quiet', host: '127.0.0.1', port, user: 'tester', password: 'pw' })
    const startedAt = Date.now()
    const tested = await call(base, token, '/api/test', { alias: 'quiet' })
    const took = Date.now() - startedAt
    const text = tested.body.lines.join('\n')
    assert.match(text, /handshake/i, text)
    assert.equal(tested.body.ok, false)
    assert.ok(took < 6000, 'the test button waited ' + took + ' ms with connectTimeoutMs: 1200')
  } finally {
    child.kill()
    for (const socket of sockets) { try { socket.destroy() } catch {} }
    await new Promise((resolve) => blackhole.close(resolve))
    rmSync(home, { recursive: true, force: true })
  }
})

test('the test button honours useCredentialFile: false', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    useCredentialFile: false',
  ].join('\n'))
  const { child, base, token } = await start(home)
  try {
    // The page can still store an entry; the plugin will not read it.
    await call(base, token, '/api/save', { alias: 'box', host: '10.0.0.9', user: 'root', password: 'pw' })
    const tested = await call(base, token, '/api/test', { alias: 'box' })
    assert.equal(tested.body.ok, false, 'a file the plugin ignores must not test green')
    const text = tested.body.lines.join('\n')
    assert.match(text, /useCredentialFile/)
    assert.match(text, /\[warn\] 凭据文件/)
    assert.match(text, /\[FAIL\] 配置/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})
test('saving replaces the credential file atomically', { skip: dpapiAvailable() ? false : 'DPAPI is a Windows feature' }, async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  const credFile = path.join(home, 'dsh-ssh-safe', 'credentials.json')
  try {
    for (let i = 0; i < 20; i++) {
      await call(base, token, '/api/save', { alias: 'm' + i, host: '10.0.0.' + i, user: 'root', password: 'pw' + i })
    }
    // Every save must leave exactly the target behind: no temp files, and a
    // file a reader in another process can parse at any moment.
    const dir = path.dirname(credFile)
    const left = readdirSync(dir).filter((name) => name.includes('.tmp-'))
    assert.deepEqual(left, [], 'no temporary files may survive a save')
    const parsed = JSON.parse(readFileSync(credFile, 'utf8'))
    assert.equal(Object.keys(parsed).length, 20)
    assert.equal(parsed.m19.host, '10.0.0.19')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})
test('an alias that cannot be used is refused, not silently rewritten', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    // Silently stripping used to store 'prodx' for 'prod/x' and 'ab' for 'a b',
    // so the page listed a machine the caller never typed.
    for (const alias of ['prod/x', 'a b', '服务器']) {
      const bad = await call(base, token, '/api/save', { alias, host: 'h', user: 'u', password: 'p' })
      assert.equal(bad.status, 400, alias + ' must be refused')
      // "字母" alone was wrong: ü is a letter and is refused. The message must say
    // which letters.
    assert.match(bad.body.error, /别名只能用 a-z 的英文字母、数字、点、下划线、连字符/)
    }

    // No password: this test is about the alias, and a save with one needs
    // DPAPI, which is Windows-only -- it would fail for an unrelated reason.
    const good = await call(base, token, '/api/save', { alias: ' Prod ', host: 'h', user: 'u' })
    assert.equal(good.status, 200, JSON.stringify(good.body))
    const listed = await call(base, token, '/api/state')
    const aliases = listed.body.machines.map((m) => m.alias)
    assert.deepEqual(aliases, ['prod'], 'only the trimmed, lower-cased alias is stored')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})
test('quoted values and trailing comments in the settings form parse like YAML', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    machines:',
    '      prod:',
    '        host: "10.0.0.5"          # quoted, with a comment',
    "        user: 'deploy'",
    '        port: "2222"',
    '        keyPath: /home/deploy/.ssh/id_rsa # comment after an unquoted value',
    '      odd:',
    String.raw`        user: "a\"b"`,
    '        host: 10.0.0.6 # comment',
  ].join('\n'))
  const { child, base, token } = await start(home)
  try {
    const state = await call(base, token, '/api/state')
    const prod = state.body.machines.find((m) => m.alias === 'prod')
    // This used to arrive as 10.0.0.5"   # quoted: the page showed, and the
    // test button tried, a host the plugin would never use.
    assert.equal(prod.host, '10.0.0.5')
    assert.equal(prod.username, 'deploy')
    assert.equal(prod.port, 2222, 'a quoted number is still a number')
    assert.equal(prod.keyPath, '/home/deploy/.ssh/id_rsa')
    const odd = state.body.machines.find((m) => m.alias === 'odd')
    assert.equal(odd.username, 'a"b', 'an escaped quote inside double quotes')
    assert.equal(odd.host, '10.0.0.6')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})
test('useCredentialFile: false hides the file and warns when saving', { skip: dpapiAvailable() ? false : 'DPAPI is a Windows feature' }, async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    useCredentialFile: false',
    '    machines:',
    '      formbox:',
    '        host: 10.1.2.3',
    '        user: root',
  ].join('\n'))
  mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
  writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
    ghost: { host: '9.9.9.9', user: 'g', password: 'p' },
  }))
  const { child, base, token } = await start(home)
  try {
    const state = await call(base, token, '/api/state')
    assert.equal(state.body.fileEnabled, false)
    const aliases = state.body.machines.map((m) => m.alias)
    assert.ok(aliases.includes('formbox'))
    assert.ok(!aliases.includes('ghost'), 'a disabled file must not contribute machines: ' + aliases.join(','))

    const saved = await call(base, token, '/api/save', { alias: 'formbox', host: '10.1.2.3', user: 'root', password: 'secret' })
    assert.equal(saved.status, 200)
    assert.ok(saved.body.warnings.some((w) => w.includes('useCredentialFile 为 false')), JSON.stringify(saved.body.warnings))
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})
test('a field that is not text is refused instead of stringified into the file', async () => {
  // String({a:1}) is '[object Object]', and that was written as the host name;
  // Number(true) is 1, a valid port, so a boolean port saved silently.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  const { child, base, token } = await start(home)
  try {
    const shapes = [
      { alias: 'a1', host: { a: 1 }, user: 'u' },
      { alias: 'a2', host: ['9.9.9.9'], user: 'u' },
      { alias: 'a3', host: 'h', port: true },
      { alias: 'a4', host: 'h', user: 42 },
      { alias: 'a5', host: 'h', user: 'u', keyPath: { p: 1 } },
    ]
    for (const shape of shapes) {
      const saved = await call(base, token, '/api/save', shape)
      assert.equal(saved.status, 400, JSON.stringify(shape) + ' must be refused')
      assert.match(saved.body.error, /必须是字符串|端口必须是/)
    }
    assert.equal(existsSync(path.join(home, 'dsh-ssh-safe', 'credentials.json')), false,
      'nothing may be written for a refused save')

    const ok = await call(base, token, '/api/save', { alias: 'good', host: '  10.0.0.5  ', user: ' deploy ', port: '2222' })
    assert.equal(ok.status, 200)
    const saved = JSON.parse(readFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), 'utf8'))
    assert.deepEqual(saved.good, { host: '10.0.0.5', user: 'deploy', port: 2222 })
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})
test('deleting a machine that the settings form defines says where it lives', { skip: dpapiAvailable() ? false : 'DPAPI is a Windows feature' }, async () => {
  // The row stayed on the page after a successful-looking delete: the entry
  // was never in this file to begin with.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    machines:',
    '      formonly:',
    '        host: 10.1.2.3',
    '        user: root',
  ].join('\n'))
  const { child, base, token } = await start(home)
  try {
    const onlySettings = await call(base, token, '/api/delete', { alias: 'formonly' })
    assert.equal(onlySettings.status, 200)
    assert.equal(onlySettings.body.removed, false)
    assert.ok(onlySettings.body.warnings.some((w) => w.includes('设置界面')), JSON.stringify(onlySettings.body))

    // Present in both sources: the file entry goes, the settings one stays.
    await call(base, token, '/api/save', { alias: 'formonly', host: '10.1.2.3', user: 'root', password: 'x' })
    const both = await call(base, token, '/api/delete', { alias: 'formonly' })
    assert.equal(both.body.removed, true)
    assert.ok(both.body.warnings.some((w) => w.includes('设置界面')), JSON.stringify(both.body))
    const state = await call(base, token, '/api/state')
    assert.ok(state.body.machines.some((m) => m.alias === 'formonly'), 'the settings machine is still there')

    const unknown = await call(base, token, '/api/delete', { alias: 'ghost' })
    assert.equal(unknown.body.removed, false)
    assert.ok(unknown.body.warnings.some((w) => w.includes('没有可删除的内容')), JSON.stringify(unknown.body))
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a body over the limit answers 413 instead of dropping the socket', async () => {
  // readBody called req.destroy() the moment the limit was crossed, so the 413
  // never reached the caller: the connection just closed. A 100 KB alias
  // produced 'other side closed' instead of a reason.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-large-'))
  const { child, base, token } = await start(home)
  try {
    const res = await fetch(base + '/api/save', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-gui-token': token },
      body: JSON.stringify({ alias: 'x'.repeat(100 * 1024), host: 'h', user: 'u' }),
    })
    assert.equal(res.status, 413)
    const body = await res.json()
    assert.match(body.error, /body too large/)

    // The server is still serving: the connection was dropped, not the process.
    const state = await fetch(base + '/api/state', { headers: { 'x-gui-token': token } })
    assert.equal(state.status, 200)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('the test button refuses to call a changed host key a pass', { skip: dpapiAvailable() ? false : 'DPAPI is a Windows feature' }, async () => {
  const first = await startServer()
  const port = first.port
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-hk-'))
  // Record the first key through the plugin's own store, then restart the server
  // with a different one: the page must not report a green result.
  const pool = new SshPool({
    hostKeyPolicy: 'tofu', allowPlaintextPassword: true, connectTimeoutMs: 3000,
    reconnectCooldownMs: 0, machines: { t: machineFor('t', port) },
  }, { dshHome: home })
  await pool.connect('t')
  await pool.closeAll({ force: true })
  await first.close()
  const second = await startServer({ port, key: alternateHostKey() })
  const { child, base: url, token } = await start(home)
  try {
    const saved = await call(url, token, '/api/save', {
      alias: 't', host: '127.0.0.1', port: String(port), user: 'tester', password: 'test-pass',
    })
    assert.equal(saved.status, 200, JSON.stringify(saved.body))
    const tested = await call(url, token, '/api/test', { alias: 't' })
    const text = tested.body.lines.join('\n')
    assert.match(text, /\[FAIL\] 主机密钥/, text)
    assert.match(text, /不一致/, text)
    assert.equal(tested.body.ok, false, 'a mismatched key must not read as a pass: ' + text)
  } finally {
    child.kill()
    await second.close()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a port that the settings form will override is announced on save', async () => {
  // The save warnings named host and user but not port, while the plugin gives
  // the settings form precedence over the file for all three: a saved 2222 lost
  // to the settings 2200 without a word.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-guiport-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    hostKeyPolicy: tofu',
    '    machines:',
    '      svc:',
    '        host: settings-host.example',
    '        port: 2200',
    '        user: settings-user',
    '- id: something-else',
    '  config: {}',
    ''].join('\n'))
  const { child, base: url, token } = await start(home, ['--profile', profile])
  try {
    const saved = await call(url, token, '/api/save', {
      alias: 'svc', host: 'page-host.example', port: '2222', user: 'page-user', password: 'pw',
    })
    assert.equal(saved.status, 200, JSON.stringify(saved.body))
    const text = saved.body.warnings.join('\n')
    assert.match(text, /host 在 DSH 设置界面里定义/)
    assert.match(text, /user 在 DSH 设置界面里定义/)
    assert.match(text, /port 在 DSH 设置界面里定义/, 'a saved port that will lose must be named: ' + text)

    // The same port in the settings is not a conflict.
    const same = await call(url, token, '/api/save', {
      alias: 'svc', host: 'settings-host.example', port: '2200', user: 'settings-user', password: 'pw',
    })
    assert.doesNotMatch(same.body.warnings.join('\n'), /port 在 DSH 设置界面里定义/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('an invalid settings-form port is reported, not replaced by 22', async () => {
  // The state said port 22 and the test button said '[ok] 配置', so a bad port in
  // the settings form looked like a working machine.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-guiport2-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    machines:',
    '      evil:',
    '        host: "h.example"',
    '        port: 99999',
    '        user: "u"',
    '- id: other',
    '  config: {}',
    ''].join('\n'))
  const { child, base: url, token } = await start(home, ['--profile', profile])
  try {
    const state = await call(url, token, '/api/state', undefined)
    const evil = state.body.machines.find((m) => m.alias === 'evil')
    assert.match(String(evil.portProblem), /not an integer between 1 and 65535/)
    assert.equal(evil.portRaw, '99999')
    const tested = await call(url, token, '/api/test', { alias: 'evil' })
    const text = tested.body.lines.join('\n')
    assert.match(text, /\[FAIL\] 配置: 端口无效/, text)
    assert.doesNotMatch(text, /\[ok\] 配置/, 'a broken port must not read as a working configuration')
    assert.equal(tested.body.ok, false)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('repeated save/delete cycles never lose an operation to a busy file', async () => {
  // On Windows a rename over the credential file fails with EPERM while another
  // handle has it open (a scanner, a sync client, or this page's own icacls).
  // Measured before the retry: one cycle in forty answered 500 and the machine
  // list still held both entries.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    for (let i = 0; i < 20; i++) {
      const a = await call(base, token, '/api/save', { alias: 'a', host: 'h', user: 'u' })
      const b = await call(base, token, '/api/save', { alias: 'b', host: 'h', user: 'u' })
      const del = await call(base, token, '/api/delete', { alias: 'a' })
      assert.equal(a.status, 200, 'save a: ' + JSON.stringify(a.body))
      assert.equal(b.status, 200, 'save b: ' + JSON.stringify(b.body))
      assert.equal(del.status, 200, 'delete a: ' + JSON.stringify(del.body))
      const s = await call(base, token, '/api/state')
      assert.deepEqual(s.body.machines.map((m) => m.alias), ['b'], 'cycle ' + i)
    }
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a bad --port or --idle-ms is refused with a message, not a stack trace', async () => {
  // --port abc reached server.listen(NaN) and died with a RangeError stack trace;
  // --idle-ms abc became NaN, which setTimeout treats as 0, so the page exited at
  // once while its banner promised 'NaN 秒'.
  const { spawnSync } = await import('node:child_process')
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-args-'))
  try {
    const run = (...args) => spawnSync(process.execPath, [script, '--no-open', '--dsh-home', home, ...args], {
      encoding: 'utf8', timeout: 20000,
    })
    const cases = [
      [['--port', 'abc'], /--port must be an integer between 0 and 65535.*"abc"/],
      [['--port', '70000'], /--port must be an integer between 0 and 65535/],
      [['--port'], /--port needs a value/],
      [['--idle-ms', 'abc'], /--idle-ms must be a whole number of milliseconds, at least 1000/],
      [['--idle-ms', '0'], /0 would exit at once, not never/],
      [['--idle-ms'], /--idle-ms needs a value/],
    ]
    for (const [args, expected] of cases) {
      const result = run(...args)
      assert.equal(result.status, 2, JSON.stringify(args) + ' should exit 2, saw ' + result.status)
      assert.match(result.stderr, expected, JSON.stringify(args) + ' stderr: ' + result.stderr)
      assert.doesNotMatch(result.stderr, /at Server|RangeError|at ModuleJob/, JSON.stringify(args) + ' must not print a stack trace')
    }
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('the settings parser reads whatever indentation the file uses', async () => {
  // Only the exact shape DSH writes used to parse: four-space indentation, a
  // quoted alias, or an alias with a trailing comment produced an EMPTY list, so
  // the page showed no machines while the plugin connected to them fine.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    machines:',
    '        fourspace:            # four-space children',
    '            host: 10.2.2.2',
    '            user: root',
    '        "quoted-name":',
    '            host: 10.3.3.3',
    '            user: admin',
    '        commented:   # the lab box',
    '            host: 10.4.4.4',
    '            user: ops',
    '        emptyone: {}',
  ].join('\n'))
  const { child, base, token } = await start(home)
  try {
    const state = await call(base, token, '/api/state')
    const byAlias = Object.fromEntries(state.body.machines.map((m) => [m.alias, m]))
    assert.equal(byAlias.fourspace?.host, '10.2.2.2', 'four-space children: ' + JSON.stringify(state.body.machines))
    assert.equal(byAlias['quoted-name']?.host, '10.3.3.3', 'quoted alias')
    assert.equal(byAlias.commented?.host, '10.4.4.4', 'alias with a trailing comment')
    assert.ok(byAlias.emptyone, 'an empty {} machine is still a machine')
    assert.equal(state.body.machinesProblem, '')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('flow-style machines say so instead of looking like none', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    machines: { gpu: { host: 10.5.5.5, user: root } }',
  ].join('\n'))
  const { child, base, token } = await start(home)
  try {
    const state = await call(base, token, '/api/state')
    assert.deepEqual(state.body.machines, [])
    assert.match(state.body.machinesProblem, /one line/)
    assert.match(state.body.machinesProblem, /cannot edit/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a machine written on one line is reported, not dropped', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    machines:',
    '      blocky:',
    '        host: 10.6.6.6',
    '      inliney: { host: 10.7.7.7 }',
  ].join('\n'))
  const { child, base, token } = await start(home)
  try {
    const state = await call(base, token, '/api/state')
    assert.ok(state.body.machines.find((m) => m.alias === 'blocky'), 'the readable machine is still listed')
    assert.match(state.body.machinesProblem, /inliney/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a plugin id with a comment or quotes is still the plugin entry', async () => {
  // The exact match made the whole entry invisible: the page showed no machines and
  // no credential-file state for a file DSH reads fine.
  for (const idLine of ['- id: dsh-ssh-safe   # the ssh plugin', '- id: "dsh-ssh-safe"']) {
    const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
    const profile = path.join(home, 'profiles', 'desktop')
    mkdirSync(profile, { recursive: true })
    writeFileSync(path.join(profile, 'cordis.patch.yml'), [
      idLine,
      '  config:',
      '    machines:',
      '      gpu:',
      '        host: 10.8.8.8',
    ].join('\n'))
    const { child, base, token } = await start(home)
    try {
      const state = await call(base, token, '/api/state')
      assert.ok(state.body.machines.find((m) => m.alias === 'gpu'), JSON.stringify(idLine) + ' must be found: ' + JSON.stringify(state.body.machines))
      assert.equal(state.body.machinesProblem, '')
    } finally {
      child.kill()
      rmSync(home, { recursive: true, force: true })
    }
  }
})

test('two plugin entries are read but reported as ambiguous', async () => {
  // DSH may take the last entry; this page reads the first. Saying nothing made the
  // displayed (and saved) machines look authoritative.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    machines:',
    '      first:',
    '        host: 10.1.1.1',
    '- id: dsh-ssh-safe',
    '  config:',
    '    machines:',
    '      second:',
    '        host: 10.2.2.2',
  ].join('\n'))
  const { child, base, token } = await start(home)
  try {
    const state = await call(base, token, '/api/state')
    assert.ok(state.body.machines.find((m) => m.alias === 'first'), 'the first entry is still listed')
    assert.match(state.body.machinesProblem, /more than one plugin entry/)
    assert.match(state.body.machinesProblem, /Remove the duplicate/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('testing an alias nothing defines says so instead of blaming the form', async () => {
  // It answered '缺少主机或用户，请在上方填写后保存' for a machine that does not exist:
  // the page was asking the user to fill in a host for an alias nothing defines.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    const unknown = await call(base, token, '/api/test', { alias: 'nosuchmachine' })
    assert.equal(unknown.status, 200)
    assert.equal(unknown.body.ok, false)
    const text = unknown.body.lines.join('\n')
    assert.match(text, /没有名为 "nosuchmachine" 的机器/)
    assert.doesNotMatch(text, /缺少主机或用户/, 'a missing machine is not an incomplete one')

    // A machine that exists but has no host keeps the original wording.
    await call(base, token, '/api/save', { alias: 'halfdone', user: 'root' })
    const incomplete = await call(base, token, '/api/test', { alias: 'halfdone' })
    assert.match(incomplete.body.lines.join('\n'), /缺少主机或用户/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a per-machine hostKeyPolicy does not become the global one', { skip: dpapiAvailable() ? false : 'DPAPI is a Windows feature' }, async () => {
  // The global readers accepted any indentation, so one machine's
  // 'hostKeyPolicy: off' became the policy for EVERY machine: the page reported
  // '[ok] 主机密钥（已记录，校验通过）' for a host the plugin would refuse.
  const srv = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    machines:',
    '      alab:',
    '        host: 127.0.0.1',
    '        port: ' + srv.port,
    '        user: tester',
    '        hostKeyPolicy: off',
    '      bplain:',
    '        host: 127.0.0.1',
    '        port: ' + srv.port,
    '        user: tester',
  ].join('\n'))
  const { child, base, token } = await start(home)
  try {
    await call(base, token, '/api/save', { alias: 'alab', password: 'test-pass' })
    await call(base, token, '/api/save', { alias: 'bplain', password: 'test-pass' })

    const plain = (await call(base, token, '/api/test', { alias: 'bplain' })).body.lines.join('\n')
    assert.match(plain, /\[warn\] 主机密钥/, 'a machine with no override is tested under the default strict: ' + plain)
    assert.match(plain, /还没有记录/)
    assert.doesNotMatch(plain, /已记录，校验通过/)

    const off = (await call(base, token, '/api/test', { alias: 'alab' })).body.lines.join('\n')
    assert.match(off, /hostKeyPolicy 为 "off"/, 'the page must not claim a check that did not happen: ' + off)
    assert.doesNotMatch(off, /已记录，校验通过/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
    await srv.close()
  }
})

test('delete and test use the same alias rule as save', { skip: dpapiAvailable() ? false : 'DPAPI is a Windows feature' }, async () => {
  // aliasOf() stripped characters, so deleting 'gpu/1' deleted the credentials of
  // the different machine called 'gpu1' -- and testing it reported on that one.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-'))
  const { child, base, token } = await start(home)
  try {
    const saved = await call(base, token, '/api/save', { alias: 'gpu1', host: '10.0.0.1', user: 'root' })
    assert.equal(saved.status, 200, JSON.stringify(saved.body))
    const file = path.join(home, 'dsh-ssh-safe', 'credentials.json')
    assert.ok(JSON.parse(readFileSync(file, 'utf8')).gpu1)

    const deleted = await call(base, token, '/api/delete', { alias: 'gpu/1' })
    assert.equal(deleted.status, 400, JSON.stringify(deleted.body))
    assert.match(deleted.body.error, /别名只能用/)
    assert.ok(JSON.parse(readFileSync(file, 'utf8')).gpu1, 'the other machine must survive')

    const tested = await call(base, token, '/api/test', { alias: 'gpu/1' })
    assert.equal(tested.status, 400)
    assert.match(tested.body.error, /别名只能用/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a non-object JSON body is refused with 400, not a 500', { skip: dpapiAvailable() ? false : 'DPAPI is a Windows feature' }, async () => {
  // null is valid JSON; reading .alias from it answered 500 with
  // "Cannot read properties of null (reading 'alias')" for a client mistake.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-body-'))
  const { child, base, token } = await start(home)
  try {
    for (const body of ['null', '[]', '"hi"', '42', 'true']) {
      const res = await fetch(base + '/api/save', {
        method: 'POST',
        headers: { 'x-gui-token': token, 'content-type': 'application/json' },
        body,
      })
      assert.equal(res.status, 400, body + ' must be a client error')
      const json = await res.json()
      assert.equal(json.error, 'body must be a JSON object')
    }
    // An object still works, and an empty body keeps its old answer.
    const ok = await call(base, token, '/api/save', { alias: 'good', host: 'h', user: 'u' })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    const empty = await fetch(base + '/api/save', { method: 'POST', headers: { 'x-gui-token': token } })
    assert.equal(empty.status, 400)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('the page can clear a stored password', async () => {
  // A saved password could not be removed from the page at all: saving without one
  // means 'leave it alone', so the blob stayed until the machine was deleted.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-clear-'))
  const { child, base, token } = await start(home)
  const file = path.join(home, 'dsh-ssh-safe', 'credentials.json')
  try {
    assert.equal((await call(base, token, '/api/save', { alias: 'g1', host: 'h1', user: 'u', password: 'pw' })).status, 200)
    assert.equal((await call(base, token, '/api/save', { alias: 'g2', host: 'h2', password: 'pw2' })).status, 200)
    const stored = JSON.parse(readFileSync(file, 'utf8'))
    assert.ok(stored.g1.passwordDpapi, 'the password must be stored first')

    const cleared = await call(base, token, '/api/clear-password', { alias: 'g1' })
    assert.equal(cleared.status, 200)
    assert.equal(cleared.body.cleared, true)
    const after = JSON.parse(readFileSync(file, 'utf8'))
    assert.equal(after.g1.passwordDpapi, undefined)
    assert.equal(after.g1.host, 'h1', 'other fields stay')
    assert.ok(after.g2.passwordDpapi, 'another machine is untouched')

    // Clearing twice is not an error, but it must not claim to have cleared.
    const again = await call(base, token, '/api/clear-password', { alias: 'g1' })
    assert.equal(again.status, 200)
    assert.equal(again.body.cleared, false)
    assert.match(String(again.body.warnings.join(' ')), /没有该别名的已存密码/)

    // An entry that held only the password disappears entirely.
    await call(base, token, '/api/save', { alias: 'solo', password: 'pw3' })
    const removed = await call(base, token, '/api/clear-password', { alias: 'solo' })
    assert.equal(removed.body.cleared, true)
    assert.equal(removed.body.removedEntry, true)
    assert.equal(JSON.parse(readFileSync(file, 'utf8')).solo, undefined)

    // The same alias rules as save and delete.
    const bad = await call(base, token, '/api/clear-password', { alias: 'a/b' })
    assert.equal(bad.status, 400)
    assert.match(String(bad.body.error), /别名/)

    // No endpoint returns the password itself.
    const state = await call(base, token, '/api/state', {})
    assert.doesNotMatch(JSON.stringify(state.body), /pw2/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('the page offers a clear button only where this file holds the password', () => {
  // Placed unconditionally it would appear on machines whose password comes from the
  // environment or the settings form, where it can only say it has nothing to clear.
  const html = readFileSync(path.join(here, '..', 'scripts', 'gui.html'), 'utf8')
  assert.match(html, /data-act="clear-password"/)
  assert.match(html, /m\.passwordSource === 'file-dpapi' \|\| m\.passwordSource === 'file-plaintext'/)
  // The handler posts to the endpoint the server serves.
  assert.match(html, /api\("\/api\/clear-password", \{ alias \}\)/)
  // And asks first: the blob cannot be recovered.
  assert.match(html, /confirm\("清除 " \+ alias/)
})

test('the page names why TCP failed instead of saying the host is unreachable', async () => {
  // ECONNREFUSED means the host answered and nothing is listening; the page said
  // 主机不可达 and printed the bare errno, while the tool had the right advice.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-tcpmsg-'))
  const { child, base, token } = await start(home)
  try {
    await call(base, token, '/api/save', { alias: 'refused', host: '127.0.0.1', port: 45999, user: 'u' })
    const refused = await call(base, token, '/api/test', { alias: 'refused' })
    assert.equal(refused.status, 200)
    const text = refused.body.lines.join('\n')
    assert.match(text, /ECONNREFUSED/)
    assert.match(text, /端口上没有服务在监听/)
    assert.doesNotMatch(text, /主机不可达/)
    assert.match(text, /已停止：TCP 没有连通/)

    await call(base, token, '/api/save', { alias: 'nodns', host: 'no-such-host.invalid', user: 'u' })
    const dns = await call(base, token, '/api/test', { alias: 'nodns' })
    const dnsText = dns.body.lines.join('\n')
    assert.match(dnsText, /ENOTFOUND/)
    assert.match(dnsText, /主机名解析不了/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('the page explains a refused command channel instead of printing ssh2 text', async () => {
  // '(SSH) Channel open failure: ' with an empty reason names the stage but not the
  // cause; the tool layer explains MaxSessions, the page printed the raw string.
  const ssh2 = (await import('ssh2')).default
  const hostKey = testHostKey()
  const server = new ssh2.Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => ctx.accept())
    client.on('ready', () => {
      client.on('session', (accept, reject) => { if (reject) reject(); else accept().end() })
    })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-guisess-'))
  const { child, base, token } = await start(home)
  try {
    await call(base, token, '/api/save', { alias: 'sess', host: '127.0.0.1', port, user: 'u', password: 'pw' })
    const result = await call(base, token, '/api/test', { alias: 'sess' })
    const text = (result.body.lines || []).join('\n')
    assert.match(text, /\[ok\] 认证/)
    assert.match(text, /\[FAIL\] 命令通道: 服务器拒绝再开一个会话通道/)
    assert.match(text, /MaxSessions/)
    assert.doesNotMatch(text, /Channel open failure: $/m, 'the bare ssh2 text must be gone')
  } finally {
    child.kill()
    server.close()
    rmSync(home, { recursive: true, force: true })
  }
})

test('the page names the recorded fingerprint and the remedy when the key changed', async () => {
  // It said '与记录的指纹不一致' without saying WHICH, and gave no way to fix it.
  const ssh2 = (await import('ssh2')).default
  const { createHash } = await import('node:crypto')
  const { encryptDpapi } = await import('../src/dpapi.js')
  const srv2 = await startServer()
  const otherPublic = testKeyPair().public
  const blob = Buffer.from(otherPublic.split(' ')[1], 'base64')
  const recorded = 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-guihk-'))
  const known = path.join(home, 'known_hosts')
  writeFileSync(known, '[127.0.0.1]:' + srv2.port + ' ' + otherPublic + '\n')
  mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
  writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
    hk: { host: '127.0.0.1', port: srv2.port, user: 'tester', passwordDpapi: encryptDpapi('test-pass'), knownHosts: known },
  }, null, 2))
  const { child, base, token } = await start(home)
  try {
    const result = await call(base, token, '/api/test', { alias: 'hk' })
    const text = (result.body.lines || []).join('\n')
    assert.match(text, /\[FAIL\] 主机密钥/)
    assert.match(text, /与记录的不一致/)
    assert.ok(text.includes(recorded), 'the recorded fingerprint must be named: ' + recorded)
    assert.match(text, /ssh-keygen -R/)
    assert.equal(result.body.ok, false, 'a changed key is never a green verdict')
  } finally {
    child.kill()
    await Promise.race([srv2.close(), new Promise((r) => setTimeout(r, 1200))])
    rmSync(home, { recursive: true, force: true })
  }
})

test('the page explains a credential problem instead of pasting a Node error', async () => {
  // '私钥读取失败：cannot read the private key C:/nope/id_ed25519: ENOENT: no such
  // file or directory, open' labelled a passphrase problem as a read failure and cut
  // the path mid-quote. Each cause has its own sentence and its own remedy now.
  const ssh2 = (await import('ssh2')).default
  const srv2 = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-guicred-'))
  mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
  const encrypted = ssh2.utils.generateKeyPairSync('ed25519', { passphrase: 'pw', cipher: 'aes256-cbc' }).private
  const keyFile = path.join(home, 'key_enc')
  writeFileSync(keyFile, String(encrypted))
  writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
    missing: { host: '127.0.0.1', port: srv2.port, user: 'u', keyPath: 'C:/nope/id_ed25519' },
    directory: { host: '127.0.0.1', port: srv2.port, user: 'u', keyPath: home },
    encrypted: { host: '127.0.0.1', port: srv2.port, user: 'u', keyPath: keyFile },
  }, null, 2))
  const { child, base, token } = await start(home)
  try {
    const credLine = async (alias) => {
      const result = await call(base, token, '/api/test', { alias })
      return (result.body.lines || []).find((line) => line.includes('凭据')) || ''
    }
    const missing = await credLine('missing')
    assert.match(missing, /找不到私钥文件：C:\/nope\/id_ed25519/)
    assert.doesNotMatch(missing, /ENOENT/, 'the raw Node text is not the explanation')
    assert.doesNotMatch(missing, /id_ed25519:/, 'the separating colon must not be part of the path')
    const directory = await credLine('directory')
    assert.match(directory, /指向的是目录/)
    assert.match(directory, /~\/\.ssh\/id_ed25519/)
    const passphrase = await credLine('encrypted')
    assert.match(passphrase, /私钥有口令保护/)
    assert.match(passphrase, /keyPassphrase/)
    assert.doesNotMatch(passphrase, /私钥读取失败/, 'it was never a read failure')
  } finally {
    child.kill()
    await Promise.race([srv2.close(), new Promise((r) => setTimeout(r, 1200))])
    rmSync(home, { recursive: true, force: true })
  }
})

test('the page can clear a stored key passphrase', async () => {
  // --clear-key-passphrase existed in the CLI and nowhere on the page, so a
  // passphrase saved from the page could only be revoked from a terminal.
  const { encryptDpapi, dpapiAvailable } = await import('../src/dpapi.js')
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-guikp-'))
  mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
  const blob = dpapiAvailable() ? encryptDpapi('KPPW') : 'DPAPIBLOB:x'
  const store = path.join(home, 'dsh-ssh-safe', 'credentials.json')
  writeFileSync(store, JSON.stringify({
    k: { host: 'h', user: 'u', keyPath: '~/.ssh/id_ed25519', keyPassphraseDpapi: blob },
    other: { host: 'h2', user: 'u', keyPath: '~/.ssh/id_rsa', keyPassphraseDpapi: blob },
  }, null, 2))
  const { child, base, token } = await start(home)
  try {
    const state = await fetch(base + '/api/state', { headers: { 'x-gui-token': token } }).then((r) => r.json())
    const row = (state.machines || []).find((m) => m.alias === 'k')
    assert.equal(row.keyPassphraseSource, 'file-dpapi')
    const html = await fetch(base + '/?t=' + token, { headers: { 'x-gui-token': token } }).then((r) => r.text())
    assert.match(html, /清除已存口令/)

    const cleared = await call(base, token, '/api/clear-key-passphrase', { alias: 'k' })
    assert.equal(cleared.status, 200)
    assert.equal(cleared.body.cleared, true)
    const after = JSON.parse(readFileSync(store, 'utf8'))
    assert.deepEqual(after.k, { host: 'h', user: 'u', keyPath: '~/.ssh/id_ed25519' })
    assert.ok(after.other.keyPassphraseDpapi, 'another machine keeps its passphrase')

    // Nothing to clear is not an error, like the password endpoint.
    const again = await call(base, token, '/api/clear-key-passphrase', { alias: 'k' })
    assert.equal(again.status, 200)
    assert.equal(again.body.cleared, false)
    assert.match(again.body.warnings.join(' '), /没有该别名的已存口令/)

    const bad = await call(base, token, '/api/clear-key-passphrase', { alias: 'bad alias!' })
    assert.equal(bad.status, 400)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('the page says when it stopped instead of leaving stages out', async () => {
  // A run that failed at 凭据 printed no 主机密钥 or 认证 line at all, and an absent
  // stage reads like a stage that passed.
  const srv2 = await startServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-guistop-'))
  mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
  writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
    nokey: { host: '127.0.0.1', port: srv2.port, user: 'u', keyPath: 'C:/nope/id' },
    nowhere: { host: '127.0.0.1', port: srv2.port, user: '' },
  }, null, 2))
  const { child, base, token } = await start(home)
  try {
    const nokey = await call(base, token, '/api/test', { alias: 'nokey' })
    const text = (nokey.body.lines || []).join('\n')
    assert.match(text, /\[FAIL\] 凭据: 找不到私钥文件/)
    assert.match(text, /已停止：凭据不能用，后面的检查没有进行。/)
    assert.equal(nokey.body.ok, false)

    const nowhere = await call(base, token, '/api/test', { alias: 'nowhere' })
    const text2 = (nowhere.body.lines || []).join('\n')
    assert.match(text2, /\[FAIL\] 配置: 缺少主机或用户/)
    assert.match(text2, /已停止：缺少主机或用户，后面的检查没有进行。/)
  } finally {
    child.kill()
    await Promise.race([srv2.close(), new Promise((r) => setTimeout(r, 1200))])
    rmSync(home, { recursive: true, force: true })
  }
})

test('a temp file a crashed save left behind is swept, a live one is not', async () => {
  // writeStore() writes credentials.json.tmp-<pid> and renames it over the real
  // file. A crash in that window left every password in the profile directory at a
  // path nothing ever mentioned, and on Windows the ACL restriction covers only
  // credentials.json.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-tmpsweep-'))
  const dir = path.join(home, 'dsh-ssh-safe')
  mkdirSync(dir, { recursive: true })
  const stale = path.join(dir, 'credentials.json.tmp-99999')
  const fresh = path.join(dir, 'credentials.json.tmp-20000')
  writeFileSync(stale, JSON.stringify({ old: { host: 'h', user: 'u', password: 'LEFT-BEHIND' } }))
  writeFileSync(fresh, JSON.stringify({ live: { host: 'h', user: 'u', password: 'IN-FLIGHT' } }))
  const past = new Date(Date.now() - 60 * 60 * 1000)
  utimesSync(stale, past, past)
  const { child, output } = await start(home)
  try {
    assert.equal(existsSync(stale), false, 'a stale temp file must be removed')
    assert.equal(existsSync(fresh), true, 'a temp file a live writer may be using must stay')
    // The URL line is printed before the sweep line, so give stdout a moment to
    // catch up instead of asserting the instant start() resolves.
    const deadline = Date.now() + 2000
    while (Date.now() < deadline && !/残留的临时文件/.test(output())) await new Promise((r) => setTimeout(r, 25))
    assert.match(output(), /已清理上次写入残留的临时文件: credentials\.json\.tmp-99999/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a taken --port says how to fix it, not just the errno', async () => {
  // 'listen EADDRINUSE: address already in use 127.0.0.1:4191' is true and tells
  // the user nothing they can act on. The port is the one startup failure a
  // second flag fixes, so the message names both ways out.
  const { spawnSync } = await import('node:child_process')
  const net = await import('node:net')
  const blocker = net.createServer((socket) => { socket.on('error', () => {}) })
  await new Promise((resolve) => blocker.listen(0, '127.0.0.1', resolve))
  const port = blocker.address().port
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-port-'))
  try {
    const result = spawnSync(process.execPath, [script, '--no-open', '--port', String(port), '--dsh-home', home], {
      encoding: 'utf8', timeout: 20000,
    })
    assert.equal(result.status, 1)
    assert.ok(result.stderr.includes('127.0.0.1:' + port + ' '), 'the message must name the port: ' + result.stderr)
    assert.ok(/--port 0|--port 设为 0/.test(result.stderr), 'the message must offer --port 0: ' + result.stderr)
    assert.doesNotMatch(result.stderr, /EADDRINUSE/)
  } finally {
    blocker.close()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a machine field the plugin refuses to load is named, not rendered as text', async () => {
  // `host: 123` fails the plugin's schema and the whole plugin does not load, while
  // the page rendered it as the string "123" and said nothing — the settings looked
  // usable and the tools would never start.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-badfield-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    machines:',
    '        good:',
    '            host: h.example',
    '            user: u',
    '        numeric:',
    '            host: 123',
    '            user: u',
  ].join('\n'))
  const { child, base, token } = await start(home)
  try {
    const state = await call(base, token, '/api/state')
    assert.match(state.body.machinesProblem, /refuses to load this machines block/)
    assert.match(state.body.machinesProblem, /numeric\.host is number \(123\)/)
    assert.match(state.body.machinesProblem, /quoted text/)
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a machine whose value is a plain string is named as such, not as a flow map', async () => {
  // `plain: "just a string"` was reported as `plain: { … }` — a block that is not in
  // the file — so the advice pointed at the wrong shape.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-scalar-'))
  const profile = path.join(home, 'profiles', 'desktop')
  mkdirSync(profile, { recursive: true })
  writeFileSync(path.join(profile, 'cordis.patch.yml'), [
    '- id: dsh-ssh-safe',
    '  config:',
    '    machines:',
    '        good:',
    '            host: h.example',
    '            user: u',
    '        plain: "just a string"',
  ].join('\n'))
  const { child, base, token } = await start(home)
  try {
    const state = await call(base, token, '/api/state')
    assert.match(state.body.machinesProblem, /as a single value/)
    assert.doesNotMatch(state.body.machinesProblem, /one line/)
    assert.equal(state.body.machines.find((m) => m.alias === 'good')?.host, 'h.example', 'the good machine still shows')
  } finally {
    child.kill()
    rmSync(home, { recursive: true, force: true })
  }
})

test('a misspelled page option is refused instead of ignored', async () => {
  // The tools refuse an argument they do not declare. This script accepted any
  // --key, so '--proflie desktop' started against the default profile without a
  // word and every save edited a credential file the user had not named.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-args-'))
  try {
    const run = (args) => new Promise((resolve) => {
      const child = spawn(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] })
      let out = ''
      child.stdout.on('data', (chunk) => { out += chunk.toString('utf8') })
      child.stderr.on('data', (chunk) => { out += chunk.toString('utf8') })
      const timer = setTimeout(() => { child.kill(); resolve({ code: null, out }) }, 8000)
      child.on('exit', (code) => { clearTimeout(timer); resolve({ code, out }) })
    })
    const typo = await run(['--no-open', '--proflie', 'desktop', '--dsh-home', home])
    assert.equal(typo.code, 2, 'a misspelled option must be refused: ' + typo.out)
    assert.match(typo.out, /Unknown option\(s\): --proflie/)
    assert.match(typo.out, /Accepted: --dsh-home, --profile, --port, --idle-ms, --no-open/)
    // The accepted spelling still starts the server.
    const good = await run(['--no-open', '--port', '0', '--dsh-home', home, '--idle-ms', '5000'])
    assert.match(good.out, /http:\/\/127\.0\.0\.1:\d+/, 'the accepted options must work: ' + good.out)
    if (good.code === null) return
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('--help prints the usage and exits 0 instead of being refused', async () => {
  // 0.7.337 refused every unknown option, which included --help: the one flag a
  // CLI is expected to answer.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-gui-help-'))
  try {
    const run = (args) => new Promise((resolve) => {
      const child = spawn(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] })
      let out = ''
      child.stdout.on('data', (chunk) => { out += chunk.toString('utf8') })
      child.stderr.on('data', (chunk) => { out += chunk.toString('utf8') })
      child.on('exit', (code) => resolve({ code, out }))
    })
    const help = await run(['--help'])
    assert.equal(help.code, 0, 'help must not be an error: ' + help.out)
    for (const flag of ['--dsh-home', '--profile', '--port', '--idle-ms', '--no-open', '--help']) {
      assert.match(help.out, new RegExp(flag), 'the usage must name ' + flag)
    }
    // The default it quotes is the one the code uses.
    const source = readFileSync(script, 'utf8')
    const declared = source.match(/const DEFAULT_IDLE_MS = ([^\n]+)/)
    assert.ok(declared, 'the idle default must be a named constant')
    const value = Function('return ' + declared[1])()
    assert.match(help.out, new RegExp('default: ' + value + '.'), 'help must quote the real default')
  } finally { rmSync(home, { recursive: true, force: true }) }
})
