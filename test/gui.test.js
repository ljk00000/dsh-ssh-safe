import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { request as httpRequest } from 'node:http'
import { startServer } from './helpers/local-ssh-server.js'
import { mkdirSync, writeFileSync } from 'node:fs'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { dpapiAvailable } from '../src/dpapi.js'

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
      assert.match(bad.body.error, /别名只能用字母、数字、点、下划线、连字符/)
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
