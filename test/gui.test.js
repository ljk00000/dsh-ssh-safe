import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { request as httpRequest } from 'node:http'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
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

/** Start the server, wait for the URL it prints, hand back the token. */
function start(home) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, '--no-open', '--port', '0',
      '--dsh-home', home, '--idle-ms', '60000'], { stdio: ['ignore', 'pipe', 'pipe'] })
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
        resolve({ child, base: 'http://127.0.0.1:' + match[1], token: match[2] })
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
  const { child, base, token } = await start(home)
  const exited = new Promise((resolve) => child.on('exit', resolve))
  try {
    await call(base, token, '/api/shutdown', {})
    const code = await Promise.race([
      exited,
      new Promise((resolve) => setTimeout(() => resolve('timeout'), 5000)),
    ])
    assert.equal(code, 0, 'it exits cleanly')
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

test('saving a machine stores the password encrypted, never in plaintext', async () => {
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
