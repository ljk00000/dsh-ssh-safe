import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { existsSync, renameSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { acquireStoreLock, withStoreLock } from '../scripts/lib/store-lock.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.join(here, '..')

test('the store lock excludes a second holder and frees it on release', () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-lock-'))
  const file = path.join(home, 'credentials.json')
  try {
    const first = acquireStoreLock(file)
    assert.equal(first.timedOut, false)
    const second = acquireStoreLock(file, { waitMs: 60 })
    assert.equal(second.timedOut, true, 'a held lock must not be granted twice')
    assert.equal(second.path, file + '.lock')
    first.release()
    const third = acquireStoreLock(file, { waitMs: 60 })
    assert.equal(third.timedOut, false)
    third.release()
    // Released twice is harmless.
    third.release()
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('a lock left by a dead process is broken instead of blocking saves', () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-lockstale-'))
  const file = path.join(home, 'credentials.json')
  try {
    mkdirSync(home, { recursive: true })
    writeFileSync(file + '.lock', '{"pid":1}\n')
    const old = new Date(Date.now() - 60_000)
    utimesSync(file + '.lock', old, old)
    const lock = acquireStoreLock(file, { waitMs: 60 })
    assert.equal(lock.timedOut, false, 'a stale lock must be broken, not waited out')
    lock.release()
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('withStoreLock serialises a counter across two processes', async () => {
  // Without the lock the two children lose increments: each reads, adds one and
  // writes, so a read that lands in the other's window is overwritten.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-lockcount-'))
  const file = path.join(home, 'counter.json')
  writeFileSync(file, '{"n":0}')
  // The child lives in a temp directory, so the import must be an absolute URL.
  const lockUrl = new URL('../scripts/lib/store-lock.mjs', import.meta.url).href
  const script = [
    "import { readFileSync, writeFileSync } from 'node:fs'",
    'import { withStoreLock } from ' + JSON.stringify(lockUrl),
    'const file = process.argv[2]',
    'for (let i = 0; i < 40; i++) {',
    // 40 locked increments from two processes: under a loaded machine a 4-second
    // default wait was not enough and the child exited 1 ('child exit 1' was all the
    // test could say, because its stderr was thrown away).
    '  withStoreLock(file, () => {',
    '    const n = JSON.parse(readFileSync(file).toString()).n',
    '    writeFileSync(file, JSON.stringify({ n: n + 1 }))',
    '  }, { waitMs: 30000 })',
    '}',
  ].join('\n')
  const scriptPath = path.join(home, 'count.mjs')
  writeFileSync(scriptPath, script)
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath, file, '40'], { cwd: root, stdio: ['ignore', 'ignore', 'pipe'] })
    let stderr = ''
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.on('error', reject)
    child.on('exit', (code) => {
      if (code === 0) {
        resolve()
        return
      }
      const detail = stderr ? ': ' + stderr.trim().split('\n')[0] : ''
      reject(new Error('child exit ' + code + detail))
    })
  })
  try {
    await Promise.all([run(), run()])
    const n = JSON.parse(readFileSync(file, 'utf8')).n
    assert.equal(n, 80, 'both processes\' increments must survive: ' + n)
  } finally { rmSync(home, { recursive: true, force: true }) }
})

test('two page instances saving at the same moment keep both machines', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-pagerace-'))
  mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
  const startPage = async () => {
    const child = spawn(process.execPath, ['scripts/gui.mjs', '--no-open', '--port', '0', '--dsh-home', home, '--idle-ms', '180000'], { cwd: root, env: { ...process.env, DSH_HOME: home } })
    let out = ''
    const base = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('the page did not print a URL')), 15000)
      child.stdout.on('data', (chunk) => {
        out += String(chunk)
        const m = out.match(/http:\/\/127\.0\.0\.1:(\d+)\/\?t=([0-9a-f]+)/)
        if (m) { clearTimeout(timer); resolve({ base: 'http://127.0.0.1:' + m[1], token: m[2] }) }
      })
    })
    return { child, ...base }
  }
  const save = async (page, alias, password) => {
    const res = await fetch(page.base + '/api/save', {
      method: 'POST',
      headers: { 'x-gui-token': page.token, 'content-type': 'application/json' },
      body: JSON.stringify({ alias, host: 'h-' + alias + '.example', user: 'u', password }),
    })
    assert.equal(res.status, 200, await res.text())
  }
  let a, b
  try {
    a = await startPage()
    b = await startPage()
    // Warm both stores so the first write is not the one being measured.
    await save(a, 'alpha', 'warm')
    await save(b, 'beta', 'warm')
    for (let i = 0; i < 25; i++) {
      await Promise.all([save(a, 'alpha', 'A' + i), save(b, 'beta', 'B' + i)])
      const store = JSON.parse(readFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), 'utf8'))
      assert.ok(store.alpha && store.beta, 'trial ' + i + ' lost a machine: ' + Object.keys(store).join(','))
    }
  } finally {
    a?.child.kill('SIGTERM')
    b?.child.kill('SIGTERM')
    await new Promise((r) => setTimeout(r, 300))
    rmSync(home, { recursive: true, force: true })
  }
})

test('the lock and its writes also work on a network share', async (t) => {
  // DSH_HOME can point at a share, and a lock is only worth having if O_EXCL is
  // atomic there. The SMB admin share of this machine is used when it exists; on
  // a machine without it the case is skipped rather than faked.
  const bs = String.fromCharCode(92, 92)
  const shareRoot = bs + 'localhost' + String.fromCharCode(92) + 'C$'
  if (!existsSync(shareRoot)) return t.skip('no \\\\localhost\\C$ share on this machine')
  const base = mkdtempSync(path.join(shareRoot, 'Users', 'Public', 'dsh-lockshare-'))
  const file = path.join(base, 'credentials.json')
  try {
    const first = acquireStoreLock(file)
    assert.equal(first.timedOut, false)
    const second = acquireStoreLock(file, { waitMs: 80 })
    assert.equal(second.timedOut, true, 'O_EXCL must exclude a second holder over SMB')
    first.release()
    const third = acquireStoreLock(file, { waitMs: 80 })
    assert.equal(third.timedOut, false)
    third.release()

    // Two child processes incrementing a counter through the lock.
    const lockUrl = new URL('../scripts/lib/store-lock.mjs', import.meta.url).href
    const script = [
      "import { readFileSync, writeFileSync } from 'node:fs'",
      'import { withStoreLock } from ' + JSON.stringify(lockUrl),
      'const file = process.argv[2]',
      'for (let i = 0; i < 10; i++) {',
      '  withStoreLock(file, () => {',
      '    const n = JSON.parse(readFileSync(file).toString()).n',
      '    writeFileSync(file, JSON.stringify({ n: n + 1 }))',
      '  })',
      '}',
    ].join('\n')
    // The script itself must stay on the local disk: Node cannot load an ESM entry
    // point from a UNC path (ERR_INVALID_FILE_URL_PATH). Only the data file is on
    // the share, which is also how a real user has it.
    const scriptPath = path.join(mkdtempSync(path.join(tmpdir(), 'dsh-smbsrc-')), 'count.mjs')
    writeFileSync(file, '{"n":0}')
    writeFileSync(scriptPath, script)
    const run = () => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [scriptPath, file], { cwd: root })
      child.on('error', reject)
      child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error('child exit ' + code))))
    })
    await Promise.all([run(), run()])
    assert.equal(JSON.parse(readFileSync(file, 'utf8')).n, 20, 'both children increments must survive over SMB')

    // And the rename the page uses instead of writing in place.
    const tmp = file + '.tmp-test'
    writeFileSync(tmp, '{"n":"renamed"}')
    renameSync(tmp, file)
    assert.equal(JSON.parse(readFileSync(file, 'utf8')).n, 'renamed')
  } finally {
    rmSync(base, { recursive: true, force: true })
  }
})

test('an unremovable stale lock times out instead of spinning forever', () => {
  // Measured before the fix: acquireStoreLock({ waitMs: 120 }) with a non-empty
  // directory at the lock path never returned — the stale branch 'continue'd before
  // the deadline check and before the wait, so the loop was a synchronous busy spin
  // (even a setTimeout guard in the same process could not fire). Now: 125 ms.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-lock-stale-'))
  const file = path.join(home, 'credentials.json')
  const target = file + '.lock'
  try {
    mkdirSync(target)
    writeFileSync(path.join(target, 'child'), 'x')
    const old = new Date(Date.now() - 120_000)
    utimesSync(target, old, old)
    const started = Date.now()
    const lock = acquireStoreLock(file, { waitMs: 120 })
    const elapsed = Date.now() - started
    assert.equal(lock.timedOut, true, 'an unremovable stale lock is a timeout, not a lock')
    assert.ok(elapsed < 3000, 'it must return promptly, took ' + elapsed + 'ms')
    lock.release()
  } finally {
    rmSync(target, { recursive: true, force: true })
    rmSync(home, { recursive: true, force: true })
  }
})

test('an async callback keeps the lock until it settles', async () => {
  // The finally-based version released the lock as soon as fn() handed back its
  // promise, so a second writer entered while the first was still awaiting. The
  // lock looked held and was not.
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-lock-async-'))
  const file = path.join(home, 'credentials.json')
  try {
    let secondResult = null
    await withStoreLock(file, async () => {
      // While this callback is awaiting, another writer must not get in.
      await new Promise((resolve) => setTimeout(resolve, 120))
      secondResult = acquireStoreLock(file, { waitMs: 60 })
    })
    assert.equal(secondResult.timedOut, true, 'the lock must still be held while the callback awaits')
    secondResult.release()

    // And once it settles, the lock is free again.
    const after = acquireStoreLock(file, { waitMs: 60 })
    assert.equal(after.timedOut, false, 'the lock must be released when the promise settles')
    after.release()

    // A rejection releases it too.
    await assert.rejects(
      () => withStoreLock(file, async () => { throw new Error('boom') }),
      /boom/,
    )
    const afterFailure = acquireStoreLock(file, { waitMs: 60 })
    assert.equal(afterFailure.timedOut, false, 'a failed callback must not keep the lock')
    afterFailure.release()
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})
