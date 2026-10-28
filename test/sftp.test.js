import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { readRemoteFile, writeRemoteFile, listRemoteDir } from '../src/sftp.js'

// sftp.js was the only module with no direct test: its 183 lines ran only through
// a fake sftp inside pool tests, so the error branches (sftp() failing,
// createReadStream throwing, readdir failing) were never executed.

class FakeSftp {
  constructor(options = {}) {
    this.options = options
    this.dirs = options.dirs || {}
  }
  createReadStream() {
    if (this.options.readError) throw new Error(this.options.readError)
    const rs = new EventEmitter()
    rs.destroy = () => { rs.destroyed = true }
    rs.setEncoding = () => rs
    setImmediate(() => {
      for (const chunk of this.options.chunks || []) rs.emit('data', Buffer.from(chunk))
      rs.emit('end')
    })
    return rs
  }
  createWriteStream() {
    if (this.options.writeError) throw new Error(this.options.writeError)
    const ws = new EventEmitter()
    ws.destroy = () => {}
    ws.end = (payload) => { this.options.written = payload; setImmediate(() => ws.emit('finish')) }
    return ws
  }
  readdir(_path, cb) {
    if (this.options.readdirError) return cb(new Error(this.options.readdirError))
    cb(null, this.options.entries || [])
  }
}

function client(sftpOrError) {
  return {
    sftp(cb) {
      if (sftpOrError instanceof Error) cb(sftpOrError)
      else cb(null, sftpOrError)
    },
  }
}

const opts = (extra = {}) => ({ maxBytes: 1024, timeoutMs: 500, ...extra })

// ── read ─────────────────────────────────────────────────────────────────

test('readRemoteFile returns content and reports the path it used', async () => {
  const r = await readRemoteFile(client(new FakeSftp({ chunks: ['hello'] })), '/tmp//a.txt', opts())
  assert.equal(r.content, 'hello')
  assert.equal(r.path, '/tmp/a.txt', 'the normalised path is returned')
  assert.equal(r.truncated, false)
})

test('readRemoteFile truncates at the byte cap and says so', async () => {
  const r = await readRemoteFile(client(new FakeSftp({ chunks: ['abcdefghij'] })), '/tmp/a', opts({ maxBytes: 4 }))
  assert.ok(r.content.length <= 4)
  assert.equal(r.truncated, true)
})

test('readRemoteFile rejects when the sftp session cannot open', async () => {
  await assert.rejects(
    () => readRemoteFile(client(new Error('no sftp subsystem')), '/tmp/a', opts()),
    (err) => { assert.match(err.message, /no sftp subsystem/); return true }
  )
})

test('readRemoteFile rejects when createReadStream throws', async () => {
  await assert.rejects(
    () => readRemoteFile(client(new FakeSftp({ readError: 'permission denied' })), '/tmp/a', opts()),
    (err) => { assert.match(err.message, /permission denied/); return true }
  )
})

test('readRemoteFile gives up at the deadline', async () => {
  // A stream that never emits anything: only the deadline can settle this.
  const silent = {
    createReadStream() {
      const rs = new EventEmitter()
      rs.destroy = () => {}
      return rs
    },
  }
  const started = Date.now()
  await assert.rejects(
    () => readRemoteFile(client(silent), '/tmp/a', { maxBytes: 10, timeoutMs: 80 }),
    (err) => { assert.match(err.message, /did not complete within/); return true }
  )
  assert.ok(Date.now() - started < 1000, 'the deadline must fire promptly')
})

// ── write ────────────────────────────────────────────────────────────────

test('writeRemoteFile writes the payload and reports bytes', async () => {
  const sftp = new FakeSftp()
  const r = await writeRemoteFile(client(sftp), '/tmp/x', 'hello', opts())
  assert.equal(r.bytes, 5)
  assert.equal(r.path, '/tmp/x')
  assert.equal(String(sftp.options.written), 'hello')
})

test('writeRemoteFile rejects when the session cannot open', async () => {
  await assert.rejects(
    () => writeRemoteFile(client(new Error('subsystem unavailable')), '/tmp/x', 'x', opts()),
    (err) => { assert.match(err.message, /subsystem unavailable/); return true }
  )
})

test('writeRemoteFile rejects when createWriteStream throws', async () => {
  await assert.rejects(
    () => writeRemoteFile(client(new FakeSftp({ writeError: 'read-only' })), '/tmp/x', 'x', opts()),
    (err) => { assert.match(err.message, /read-only/); return true }
  )
})

test('writeRemoteFile gives up at the deadline when the stream stalls', async () => {
  const stalled = {
    createWriteStream() {
      const ws = new EventEmitter()
      ws.destroy = () => {}
      ws.end = () => {} // never emits finish or close
      return ws
    },
  }
  await assert.rejects(
    () => writeRemoteFile(client(stalled), '/tmp/x', 'x', { timeoutMs: 80 }),
    (err) => { assert.match(err.message, /did not complete within/); return true }
  )
})

// ── list ─────────────────────────────────────────────────────────────────

test('listRemoteDir maps entries and reports the path', async () => {
  const sftp = new FakeSftp({
    entries: [
      { filename: 'file.txt', attrs: { size: 12, mode: 0o100644, mtime: 1700000000 } },
      { filename: 'sub', attrs: { size: 4096, mode: 0o040755, mtime: 1700000000 } },
    ],
  })
  const r = await listRemoteDir(client(sftp), '/home/user', opts())
  assert.equal(r.path, '/home/user')
  assert.equal(r.items.length, 2)
  assert.equal(r.items[0].name, 'file.txt')
  assert.equal(r.items[0].dir, false)
  assert.equal(r.items[1].dir, true)
  assert.match(String(r.items[0].mtime), /^\d{4}-/)
})

test('listRemoteDir defaults to the current directory', async () => {
  const r = await listRemoteDir(client(new FakeSftp({ entries: [] })), '', opts())
  assert.equal(r.path, '.')
})

test('listRemoteDir rejects when the session cannot open', async () => {
  await assert.rejects(
    () => listRemoteDir(client(new Error('no sftp')), '/tmp', opts()),
    (err) => { assert.match(err.message, /no sftp/); return true }
  )
})

test('listRemoteDir rejects when readdir fails', async () => {
  await assert.rejects(
    () => listRemoteDir(client(new FakeSftp({ readdirError: 'not a directory' })), '/tmp/a.txt', opts()),
    (err) => { assert.match(err.message, /not a directory/); return true }
  )
})

test('listRemoteDir gives up at the deadline', async () => {
  const silent = { readdir() { /* never calls back */ } }
  await assert.rejects(
    () => listRemoteDir(client(silent), '/tmp', { timeoutMs: 80 }),
    (err) => { assert.match(err.message, /did not complete within/); return true }
  )
})

// ── path validation happens before any network work ──────────────────────

test('an invalid path is rejected without touching the session', async () => {
  let touched = false
  const sentinel = { sftp() { touched = true } }
  await assert.rejects(() => readRemoteFile(sentinel, '~/x', opts()))
  await assert.rejects(() => writeRemoteFile(sentinel, 'rel/x', 'y', opts()))
  assert.equal(touched, false, 'no sftp session should have been opened')
})
