import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { readRemoteFile, writeRemoteFile, listRemoteDir } from '../src/sftp.js'

// Every transfer opens its own SFTP session, and sshd counts sessions per
// connection (MaxSessions, 10 by default). Nothing closed them, so a long
// session leaked one channel per read/write/list and eventually the server
// answered "(SSH) Channel open failure: open failed" -- reproducible after
// about ten operations against a real host.
//
// Closing the session introduced a second hazard: ssh2 fails any request still
// in flight and emits the error on the stream, so removing the stream's
// listeners before closing turned it into an unhandled 'error' event that
// killed the process (seen while reading a missing file).

class CleanupSftp {
  constructor(options = {}) {
    this.options = options
    this.ended = 0
    this.mkdirs = []
    this.existing = new Set(options.existing || [])
    this.stream = null
  }
  end() { this.ended += 1 }
  stat(path, cb) {
    if (this.existing.has(path)) cb(null, {})
    else cb(Object.assign(new Error('No such file'), { code: 2 }))
  }
  mkdir(path, cb) {
    this.mkdirs.push(path)
    this.existing.add(path)
    cb(null)
  }
  createReadStream() {
    const rs = new EventEmitter()
    this.stream = rs
    rs.destroy = () => { rs.destroyed = true }
    setImmediate(() => {
      if (this.options.readError) {
        rs.emit('error', Object.assign(new Error(this.options.readError), { code: 2 }))
        return
      }
      for (const chunk of this.options.chunks || []) rs.emit('data', Buffer.from(chunk))
      rs.emit('end')
    })
    return rs
  }
  createWriteStream() {
    const ws = new EventEmitter()
    this.stream = ws
    ws.destroy = () => { ws.destroyed = true }
    ws.end = () => setImmediate(() => {
      if (this.options.writeError) ws.emit('error', new Error(this.options.writeError))
      else ws.emit('finish')
    })
    return ws
  }
  readdir(_path, cb) {
    if (this.options.readdirError) return cb(new Error(this.options.readdirError))
    cb(null, [])
  }
}

const client = (sftp) => ({ sftp: (cb) => cb(null, sftp) })
const opts = (extra = {}) => ({ maxBytes: 4096, timeoutMs: 500, ...extra })

test('a successful read ends its SFTP session', async () => {
  const sftp = new CleanupSftp({ chunks: ['hi'] })
  await readRemoteFile(client(sftp), '/tmp/a', opts())
  await new Promise((r) => setImmediate(r))
  assert.equal(sftp.ended, 1, 'the session must be closed exactly once')
})

test('a failed read ends its session and leaves no unhandled error', async () => {
  const sftp = new CleanupSftp({ readError: 'No such file' })
  await assert.rejects(() => readRemoteFile(client(sftp), '/tmp/missing', opts()), /No such file/)
  await new Promise((r) => setImmediate(r))
  assert.equal(sftp.ended, 1)
  // ssh2 reports the abandoned request on the stream after the session closes.
  assert.doesNotThrow(() => sftp.stream.emit('error', new Error('No response from server')))
})

test('a write ends its session', async () => {
  const sftp = new CleanupSftp()
  await writeRemoteFile(client(sftp), '/tmp/a', 'x', opts())
  await new Promise((r) => setImmediate(r))
  assert.equal(sftp.ended, 1)
})

test('a listing ends its session', async () => {
  const sftp = new CleanupSftp()
  await listRemoteDir(client(sftp), '/tmp', opts())
  await new Promise((r) => setImmediate(r))
  assert.equal(sftp.ended, 1)
})

test('createDirs creates only the missing parent components', async () => {
  const sftp = new CleanupSftp({ existing: ['/tmp'] })
  await writeRemoteFile(client(sftp), '/tmp/new/deeper/a.txt', 'x', opts({ createDirs: true }))
  assert.deepEqual(sftp.mkdirs, ['/tmp/new', '/tmp/new/deeper'])
})

test('without createDirs a missing parent is an error that names the path', async () => {
  const sftp = new CleanupSftp({ writeError: 'No such file' })
  await assert.rejects(
    () => writeRemoteFile(client(sftp), '/tmp/missing/a.txt', 'x', opts()),
    (err) => {
      assert.match(err.message, /No such file/)
      assert.match(err.message, /\/tmp\/missing\/a\.txt/, 'the failing path is part of the message')
      return true
    }
  )
  assert.deepEqual(sftp.mkdirs, [], 'nothing is created unless asked')
})
