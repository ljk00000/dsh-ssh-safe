// A tiny SFTP v3 server over a virtual filesystem, for tests.
//
// The plugin's read/write/list paths only ever ran against hand-written fakes:
// the shape of a real SFTP conversation (open -> fstat -> read ... close) was
// never exercised, so the client's stream helpers were never asked for a
// handle, a stat or an EOF. This speaks enough of the protocol for ssh2's
// createReadStream / createWriteStream / readdir to work against it.
//
// Nothing here touches the real filesystem.

import path from 'node:path'

const FXP = {
  INIT: 1, VERSION: 2, OPEN: 3, CLOSE: 4, READ: 5, WRITE: 6, LSTAT: 7, FSTAT: 8,
  SETSTAT: 9, FSETSTAT: 10, OPENDIR: 11, READDIR: 12, REMOVE: 13, MKDIR: 14,
  RMDIR: 15, REALPATH: 16, STAT: 17, RENAME: 18,
  STATUS: 101, HANDLE: 102, DATA: 103, NAME: 104, ATTRS: 105,
}

const STATUS = { OK: 0, EOF: 1, NO_SUCH_FILE: 2, PERMISSION_DENIED: 3, FAILURE: 4 }

const PFLAG = { READ: 1, WRITE: 2, APPEND: 4, CREAT: 8, TRUNC: 16, EXCL: 32 }

const u32 = (value) => {
  const buf = Buffer.alloc(4)
  buf.writeUInt32BE(value >>> 0, 0)
  return buf
}

const u64 = (value) => {
  const buf = Buffer.alloc(8)
  buf.writeUInt32BE(Math.floor(value / 2 ** 32), 0)
  buf.writeUInt32BE(value >>> 0, 4)
  return buf
}

const str = (value) => {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8')
  return Buffer.concat([u32(body.length), body])
}

class Reader {
  constructor(buf) { this.buf = buf; this.off = 0 }
  u8() { const v = this.buf.readUInt8(this.off); this.off += 1; return v }
  u32() { const v = this.buf.readUInt32BE(this.off); this.off += 4; return v }
  u64() {
    const hi = this.buf.readUInt32BE(this.off)
    const lo = this.buf.readUInt32BE(this.off + 4)
    this.off += 8
    return hi * 2 ** 32 + lo
  }
  string() { const n = this.u32(); const v = this.buf.subarray(this.off, this.off + n); this.off += n; return v }
  path() { return this.string().toString('utf8') }
  skipAttrs() {
    const flags = this.u32()
    if (flags & 0x1) this.off += 8
    if (flags & 0x2) this.off += 8
    if (flags & 0x4) this.off += 4
    if (flags & 0x8) this.off += 8
    if (flags & 0x80000000) {
      const count = this.u32()
      for (let i = 0; i < count; i++) { this.string(); this.string() }
    }
  }
}

/** An in-memory tree the SFTP handler reads and writes. */
export function createVfs() {
  const files = new Map()
  const dirs = new Set(['/'])
  const now = () => Math.floor(Date.now() / 1000)

  const normalize = (value) => {
    let p = path.posix.normalize(String(value || '/'))
    if (!p.startsWith('/')) p = '/' + p
    if (p.length > 1 && p.endsWith('/')) p = p.replace(/\/+$/, '')
    return p
  }

  const mkdirp = (p) => {
    const parts = normalize(p).split('/').filter(Boolean)
    let current = ''
    for (const part of parts) { current += '/' + part; dirs.add(current) }
  }

  const control = {
  stallReads: false,
  stallWrites: false,
  stallDirs: false,
  // Paths whose every operation answers "permission denied", the way sshd
  // answers for a file the login user may not touch.
  denied: new Set(),
  deny(target) { control.denied.add(String(target)) },
  undeny() { control.denied.clear() },
}

  return {
    control,
    normalize,
    putFile(p, content) {
      const target = normalize(p)
      mkdirp(path.posix.dirname(target))
      files.set(target, Buffer.isBuffer(content) ? Buffer.from(content) : Buffer.from(String(content), 'utf8'))
    },
    putDir(p) { mkdirp(p) },
    getFile(p) { return files.get(normalize(p)) },
    list(p) {
      const target = normalize(p)
      if (dirs.has(target)) {
        const prefix = target === '/' ? '/' : target + '/'
        const names = new Set()
        for (const dir of dirs) if (dir.startsWith(prefix) && dir !== target) names.add(dir.slice(prefix.length).split('/')[0])
        for (const file of files.keys()) if (file.startsWith(prefix)) names.add(file.slice(prefix.length).split('/')[0])
        return [...names]
      }
      return null
    },
    stat(p) {
      const target = normalize(p)
      if (dirs.has(target)) return { dir: true, size: 4096, mode: 0o040755, mtime: now() }
      const buf = files.get(target)
      if (buf) return { dir: false, size: buf.length, mode: 0o100644, mtime: now() }
      return null
    },
    read(p, offset, length) {
      const buf = files.get(normalize(p))
      if (!buf || offset >= buf.length) return null
      return buf.subarray(offset, Math.min(buf.length, offset + length))
    },
    write(p, offset, data) {
      const target = normalize(p)
      const existing = files.get(target) || Buffer.alloc(0)
      const end = offset + data.length
      const next = Buffer.alloc(Math.max(existing.length, end))
      existing.copy(next, 0)
      data.copy(next, offset)
      files.set(target, next)
      return next.length
    },
    truncate(p) { const target = normalize(p); files.set(target, Buffer.alloc(0)) },
    remove(p) {
      const target = normalize(p)
      if (files.delete(target)) return true
      if (dirs.delete(target)) return true
      return false
    },
  }
}

/** Answer one SFTP session on an already-accepted channel. */
export function attachSftp(stream, vfs) {
  const handles = new Map()
  let nextHandle = 1
  let pending = Buffer.alloc(0)

  const send = (type, id, ...parts) => {
    const payload = Buffer.concat([Buffer.from([type]), u32(id), ...parts])
    stream.write(Buffer.concat([u32(payload.length), payload]))
  }
  const status = (id, code, message = '') => send(FXP.STATUS, id, u32(code), str(message), str(''))
  const attrsOf = (stat) => Buffer.concat([
    u32(0x1 | 0x2 | 0x4 | 0x8),
    u64(stat.size), u32(0), u32(0), u32(stat.mode), u32(stat.mtime), u32(0),
  ])
  const newHandle = (value) => { const id = nextHandle++; handles.set(id, value); return id }

  const handlePacket = (payload) => {
    const reader = new Reader(payload)
    const type = reader.u8()

    // INIT carries no request id: it is type + version, and the answer is
    // type + version. Reading an id here consumed the version and made every
    // later request look like garbage.
    if (type === FXP.INIT) {
      reader.u32() // client version
      const body = Buffer.concat([Buffer.from([FXP.VERSION]), u32(3)])
      stream.write(Buffer.concat([u32(body.length), body]))
      return
    }

    const id = reader.u32()

    if (type === FXP.OPEN) {
      const target = vfs.normalize(reader.path())
      if (vfs.control.denied.has(target)) return status(id, STATUS.PERMISSION_DENIED, 'Permission denied')
      const pflags = reader.u32()
      reader.skipAttrs()
      const existing = vfs.stat(target)
      if (existing && existing.dir) return status(id, STATUS.FAILURE, 'is a directory')
      if (!existing) {
        if (!(pflags & PFLAG.CREAT)) return status(id, STATUS.NO_SUCH_FILE, 'no such file')
        // A real server will not create a file inside a directory that does not
        // exist; without this the plugin's createDirs advice was never reached.
        const parent = vfs.stat(path.posix.dirname(target))
        if (!parent || !parent.dir) return status(id, STATUS.NO_SUCH_FILE, 'no such file')
        vfs.putFile(target, Buffer.alloc(0))
      } else if (pflags & PFLAG.TRUNC) {
        vfs.truncate(target)
      }
      return send(FXP.HANDLE, id, str(Buffer.from(String(newHandle({ kind: 'file', path: target })))))
    }

    if (type === FXP.CLOSE) {
      const handle = Number(reader.string().toString('utf8'))
      handles.delete(handle)
      return status(id, STATUS.OK)
    }

    if (type === FXP.READ) {
      const handle = handles.get(Number(reader.string().toString('utf8')))
      const offset = reader.u64()
      const length = reader.u32()
      if (!handle) return status(id, STATUS.FAILURE, 'bad handle')
      if (vfs.control.denied.has(handle.path)) return status(id, STATUS.PERMISSION_DENIED, 'Permission denied')
      if (vfs.control.stallReads) return // no answer at all, like a wedged server
      const data = vfs.read(handle.path, offset, length)
      if (!data) return status(id, STATUS.EOF)
      return send(FXP.DATA, id, str(data))
    }

    if (type === FXP.WRITE) {
      const handle = handles.get(Number(reader.string().toString('utf8')))
      const offset = reader.u64()
      const data = reader.string()
      if (!handle) return status(id, STATUS.FAILURE, 'bad handle')
      if (vfs.control.denied.has(handle.path)) return status(id, STATUS.PERMISSION_DENIED, 'Permission denied')
      if (vfs.control.stallWrites) return
      vfs.write(handle.path, offset, data)
      return status(id, STATUS.OK)
    }

    if (type === FXP.STAT || type === FXP.LSTAT) {
      const target = vfs.normalize(reader.path())
      const stat = vfs.stat(target)
      if (!stat) return status(id, STATUS.NO_SUCH_FILE, 'no such file')
      return send(FXP.ATTRS, id, attrsOf(stat))
    }

    if (type === FXP.FSTAT) {
      const handle = handles.get(Number(reader.string().toString('utf8')))
      const stat = handle ? vfs.stat(handle.path) : null
      if (!stat) return status(id, STATUS.FAILURE, 'bad handle')
      return send(FXP.ATTRS, id, attrsOf(stat))
    }

    if (type === FXP.REALPATH) {
      const target = vfs.normalize(reader.path())
      const stat = vfs.stat(target)
      if (!stat) return status(id, STATUS.NO_SUCH_FILE, 'no such file')
      const entry = Buffer.concat([str(target), str(target), attrsOf(stat)])
      return send(FXP.NAME, id, u32(1), entry)
    }

    if (type === FXP.OPENDIR) {
      const target = vfs.normalize(reader.path())
      if (vfs.control.denied.has(target)) return status(id, STATUS.PERMISSION_DENIED, 'Permission denied')
      if (vfs.control.stallDirs) return // a readdir that never answers
      const stat = vfs.stat(target)
      if (!stat) return status(id, STATUS.NO_SUCH_FILE, 'no such file')
      if (!stat.dir) return status(id, STATUS.FAILURE, 'not a directory')
      // '.' and '..' are what a real OpenSSH server sends; the caller has to
      // decide whether to show them.
      const entries = ['.', '..', ...vfs.list(target)]
      const handleId = newHandle({ kind: 'dir', path: target, entries, sent: false })
      return send(FXP.HANDLE, id, str(Buffer.from(String(handleId))))
    }

    if (type === FXP.READDIR) {
      const handle = handles.get(Number(reader.string().toString('utf8')))
      if (!handle || handle.kind !== 'dir') return status(id, STATUS.FAILURE, 'bad handle')
      if (handle.sent) return status(id, STATUS.EOF)
      // Chunked like a real server. One packet per directory works for a
      // handful of entries and stalls on ten thousand: the whole NAME packet
      // has to fit the framing, and the client pays for parsing it in one go.
      const next = handle.entries.slice(handle.index || 0, (handle.index || 0) + 32)
      handle.index = (handle.index || 0) + next.length
      handle.sent = next.length === 0
      const parts = [u32(next.length)]
      for (const name of next) {
        const child = vfs.normalize(handle.path === '/' ? '/' + name : handle.path + '/' + name)
        const stat = vfs.stat(child) || { dir: false, size: 0, mode: 0o100644, mtime: 0 }
        parts.push(str(name), str(name), attrsOf(stat))
      }
      return send(FXP.NAME, id, ...parts)
    }

    if (type === FXP.MKDIR) {
      const target = vfs.normalize(reader.path())
      if (vfs.stat(target)) return status(id, STATUS.FAILURE, 'already exists')
      vfs.putDir(target)
      return status(id, STATUS.OK)
    }

    if (type === FXP.REMOVE || type === FXP.RMDIR) {
      const target = vfs.normalize(reader.path())
      if (!vfs.stat(target)) return status(id, STATUS.NO_SUCH_FILE, 'no such file')
      vfs.remove(target)
      return status(id, STATUS.OK)
    }

    // Anything else (SETSTAT, RENAME, ...) is not needed for these tests.
    return status(id, STATUS.FAILURE, 'unsupported operation ' + type)
  }

  stream.on('data', (chunk) => {
    pending = pending.length ? Buffer.concat([pending, chunk]) : chunk
    while (pending.length >= 4) {
      const length = pending.readUInt32BE(0)
      if (pending.length < 4 + length) break
      const payload = pending.subarray(4, 4 + length)
      pending = pending.subarray(4 + length)
      try { handlePacket(payload) } catch (err) { try { stream.destroy() } catch {} }
    }
  })
  stream.on('error', () => {})
}