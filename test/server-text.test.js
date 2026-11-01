import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import ssh2 from 'ssh2'

import { apply } from '../src/index.js'
import { testHostKey } from './helpers/local-ssh-server.js'

// What a *server* says is not our text.
//
// ssh2 puts the message from an SFTP STATUS packet straight into
// `err.message` (node_modules/ssh2/lib/protocol/SFTP.js: `new Error(errorMsg
// || STATUS_CODE_STR[errorCode] || 'Unknown status')`), so the remote host
// chooses those bytes. A host that answers every request with an ANSI escape
// used to paint the user's terminal.
//
// The server below speaks just enough SFTP to refuse everything with a chosen
// message: INIT is answered with VERSION 3, every other request with STATUS
// FAILURE carrying that text. It listens on 'subsystem' rather than 'sftp' —
// the latter hands back ssh2's own parser, which is the trap documented in the
// loopback helper.

const ESC = String.fromCharCode(27)
const HOSTILE = 'server says ' + ESC + '[31mred'

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0, 0); return b }
const str = (s) => { const b = Buffer.from(String(s), 'utf8'); return Buffer.concat([u32(b.length), b]) }

function refuseEverything(stream) {
  let acc = Buffer.alloc(0)
  stream.on('data', (chunk) => {
    acc = Buffer.concat([acc, chunk])
    for (;;) {
      if (acc.length < 4) return
      const length = acc.readUInt32BE(0)
      if (acc.length < 4 + length) return
      const payload = acc.subarray(4, 4 + length)
      acc = acc.subarray(4 + length)
      const type = payload[0]
      if (type === 1) {
        const version = Buffer.concat([Buffer.from([2]), u32(3)])
        stream.write(Buffer.concat([u32(version.length), version]))
        continue
      }
      const id = payload.readUInt32BE(1)
      const status = Buffer.concat([Buffer.from([101]), u32(id), u32(4), str(HOSTILE), str('')])
      stream.write(Buffer.concat([u32(status.length), status]))
    }
  })
  stream.on('error', () => {})
}

async function hostileServer() {
  const { Server } = ssh2
  const server = new Server({ hostKeys: [testHostKey()] }, (client) => {
    client.on('error', () => {})
    client.on('authentication', (ctx) => ctx.accept())
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept()
        session.on('subsystem', (acceptSubsystem, _reject, info) => {
          if (info && info.name === 'sftp') refuseEverything(acceptSubsystem())
        })
      })
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { server, port: server.address().port }
}

test('text a server sends in an SFTP error is escaped, not printed', async () => {
  const { server, port } = await hostileServer()
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-hostile-sftp-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  const ctx = { tools: { register: (def) => { tools[def.name] = def } }, effect: () => {}, get: () => undefined }
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
      rude: { host: '127.0.0.1', port, user: 'tester', password: 'test-pass' },
    }), 'utf8')
    await apply(ctx, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 4000, sftpTimeoutMs: 4000, commandTimeoutMs: 4000,
    })
    for (const [name, args] of [
      ['ssh_list', { machine: 'rude', path: '/' }],
      ['ssh_read', { machine: 'rude', path: '/x' }],
      ['ssh_write', { machine: 'rude', path: '/x', content: 'y' }],
    ]) {
      const message = await tools[name].execute(args, {})
        .then(() => '', (err) => String(err && err.message || err))
      assert.match(message, /server says/, name + ' lost the server text: ' + JSON.stringify(message))
      assert.match(message, /\\x1b\[31mred/, name + ' should quote the escape: ' + JSON.stringify(message))
      assert.doesNotMatch(message, /\u001b/, name + ' printed a raw escape: ' + JSON.stringify(message))
    }
  } finally {
    await tools.ssh_close?.execute({ force: true }, {}).catch(() => {})
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
    await new Promise((resolve) => server.close(resolve))
  }
})
