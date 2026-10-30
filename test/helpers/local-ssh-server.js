import ssh2 from 'ssh2'
import { attachSftp, createVfs } from './sftp-vfs.js'

const { Server, utils } = ssh2

/**
 * A local SSH server for end-to-end tests.
 *
 * It implements just enough of the protocol for the plugin's exec path: password
 * auth, one session channel, and an exec handler that answers deterministic
 * output instead of running anything. No process is spawned and no real file is
 * touched, so destructive-command tests cannot escape.
 *
 * Commands understood by the handler:
 *   echo <text>      -> "ran: echo <text>"
 *   sleep <seconds>  -> waits, then exits 0
 *   exit <code>      -> exits with that code
 *   kill             -> exits with signal KILL
 *   big <n>          -> writes n 'x' characters
 *   stderr           -> one line on stderr, then "ok" on stdout
 *   anything else    -> "ran: <command>"
 */
// One host key per process, generated once.
//
// ed25519 generation was cheap but occasionally produced a key ssh2's own
// server parser rejected ("Malformed OpenSSH private key"), which turned into a
// flaky test that had nothing to do with the code under test. RSA generation
// costs ~100 ms once per test process and is what the first version of this
// helper used without a single failure.
let cachedHostKey = null
function hostKeyOnce() {
  if (!cachedHostKey) cachedHostKey = utils.generateKeyPairSync('rsa', { bits: 2048 }).private
  return cachedHostKey
}

/**
 * A second, different host key.
 *
 * Tests that check the plugin notices a changed key need two keys; with one
 * cached key per process a "replacement" server presents the same key and the
 * test proves nothing (it then fails, which is how this was noticed).
 */
export function alternateHostKey() {
  if (!cachedAltKey) cachedAltKey = utils.generateKeyPairSync('rsa', { bits: 2048 }).private
  return cachedAltKey
}
let cachedAltKey = null

export function startServer({ port = 0, user = 'tester', password = 'test-pass', key = null } = {}) {
  const hostKey = key || hostKeyOnce()
  const vfs = createVfs()
  const clients = new Set()
  const server = new Server({ hostKeys: [hostKey] }, (client) => {
    clients.add(client)
    client.on('close', () => clients.delete(client))
    client.on('authentication', (ctx) => {
      if (ctx.method === 'password' && ctx.username === user && ctx.password === password) ctx.accept()
      else ctx.reject(['password'])
    })
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept()
        // Listen for the subsystem rather than the 'sftp' event: the latter
        // hands back ssh2's own SFTP parser, while a plain subsystem channel is
        // a raw stream this helper can speak the protocol on.
        session.on('subsystem', (acceptSubsystem, _reject, info) => {
          if (info && info.name === 'sftp') attachSftp(acceptSubsystem(), vfs)
        })
        session.on('exec', (acceptExec, _rejectExec, info) => {
          const stream = acceptExec()
          const command = String(info.command || '')
          const finish = (code, out = '') => {
            if (out) stream.write(out)
            stream.exit(code)
            stream.end()
          }
          if (/^sleep\b/.test(command)) {
            const seconds = Number((command.match(/sleep\s+([\d.]+)/) || [])[1] || 0)
            setTimeout(() => finish(0, 'slept ' + seconds + '\n'), seconds * 1000)
            return
          }
          if (/^exit\b/.test(command)) {
            return finish(Number((command.match(/exit\s+(\d+)/) || [])[1] || 0))
          }
          if (/^kill\b/.test(command)) {
            stream.exit('KILL')
            stream.end()
            return
          }
          if (/^big\b/.test(command)) {
            const n = Number((command.match(/big\s+(\d+)/) || [])[1] || 1000)
            return finish(0, 'x'.repeat(n))
          }
          if (/^slowout\b/.test(command)) {
            // Says something, then keeps going: a command killed mid-output.
            stream.write('started\n')
            stream.stderr.write('warming up\n')
            setTimeout(() => { try { stream.write('finished\n'); stream.exit(0); stream.end() } catch {} }, 600)
            return
          }
          if (/^crlf\b/.test(command)) {
            return finish(0, 'line one\r\nline two\r\n')
          }
          if (/^binary\b/.test(command)) {
            stream.write(Buffer.from([0xff, 0xfe, 0x00, 0x41]))
            stream.exit(0)
            stream.end()
            return
          }
          if (/^stderr\b/.test(command)) {
            stream.stderr.write('an error line\n')
            return finish(0, 'ok\n')
          }
          finish(0, 'ran: ' + command + '\n')
        })
      })
    })
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', () => {
      resolve({
        port: server.address().port,
        key: hostKey,
        vfs,
        clientCount: () => clients.size,
        // Sever established sessions the way a network drop would: the server
        // stops answering while the listening socket stays up.
        killClients: () => { for (const c of clients) { try { c.end(); c.destroy?.() } catch {} } },
        close: () => new Promise((done) => server.close(() => done(undefined))),
      })
    })
  })
}

/** A pool configured to talk to one local server, with an isolated DSH_HOME. */
export function machineFor(alias, port, extra = {}) {
  return {
    host: '127.0.0.1',
    port,
    user: 'tester',
    password: 'test-pass',
    ...extra,
  }
}