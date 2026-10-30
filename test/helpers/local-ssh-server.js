import ssh2 from 'ssh2'

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
export function startServer({ port = 0, user = 'tester', password = 'test-pass', key = null } = {}) {
  const hostKey = key || utils.generateKeyPairSync('ed25519').private
  const server = new Server({ hostKeys: [hostKey] }, (client) => {
    client.on('authentication', (ctx) => {
      if (ctx.method === 'password' && ctx.username === user && ctx.password === password) ctx.accept()
      else ctx.reject(['password'])
    })
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept()
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
