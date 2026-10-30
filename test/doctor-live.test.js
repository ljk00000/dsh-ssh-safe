import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { apply } from '../src/index.js'
import { startServer, machineFor } from './helpers/local-ssh-server.js'

// ssh_doctor is the tool a user reaches for when a connection fails, so its
// failure branches matter more than its success path: it has to say which stage
// broke and stop at the right place. Before this file those branches were only
// checked by grepping the source.

/** Apply the plugin with one config, hand the tools to fn, then clean up. */
async function withPlugin(config, fn) {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-doctor-'))
  process.env.DSH_HOME = home
  const tools = {}
  const ctx = {
    tools: { register: (def) => { tools[def.name] = def } },
    effect: () => {},
    get: () => undefined,
  }
  await apply(ctx, {
    allowSessionPassword: false,
    hostKeyPolicy: 'tofu',
    healthCheckIdleMs: 0,
    reconnectCooldownMs: 0,
    connectTimeoutMs: 2000,
    ...config,
  })
  try {
    return await fn({ tools, home })
  } finally {
    try { await tools.ssh_close.execute({ force: true }, {}) } catch {}
    delete process.env.DSH_HOME
    rmSync(home, { recursive: true, force: true })
  }
}

const doctor = (tools, args = {}) => tools.ssh_doctor.execute(args, {}).then((r) => String(r.text))

test('doctor stops at configuration when the host is missing', async () => {
  await withPlugin({ machines: { ghost: { user: 'root' } } }, async ({ tools }) => {
    const text = await doctor(tools, { machine: 'ghost' })
    assert.match(text, /\[FAIL\] configuration: missing DSH_SSH_GHOST_HOST/)
    assert.match(text, /Stopped: fix the above/)
    assert.doesNotMatch(text, /\[ok\] tcp/, 'it must not test the network')
  })
})

test('doctor stops when there is no credential at all', async () => {
  await withPlugin({ machines: { box: { host: '127.0.0.1', port: 1, user: 'u' } } }, async ({ tools }) => {
    const text = await doctor(tools, { machine: 'box' })
    assert.match(text, /\[ok\] configuration: u@127\.0\.0\.1:1/)
    assert.match(text, /\[FAIL\] credentials: no password, key or agent available/)
    assert.match(text, /Stopped: fix the above/)
    assert.doesNotMatch(text, /\[ok\] tcp/)
  })
})

test('doctor names a key file that is not there', async () => {
  await withPlugin({
    machines: { box: { host: '127.0.0.1', port: 1, user: 'u', keyPath: '/definitely/not/here/id_ed25519' } },
  }, async ({ tools }) => {
    const text = await doctor(tools, { machine: 'box' })
    assert.match(text, /\[FAIL\] credentials: key file not found: .*id_ed25519/)
    assert.match(text, /Stopped: fix the above/)
  })
})

test('doctor reports an unreachable port and stops before authentication', async () => {
  const dead = await startServer()
  const port = dead.port
  await dead.close()
  await withPlugin({
    allowPlaintextPassword: true,
    machines: { box: machineFor('box', port) },
  }, async ({ tools }) => {
    const text = await doctor(tools, { machine: 'box' })
    assert.match(text, /\[ok\] configuration/)
    assert.match(text, /\[ok\] credentials/)
    assert.match(text, /\[FAIL\] tcp: ECONNREFUSED/)
    assert.match(text, /Stopped: the host is unreachable/)
    assert.doesNotMatch(text, /\[ok\] host key/)
  })
})

test('doctor separates a wrong password from a host-key problem', async () => {
  const srv = await startServer({ password: 'right-one' })
  try {
    await withPlugin({
      allowPlaintextPassword: true,
      machines: { box: machineFor('box', srv.port, { password: 'wrong-one' }) },
    }, async ({ tools }) => {
      const text = await doctor(tools, { machine: 'box' })
      assert.match(text, /\[ok\] tcp/)
      assert.match(text, /\[ok\] host key/)
      assert.match(text, /\[FAIL\] authentication: .*[Aa]uthentication/)
      assert.match(text, /authorized_keys/)
    })
  } finally {
    await srv.close()
  }
})

test('doctor refuses an unknown host key under strict and skips authentication', async () => {
  const srv = await startServer()
  try {
    await withPlugin({
      allowPlaintextPassword: true,
      hostKeyPolicy: 'strict',
      machines: { box: machineFor('box', srv.port) },
    }, async ({ tools }) => {
      const text = await doctor(tools, { machine: 'box' })
      assert.match(text, /\[FAIL\] host key: Unknown host 127\.0\.0\.1:/)
      assert.match(text, /\[skip\] authentication: host key was rejected first/)
    })
  } finally {
    await srv.close()
  }
})

test('doctor reports a changed host key as a changed host key', async () => {
  const first = await startServer()
  let second = null
  try {
    await withPlugin({
      allowPlaintextPassword: true,
      hostKeyPolicy: 'tofu',
      machines: { box: machineFor('box', first.port) },
    }, async ({ tools }) => {
      // First contact records the fingerprint of the first server.
      assert.match(await doctor(tools, { machine: 'box' }), /\[ok\] authentication/)

      await first.close()
      second = await startServer({ port: first.port })
      const text = await doctor(tools, { machine: 'box' })
      assert.match(text, /\[FAIL\] host key: HOST KEY CHANGED/)
      assert.match(text, /\[skip\] authentication/)
    })
  } finally {
    await first.close()
    if (second) await second.close()
  }
})
