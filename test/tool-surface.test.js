import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import net from 'node:net'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { apply } from '../src/index.js'

// Every tool renders values that came out of a file a human may edit (the
// credential file) or out of the settings form. This sweep calls all twelve with
// hostile values and scans what comes back: one raw control character is enough
// to repaint a terminal or forge a line in a transcript.
//
// It is the check that found the workspace 'bound to' endpoint in 0.7.352.

const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u001b\u007f]/
const EVIL = '\u0000\u001b[31mred'

/** A port nothing listens on, so the failure paths run without waiting. */
async function freePort() {
  const probe = net.createServer()
  await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve))
  const { port } = probe.address()
  await new Promise((resolve) => probe.close(resolve))
  return port
}

test('no tool returns a raw control character, whatever the credential file says', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-surface-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = {}
  const ctx = { tools: { register: (def) => { tools[def.name] = def } }, effect: () => {}, get: () => undefined }
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    const dead = await freePort()
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify({
      // Every field, including the ones that only appear in error messages.
      evil: {
        host: '127.0.0.1' + EVIL,
        port: dead,
        user: 'u' + EVIL,
        keyPath: '/nope/' + EVIL,
        keyPassphrase: 'p' + EVIL,
        knownHosts: '/kh/' + EVIL,
        hostKeyPolicy: 'x' + EVIL,
      },
    }), 'utf8')
    await apply(ctx, {
      hostKeyPolicy: 'tofu', allowPlaintextPassword: true, reconnectCooldownMs: 0,
      connectTimeoutMs: 1200, commandTimeoutMs: 1200, auditLog: true,
      machines: { formevil: { host: 'h' + EVIL, user: 'u' + EVIL } },
    })

    const calls = [
      ['ssh_machines', {}],
      ['ssh_credentials', {}],
      ['ssh_config', {}],
      ['ssh_audit', { limit: 5 }],
      ['ssh_connect', { machine: 'evil' }],
      ['ssh_exec', { machine: 'evil', command: 'echo hi' }],
      ['ssh_read', { machine: 'evil', path: '/x' }],
      ['ssh_list', { machine: 'evil', path: '/' }],
      ['ssh_write', { machine: 'evil', path: '/x', content: 'y' }],
      ['ssh_workspace', { machine: 'evil' }],
      ['ssh_workspace', { action: 'create', machine: 'evil' }],
      ['ssh_doctor', { machine: 'evil' }],
      ['ssh_close', { machine: 'evil' }],
      ['ssh_doctor', { machine: 'formevil' }],
      ['ssh_machines', { machine: 'formevil' }],
      ['ssh_credentials', { machine: 'formevil' }],
    ]
    const leaks = []
    for (const [name, args] of calls) {
      let text
      try {
        const result = await tools[name].execute(args, {})
        text = String(result && result.text !== undefined ? result.text : '')
      } catch (err) {
        text = String(err && err.message || err)
      }
      assert.ok(text.length > 0, name + ' answered nothing')
      for (const line of text.split('\n')) {
        if (CONTROL.test(line)) leaks.push(name + ' ' + JSON.stringify(args) + ': ' + JSON.stringify(line.slice(0, 120)))
      }
      // Whatever the value is, it must never come back as a flattened object.
      assert.doesNotMatch(text, /\[object Object\]/, name + ' flattened a value')
    }
    assert.deepEqual(leaks, [], 'replies carrying a raw control character')
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})
