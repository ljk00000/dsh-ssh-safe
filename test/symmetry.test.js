import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

// Every tool that reaches the network must accept the same two optional
// arguments the pool already supports: a session password (for profiles that
// allow it) and a per-call deadline.
//
// The pool implemented sessionPassword in exec/readFile/writeFile/list from the
// start, but only ssh_connect declared it, so a session-password user lost the
// ability to reconnect once the connection was evicted or closed.

const source = readFileSync(new URL('../src/index.js', import.meta.url), 'utf8')

function toolBlock(name) {
  const start = source.indexOf("name: '" + name + "'")
  assert.ok(start > 0, 'tool not found: ' + name)
  return source.slice(start, start + 1800)
}

for (const name of ['ssh_exec', 'ssh_read', 'ssh_write', 'ssh_list']) {
  test(name + ' declares a password argument', () => {
    assert.match(toolBlock(name), /password: \{ type: 'string'/, name + ' must accept password')
  })

  test(name + ' forwards the password to the pool', () => {
    assert.match(toolBlock(name), /sessionPassword: args\.password/, name + ' must forward password')
  })

  test(name + ' declares a timeoutMs argument', () => {
    assert.match(toolBlock(name), /timeoutMs: \{ type: 'integer'/, name + ' must accept timeoutMs')
  })
}

test('ssh_connect still accepts trustHostKey and force', () => {
  const block = toolBlock('ssh_connect')
  assert.match(block, /trustHostKey: \{ type: 'boolean'/)
  assert.match(block, /force: \{ type: 'boolean'/)
})
