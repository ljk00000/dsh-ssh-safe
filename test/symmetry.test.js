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

// These assertions name the shared validators rather than `args.password`
// because that is the contract now. ssh_exec and ssh_read used to hand the raw
// value to the pool -- and ssh_read passed maxBytes/timeoutMs through a bare
// Number() -- so a wrong type surfaced as NaN or a connection error instead of
// a message naming the argument. Pinning optionalText(...)/optionalBudget(...)
// here means a regression to the raw form fails the suite.

const source = readFileSync(new URL('../src/index.js', import.meta.url), 'utf8')

// Slice to the next tool definition rather than a fixed length: the blocks grow
// whenever a comment is added, and a fixed window would silently start reading
// the neighbouring tool.
function toolBlock(name) {
  const start = source.indexOf("name: '" + name + "'")
  assert.ok(start > 0, 'tool not found: ' + name)
  const next = source.indexOf("name: '", start + 10)
  return source.slice(start, next === -1 ? source.length : next)
}

for (const name of ['ssh_exec', 'ssh_read', 'ssh_write', 'ssh_list']) {
  test(name + ' declares a password argument', () => {
    assert.match(toolBlock(name), /password: \{ type: 'string'/, name + ' must accept password')
  })

  test(name + ' forwards the password through the shared validator', () => {
    assert.match(
      toolBlock(name),
      /sessionPassword: optionalText\(args\.password, 'password'\)/,
      name + ' must forward password through optionalText',
    )
  })

  test(name + ' declares a timeoutMs argument', () => {
    assert.match(toolBlock(name), /timeoutMs: \{ type: 'integer'/, name + ' must accept timeoutMs')
  })

  test(name + ' validates its deadline', () => {
    assert.match(
      toolBlock(name),
      /optionalBudget\(args\.timeoutMs, 'timeoutMs'\)/,
      name + ' must pass timeoutMs through optionalBudget',
    )
  })
}

test('ssh_connect still accepts trustHostKey and force', () => {
  const block = toolBlock('ssh_connect')
  assert.match(block, /trustHostKey: \{ type: 'boolean'/)
  assert.match(block, /force: \{ type: 'boolean'/)
})
