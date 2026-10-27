import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

// ssh_doctor exists because 'All configured authentication methods failed' does
// not tell a user whether DNS failed, the port is closed, the host key changed,
// or the credential was rejected.

const source = readFileSync(new URL('../src/index.js', import.meta.url), 'utf8')

test('ssh_doctor is registered', () => {
  assert.match(source, /name: 'ssh_doctor'/)
})

test('ssh_doctor reports the configuration stage first', () => {
  const block = source.slice(source.indexOf("name: 'ssh_doctor'"), source.indexOf("name: 'ssh_close'"))
  assert.match(block, /'configuration'/)
  assert.match(block, /'credentials'/)
})

test('ssh_doctor tests tcp before authentication', () => {
  const block = source.slice(source.indexOf("name: 'ssh_doctor'"), source.indexOf("name: 'ssh_close'"))
  const tcpAt = block.indexOf("'tcp'")
  const authAt = block.indexOf("'authentication'")
  assert.ok(tcpAt > 0 && authAt > tcpAt, 'tcp is checked first so a closed port is not reported as an auth failure')
})

test('ssh_doctor distinguishes a host-key rejection from an auth rejection', () => {
  const block = source.slice(source.indexOf("name: 'ssh_doctor'"), source.indexOf("name: 'ssh_close'"))
  assert.match(block, /HOST KEY CHANGED|host key/i)
  assert.match(block, /authorized_keys/, 'it tells the user where to look')
})

test('ssh_doctor redacts before printing an error', () => {
  const block = source.slice(source.indexOf("name: 'ssh_doctor'"), source.indexOf("name: 'ssh_close'"))
  assert.match(block, /redact\(/)
})
