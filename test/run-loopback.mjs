#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Run the opt-in integration tests (test/integration.test.js) against a
// loopback SSH server instead of a real host.
//
//   npm run test:loopback
//
// test/integration.test.js is the one file that talks to a real sshd; it skips
// unless DSH_SSH_TEST_TARGET names a configured alias. Waiting for a real host
// to check that the client half still works is a poor trade -- the loopback
// server in test/helpers speaks enough SSH and SFTP for those four tests, so
// this wires the two together. It is a repository tool: test/ is not shipped.

import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { startServer } from './helpers/local-ssh-server.js'

const root = path.resolve(import.meta.dirname, '..')
const server = await startServer()
server.vfs.putDir('/etc')
server.vfs.putFile('/etc/hostname', 'loopback-host\n')

const home = mkdtempSync(path.join(tmpdir(), 'dsh-ssh-loopback-'))
const env = {
  ...process.env,
  DSH_SSH_TEST_TARGET: 'loop',
  DSH_SSH_LOOP_HOST: '127.0.0.1',
  DSH_SSH_LOOP_PORT: String(server.port),
  DSH_SSH_LOOP_USER: 'tester',
  DSH_SSH_LOOP_PASSWORD: 'test-pass',
  DSH_HOME: home,
}

console.log('loopback sshd on 127.0.0.1:' + server.port)
// spawn, not spawnSync: the server lives in THIS process, so blocking the
// event loop here would stop it answering the child it just started. That is
// exactly what happened the first time this script ran -- every test timed out
// at the connect deadline.
const child = spawn(process.execPath, ['--test', 'test/integration.test.js'], {
  cwd: root,
  env,
  stdio: 'inherit',
})
const status = await new Promise((resolve) => {
  child.on('exit', (code) => resolve(code))
  child.on('error', () => resolve(1))
})

await server.close()
rmSync(home, { recursive: true, force: true })
process.exit(status === null ? 1 : status)