import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { apply } from '../src/index.js'

// The renderers take their text from files a human may edit: the audit log and the
// credential file. Fuzzing them by hand is how 0.7.342 (raw NUL and ANSI escapes in
// audit detail fields) and 0.7.343 ([object Object] in three listings) were found;
// this file keeps that sweep running, with a fixed seed so a failure is reproducible.

const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u001b\u007f]/
const BROKEN = /\[object Object\]|undefined|NaN/

/** Deterministic pseudo-random numbers, so a failure can be replayed. */
function seeded(seed) {
  let state = seed
  return () => {
    state = (state * 1103515245 + 12345) % 2147483648
    return state / 2147483648
  }
}

const VALUES = [null, true, 0, -1, 1e12, '', 'x', '\u0000\u001b[31mred', '\u001b]0;title\u0007',
  {}, [], [1], { a: 1 }, 'h.example', 22, 'a'.repeat(300)]

function fuzzRows(count, seed) {
  const rnd = seeded(seed)
  const pick = (list) => list[Math.floor(rnd() * list.length)]
  const keys = ['at', 'kind', 'outcome', 'machine', 'command', 'path', 'bytes', 'ms', 'mode', 'reason',
    'pattern', 'direction', 'error', 'hostKey', 'fingerprint', 'entries', 'truncated', 'redacted',
    'signal', 'exitCode', 'linkTarget']
  const rows = []
  for (let i = 0; i < count; i++) {
    const row = {}
    for (const key of keys) if (rnd() < 0.55) row[key] = pick(VALUES)
    rows.push(JSON.stringify(row))
  }
  return rows
}

function ownTools(home) {
  const tools = {}
  const ctx = { tools: { register: (def) => { tools[def.name] = def } }, effect: () => {}, get: () => undefined }
  return { tools, ctx }
}

test('the audit renderer never prints a control character or [object Object]', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-fuzz-audit-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'audit.ndjson'),
      fuzzRows(80, 133).join('\n') + '\n', 'utf8')
    const { tools, ctx } = ownTools(home)
    await apply(ctx, { hostKeyPolicy: 'tofu', auditLog: true, machines: {} })
    const shown = String((await tools.ssh_audit.execute({ limit: 200 }, {})).text)
    for (const line of shown.split('\n')) {
      assert.doesNotMatch(line, CONTROL, 'a control character reached the terminal: ' + JSON.stringify(line))
      assert.doesNotMatch(line, BROKEN, 'a value was lost: ' + JSON.stringify(line))
    }
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('the listings never print a control character or [object Object]', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-fuzz-list-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    mkdirSync(path.join(home, 'dsh-ssh-safe'), { recursive: true })
    const rnd = seeded(343)
    const pick = (list) => list[Math.floor(rnd() * list.length)]
    const store = {}
    for (let i = 0; i < 12; i++) {
      const entry = {}
      for (const key of ['host', 'port', 'user', 'keyPath', 'keyPassphrase', 'password',
        'hostKeyPolicy', 'knownHosts']) {
        if (rnd() < 0.5) entry[key] = pick(VALUES)
      }
      store['m' + i] = entry
    }
    writeFileSync(path.join(home, 'dsh-ssh-safe', 'credentials.json'), JSON.stringify(store), 'utf8')
    const { tools, ctx } = ownTools(home)
    await apply(ctx, { hostKeyPolicy: 'tofu', allowPlaintextPassword: true, machines: {} })
    for (const name of ['ssh_machines', 'ssh_credentials']) {
      const shown = String((await tools[name].execute({}, {})).text)
      for (const line of shown.split('\n')) {
        assert.doesNotMatch(line, CONTROL, name + ' printed a control character: ' + JSON.stringify(line))
        assert.doesNotMatch(line, BROKEN, name + ' lost a value: ' + JSON.stringify(line))
      }
    }
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})
