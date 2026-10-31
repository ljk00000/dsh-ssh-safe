import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { AuditLog } from '../src/audit.js'

// The audit log stored the command verbatim: 'mysql -uroot -pSECRET' went to disk
// in clear and ssh_audit read it back into the conversation. The plugin promises
// that no secret reaches a log, and the log is a log.

test('audit records are redacted before they reach the disk', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dsh-audit-redact-'))
  try {
    const log = new AuditLog(dir, { enabled: true })
    log.write({ kind: 'exec', machine: 'a', command: 'mysql -uroot -pSuperSecret1 -e "select 1"' })
    log.write({ kind: 'exec', machine: 'a', command: 'TOKEN=abcdef123 curl -H "Authorization: Bearer sk-live-9" https://x' })
    log.write({ kind: 'error', machine: 'a', error: 'auth failed for password: hunter2' })

    const text = readFileSync(path.join(dir, 'audit.ndjson'), 'utf8')
    for (const secret of ['SuperSecret1', 'abcdef123', 'sk-live-9', 'hunter2']) {
      assert.equal(text.includes(secret), false, secret + ' reached the audit log')
    }
    assert.match(text, /-p<redacted>/)
    assert.match(text, /password: <redacted>/)
    // The record is still useful: the command shape and the machine survive.
    assert.match(text, /"machine":"a"/)
    assert.match(text, /mysql -uroot -p<redacted>/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
