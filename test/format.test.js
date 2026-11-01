import { test } from 'node:test'
import assert from 'node:assert/strict'
import { exitLine, formatListing } from '../src/format.js'

// A command killed by a signal has no exit code. ssh2 reports
// close(null, 'SIGKILL'), and rendering that as '[exit unknown]' hides the only
// useful fact: the process was killed, not that its status was lost.
test('a killed process names the signal instead of "unknown"', () => {
  assert.equal(exitLine({ code: null, signal: 'SIGKILL' }), '[signal SIGKILL]')
  assert.equal(exitLine({ code: null, signal: 'TERM' }), '[signal TERM]')
})

test('an ordinary exit keeps the exit code', () => {
  assert.equal(exitLine({ code: 0, signal: null }), '[exit 0]')
  assert.equal(exitLine({ code: 3 }), '[exit 3]')
})

test('no code and no signal is still reported as unknown', () => {
  assert.equal(exitLine({ code: null }), '[exit unknown]')
  assert.equal(exitLine({}), '[exit unknown]')
})

// A directory of 200k files used to come back as a 20 MB tool result with no
// ceiling. The rendering lives in its own module now, so the cap, the ordering
// and the omitted count can be checked without an SSH session.

const listing = (names, path = '/tmp/dir') => ({
  path,
  items: names.map((name) => ({ name, size: 1, dir: false, mtime: null })),
})

test('an empty directory says so and names the path', () => {
  assert.equal(formatListing({ path: '/x', items: [] }), '(empty directory: /x)')
})

test('directories sort before files, each group by name', () => {
  const out = formatListing({
    path: '/x',
    items: [
      { name: 'b.txt', size: 2, dir: false, mtime: null },
      { name: 'zdir', size: 0, dir: true, mtime: null },
      { name: 'a.txt', size: 1, dir: false, mtime: null },
      { name: 'adir', size: 0, dir: true, mtime: null },
    ],
  })
  const names = out.split('\n').slice(1).map((row) => row.split('  ').pop())
  assert.deepEqual(names, ['adir', 'zdir', 'a.txt', 'b.txt'])
})

test('the cap keeps the first N rows and reports the rest', () => {
  const names = Array.from({ length: 500 }, (_, i) => 'f' + i)
  const out = formatListing(listing(names), 50)
  const rows = out.split('\n').filter((row) => /^[d-] /.test(row))
  assert.equal(rows.length, 50)
  assert.match(out, /450 more entries not shown/)
  assert.match(out, /maxListEntries = 50/)
})

test('limit 0 means no limit', () => {
  const names = Array.from({ length: 500 }, (_, i) => 'f' + i)
  const out = formatListing(listing(names), 0)
  assert.equal(out.split('\n').filter((row) => /^[d-] /.test(row)).length, 500)
  assert.doesNotMatch(out, /not shown/)
})

test('one omitted entry reads as "entry", not "entries"', () => {
  const out = formatListing(listing(['a', 'b']), 1)
  assert.match(out, /1 more entry not shown/)
})

test('a name containing a newline cannot forge an extra row', () => {
  const out = formatListing(listing(['line\nbreak.txt']))
  const rows = out.split('\n').filter((row) => /^[d-] /.test(row))
  assert.equal(rows.length, 1, 'one entry must render as one row')
  assert.match(out, /line\\nbreak\.txt/, 'the newline is shown escaped, not silently dropped')
})
test('an IPv6 literal is printed once, in brackets', async () => {
  // 'user@::1:22' reads as host "::1:22"; the port is unrecoverable from it.
  const { formatHost } = await import('../src/pool.js')
  assert.equal(formatHost('::1'), '[::1]')
  assert.equal(formatHost('[::1]'), '[::1]', 'already bracketed is not doubled')
  assert.equal(formatHost('fe80::1'), '[fe80::1]')
  assert.equal(formatHost('10.0.0.5'), '10.0.0.5')
  assert.equal(formatHost('example.com'), 'example.com')
  // Not an IPv6 literal, but a whole address pasted into the host field: quote
  // it so the port after it is not swallowed into the host.
  assert.equal(formatHost('example.com:2222'), '"example.com:2222"')
  assert.equal(formatHost('ssh://h'), '"ssh://h"')
  assert.equal(formatHost(''), '')
})

test('a signal name a server chose is escaped', () => {
  // ssh2 passes the exit-signal payload through untouched:
  //   client.js:676  exit.signal = `SIG${data.signal}`
  // so the host writes this text. It used to reach the reply as
  //   [signal SIGKILL<ESC>[31MRED]
  // A unit test is enough: reaching this through the protocol needs a hand-built
  // packet, and the escaping is a pure function. The audit row is covered by
  // test/render-fuzz.test.js.
  assert.equal(exitLine({ code: null, signal: 'SIGKILL' }), '[signal SIGKILL]')
  assert.equal(exitLine({ code: null, signal: 'KILL' + String.fromCharCode(27) + '[31mred' }),
    '[signal KILL\\x1b[31mred]')
  assert.equal(exitLine({ code: 3 }), '[exit 3]')
  assert.equal(exitLine({ code: null, signal: null }), '[exit unknown]')
})

test('the path in a listing header is escaped like the names beside it', () => {
  // A directory may legally be named with a control character, and copying that
  // name into ssh_list printed it raw: three headers did (listing, empty
  // directory, offset past the end) while the names below were escaped.
  const evil = '/d' + String.fromCharCode(27) + '[31mred'
  const shown = formatListing({ path: evil, items: [{ name: 'inside.txt', size: 1, dir: false, mtime: '2026-11-01T00:00:00Z' }] })
  assert.match(shown.split('\n')[0], /\\x1b\[31mred/)
  assert.doesNotMatch(shown, /\u001b/)
  assert.match(formatListing({ path: evil, items: [] }), /\(empty directory: \/d\\x1b\[31mred\)/)
  assert.match(formatListing({ path: evil, items: [{ name: 'a', size: 1, dir: false }] }, 0, 5),
    /\/d\\x1b\[31mred\n\(offset 5 is past the last of 1 entries\)/)
  // An ordinary path is untouched.
  assert.match(formatListing({ path: '/home/user', items: [] }), /^\(empty directory: \/home\/user\)$/)
})
