import { test } from 'node:test'
import assert from 'node:assert/strict'
import { formatListing } from '../src/format.js'

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
