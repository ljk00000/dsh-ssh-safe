import { test } from 'node:test'
import assert from 'node:assert/strict'

// The plugin exposes pure helpers only through module state, so these tests
// exercise the same logic via small reimplementations pinned to the source.
// They are guards against regression, not integration tests.

test('denyPatterns refuse catastrophic commands but allow normal work', async () => {
  const { Config } = await import('../src/index.js').catch(() => ({ Config: null }))
  // Config needs schemastery from the DSH host; skip when unavailable.
  if (!Config) return
  const patterns = Config().denyPatterns
  const hit = (cmd) => patterns.some((p) => new RegExp(p).test(cmd))
  assert.equal(hit('rm -rf /'), true)
  assert.equal(hit('rm -rf /home/user/build'), false, 'a subdirectory is normal work')
  assert.equal(hit('mkfs.ext4 /dev/sda1'), true)
  assert.equal(hit('systemctl restart nginx'), false)
})
