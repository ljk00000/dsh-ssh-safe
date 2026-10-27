import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import path from 'node:path'

// The unit tests import from src/, but the plugin runs from the installed copy
// in the DSH profile. Those can diverge: pnpm's file: install hard-links the
// package contents and does not re-copy files that were added afterwards, so a
// new module can be missing from the profile while every src/ test passes.
// That happened once already (buffer.js). This test closes the gap by loading
// the installed artifact when one is present.

const dshHome = process.env.DSH_HOME || path.join(homedir(), '.dsh')
const profile = path.join(dshHome, 'profiles', 'desktop')
const installed = path.join(profile, 'node_modules', 'dsh-ssh-safe')

const hasInstalled = existsSync(path.join(installed, 'package.json'))

test('the installed copy contains every module the entry imports', { skip: !hasInstalled && 'plugin not installed in this profile' }, () => {
  const srcDir = path.join(installed, 'src')
  assert.ok(existsSync(srcDir), 'installed package has no src/ directory')

  // Capture the specifier exactly as written (it already carries .js).
  const specs = [...readFileSync(path.join(srcDir, 'index.js'), 'utf8')
    .matchAll(/from '\.\/([\w.-]+)'/g)].map((m) => m[1])
  assert.ok(specs.length > 0, 'index.js should import local modules')
  const installedFiles = new Set(specs)

  // Any local import must exist on disk in the installed copy.
  for (const file of installedFiles) {
    assert.ok(existsSync(path.join(srcDir, file)), 'missing from the installed copy: ' + file)
  }
})

test('the installed entry exports the plugin contract', { skip: !hasInstalled && 'plugin not installed in this profile' }, async () => {
  const entry = path.join(installed, 'src', 'index.js')
  const mod = await import('file://' + entry.split(path.sep).join('/'))
  for (const key of ['name', 'inject', 'Config', 'apply']) {
    assert.ok(mod[key] !== undefined, 'missing export: ' + key)
  }
  assert.equal(mod.name, 'dsh-ssh-safe')
})

test('the installed copy matches the working tree file list', { skip: !hasInstalled && 'plugin not installed in this profile' }, () => {
  const srcHere = path.join(process.cwd(), 'src')
  if (!existsSync(srcHere)) return
  const here = new Set(readFileSync(srcHere + path.sep + 'index.js', 'utf8')
    .match(/from '\.\/([\w.-]+)'/g) || [])
  const there = readFileSync(path.join(installed, 'src', 'index.js'), 'utf8')
  assert.equal(here.size > 0, there.length > 0, 'both copies should import local modules')
})
