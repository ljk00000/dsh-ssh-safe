import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { apply } from '../src/index.js'
import { remoteDir } from '../src/remote-workspace.js'

// A directory that existed but was not a placeholder was listed as 未创建, next
// to its own path: the row contradicted itself. A file where the directory should
// be answered with a bare EEXIST: file already exists, mkdir ...

let home
let tools

before(async () => {
  home = mkdtempSync(path.join(tmpdir(), 'dsh-ws-states-'))
  process.env.DSH_HOME = home
  tools = {}
  await apply({ tools: { register: (definition) => { tools[definition.name] = definition } }, effect: () => {}, get: () => undefined }, {
    defaultMachine: 'a',
    hostKeyPolicy: 'tofu',
    machines: {
      a: { host: 'h', port: 22, user: 'u', password: 'p' },
      b: { host: 'h2', port: 22, user: 'u', password: 'p' },
    },
  })
})

after(() => {
  rmSync(home, { recursive: true, force: true })
})

const listText = async () => String((await tools.ssh_workspace.execute({ action: 'list' }, {})).text)

test('a directory that is not a placeholder is not called 未创建', async () => {
  mkdirSync(remoteDir(home, 'a'), { recursive: true })
  const text = await listText()
  assert.match(text, /目录已存在，但不是占位目录/)
  const rowOfA = text.split('• ').find((block) => block.startsWith('a ')) || ''
  assert.doesNotMatch(rowOfA, /未创建/, 'the row must not claim it was never created')
})

test('a placeholder whose instructions were deleted says so', async () => {
  const dir = remoteDir(home, 'a')
  writeFileSync(path.join(dir, '.dsh-remote-workspace.json'), '{"alias":"a"}\n')
  const withoutInstructions = await listText()
  assert.match(withoutInstructions, /AGENTS\.md 已被删除/)

  await tools.ssh_workspace.execute({ action: 'create', machine: 'a' }, {})
  assert.equal(existsSync(path.join(dir, 'AGENTS.md')), true)
  const healthy = await listText()
  assert.doesNotMatch(healthy, /AGENTS\.md 已被删除/)
})

test('a file where the placeholder belongs gets an explanation, not EEXIST', async () => {
  writeFileSync(remoteDir(home, 'b'), 'i am a file')
  const escape = (text) => text.replace(/[.*+?${}()|[\]\\]/g, '\\$&')
  await assert.rejects(
    () => tools.ssh_workspace.execute({ action: 'create', machine: 'b' }, {}),
    (err) => {
      assert.match(err.message, /无法创建机器 "b" 的远程工作区/)
      assert.match(err.message, /已经有一个同名文件/)
      assert.match(err.message, new RegExp(escape(remoteDir(home, 'b'))))
      assert.doesNotMatch(err.message, /^EEXIST/)
      return true
    },
  )
})

test('create then remove leaves the directory only when asked to', async () => {
  await tools.ssh_workspace.execute({ action: 'create', machine: 'a' }, {})
  const kept = String((await tools.ssh_workspace.execute({ action: 'remove', machine: 'a' }, {})).text)
  assert.match(kept, /占位目录保留/)
  assert.equal(existsSync(remoteDir(home, 'a')), true)

  const deleted = String((await tools.ssh_workspace.execute({ action: 'remove', machine: 'a', deleteFiles: true }, {})).text)
  assert.match(deleted, /占位目录已删除/)
  assert.equal(existsSync(remoteDir(home, 'a')), false)
})
test('remove tells the truth about a directory that is not there', async () => {
  // '占位目录保留' for a directory that does not exist, and 'not a placeholder'
  // from the marker check, both sent the reader looking for files that were
  // never created.
  const gone = String((await tools.ssh_workspace.execute({ action: 'remove', machine: 'a' }, {})).text)
  assert.match(gone, /占位目录本来就不存在/)
  assert.doesNotMatch(gone, /占位目录保留/)

  const deleted = String((await tools.ssh_workspace.execute({ action: 'remove', machine: 'a', deleteFiles: true }, {})).text)
  assert.match(deleted, /占位目录本来就不存在/)
  assert.doesNotMatch(deleted, /not a remote workspace placeholder/)
})

