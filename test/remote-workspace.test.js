import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply } from '../src/index.js'
import {
  findWorkspace,
  readMarker,
  remoteDir,
  remoteRoot,
  remoteTitle,
  remoteInstructions,
  removeRemoteDir,
  writeRemoteWorkspace,
} from '../src/remote-workspace.js'

// A remote workspace is a local placeholder directory standing in for a remote
// host, registered as a normal DSH workspace. The instructions it drops into
// AGENTS.md are what teach the agent that this directory is a pointer and that
// every file or command operation has to go through the ssh_* tools -- so the
// text is the feature, and it is worth asserting on.

const home = () => mkdtempSync(join(tmpdir(), 'dsh-ws-'))
const machine = { host: 'gpu.example.com', port: 2222, username: 'root' }

test('the instructions name the machine, the endpoint and the env var', () => {
  const text = remoteInstructions('gpu', machine)
  assert.match(text, /远程工作区：gpu/)
  assert.match(text, /root@gpu\.example\.com:2222/)
  assert.match(text, /DSH_SSH_GPU_PASSWORD/)
  assert.match(text, /ssh_exec/)
  assert.match(text, /不要用本地的 read/)
  assert.doesNotMatch(text, /hunter2|password=/i, 'instructions must never carry a credential')
})

test('an unconfigured machine still produces usable instructions', () => {
  const text = remoteInstructions('box', {})
  assert.match(text, /未配置主机/)
  assert.match(text, /:22/)
})

test('writeRemoteWorkspace creates the directory and both files', () => {
  const dshHome = home()
  const { dir, created } = writeRemoteWorkspace(dshHome, 'gpu', machine)
  assert.equal(created, true)
  assert.equal(dir, join(remoteRoot(dshHome), 'gpu'))
  assert.deepEqual(readdirSync(dir).sort(), ['.dsh-remote-workspace.json', 'AGENTS.md'])
  const marker = JSON.parse(readFileSync(join(dir, '.dsh-remote-workspace.json'), 'utf8'))
  assert.equal(marker.alias, 'gpu')
  assert.equal(marker.host, 'gpu.example.com')
  assert.equal(marker.port, 2222)
})

test('a second call refreshes the endpoint instead of staying stale', () => {
  const dshHome = home()
  writeRemoteWorkspace(dshHome, 'gpu', machine)
  const second = writeRemoteWorkspace(dshHome, 'gpu', { host: 'new.example.com', port: 40047, username: 'root' })
  assert.equal(second.created, false)
  const text = readFileSync(join(second.dir, 'AGENTS.md'), 'utf8')
  assert.match(text, /new\.example\.com:40047/)
  assert.doesNotMatch(text, /gpu\.example\.com:2222/)
})

test('readMarker reports null for a directory that is not a workspace', () => {
  const dshHome = home()
  assert.equal(readMarker(dshHome, 'ghost'), null)
  mkdirSync(remoteDir(dshHome, 'plain'), { recursive: true })
  assert.equal(readMarker(dshHome, 'plain'), null)
})

test('findWorkspace matches the canonical path case-insensitively', () => {
  const registry = { list: () => [{ id: 'a', path: 'C:\\Work\\Remote', title: 'x' }] }
  assert.equal(findWorkspace(registry, 'c:\\work\\remote').id, 'a')
  assert.equal(findWorkspace(registry, 'C:\\other'), null)
  assert.equal(findWorkspace(undefined, 'C:\\Work\\Remote'), null, 'a missing registry is not an error')
})

test('removeRemoteDir deletes the placeholder', () => {
  const dshHome = home()
  writeRemoteWorkspace(dshHome, 'gpu', machine)
  const dir = removeRemoteDir(dshHome, 'gpu')
  assert.equal(existsSync(dir), false)
})

// ── the tool ──────────────────────────────────────────────────────────────

class FakeRegistry {
  constructor() { this.items = []; this.next = 1 }
  list() { return this.items.slice() }
  async create(path, title) {
    const found = this.items.find((w) => w.path === path)
    if (found) return found
    const workspace = { id: 'ws' + (this.next++), path, title }
    this.items.push(workspace)
    return workspace
  }
  async delete(id) {
    const index = this.items.findIndex((w) => w.id === id)
    if (index < 0) return false
    this.items.splice(index, 1)
    return true
  }
}

async function toolsFor(env = {}, registry = new FakeRegistry()) {
  const saved = { ...process.env }
  const dshHome = home()
  process.env.DSH_HOME = dshHome
  for (const [key, value] of Object.entries(env)) process.env[key] = value
  const tools = {}
  const ctx = {
    tools: { register: (def) => { tools[def.name] = def } },
    effect: () => {},
    get: (name) => (name === 'workspaceRegistry' ? registry : undefined),
  }
  await apply(ctx, { defaultMachine: 'gpu' })
  const restore = () => {
    for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key]
    Object.assign(process.env, saved)
    rmSync(dshHome, { recursive: true, force: true })
  }
  return { tools, registry, dshHome, restore }
}

const TEXT_OF = (result) => String(result && result.text || '')

test('create makes the placeholder and registers it', async () => {
  const { tools, registry, restore } = await toolsFor({
    DSH_SSH_GPU_HOST: 'gpu.example.com',
    DSH_SSH_GPU_USER: 'root',
    DSH_SSH_GPU_PORT: '2222',
  })
  try {
    const text = TEXT_OF(await tools.ssh_workspace.execute({ action: 'create', machine: 'gpu' }))
    assert.match(text, /已创建远程工作区/)
    assert.match(text, /远程 · gpu/)
    assert.equal(registry.items.length, 1)
    assert.equal(registry.items[0].title, remoteTitle('gpu'))
  } finally { restore() }
})

test('create is idempotent: the second call reuses the registration', async () => {
  const { tools, registry, restore } = await toolsFor({ DSH_SSH_GPU_HOST: 'h', DSH_SSH_GPU_USER: 'u' })
  try {
    await tools.ssh_workspace.execute({ action: 'create', machine: 'gpu' })
    await tools.ssh_workspace.execute({ action: 'create', machine: 'gpu' })
    assert.equal(registry.items.length, 1)
  } finally { restore() }
})

test('create refuses a machine without a host', async () => {
  const { tools, restore } = await toolsFor({})
  try {
    await assert.rejects(
      () => tools.ssh_workspace.execute({ action: 'create', machine: 'ghost' }),
      (err) => { assert.match(err.message, /DSH_SSH_GHOST_HOST/); return true }
    )
  } finally { restore() }
})

test('list reports created and registered state', async () => {
  const { tools, restore } = await toolsFor({ DSH_SSH_GPU_HOST: 'h', DSH_SSH_GPU_USER: 'u' })
  try {
    const before = TEXT_OF(await tools.ssh_workspace.execute({}))
    assert.match(before, /未创建/)
    await tools.ssh_workspace.execute({ action: 'create', machine: 'gpu' })
    const after = TEXT_OF(await tools.ssh_workspace.execute({}))
    assert.match(after, /已注册为工作区/)
  } finally { restore() }
})

test('remove deletes the registration and keeps the placeholder by default', async () => {
  const { tools, registry, dshHome, restore } = await toolsFor({ DSH_SSH_GPU_HOST: 'h', DSH_SSH_GPU_USER: 'u' })
  try {
    await tools.ssh_workspace.execute({ action: 'create', machine: 'gpu' })
    const dir = remoteDir(dshHome, 'gpu')
    const text = TEXT_OF(await tools.ssh_workspace.execute({ action: 'remove', machine: 'gpu' }))
    assert.match(text, /已从侧栏移除/)
    assert.equal(registry.items.length, 0)
    assert.equal(existsSync(dir), true, 'the placeholder stays unless deleteFiles is true')

    const removed = TEXT_OF(await tools.ssh_workspace.execute({ action: 'remove', machine: 'gpu', deleteFiles: true }))
    assert.match(removed, /占位目录已删除/)
    assert.equal(existsSync(dir), false)
  } finally { restore() }
})

test('an unknown action is refused with the accepted ones', async () => {
  const { tools, restore } = await toolsFor({ DSH_SSH_GPU_HOST: 'h', DSH_SSH_GPU_USER: 'u' })
  try {
    await assert.rejects(
      () => tools.ssh_workspace.execute({ action: 'destroy' }),
      (err) => { assert.match(err.message, /list、create 或 remove/); return true }
    )
  } finally { restore() }
})
