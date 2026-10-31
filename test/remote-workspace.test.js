import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import path from 'node:path'
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

test('findWorkspace matches the canonical path the way the platform does', () => {
  // Windows and macOS fold case; Linux does not, and folding there matched a
  // different directory that happened to differ only in case -- enough for
  // 'remove' to delete the other project's workspace entry.
  const caseFolded = process.platform === 'win32' || process.platform === 'darwin'
  const dirname = caseFolded ? 'C:\\Work\\Remote' : '/work/Remote'
  const otherCase = caseFolded ? 'c:\\work\\remote' : '/work/remote'
  const registry = { list: () => [{ id: 'a', path: dirname, title: 'x' }] }

  if (caseFolded) {
    assert.equal(findWorkspace(registry, otherCase).id, 'a', 'case-insensitive on this platform')
  } else {
    assert.equal(findWorkspace(registry, otherCase), null, 'a differently-cased path is a different directory here')
    assert.equal(findWorkspace(registry, dirname).id, 'a', 'the exact path still matches')
  }
  assert.equal(findWorkspace(registry, dirname + '-other'), null)
  assert.equal(findWorkspace(undefined, dirname), null, 'a missing registry is not an error')
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
// A workspace service that is down must not take down the answer: the alias
// list and the placeholder directories have nothing to do with it.
const brokenRegistry = () => ({
  list() { throw new Error('service down') },
  async create() { return {} },
  async delete() { return true },
})

test('a failing workspace service still leaves a usable listing', async () => {
  const { tools, restore } = await toolsFor({ DSH_SSH_GPU_HOST: 'h.example', DSH_SSH_GPU_USER: 'root' }, brokenRegistry())
  try {
    const text = TEXT_OF(await tools.ssh_workspace.execute({ action: 'list' }, {}))
    assert.match(text, /无法读取工作区服务/, text)
    assert.match(text, /service down/)
    assert.match(text, /gpu/, 'the machine must still be listed')
  } finally { restore() }
})

test('remove refuses to guess when the service cannot be read', async () => {
  const { tools, dshHome, restore } = await toolsFor({ DSH_SSH_GPU_HOST: 'h.example', DSH_SSH_GPU_USER: 'root' }, brokenRegistry())
  try {
    await tools.ssh_workspace.execute({ action: 'create', machine: 'gpu' }, {})
    await assert.rejects(
      () => tools.ssh_workspace.execute({ action: 'remove', machine: 'gpu' }, {}),
      /读取工作区服务失败，未做任何改动/,
    )
    assert.equal(existsSync(remoteDir(dshHome, 'gpu')), true, 'nothing may be deleted')
  } finally { restore() }
})

test('findWorkspace tolerates a registry that throws', () => {
  assert.equal(findWorkspace(brokenRegistry(), 'C:\\x'), null)
})
test('an unknown action is refused before the machine is looked at', async () => {
  const { tools, restore } = await toolsFor({}, new FakeRegistry())
  try {
    await assert.rejects(
      () => tools.ssh_workspace.execute({ action: 'nope' }, {}),
      // It used to answer 'action "nope" needs machine', pointing at the
      // wrong argument.
      /action 只能是 list、create 或 remove（收到 "nope"）/,
    )
  } finally { restore() }
})
test('without a workspace service the listing does not promise a registration', async () => {
  // 'create' cannot register anything in a profile that mounts no workspace
  // service (headless, tui), and 'create' says so. The listing still told the
  // user to run it 'to register', which is the one thing that cannot work.
  const { tools, restore } = await toolsFor({ DSH_SSH_GPU_HOST: 'h.example', DSH_SSH_GPU_USER: 'root' }, null)
  try {
    await tools.ssh_workspace.execute({ action: 'create', machine: 'gpu' }, {})
    const text = TEXT_OF(await tools.ssh_workspace.execute({ action: 'list' }, {}))
    assert.match(text, /没有 workspace 服务/, text)
    assert.doesNotMatch(text, /用 action: "create" 注册/, text)
  } finally { restore() }
})
test('an alias cannot turn the placeholder path into another directory', () => {
  // 'ssh_workspace remove deleteFiles: true' with machine: ".." deleted
  // <dsh-home>/dsh-ssh-safe, because the alias was joined straight into the path.
  // Measured: a file one level up disappeared.
  const dshHome = home()
  for (const alias of ['..', '.', '../../important', 'a/../b', 'a\\b', 'x\u0000y', '']) {
    assert.throws(() => remoteDir(dshHome, alias), (err) => {
      assert.match(err.message, /workspace directory name|path separator|needs a machine alias/)
      return true
    }, JSON.stringify(alias))
  }
  // Ordinary aliases still resolve inside the remotes root.
  assert.equal(remoteDir(dshHome, 'prod'), path.join(remoteRoot(dshHome), 'prod'))
})

test('only a placeholder this plugin created can be deleted', () => {
  const dshHome = home()
  writeRemoteWorkspace(dshHome, 'temp', machine)
  const dir = remoteDir(dshHome, 'temp')
  // A marker-less directory under remotes/ is not ours to delete.
  const foreign = remoteDir(dshHome, 'foreign')
  mkdirSync(foreign, { recursive: true })
  writeFileSync(path.join(foreign, 'keep.txt'), 'x')
  assert.throws(() => removeRemoteDir(dshHome, 'foreign'), /not a remote workspace placeholder/)
  assert.equal(existsSync(path.join(foreign, 'keep.txt')), true)
  // The real placeholder goes.
  removeRemoteDir(dshHome, 'temp')
  assert.equal(existsSync(dir), false)
})

test('create refuses to adopt a directory that holds foreign files', () => {
  // writeRemoteWorkspace() only wrote AGENTS.md and the marker, so create over a
  // directory with someone else's files silently adopted it — and once the marker
  // was there, remove deleteFiles deleted those files.
  const dshHome = home()
  const dir = remoteDir(dshHome, 'busy')
  mkdirSync(dir, { recursive: true })
  writeFileSync(path.join(dir, 'notes.txt'), 'mine')
  assert.throws(() => writeRemoteWorkspace(dshHome, 'busy', machine), (err) => {
    assert.equal(err.code, 'DSH_WORKSPACE_FOREIGN')
    assert.match(err.message, /already holds 1 entry/)
    assert.deepEqual(err.foreign, ['notes.txt'])
    return true
  })
  assert.equal(existsSync(path.join(dir, '.dsh-remote-workspace.json')), false, 'no marker was written')
  assert.equal(readFileSync(path.join(dir, 'notes.txt'), 'utf8'), 'mine')

  // An empty directory is a normal case (a first run that made the folder).
  const empty = remoteDir(dshHome, 'fresh')
  mkdirSync(empty, { recursive: true })
  const made = writeRemoteWorkspace(dshHome, 'fresh', machine)
  assert.equal(made.created, false)
  assert.equal(existsSync(path.join(empty, 'AGENTS.md')), true)
})

test('a registry that returns an empty object is not reported as registered', async () => {
  // create() resolving is not the same as the workspace being there: a stub that
  // answered {} produced '已注册到侧栏工作区' while the next list call said
  // '有占位目录，但未注册'.
  const hollow = {
    list: async () => [],
    create: async () => ({}),
  }
  const { tools, restore } = await toolsFor({ DSH_SSH_GPU_HOST: 'h', DSH_SSH_GPU_USER: 'u' }, hollow)
  try {
    const text = TEXT_OF(await tools.ssh_workspace.execute({ action: 'create', machine: 'gpu' }))
    assert.doesNotMatch(text, /已注册到侧栏工作区/)
    assert.match(text, /注册请求已发出，但工作区服务没有返回可用的工作区/)
    // And what the next listing says agrees with it.
    const list = TEXT_OF(await tools.ssh_workspace.execute({ action: 'list' }))
    assert.match(list, /未注册/)
  } finally { restore() }
})

test('a registry delete that does nothing is not reported as removed', async () => {
  // A service answering false was reported as success, and a service that threw
  // produced a bare error with no alias and no statement of what was left.
  // The listing has to name this machine's real placeholder directory: matching
  // is by path.
  const half = {
    list: () => [{ id: 'w9', path: remoteDir(process.env.DSH_HOME, 'a'), title: '远程 · a' }],
    delete: async () => false,
  }
  const { tools: tools2, restore } = await toolsFor({ DSH_SSH_A_HOST: 'h', DSH_SSH_A_USER: 'u' }, half)
  try {
    const text = String((await tools2.ssh_workspace.execute({ action: 'remove', machine: 'a' }, {})).text)
    assert.match(text, /工作区服务没有删除「远程 · a」/)
    assert.doesNotMatch(text, /已从侧栏移除/)
  } finally { restore() }

  const broken = {
    // Synchronous: listWorkspaces() reads the service's return value directly, so
    // a Promise looks like an empty registry.
    list: () => [{ id: 'w9', path: remoteDir(process.env.DSH_HOME, 'a'), title: '远程 · a' }],
    delete: async () => { throw new Error('nope') },
  }
  const { tools: tools3, restore: restore3 } = await toolsFor({ DSH_SSH_A_HOST: 'h', DSH_SSH_A_USER: 'u' }, broken)
  try {
    await assert.rejects(
      () => tools3.ssh_workspace.execute({ action: 'remove', machine: 'a' }, {}),
      /从侧栏移除「远程 · a」失败，注册记录仍在：nope/
    )
  } finally { restore3() }
})

test('two concurrent creates leave one registration, not two', async () => {
  // Both calls read "not registered" before either had registered, and the
  // sidebar ended up with two entries pointing at the same directory.
  const store = []
  const slow = {
    list: () => store.slice(),
    create: async (dir, title) => {
      await new Promise((resolve) => setTimeout(resolve, 50))
      const workspace = { id: 'w' + store.length, path: dir, title }
      store.push(workspace)
      return workspace
    },
    delete: async (id) => {
      const index = store.findIndex((workspace) => workspace.id === id)
      if (index < 0) return false
      store.splice(index, 1)
      return true
    },
  }
  const { tools, restore } = await toolsFor({ DSH_SSH_A_HOST: 'h', DSH_SSH_A_USER: 'u' }, slow)
  try {
    const results = await Promise.all([
      tools.ssh_workspace.execute({ action: 'create', machine: 'a' }, {}),
      tools.ssh_workspace.execute({ action: 'create', machine: 'a' }, {}),
    ])
    for (const result of results) assert.match(String(result.text), /已注册到侧栏工作区/)
    assert.equal(store.length, 1, 'one directory must not produce two sidebar entries')
    assert.equal(store[0].title, remoteTitle('a'))
  } finally { restore() }
})

test('a placeholder that belongs to another alias is not adopted', async () => {
  // Rewriting it left the other alias's sessions reading this machine's
  // instructions: the session then runs commands on the wrong host.
  const created = []
  const registry = {
    list: () => created,
    create: async (dir, title) => { const w = { id: 'w' + created.length, path: dir, title }; created.push(w); return w },
    delete: async () => true,
  }
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-wsalias-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const own = {}
    await apply({
      tools: { register: (d) => { own[d.name] = d } },
      effect: () => {}, get: (name) => (name === 'workspaceRegistry' ? registry : undefined),
    }, {
      defaultMachine: 'alpha', hostKeyPolicy: 'tofu',
      machines: { alpha: { host: 'h', port: 22, user: 'u' }, beta: { host: 'h2', port: 22, user: 'u2' } },
    })
    const dir = path.join(remoteRoot(home), 'alpha')
    mkdirSync(dir, { recursive: true })
    writeFileSync(path.join(dir, '.dsh-remote-workspace.json'), JSON.stringify({ alias: 'beta' }))
    writeFileSync(path.join(dir, 'AGENTS.md'), '# remote beta')

    await assert.rejects(
      () => own.ssh_workspace.execute({ action: 'create', machine: 'alpha' }, {}),
      (err) => {
        assert.match(err.message, /别名 "beta" 的占位目录/)
        assert.match(err.message, /可能发到错的主机/)
        return true
      },
    )
    // Nothing was rewritten and nothing was registered.
    assert.equal(JSON.parse(readFileSync(path.join(dir, '.dsh-remote-workspace.json'), 'utf8')).alias, 'beta')
    assert.match(readFileSync(path.join(dir, 'AGENTS.md'), 'utf8'), /remote beta/)
    assert.equal(created.length, 0)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('remove refuses a placeholder that belongs to another alias, before it unregisters', async () => {
  // It deleted the registration first and then refused the directory, so the other
  // alias lost its sidebar entry while its files stayed.
  const entries = [{ id: 'w1', path: '', title: '远程 · beta' }]
  const registry = {
    list: () => entries,
    create: async () => ({ id: 'w1' }),
    delete: async (id) => { const i = entries.findIndex((w) => w.id === id); if (i >= 0) { entries.splice(i, 1); return true } return false },
  }
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-wsrm2-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const dir = path.join(remoteRoot(home), 'alpha')
    entries[0].path = dir
    const own = {}
    await apply({
      tools: { register: (d) => { own[d.name] = d } },
      effect: () => {}, get: (name) => (name === 'workspaceRegistry' ? registry : undefined),
    }, {
      defaultMachine: 'alpha', hostKeyPolicy: 'tofu',
      machines: { alpha: { host: 'h', port: 22, user: 'u' }, beta: { host: 'h2', port: 22, user: 'u2' } },
    })
    mkdirSync(dir, { recursive: true })
    writeFileSync(path.join(dir, '.dsh-remote-workspace.json'), JSON.stringify({ alias: 'beta' }))
    writeFileSync(path.join(dir, 'AGENTS.md'), '# remote beta')
    writeFileSync(path.join(dir, 'notes.txt'), 'work in progress')

    await assert.rejects(
      () => own.ssh_workspace.execute({ action: 'remove', machine: 'alpha', deleteFiles: true }, {}),
      (err) => {
        assert.match(err.message, /没有删除任何东西/)
        assert.match(err.message, /别名 "beta" 的占位目录/)
        return true
      },
    )
    assert.equal(existsSync(path.join(dir, 'notes.txt')), true, 'the files must survive')
    assert.equal(JSON.parse(readFileSync(path.join(dir, '.dsh-remote-workspace.json'), 'utf8')).alias, 'beta')
    assert.equal(entries.length, 1, 'the other alias must stay registered')
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})

test('list names the alias a placeholder belongs to instead of suggesting create', async () => {
  // The row said '有占位目录，但未注册（用 action: "create" 注册）' for a directory
  // that records another alias — advice create refuses to follow.
  const registry = {
    list: () => [],
    create: async () => ({ id: 'w1' }),
    delete: async () => true,
  }
  const home = mkdtempSync(path.join(tmpdir(), 'dsh-wsowner-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const own = {}
    await apply({
      tools: { register: (d) => { own[d.name] = d } },
      effect: () => {}, get: (name) => (name === 'workspaceRegistry' ? registry : undefined),
    }, {
      defaultMachine: 'alpha', hostKeyPolicy: 'tofu',
      machines: { alpha: { host: 'h', port: 22, user: 'u' }, beta: { host: 'h2', port: 22, user: 'u2' } },
    })
    const dir = path.join(remoteRoot(home), 'alpha')
    mkdirSync(dir, { recursive: true })
    writeFileSync(path.join(dir, '.dsh-remote-workspace.json'), JSON.stringify({ alias: 'beta' }))
    writeFileSync(path.join(dir, 'AGENTS.md'), '# beta')

    const text = String((await own.ssh_workspace.execute({ action: 'list' }, {})).text)
    assert.match(text, /有占位目录，但属于别名 "beta"（不是 "alpha"）/)
    assert.doesNotMatch(text, /但未注册（用 action: "create" 注册）/)
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})
