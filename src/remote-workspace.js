// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ljk00000
//
// Part of dsh-ssh-safe. See LICENSE.
// dsh-ssh-safe — remote workspaces.
//
// A DSH workspace is an existing local directory: the registry canonicalizes the
// path, groups sessions by it, and the agent's working directory is that path.
// A remote host has no local directory, so a "remote workspace" is a local
// placeholder directory that stands for the host:
//
//   ~/.dsh/dsh-ssh-safe/remotes/<alias>/
//     AGENTS.md                      instructions the agent loads automatically
//     .dsh-remote-workspace.json     alias, endpoint, when it was generated
//
// Registering that directory turns it into a normal workspace in the sidebar.
// Starting a session there loads AGENTS.md as project instructions, which is how
// the agent learns that this directory points at a remote host and that every
// file or command operation must go through the ssh_* tools.
//
// Nothing here holds a credential. The placeholder directory stays empty apart
// from those two files, so a local tool pointed at it finds nothing to confuse
// with the remote tree.

import { createHash } from 'node:crypto'
import { printable } from './format.js'
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { envNames } from './credentials.js'

const MARKER = '.dsh-remote-workspace.json'
const FENCE = String.fromCharCode(96).repeat(3)

/** Root that holds every placeholder directory. */
export function remoteRoot(dshHome) {
  return join(String(dshHome || ''), 'dsh-ssh-safe', 'remotes')
}

/**
 * An alias that is safe to use as one directory name.
 *
 * The alias arrives from a tool argument, and '..' turned the placeholder path
 * into the directory above it: 'ssh_workspace remove deleteFiles: true' with
 * machine: ".." deleted <dsh-home>/dsh-ssh-safe. A slash, a backslash, '..' or a
 * control character is refused before a path is built.
 *
 * @param {unknown} alias
 * @returns {string}
 */
export function safeAlias(alias) {
  const text = String(alias ?? '')
  if (text.length === 0) throw new Error('a workspace needs a machine alias')
  if (text === '.' || text === '..') {
    throw new Error('"' + text + '" cannot be used as a workspace directory name')
  }
  if (/[\\/\u0000-\u001f]/.test(text)) {
    throw new Error(
      'the alias ' + JSON.stringify(text) + ' contains a path separator or control character, ' +
      'so it cannot name a workspace directory'
    )
  }
  // safeField() / printable() rewrite these for AGENTS.md, and the instructions
  // have to name the alias exactly: with a right-to-left override the heading
  // said 'prod\u202etxt' while the real alias holds the raw character, so the
  // agent was told to use machine: "prod\u202etxt" -- an alias that does not
  // exist. The directory name displays as something other than what it is too.
  if (/[\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/.test(text)) {
    throw new Error(
      'the alias ' + JSON.stringify(text) + ' contains a character that cannot be shown or typed ' +
      'exactly (a line separator or a right-to-left override), so the instructions could not ' +
      'name it and the workspace directory would display as something it is not'
    )
  }
  return text
}

/** What each host-key policy means for the agent working in this workspace. */
const POLICY_SENTENCE = {
  strict: '未知主机的密钥不会被自动接受，指纹变化也会拒绝连接；这是有意的，遇到拒绝请让用户核对指纹，不要绕过。',
  tofu: '首次连接会记录指纹，此后指纹变化会拒绝连接；首次连接前仍应让用户确认指纹来源可信。',
  off: '主机密钥不做校验（用户显式关闭），因此连接不能证明对方是不是 impostor。',
}

/** Placeholder directory for one alias. */
export function remoteDir(dshHome, alias) {
  return join(remoteRoot(dshHome), safeAlias(alias))
}

/** Display title used when the workspace is created. */
export function remoteTitle(alias) {
  return '远程 · ' + String(alias)
}

/**
 * The instructions placed in AGENTS.md.
 *
 * Written for a model that has just been dropped into this directory with no
 * other context: it must not mistake the placeholder for the project, and it
 * must not reach for local file tools to touch remote paths.
 *
 * @param {string} alias
 * @param {{host?: string, port?: number, username?: string}} machine
 * @param {string} [policy] the host-key policy in effect ('strict', 'tofu' or 'off')
 * @returns {string}
 */
/**
 * Text safe to place inside the instructions file.
 *
 * AGENTS.md is instructions the agent trusts. A host or alias containing a newline
 * put '## NEW INSTRUCTIONS' at the top level of that file in the probe, which is
 * text injected into the agent's instructions by a machine definition.
 */
function safeField(value) {
  return printable(String(value ?? ''))
}

export function remoteInstructions(alias, machine = {}, policy = 'strict', hideHost = false) {
  const host = machine.host ? safeField(machine.host) : '<未配置主机>'
  const port = machine.port || 22
  const user = machine.username ? safeField(machine.username) : '<未配置用户>'
  // machineInventory: alias keeps host, port and user out of the conversation, and
  // AGENTS.md is read into a session: the file that said 'secretuser@10.9.9.9:2222'
  // undid the setting the same command had just honoured in its own reply.
  const endpoint = hideHost ? '地址按 machineInventory: alias 隐藏' : user + '@' + host + ':' + port
  const name = safeField(alias)
  const lines = [
    '# 远程工作区：' + name,
    '',
    '这个目录**不是项目目录**，它只是远程主机 ' + name + '（' + endpoint + '）的占位。',
    '目录里除了本文件和 .dsh-remote-workspace.json 之外没有别的内容，远端文件也不在这里。',
    '',
    '## 规则',
    '',
    '1. 一切远端操作都用 dsh-ssh-safe 的工具，并显式带上 machine: "' + name + '"：',
    '   - ssh_exec 执行命令',
    '   - ssh_read / ssh_write 读写远端文件（路径必须是**远端**绝对路径）',
    '   - ssh_list 列远端目录',
    '2. **不要用本地的 read / write / glob / grep / pwsh / shell 去操作远端路径**。',
    '   它们只看得见本机，把远端路径当本地路径会失败或写错地方。',
    '3. 第一次在这个会话里动手之前，先用 ssh_machines 确认别名，',
    '   再用 ssh_doctor 验证 配置 / TCP / 主机密钥 / 认证。',
    // The line said 'strict' whatever the policy was: an agent working under
    // tofu was told a first-contact key would be refused, which it is not.
    '4. 主机密钥策略（' + (POLICY_SENTENCE[policy] ? policy : 'strict') + '）：' + POLICY_SENTENCE[POLICY_SENTENCE[policy] ? policy : 'strict'],
    '5. 密码、口令、私钥内容**不要写进对话**，也不要写进远端文件开头。',
    '   凭据来自凭据文件（DPAPI 加密）或环境变量 ' + safeField(envNames(alias).password) + '。',
    '',
    '## 快速开始',
    '',
    FENCE,
    // /root is readable only by root: for every other account the first command in a
    // fresh workspace failed with 'permission denied', which reads as 'these tools do
    // not work here'. Omitting path lists the account's own home directory.
    'ssh_exec { machine: "' + name + '", command: "uname -a" }',
    'ssh_list { machine: "' + name + '" }            # 家目录；path 可省略',
    FENCE,
    '',
  ]
  return lines.join('\n')
}

/**
 * A stable digest of the endpoint these instructions were written for.
 *
 * The hash, not the address: with machineInventory: alias the marker must not hold
 * host, port or user, and a placeholder whose machine moved keeps telling sessions
 * about the old host until someone re-runs create.
 *
 * @param {{host?: string, port?: number, username?: string}} machine
 * @returns {string}
 */
export function endpointHash(machine = {}) {
  const text = String(machine.username || '') + '@' + String(machine.host || '') + ':' +
    String(machine.port || 22)
  return createHash('sha256').update(text).digest('hex').slice(0, 16)
}

/**
 * Whether the marker still describes this machine.
 *
 * @param {object|null} marker
 * @param {{host?: string, port?: number, username?: string}} machine
 * @returns {'' | 'stale' | 'unknown'} 'unknown' for a marker written before the hash existed
 */
export function markerFreshness(marker, machine = {}) {
  if (!marker || typeof marker.endpointHash !== 'string' || marker.endpointHash === '') return 'unknown'
  return marker.endpointHash === endpointHash(machine) ? '' : 'stale'
}

/** Read the marker of a placeholder directory, or null when it is not one. */
export function readMarker(dshHome, alias) {
  try {
    const raw = readFileSync(join(remoteDir(dshHome, alias), MARKER), 'utf8')
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? parsed : null
  } catch {
    return null
  }
}

/**
 * Create or refresh the placeholder directory and its instructions.
 *
 * Refresh rather than create-once: the endpoint can move (a new port on the
 * same provider), and instructions naming the old one are worse than none.
 *
 * @param {string} dshHome
 * @param {string} alias
 * @param {{host?: string, port?: number, username?: string}} machine
 * @returns {{dir: string, created: boolean}}
 */
/**
 * Whether 'AGENTS.md' in this directory is the file this plugin writes.
 *
 * Only a regular file counts. A *directory* of that name is the user's, and
 * deleting it removed their files: /AGENTS.md/inside/keep.txt disappeared with
 * 'remove deleteFiles: true'.
 */
function agentsFileIsOurs(dir) {
  try {
    return lstatSync(join(dir, 'AGENTS.md')).isFile()
  } catch {
    return false
  }
}

export function writeRemoteWorkspace(dshHome, alias, machine = {}, policy = 'strict', hideHost = false) {
  const dir = remoteDir(dshHome, alias)
  const created = !existsSync(dir)
  // Adopting a directory that already holds someone else's files would make it
  // a placeholder, and 'remove deleteFiles: true' would then delete them — the
  // marker check only recognises directories this plugin marked, and this is how
  // a foreign directory could acquire a marker. An empty directory is fine.
  if (!created && !existsSync(join(dir, MARKER))) {
    const foreign = readdirSync(dir)
      .filter((name) => name !== MARKER && !(name === 'AGENTS.md' && agentsFileIsOurs(dir)))
    if (foreign.length > 0) {
      const err = new Error(
        'refusing to use ' + dir + ' as a workspace: it already holds ' +
        foreign.length + ' entr' + (foreign.length === 1 ? 'y' : 'ies') +
        ' this plugin did not create (first: ' + foreign[0] + '). ' +
        'Move them elsewhere, or pick a different machine alias.'
      )
      // @ts-expect-error -- marking the error so the tool can say it in the user's language
      err.code = 'DSH_WORKSPACE_FOREIGN'
      // @ts-expect-error -- same
      err.foreign = foreign
      throw err
    }
  }
  // A placeholder that belongs to ANOTHER alias: rewriting it would leave the
  // other alias's sessions reading instructions for this machine, which is how a
  // session ends up running commands on the wrong host. Refuse and name the owner.
  if (!created) {
    const existing = (() => {
      try {
        const parsed = JSON.parse(readFileSync(join(dir, MARKER), 'utf8'))
        return parsed && typeof parsed === 'object' ? parsed : null
      } catch {
        return null
      }
    })()
    const owner = existing && typeof existing.alias === 'string' ? existing.alias : ''
  if (owner && owner !== alias) {
      const err = new Error(
        'refusing to use ' + dir + ' as a workspace for "' + alias + '": it is the placeholder ' +
        'for "' + owner + '". Rewriting it would leave ' + owner + ' sessions reading ' + alias +
        ' instructions — the wrong host. Use machine: "' + owner + '" for this workspace, or ' +
        'remove the ' + owner + ' workspace first (ssh_workspace action: "remove", machine: "' +
        owner + '", deleteFiles: true).'
      )
      // @ts-expect-error -- marking the error so the tool can say it in the user's language
      err.code = 'DSH_WORKSPACE_FOREIGN_ALIAS'
      // @ts-expect-error -- same
      err.owner = owner
      throw err
    }
  }
  mkdirSync(dir, { recursive: true })
  // writeFileSync follows a symlink: an AGENTS.md linked to a file outside the
  // placeholder had that file overwritten with these instructions (measured:
  // 'DO NOT TOUCH' became the workspace text). Only a regular file is ours to
  // rewrite; anything else there is the user's and is named in the refusal.
  for (const name of ['AGENTS.md', MARKER]) {
    let entry = null
    try {
      entry = lstatSync(join(dir, name))
    } catch { /* absent: nothing to protect */ }
    if (entry && !entry.isFile()) {
      const kind = entry.isSymbolicLink() ? 'symbolic link' : entry.isDirectory() ? 'directory' : 'special file'
      const err = new Error(
        'refusing to write into ' + dir + ': ' + name + ' is not a regular file (it is a ' + kind +
        '), and writing through it would change something outside the placeholder. ' +
        'Move or delete it, then create the workspace again.'
      )
      // @ts-expect-error -- marking the error so the tool can say it in the user's language
      err.code = 'DSH_WORKSPACE_ENTRY_NOT_FILE'
      // @ts-expect-error -- same
      err.entry = name
      // @ts-expect-error -- same
      err.kind = kind
      throw err
    }
  }
  writeFileSync(join(dir, 'AGENTS.md'), remoteInstructions(alias, machine, policy, hideHost), 'utf8')
  // readMarker() only ever reads .alias, so the endpoint fields were written and
  // never used -- except as the address that machineInventory: alias is meant to
  // keep out of sight, sitting in a file inside the agent's own workspace.
  // A hash of the endpoint, always — including under machineInventory: alias, where
  // the plain address is deliberately not written. It is what lets `list` notice that
  // the machine has moved since the placeholder was generated, without putting the
  // address into a file inside the agent's own workspace.
  writeFileSync(join(dir, MARKER), JSON.stringify({
    alias,
    ...(hideHost ? {} : {
      host: machine.host || '',
      port: machine.port || 22,
      username: machine.username || '',
    }),
    endpointHash: endpointHash(machine),
    generatedAt: new Date().toISOString(),
  }, null, 2) + '\n', 'utf8')
  return { dir, created }
}

/**
 * Find the registry entry for a directory, if one exists.
 *
 * The registry returns entities with id, path and title. A missing registry is
 * tolerated so the tool still creates the directory in a profile that does not
 * mount workspaces (headless, or a tui without the plugin).
 */
export function findWorkspace(registry, dir) {
  const { items } = listWorkspaces(registry)
  // Case folding is a Windows/macOS rule. On Linux '/work/App' and '/work/app'
  // are two different directories, and folding them meant 'remove' could delete
  // the other project's workspace entry -- or report a placeholder as registered
  // because a differently-cased one was.
  const fold = process.platform === 'win32' || process.platform === 'darwin'
  const normalize = (value) => {
    const text = String(value || '')
    return fold ? text.toLowerCase() : text
  }
  const wanted = normalize(dir)
  for (const workspace of items) {
    if (normalize(workspace && workspace.path || '') === wanted) return workspace
  }
  return null
}

/**
 * Read the registry's workspaces without letting a host service failure escape.
 *
 * The workspace registry is DSH's, not this plugin's: it can be unavailable
 * while the page (or a headless profile) is perfectly healthy. Listing the
 * remote workspaces used to throw "registry unavailable" and lose the whole
 * answer, including the placeholder directories that had nothing to do with it.
 *
 * @param {any} registry
 * @returns {{items: any[], error: string}}
 */
export function listWorkspaces(registry) {
  if (!registry || typeof registry.list !== 'function') return { items: [], error: '' }
  try {
    const items = registry.list()
    return { items: Array.isArray(items) ? items : [], error: '' }
  } catch (err) {
    return { items: [], error: String(err && err.message ? err.message : err).slice(0, 200) }
  }
}

/**
 * The alias a placeholder directory belongs to, when its marker names one.
 *
 * Used before anything is deleted or rewritten: a directory recording another
 * alias is that alias workspace, not this one.
 *
 * @param {string} dshHome
 * @param {string} alias
 * @returns {string} empty when there is no marker or it names no alias
 */
export function workspaceOwner(dshHome, alias) {
  try {
    const parsed = JSON.parse(readFileSync(join(remoteDir(dshHome, alias), MARKER), 'utf8'))
    return parsed && typeof parsed === 'object' && typeof parsed.alias === 'string' ? parsed.alias : ''
  } catch {
    return ''
  }
}

/** Remove the placeholder directory entirely. */
export function removeRemoteDir(dshHome, alias) {
  const dir = remoteDir(dshHome, alias)
  // Already gone is the outcome the caller asked for, not a refusal: reporting
  // "not a placeholder" for a directory that does not exist sends them looking
  // for files that were never there.
  if (!existsSync(dir)) return ''
  // Only a directory this plugin created: the marker is what makes it a
  // placeholder rather than whatever else happens to sit under remotes/.
  if (!existsSync(join(dir, MARKER))) {
    throw new Error(
      'refusing to delete ' + dir + ': it is not a remote workspace placeholder ' +
      '(no ' + MARKER + '). Remove it yourself if that is what you meant.'
    )
  }
  // A placeholder that belongs to ANOTHER alias: deleting it takes that alias's
  // workspace, and any files the user left in it, with no way back. The mirror of
  // the create-side refusal.
  const owner = (() => {
    try {
      const parsed = JSON.parse(readFileSync(join(dir, MARKER), 'utf8'))
      return parsed && typeof parsed === 'object' && typeof parsed.alias === 'string' ? parsed.alias : ''
    } catch {
      return ''
    }
  })()
  // A marker that exists but cannot be parsed is not proof that this directory is
  // ours: recognising what this plugin created is the whole point of the marker.
  // It used to fall through as if unowned and the directory was then deleted.
  if (!owner) {
    throw new Error(
      'refusing to delete ' + dir + ': its ' + MARKER + ' cannot be parsed, so this plugin ' +
      'cannot confirm the directory is a remote workspace placeholder. Delete it yourself ' +
      'if that is what you meant.'
    )
  }
  if (owner && owner !== alias) {
    const err = new Error(
      'refusing to delete ' + dir + ' for "' + alias + '": it is the placeholder for "' + owner +
      '". Delete the ' + owner + ' workspace instead (machine: "' + owner + '").'
    )
    // @ts-expect-error -- marking the error so the tool can say it in the user's language
    err.code = 'DSH_WORKSPACE_FOREIGN_ALIAS'
    // @ts-expect-error -- same
    err.owner = owner
    throw err
  }
  // Files the user put in this directory are theirs. The create side already
  // refuses to adopt such a directory, and the delete side used to remove it
  // without a word — measured: 'important.txt' disappeared with the workspace.
  // 'AGENTS.md' is ours only while it is the file this plugin wrote. A directory of
  // that name is the user's, and it was deleted along with its contents.
  const foreign = readdirSync(dir)
    .filter((name) => name !== MARKER && !(name === 'AGENTS.md' && agentsFileIsOurs(dir)))
  if (foreign.length > 0) {
    const err = new Error(
      'refusing to delete ' + dir + ': it holds ' + foreign.length + ' entr' +
      (foreign.length === 1 ? 'y' : 'ies') + ' this plugin did not create (first: ' +
      foreign[0] + '). Those files are yours; move or delete them, then remove the workspace again.'
    )
    // @ts-expect-error -- marking the error so the tool can say it in the user's language
    err.code = 'DSH_WORKSPACE_DIRTY'
    // @ts-expect-error -- same
    err.foreign = foreign
    throw err
  }
  rmSync(dir, { recursive: true, force: true })
  return dir
}
