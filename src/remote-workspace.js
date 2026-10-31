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

import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
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
  return text
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
 * @returns {string}
 */
export function remoteInstructions(alias, machine = {}) {
  const host = machine.host || '<未配置主机>'
  const port = machine.port || 22
  const user = machine.username || '<未配置用户>'
  const lines = [
    '# 远程工作区：' + alias,
    '',
    '这个目录**不是项目目录**，它只是远程主机 ' + alias + '（' + user + '@' + host + ':' + port + '）的占位。',
    '目录里除了本文件和 .dsh-remote-workspace.json 之外没有别的内容，远端文件也不在这里。',
    '',
    '## 规则',
    '',
    '1. 一切远端操作都用 dsh-ssh-safe 的工具，并显式带上 machine: "' + alias + '"：',
    '   - ssh_exec 执行命令',
    '   - ssh_read / ssh_write 读写远端文件（路径必须是**远端**绝对路径）',
    '   - ssh_list 列远端目录',
    '2. **不要用本地的 read / write / glob / grep / pwsh / shell 去操作远端路径**。',
    '   它们只看得见本机，把远端路径当本地路径会失败或写错地方。',
    '3. 第一次在这个会话里动手之前，先用 ssh_machines 确认别名，',
    '   再用 ssh_doctor 验证 配置 / TCP / 主机密钥 / 认证。',
    '4. 主机密钥策略默认 strict：指纹变了会拒绝连接，这是有意的，不要绕过。',
    '5. 密码、口令、私钥内容**不要写进对话**，也不要写进远端文件开头。',
    '   凭据来自凭据文件（DPAPI 加密）或环境变量 ' + envNames(alias).password + '。',
    '',
    '## 快速开始',
    '',
    FENCE,
    'ssh_exec { machine: "' + alias + '", command: "uname -a" }',
    'ssh_list { machine: "' + alias + '", path: "/root" }',
    FENCE,
    '',
  ]
  return lines.join('\n')
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
export function writeRemoteWorkspace(dshHome, alias, machine = {}) {
  const dir = remoteDir(dshHome, alias)
  const created = !existsSync(dir)
  // Adopting a directory that already holds someone else's files would make it
  // a placeholder, and 'remove deleteFiles: true' would then delete them — the
  // marker check only recognises directories this plugin marked, and this is how
  // a foreign directory could acquire a marker. An empty directory is fine.
  if (!created && !existsSync(join(dir, MARKER))) {
    const foreign = readdirSync(dir).filter((name) => name !== MARKER && name !== 'AGENTS.md')
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
  writeFileSync(join(dir, 'AGENTS.md'), remoteInstructions(alias, machine), 'utf8')
  writeFileSync(join(dir, MARKER), JSON.stringify({
    alias,
    host: machine.host || '',
    port: machine.port || 22,
    username: machine.username || '',
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
  rmSync(dir, { recursive: true, force: true })
  return dir
}
