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

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { envNames } from './credentials.js'

const MARKER = '.dsh-remote-workspace.json'
const FENCE = String.fromCharCode(96).repeat(3)

/** Root that holds every placeholder directory. */
export function remoteRoot(dshHome) {
  return join(String(dshHome || ''), 'dsh-ssh-safe', 'remotes')
}

/** Placeholder directory for one alias. */
export function remoteDir(dshHome, alias) {
  return join(remoteRoot(dshHome), String(alias))
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
  if (!registry || typeof registry.list !== 'function') return null
  const wanted = String(dir).toLowerCase()
  for (const workspace of registry.list()) {
    const path = String(workspace && workspace.path || '').toLowerCase()
    if (path === wanted) return workspace
  }
  return null
}

/** Remove the placeholder directory entirely. */
export function removeRemoteDir(dshHome, alias) {
  const dir = remoteDir(dshHome, alias)
  rmSync(dir, { recursive: true, force: true })
  return dir
}
