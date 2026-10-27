# dsh-ssh-safe

> Security-first SSH tools for DeepSeek Harness. No telemetry, no cloud, no
> auto-update, no host patching. Credentials from environment variables by default.

[English](#english) · [中文](#中文)

---

## 中文

### 这个插件解决什么问题

让 DSH Agent 能操作远程 Linux 服务器（跑命令、读写文件、列目录），**同时不把你的服务器凭据交给任何第三方**。

### 设计约束（为什么值得信任）

这个插件存在的理由是：同类插件普遍做了下面这些事，而它**一件都不做**。

| 常见做法 | dsh-ssh-safe |
| --- | --- |
| 上报安装心跳到某个云函数 | **无任何遥测**。全包没有 HTTP 客户端，`grep -r 'fetch(' src/` 结果为空 |
| 自动检查并热替换自身代码 | **无自动更新**。从不拉取版本，从不改写自己 |
| 修改 `app.asar` 内的 DSH 源文件 | **不碰宿主**。`cordis.patch.yml` 只 `insert` 自己一条 |
| 禁用 `fs-sandbox` / `bash-sandbox` | **不禁用**。本地沙箱保持原样 |
| 把密码写进 `cordis.patch.yml` 明文 | **不落盘**。默认只从环境变量读取 |

### 安装

尚未发布到 npm。用 git 或本地路径安装，然后重启 DSH：

```sh
# 从 GitHub
dsh plugin --profile desktop add github:ljk00000/dsh-ssh-safe

# 或从本地克隆
dsh plugin --profile desktop add file:/path/to/dsh-ssh-safe
```

> **本地 `file:` 安装的坑**：pnpm 不会重新拷贝后来新增的文件。改了源码后如果加了新文件,
> 必须先 `remove` 再 `add`，否则插件会因 `ERR_MODULE_NOT_FOUND` 崩溃。
> （`test/installed.test.js` 就是为了逮住这种情况。)

### 配置服务器凭据

用一个「别名 + 环境变量」的方式。别名 `prod` 对应下面这些变量：

```sh
DSH_SSH_PROD_HOST=10.0.0.5
DSH_SSH_PROD_PORT=22
DSH_SSH_PROD_USER=ubuntu
DSH_SSH_PROD_KEY_PATH=~/.ssh/id_ed25519
```

或用密码代替密钥：

```sh
DSH_SSH_PROD_PASSWORD=...
```

可选：

```sh
DSH_SSH_PROD_KEY_PASSPHRASE=...      # 加密私钥的口令
DSH_SSH_PROD_HOST_KEY_POLICY=tofu    # strict（默认）/ tofu / off
DSH_SSH_PROD_KNOWN_HOSTS=~/.ssh/known_hosts.json
```

设置完**重启 DSH**——环境变量在进程启动时读取，不会热加载。

### 工具

| 工具 | 作用 |
| --- | --- |
| `ssh_machines` | 列出已配置的机器、认证方式、指纹信任状态（**不显示任何密钥**） |
| `ssh_connect` | 建立或复用连接，返回主机指纹与远端 `uname` |
| `ssh_exec` | 在远端执行命令，返回 stdout / stderr / 退出码 |
| `ssh_read` | 读远端文件（UTF-8，按字节上限截断） |
| `ssh_write` | 写远端文件（覆盖） |
| `ssh_list` | 列远端目录 |
| `ssh_close` | 关闭连接 |

### 主机密钥校验

默认 `strict`：**只有已记录过指纹的主机才能连**。首次连接需要显式确认：

```
ssh_connect { machine: "prod", trustHostKey: true }
```

指纹会存进 `~/.dsh/dsh-ssh-safe/known_hosts.json`（权限 0600），内容只有主机、端口、指纹——**没有用户名、密码、密钥**。

如果服务器的指纹**变了**，插件会拒绝连接并说明原因，而不是自动接受。这是防中间人攻击的核心行为。

每台机器可以用 `DSH_SSH_<ALIAS>_HOST_KEY_POLICY` **单独覆盖**全局策略（收紧或放宽都行）：

```sh
DSH_SSH_PROD_HOST_KEY_POLICY=strict   # 这台机器强制 strict，即使全局是 tofu
```

### 可选：`ssh_read` 的脱敏

`ssh_read` 默认会把你读到的内容里的密钥样式文本替换成 `<redacted>`——
因为读 `.env` 或配置文件正是密码最容易流进对话记录的路径。

需要看原文时传 `raw: true`：

```
ssh_read { machine: "prod", path: "/opt/app/.env", raw: true }
```

### 可选：隐藏主机拓扑

`ssh_machines` 默认显示 `user@host:port` 和私钥路径。
如果会话记录可能被分享或导出，改成只显示别名：

```yaml
- id: dsh-ssh-safe
  name: 'dsh-ssh-safe'
  config:
    machineInventory: alias    # 隐藏 host / port / 私钥路径
```

### 连接上限

最多保活 8 条连接，超出时关闭最久未使用的（LRU）。
配了很多机器时不会无限累积 socket：

```yaml
    maxConnections: 8    # 0 = 不限制
```

### 可选：允许在会话里传密码

默认关闭。开启方式（在 profile 的插件配置里）：

```yaml
- id: dsh-ssh-safe
  name: 'dsh-ssh-safe'
  config:
    allowSessionPassword: true
```

开启后可以用 `ssh_connect { machine: "prod", password: "..." }`。**代价**：密码会进入对话记录（transcript）。这就是为什么它默认关闭。

### 可选：执行前确认

```yaml
- id: dsh-ssh-safe
  name: 'dsh-ssh-safe'
  config:
    execGuard: confirm     # ssh_exec 必须带 confirm: true 才会执行
```

防止模型自作主张跑命令。

### 危险命令拦截

默认拒绝这些模式（可配置）：

- `rm -rf /`
- `mkfs.*`
- `dd if=... of=/dev/sd*`
- fork 炸弹
- `shutdown` / `reboot` / `halt` / `poweroff`

**注意**：这是防手滑的安全带，不是安全边界。shell 总有别的路径可达。


### 可选：原生加速绑定（`ERR_PNPM_IGNORED_BUILDS`）

`ssh2` 带两个**可选**原生模块：`cpu-features`（CPU 特性探测）和 `sshcrypto`（更快的加密）。
不编译它们插件照样能用（纯 JS 回退），但 pnpm 会把「忽略构建脚本」当成错误，让安装以非零码退出。

遇到这个报错时，在 profile 目录跑一次：

```sh
cd ~/.dsh/profiles/desktop
pnpm approve-builds --all
```

注意必须用**与 DSH 相同的大版本** pnpm。DSH 内置的是 pnpm 11，
如果你系统里的 `pnpm` 是 10，就要用 `npx pnpm@11 approve-builds --all`，
否则 `node_modules` 的 store 标记会被改写，之后 `dsh plugin` 会报 `ERR_PNPM_UNEXPECTED_STORE`。

### 它不做什么

- 不接管 `ctx.fs` / `ctx.shell`。你本地的 `read` / `write` / `bash` 完全不受影响
- 不提供端口转发、跳板机、SFTP 目录同步、远程界面
- 不读 `~/.ssh/config`（需要显式设环境变量）

想要这些功能，`dsh-remote` 更全。本插件只做「安全地跑命令和读写文件」。

---

## English

### What this solves

Gives a DeepSeek Harness agent the ability to work on a remote Linux server
(run commands, read/write files, list directories) **without handing server
credentials to a third party**.

### Design constraints

| What similar plugins do | What dsh-ssh-safe does |
| --- | --- |
| POST an install heartbeat to a cloud function | **No telemetry.** The package contains no HTTP client; `grep -r 'fetch(' src/` is empty |
| Check for and hot-swap its own code | **No auto-update.** Never fetches a version, never rewrites itself |
| Patch DeepSeek Harness files inside `app.asar` | **No host patching.** `cordis.patch.yml` only inserts this plugin |
| Disable `fs-sandbox` / `bash-sandbox` | **Leaves them alone.** Local sandboxing is unchanged |
| Store the SSH password in plaintext config | **Never persisted.** Environment variables by default |

### Install

```sh
dsh plugin --profile desktop add dsh-ssh-safe
```

Restart DeepSeek Harness afterwards.

### Configure a machine

Alias `prod` maps to these environment variables:

```sh
DSH_SSH_PROD_HOST=10.0.0.5
DSH_SSH_PROD_PORT=22
DSH_SSH_PROD_USER=ubuntu
DSH_SSH_PROD_KEY_PATH=~/.ssh/id_ed25519
```

Or a password instead of a key:

```sh
DSH_SSH_PROD_PASSWORD=...
```

Optional:

```sh
DSH_SSH_PROD_KEY_PASSPHRASE=...      # passphrase for an encrypted key
DSH_SSH_PROD_HOST_KEY_POLICY=tofu    # strict (default) / tofu / off
DSH_SSH_PROD_KNOWN_HOSTS=~/.ssh/known_hosts.json
```

Restart DeepSeek Harness — environment variables are read at process start.

### Tools

| Tool | Purpose |
| --- | --- |
| `ssh_machines` | Configured machines, auth kind, fingerprint trust (never shows key material) |
| `ssh_connect` | Open/reuse a connection; reports fingerprint and remote `uname` |
| `ssh_exec` | Run a command; returns stdout, stderr, exit code |
| `ssh_read` | Read a remote file (UTF-8, byte-capped) |
| `ssh_write` | Write a remote file (overwrite) |
| `ssh_list` | List a remote directory |
| `ssh_close` | Close connections |

### Host key verification

`strict` by default: only hosts already recorded may connect. First contact
requires an explicit `trustHostKey: true` on `ssh_connect`.

Fingerprints are stored in `~/.dsh/dsh-ssh-safe/known_hosts.json` (mode 0600)
and contain host, port and fingerprint only — never a username, password or key.

A **changed** host key fails the connection with an explanation rather than
being accepted. That is the whole point of host verification.

### Opt-in: password from the conversation

Off by default. Enable it in the profile plugin config:

```yaml
- id: dsh-ssh-safe
  name: 'dsh-ssh-safe'
  config:
    allowSessionPassword: true
```

Then `ssh_connect { machine: "prod", password: "..." }` works. The trade-off:
the password enters the conversation transcript. That is why it is off.

### Opt-in: confirm before exec

```yaml
- id: dsh-ssh-safe
  name: 'dsh-ssh-safe'
  config:
    execGuard: confirm
```

`ssh_exec` then requires `confirm: true`, so a model cannot run commands purely
on its own initiative.

### Denied command patterns

`rm -rf /`, `mkfs.*`, `dd ... of=/dev/sd*`, fork bombs, and
`shutdown`/`reboot`/`halt`/`poweroff` are refused by default.

A safety rail against catastrophic typos — **not** a security boundary.

### Not included

Port forwarding, bastion/jump hosts, SFTP mirroring, remote web UI. It also
does not read `~/.ssh/config` (set environment variables explicitly).

Use `dsh-remote` if you need those.

---

## License

MIT
