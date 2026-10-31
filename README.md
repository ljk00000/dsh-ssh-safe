# dsh-ssh-safe

> Security-first SSH tools for DeepSeek Harness. No telemetry, no cloud, no
> auto-update, no host patching. Credentials from environment variables by default.

**v0.2.0** · [更新日志](CHANGELOG.md) · MIT

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

## 兼容性要求

| 项目 | 要求 |
| --- | --- |
| DeepSeek Harness | `>=0.1.7-rc.1 <0.3.0`（见 `package.json` 的 `dsh.engines.dsh`） |
| Node.js | `>=20` |
| 目标主机 | 运行中的 `sshd`。`ssh_list`/SFTP 需要 sshd 启用 sftp 子系统（现代发行版默认开启） |
| 工具注册 API | 自动适配：`ctx.tools.register`（0.2.1+）与 `ctx.tools.defineTool`（0.1.x）。两者都没有时以版本提示拒绝加载，而不是静默消失 |
| 认证 | 密码、私钥文件、或 SSH agent（`SSH_AUTH_SOCK`）三者之一 |

不需要在目标主机上安装任何东西，也不需要 Python、Node 或 `ripgrep`。

### 已知限制

- **长任务**：`commandTimeoutMs` 默认 30 秒，超时会向远端发送 `TERM`。跑训练、`apt upgrade` 这类长任务需要显式提高 `timeoutMs`。
- **不支持二进制传输**：`ssh_read`/`ssh_write` 只处理 UTF-8 文本，单次上限 `maxFileBytes`（默认 1 MB）。
- **不支持端口转发 / 跳板机 / 多机批量**：设计上只做「安全地跑命令和读写文件」。
- **`denyPatterns` 是安全带，不是边界**：它能挡住手滑和常见的包装写法，但 shell 是图灵完备的。真正的隔离属于远端账号权限。
- **命令输出里的方括号标记可能被伪造**：`ssh_exec` 用 `[stderr]` 标记输出流切换，并在末尾追加插件自己的说明（`[note]`、`[exit N]`、`[signal …]`、`[timed out …]`、`[output truncated …]`、`[binary file …]`）。命令输出按原样呈现，所以远端如果打印了同样开头的行，看上去会和这些标记一模一样。判断一条命令的结果请以**最后一行状态**为准（`[exit N]` / `[signal …]`）——那行是插件写在末尾的，不来自远端。

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

## 三种配置来源（密码经常变化时看这里）

机器可以从三个地方定义，各有用途：

| 来源 | 适合放什么 | 改了要重启吗 |
| --- | --- | --- |
| **设置界面** `machines.<别名>` | host / port / user / 私钥路径 / 主机密钥策略 | 需要重载插件 |
| **凭据文件** `~/.dsh/dsh-ssh-safe/credentials.json` | 密码、私钥口令（**DPAPI 加密**） | **不用，下次连接即生效** |
| **环境变量** `DSH_SSH_<别名>_*` | CI、不想落盘的场景 | 需要重启 DSH |

优先级（从高到低）：**设置界面的密码 → 凭据文件（DPAPI 加密）→ 凭据文件（明文，需显式允许）→ 环境变量 → 私钥 → 会话密码 → SSH agent**。
空值不参与比较，所以设置界面留空不会遮蔽环境变量。

注意：**任何可用的密码都优先于私钥**。想让某台机器走私钥，就把它的密码来源（设置界面、凭据文件、环境变量）清掉。
不知道某台机器最终用了哪个来源时，看 `ssh_credentials` 列出的那个来源。

## 图形界面（按需打开，用完即退出）

```bash
cd <插件目录>
node scripts/gui.mjs
```

会自动打开浏览器页面，可以：

- 看到所有机器（凭据文件 + 环境变量 + DSH 设置里定义的）
- 填 host / 端口 / 用户 / 私钥路径
- **填入密码 → 立即 DPAPI 加密**，磁盘上不留明文
- **点「测试连接」** → 依次报告 配置 / TCP / 主机密钥 / 认证 / 命令通道
- 点「删除」移除某个别名

### 它不是常驻服务

| 设计 | 原因 |
| --- | --- |
| **独立进程**，不是插件里的服务 | 插件保持「不开端口」的定位 |
| 只绑 `127.0.0.1`，随机端口 | 外部无法访问 |
| 每次启动随机 token，URL 里带 | 本机其它程序无法驱动它 |
| 关闭页面 / 闲置 10 分钟即退出 | 不留后台进程 |
| 页面单文件、无 CDN、无遥测 | 不联网 |

### 测试连接不改变信任状态

页面上的「测试连接」只**报告**主机指纹，不会写入 known_hosts。
正式连接仍需 `ssh_connect`（首次可传 `trustHostKey: true`）——测试工具不应该改动被测试对象的状态。

> 密码在页面里输入 → 传到本地进程 → 立刻 DPAPI 加密 → 写入文件。
> 全程没有明文落盘，也没有任何接口会把密码返回给页面。
### 改密码（命令行方式）

```bash
cd <插件目录>
node scripts/set-password.mjs --alias gpu
```

它会提示你输入密码（**不回显、不进 shell 历史、不进对话记录**），用 **Windows DPAPI 加密**后
写入 `~/.dsh/dsh-ssh-safe/credentials.json`，并把文件 ACL 限制到「你 + SYSTEM」。

**下一条命令就是新密码，不用重启 DSH。**

也可以一次把机器信息写进去（这样连环境变量都不用配）：

```bash
node scripts/set-password.mjs --alias gpu \
  --host gpu.example.com --port 2222 --user root
```

用私钥 + 口令：

```bash
node scripts/set-password.mjs --alias prod \
  --key-path ~/.ssh/id_ed25519 --key-passphrase
```

> 为什么不提供 `.ps1`：这台机器的 PowerShell 执行策略会拒绝未签名脚本。
> Node 脚本不受该策略影响，而插件本来就依赖 Node。
### 密码怎么存：磁盘上没有明文

| 方式 | 磁盘上是什么 | 安全边界 |
| --- | --- | --- |
| 凭据文件（默认） | **DPAPI 密文** | 只有你这一个 Windows 账户能解开；文件复制到别的机器或别的用户下解不开 |
| 环境变量 | 不落盘 | 只存在于启动 DSH 的那个进程内存里 |
| SSH agent | 不落盘 | 私钥在 agent 里，插件只拿到签名 |
| 设置界面 / 明文文件 | 明文 | **默认被拒绝** |

所以：**插件默认不读明文密码**。如果在设置界面或凭据文件里写了明文，连接会失败并给出
说明（`ssh_doctor` 会显示 `[warn]`）。要强行接受明文，设 `allowPlaintextPassword: true`——但那就等于
放弃这层保护。

### 没有 DPAPI 的平台（Linux / macOS）

凭据文件只支持 DPAPI 加密，所以这些平台请用**环境变量**或 **SSH agent**：

```bash
export DSH_SSH_PROD_PASSWORD='...'   # 只在当前进程内存里
```

或者把公钥加到服务器后改用私钥 —— 私钥有口令也只会进 DPAPI 加密的口令字段。
### 推荐用法

1. 在 DSH 设置里给插件加一个机器条目（“机器”很少变）：

```
machines.prod = { host: "10.0.0.5", port: 22, user: "ubuntu" }
```

2. 密码放进凭据文件（“密码”经常变）：

```bash
# ~/.dsh/dsh-ssh-safe/credentials.json
{
  "prod": { "password": "..." },
  "gpu":  { "keyPath": "~/.ssh/id_ed25519", "keyPassphrase": "..." }
}
```

改完不用重启——插件每次连接都会重新读这个文件。

### 查看当前生效的是什么

```
ssh_credentials    # 每台机器的密码/密钥来自哪里（只报来源，不显示值）
ssh_config         # 插件配置 + 凭据文件路径
ssh_machines       # 机器清单 + 每个字段的来源
```

> **密码要不要写进设置界面？** 可以，但设置界面的内容会以明文存进 DSH 的配置文件。
> 凭据文件是独立文件、权限 0600、改动即时生效，更适合经常轮换的密码。

### 安全提醒

- 凭据文件在 Windows 上无法设置 POSIX 权限（`chmod` 无效果），请确保它位于只有你能访问的用户目录。
- 目录已通过 `.gitignore` 排除，不会被误提交。

### 配置服务器凭据（环境变量方式）

用一个「别名 + 环境变量」的方式。别名只能用字母、数字、点、下划线、连字符
（字母会被转成大写用于变量名：`prod.x` 读的是 `DSH_SSH_PROD_X_HOST`）。别名 `prod` 对应下面这些变量：

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

### 我该用哪个工具

| 情况 | 用这个 |
| --- | --- |
| 不知道有哪些机器 | `ssh_machines` |
| 连不上，不知道为什么 | **`ssh_doctor`**（分级诊断，先说清卡在哪一步） |
| 只是想建立连接 | `ssh_connect` |
| 跑命令 | `ssh_exec` |
| 改配置文件 | `ssh_read` 看清现状 → `ssh_write` 改 |
| 看目录里有什么 | `ssh_list` |
| 怀疑有异常操作，想复盘 | **`ssh_audit`**（需要先开 `auditLog: true`） |
| 某个设置不生效 | **`ssh_config`**（显示运行时实际生效的配置） |
| 手动断开 | `ssh_close` |

排障顺序永远是 **`ssh_machines` → `ssh_doctor` → 具体操作**。​`ssh_doctor` 把失败分成
配置 / 凭据 / TCP / 主机密钥 / 认证五级，比一句「认证失败」有用得多；另有三个只在需要时出现的提示行：
`audit`（审计日志写不进去，例如只读目录）、`connect`（连接阶段的失败原因）、`shell`（登录成功但远端不产出输出）。

### 工具

| 工具 | 作用 |
| --- | --- |
| `ssh_machines` | 列出已配置的机器、认证方式、指纹信任状态（**不显示任何密钥**） |
| `ssh_connect` | 建立或复用连接，返回主机指纹与远端 `uname` |
| `ssh_exec` | 在远端执行命令，返回 stdout / stderr / 退出码（输出里的密钥样式文本默认打码，见下文「脱敏」） |
| `ssh_read` | 读远端文件（UTF-8，按字节上限截断；默认对疑似密钥打码，`raw: true` 关闭） |
| `ssh_write` | 写远端文件（覆盖）；父目录不存在时报错，`createDirs: true` 自动创建；新建文件的权限用 `mode: "600"` 指定（写私钥、`.env` 时务必指定），回执里会报出实际权限 |
| `ssh_list` | 列远端目录（超过 `maxListEntries` 截断并说明略过多少条） |
| `ssh_close` | 关闭连接（有命令在跑会拒绝，除非 `force: true`） |
| `ssh_doctor` | 分级诊断：配置 / 凭据 / TCP / 主机密钥 / 认证（必要时还有 `audit` / `connect` / `shell` 提示） |
| `ssh_audit` | 查看操作记录（需 `auditLog: true`；`outcome` 取值见下表） |
| `ssh_config` | 查看运行时实际生效的配置 |
| `ssh_credentials` | 查看凭据来源与优先级（只报来源，永不打印值） |
| `ssh_workspace` | 创建 / 列出 / 移除**远程工作区**：侧栏里一个绑定到某台 SSH 主机的工作区 |

### 审计记录里的 `outcome` 取值

`ssh_audit` 与 `audit.ndjson` 里每条的 `outcome` 只取下列值之一。`ssh_exec` 早就能区分
「超时 / 被取消 / 连接中断」，传输类工具此前一律记成 `error`，同一件事在日志里读法不同；
现在四类工具用同一套词：

| `outcome` | 含义 |
| --- | --- |
| `ok` | 完成 |
| `exit` | 命令跑完但退出码非 0（仅 `ssh_exec`，`exitCode` 一并记录） |
| `signal` | 命令被信号终止（仅 `ssh_exec`，`signal` 一并记录） |
| `error` | 失败（远端报错、路径不存在、认证被拒等） |
| `timeout` | 超过 `commandTimeoutMs` / `sftpTimeoutMs` / 握手超时 |
| `cancel` | 调用方通过 `signal` 取消 |
| `incomplete` | 连接在退出码返回前断开，输出不完整（仅 `ssh_exec`） |
| `blocked` | 被 `execGuard` 或 `denyPatterns` 拦下（`kind: refused`） |
| `warn` | 仅 `ssh_doctor`：检查完成，但有告警（如 `hostKeyPolicy: off`） |
| `none` | 仅 `ssh_close`：本来就没有活动连接，无需关闭 |
| `pending` / `busy` / `unconfirmed` | 仅 `ssh_close`：仍在建立、有命令在跑、关闭未能确认 |

`kind` 取值：`connect` / `exec` / `read` / `write` / `list` / `close` / `doctor` / `refused`。
每条记录现在都带 `outcome`；此前 `refused` 记录没有，按 outcome 过滤会漏掉被拦下的操作。

### 远程工作区（侧栏）

DSH 的工作区是一个**本地目录**：注册表按路径归组会话，agent 的工作目录就是它。
远端主机没有本地目录，所以本插件用一个**占位目录**代表它：

```
~/.dsh/dsh-ssh-safe/remotes/<alias>/
  AGENTS.md                    ← agent 自动读取的说明
  .dsh-remote-workspace.json   ← 别名、主机、端口、生成时间
```

把这个目录注册成工作区，它就会出现在左侧「工作区」列表里（标题是 `远程 · <alias>`）。
在这个工作区里新开会话时，DSH 会自动把 `AGENTS.md` 当作项目指令加载；指令告诉模型：
这个目录只是指针，所有文件与命令操作都必须走 `ssh_*` 工具并带上 `machine: "<alias>"`。

```
ssh_workspace { action: "create", machine: "gpu" }   # 创建并注册
ssh_workspace { }                                     # 列出状态
ssh_workspace { action: "remove", machine: "gpu" }    # 从侧栏移除（保留占位目录）
ssh_workspace { action: "remove", machine: "gpu", deleteFiles: true }
```

创建后侧栏若没立刻刷新，按 F5 重载页面。占位目录里**没有任何凭据**，也没有远端文件；
主机或端口变了（例如换了个端口）再执行一次 `create` 即可刷新 `AGENTS.md`。

需要说清楚的边界：这是**绑定**，不是挂载。本地 `pwsh` / `read` / `write` 仍然只看得到本机，
它们不会因为会话在这个工作区里就变成远端执行——这正是 `AGENTS.md` 要反复强调的原因。

### 主机密钥校验

默认 `strict`：**只有已记录过指纹的主机才能连**。首次连接需要显式确认：

```
ssh_connect { machine: "prod", trustHostKey: true }
```

指纹会存进 `~/.dsh/dsh-ssh-safe/known_hosts.json`（权限 0600），内容只有主机、端口、指纹——**没有用户名、密码、密钥**。

如果已经有自己的 OpenSSH `known_hosts`，可以把它填进 `knownHosts`：插件会**按 OpenSSH 格式只读校验**（普通条目、通配符、`|1|...` 哈希条目、`[host]:port`、`@revoked`），但**不会往这个文件里写**——新主机请用 `ssh-keyscan` 追加，因为写回一个自己只校验了一半的格式，正是信任库腐坏的方式。

如果服务器的指纹**变了**，插件会拒绝连接并说明原因，而不是自动接受。这是防中间人攻击的核心行为。

每台机器可以用 `DSH_SSH_<ALIAS>_HOST_KEY_POLICY` **单独覆盖**全局策略（收紧或放宽都行）：

```sh
DSH_SSH_PROD_HOST_KEY_POLICY=strict   # 这台机器强制 strict，即使全局是 tofu
```

### `ssh_list` 的路径语义

`ssh_list` 允许相对路径（默认 `.`），但**拒绝含 `..` 的相对路径**：
SFTP 把相对路径解析到登录目录，而插件无从知道那是哪里（取决于 sshd 配置和账号类型）。
让 `../etc` 在猜测的基准上解析，不如直接要求绝对路径。

目录条目超过 `maxListEntries` 时，末尾会写「还有 N 条未显示」并给出下一页的 `offset`。
`maxListEntries` 是插件配置，工具调用改不了它，所以分页靠 `offset`：

```
ssh_list { machine: "prod", path: "/var/log" }              → 前 2000 条 …
ssh_list { machine: "prod", path: "/var/log", offset: 2000 } → 接着的 2000 条
```

排序是「目录在前，然后按名字」，`offset` 作用在排序之后，所以同一时间两次调用看到的顺序一致。

### 可选：密钥样式文本的脱敏

`ssh_read` 与 `ssh_exec` 都会把**看起来像密钥的文本**替换掉再返回——因为读 `.env`、
配置文件，或用命令打印它们，正是密码最容易流进对话记录的路径。三种占位符：

| 占位符 | 命中的内容 |
| --- | --- |
| `<redacted>` | `PASSWORD=` / `SECRET=` / `TOKEN=` 等键值、`.env` 行、`Authorization:` 头、`-p` / `--pass` / `redis-cli -a` 后的密码、URL 里的 `user:pass@` |
| `<redacted-pem>` | `-----BEGIN … -----END …` 的 PEM 私钥；被读取上限截断、没有 END 的也算 |
| `<redacted-ppk>` | PuTTY `.ppk` 私钥（从 `PuTTY-User-Key-File-N:` 起） |

**这不是保证，而是尽力而为**：脱敏按「形状」匹配，一句 `echo 某某 > /tmp/pw`
里的任意单词没有任何标记可依，不会被认出来；二进制或压缩内容里的密钥同样认不出。
真正的边界是：不要把密码放进对话，也不要为了看密码而读文件。

需要看原文时传 `raw: true`（只对 `ssh_read` 生效）：

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

### 并发

十二个工具都声明了自己可以并发执行：每次调用走独立的 SSH 通道，连接池按别名复用。
所以在同一台机器上同时跑两个命令、或者一边跑命令一边读文件都不会互相排队。
（少了这个声明，DSH 会把工具当作独占资源：一条 3 秒的命令会让另一条 0.2 秒的命令也等 3 秒。）

### 可选：允许在会话里传密码

默认关闭。开启方式（在 profile 的插件配置里）：

```yaml
- id: dsh-ssh-safe
  name: 'dsh-ssh-safe'
  config:
    allowSessionPassword: true
```

开启后可以用 `ssh_connect { machine: "prod", password: "..." }`。**代价**：密码会进入对话记录（transcript）。这就是为什么它默认关闭。

会话密码是**最后顺位**：设置界面、凭据文件、环境变量都优先于它。如果其中任意一个已提供，传进来的密码不会被使用，调用结果会附一行 `[note]` 说明——避免“存着的旧密码登录成功”被误读成“新密码生效”。

### 可选：执行前确认

```yaml
- id: dsh-ssh-safe
  name: 'dsh-ssh-safe'
  config:
    execGuard: confirm     # ssh_exec / ssh_read / ssh_write 都必须带 confirm: true
```

防止模型自作主张跑命令。读也在拦截范围内：一次读取就能把 `~/.ssh/id_ed25519` 带走，
所以 `ssh_read` 与 `ssh_write` 同样需要 `confirm: true`；`ssh_list` 只列元数据，不受影响。

### 危险命令拦截

默认拒绝这些模式（可配置，共 13 条）：

- `rm -rf /` 及其变体：`//`、`/*`、`/.`、`/..`
- `rm -rf ~` / `rm -rf $HOME`（家目录顶层）
- `cd /`（或 `cd ~`）之后紧跟 `rm -rf *`——斜杠在 cd 里，第一条看不见
- `find /` 配合 `-delete` 或 `-exec rm`；`find / | xargs rm`、`xargs rm -rf`（`find . | xargs rm` 不带递归时仍放行）
- `mkfs.*`、`dd if=... of=/dev/sd*`、往块设备重定向（`>: /dev/sda`）、`wipefs`、`shred`、fork 炸弹
- `shutdown` / `reboot` / `halt` / `poweroff`，且只在**命令位置**匹配（`grep -c shutdown 日志` 不再被误拦）
- 下载即执行，不经过管道也算：`bash -c "$(curl …)"`、`source <(curl …)`、`. <(wget …)`（`cat <(curl …)` 只读文本，仍放行）

设置 `denyPatterns` 会**替换**这 13 条默认规则，不是追加：只写一条自定义规则时，`rm -rf /` 就不再被拦。
`ssh_config` 会如实显示当前是内置集（`13 pattern(s) (the built-in set)`）、替换集（`2 pattern(s) — replaces the 13 built-in rules`）
还是已关闭（`0 pattern(s) — the destructive-command guard is OFF`）；写成非法正则会在加载时被拒绝，不会静默失效。

**注意**：这是防手滑的安全带，不是安全边界。shell 总有别的路径可达。
默认规则只匹配命令的开头与结尾各 8 KB，避免病态超长输入把检查拖成平方级；
真实命令远短于这个窗口。


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


### 开发与测试

- `npm test` —— 全部离线测试（不需要任何主机）
- `npm run typecheck` —— `tsc --noEmit`
- `npm run test:loopback` —— 在本机起一个内存中的 SSH/SFTP 服务端，把
  `test/integration.test.js` 那几条「真主机」用例跑一遍
- `DSH_SSH_TEST_TARGET=<别名> npm test` —— 对着真实主机跑同一组用例
  （照常设置 `DSH_SSH_<别名>_HOST` / `_USER` / `_PASSWORD` 或 `_KEY_PATH`）

loopback 服务端不执行命令、不碰磁盘，只按脚本回包——它验证的是客户端这一半：
握手、主机密钥、exec 通道、SFTP 读写与超时。

### 配置默认值一览

| 配置项 | 默认 | 作用 |
| --- | --- | --- |
| `hostKeyPolicy` | `strict` | 只连已记录指纹的主机 |
| `execGuard` | `allow` | `confirm` 时 `ssh_exec`、`ssh_read`、`ssh_write` 都必须带 `confirm: true`（`ssh_list` 不受影响） |
| `allowSessionPassword` | `false` | 是否允许在会话里传密码 |
| `allowPlaintextPassword` | `false` | 是否接受凭据文件或设置界面里的明文密码（默认只认 DPAPI 加密值） |
| `machineInventory` | `full` | `alias` 时隐藏 host/port/私钥路径 |
| `auditLog` | `false` | 是否记录操作到 `~/.dsh/dsh-ssh-safe/audit.ndjson`（单文件 4 MB 上限，滚动保留 4 代；`ssh_audit` 从旧到新读取当前文件与这 4 代） |
| `maxConnections` | `8` | 常驻连接上限，LRU 淘汰，`0` 不限制 |
| `commandTimeoutMs` | `30000` | 单条命令超时 |
| `sftpTimeoutMs` | `30000` | 单次传输超时 |
| `connectTimeoutMs` | `15000` | 建立连接超时 |
| `closeTimeoutMs` | `1500` | 等待对端确认关闭 |
| `keepaliveIntervalMs` | `20000` | SSH keepalive，`0` 关闭 |
| `maxOutputChars` | `200000` | stdout + stderr 合计上限 |
| `maxFileBytes` | `1048576` | 单次传输字节上限 |
| `maxListEntries` | `2000` | `ssh_list` 单次输出的行数上限，`0` 不限制 |
| `reconnectCooldownMs` | `15000` | 失败后冷却，期间可用 `force: true` 绕过 |
| `healthCheckIdleMs` | `300000` | 空闲多久后复用前先探活，`0` 关闭 |
| `defaultMachine` | `''` | 工具调用省略 `machine` 时使用的别名 |
| `machines` | `{}` | 机器定义（设置界面可编辑，不含密码优先） |
| `useCredentialFile` | `true` | 每次连接读取凭据文件，改密码免重启 |
| `healthCheckTimeoutMs` | `3000` | 探活探测的截止时间 |
| `pipeToShell` | `refuse` | `refuse` 拦截管道进解释器；`allow` 放行 |
| `denyPatterns` | 13 条 | 危险命令拦截（安全带，不是边界） |

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

### Compatibility

| Item | Requirement |
| --- | --- |
| DeepSeek Harness | `>=0.1.7-rc.1 <0.3.0` (see `dsh.engines.dsh` in `package.json`) |
| Node.js | `>=20` (declared as `engines.node`) |
| Target host | a running `sshd`; `ssh_list`/SFTP need the sftp subsystem (on by default on modern distros) |
| Tool registration API | Detected at load: `ctx.tools.register` (0.2.1+) or `ctx.tools.defineTool` (0.1.x); with neither, the plugin refuses to load with a version-naming error instead of vanishing |
| Auth | password, private key file, or SSH agent (`SSH_AUTH_SOCK`) |

Nothing needs to be installed on the target host — no Python, no Node, no `ripgrep`.

### Known limitations

- **Long-running tasks**: `commandTimeoutMs` defaults to 30 s and sends `TERM` on expiry. Training runs, `apt upgrade` and the like need an explicit higher `timeoutMs`.
- **No binary transfer**: `ssh_read`/`ssh_write` handle UTF-8 text only, capped at `maxFileBytes` (1 MB by default).
- **No port forwarding, jump hosts or fleet-wide fan-out**: by design this only runs commands and moves files, safely.
- **`denyPatterns` is a seatbelt, not a boundary**: it stops slips and the common wrapper spellings, but the shell is Turing-complete. Real isolation belongs to the remote account's permissions.

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
| `ssh_exec` | Run a command; returns stdout, stderr, exit code (secret-shaped text in the output is masked; see below) |
| `ssh_read` | Read a remote file (UTF-8, byte-capped; secret-shaped text masked unless `raw: true`) |
| `ssh_write` | Write a remote file (overwrite); `createDirs: true` creates missing parents; `mode: "600"` sets the permissions of a new file (always do this for keys and `.env`), and the reply reports the mode that resulted |
| `ssh_list` | List a remote directory (capped by `maxListEntries`) |
| `ssh_close` | Close connections |
| `ssh_doctor` | Stage-by-stage diagnosis (configuration / credentials / TCP / host key / authentication, plus `audit` / `connect` / `shell` notes when they apply), including a real authentication attempt |
| `ssh_audit` | Recent operations (requires `auditLog: true`) |
| `ssh_config` | The configuration actually in effect |
| `ssh_credentials` | Credential sources and precedence (never values) |
| `ssh_workspace` | Create, list or remove a **remote workspace**: a sidebar workspace bound to one SSH machine |

### Concurrency

All twelve tools declare themselves concurrency-safe: every call owns its own SSH
channel and the pool reuses one connection per alias, so two commands on the same
machine, or a command and a read, run at the same time instead of queueing.
Without that declaration the harness treats a tool as an exclusive resource — one
3-second command made an unrelated 0.2-second command wait 3 seconds.

### Remote workspaces (sidebar)

A DSH workspace is a **local directory**: the registry groups sessions by path and
the agent's working directory is that path. A remote host has no local directory,
so the plugin uses a placeholder directory to stand for it:

```
~/.dsh/dsh-ssh-safe/remotes/<alias>/
  AGENTS.md                    ← instructions the agent loads automatically
  .dsh-remote-workspace.json   ← alias, host, port, when it was generated
```

Registering that directory makes it a normal workspace in the sidebar, titled
`远程 · <alias>`. A session started there loads `AGENTS.md` as project
instructions, and those instructions say the directory is only a pointer: every
file or command operation goes through the `ssh_*` tools with
`machine: "<alias>"`.

```
ssh_workspace { action: "create", machine: "gpu" }   # create and register
ssh_workspace { }                                     # show status
ssh_workspace { action: "remove", machine: "gpu" }    # unregister, keep the directory
ssh_workspace { action: "remove", machine: "gpu", deleteFiles: true }
```

Reload the page (F5) if the sidebar has not picked up the new workspace. The
placeholder holds no credential and no remote file; re-run `create` after an
endpoint change to refresh `AGENTS.md`.

The boundary worth stating: this is a **binding**, not a mount. Local
`pwsh` / `read` / `write` still see only this machine — they do not become
remote just because the session lives in that workspace, which is exactly why
`AGENTS.md` repeats the rule.

### Host key verification

`strict` by default: only hosts already recorded may connect. First contact
requires an explicit `trustHostKey: true` on `ssh_connect`.

Fingerprints are stored in `~/.dsh/dsh-ssh-safe/known_hosts.json` (mode 0600)
and contain host, port and fingerprint only — never a username, password or key.

An OpenSSH `known_hosts` file can be used instead through the `knownHosts`
setting. It is verified **read-only** — plain, wildcard, `|1|...` hashed and
`[host]:port` entries, plus `@revoked` — and never written to; add new hosts with
`ssh-keyscan`, because writing back a format this plugin only partly validates is
how trust stores rot.

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

A session password is the **last resort**: the settings form, the credential
file and the environment all outrank it. If one of those is present the supplied
password is not used, and the call says so with a `[note]` line rather than
letting a stale stored credential look like a successful login.

### Opt-in: confirm before exec

```yaml
- id: dsh-ssh-safe
  name: 'dsh-ssh-safe'
  config:
    execGuard: confirm
```

`ssh_exec`, `ssh_read` and `ssh_write` then require `confirm: true`, so a model cannot
run commands — or copy a key off the host — purely on its own initiative. `ssh_list`
stays unguarded: it returns metadata only.

### Denied command patterns

Nine patterns ship by default:

- `rm -rf /` and its spellings `//`, `/*`, `/.`, `/..`
- `rm -rf ~` / `rm -rf $HOME` (the top of the home directory)
- `cd /` (or `cd ~`) followed by `rm -rf *` — the slash lives in the `cd`, so
  the first rule cannot see it
- `find /` with `-delete` or `-exec rm`
- `mkfs.*`, `dd if=... of=/dev/sd*`, fork bombs
- `shutdown`/`reboot`/`halt`/`poweroff`, matched only in **command position**
  (`grep -c shutdown syslog` is no longer refused)

Patterns are matched against the first and last 8 KB of a command, so a
pathological input cannot make the check quadratic. A real command is far
shorter than that window.

A safety rail against catastrophic typos — **not** a security boundary.

### Tests

- `npm test` — the whole offline suite (no host needed)
- `npm run typecheck` — `tsc --noEmit`
- `npm run test:loopback` — starts an in-memory SSH/SFTP server on this machine
  and runs the "real host" cases in `test/integration.test.js` against it
- `DSH_SSH_TEST_TARGET=<alias> npm test` — the same cases against a real host
  (with `DSH_SSH_<ALIAS>_HOST` / `_USER` / `_PASSWORD` or `_KEY_PATH` set as usual)

The loopback server runs no process and touches no disk; it answers from a
script. It proves the client half — handshake, host key, exec channel, SFTP
reads and writes, deadlines.

### Not included

Port forwarding, bastion/jump hosts, SFTP mirroring, remote web UI. It also
does not read `~/.ssh/config` (set environment variables explicitly).

Use `dsh-remote` if you need those.

---

## License

MIT
