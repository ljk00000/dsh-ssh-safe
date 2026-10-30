# Changelog

## 0.7.6 — 2026-10-31

### Fixed
- **`redactObject` removed.** It was exported, exercised only by its own test,
  and recursed without a depth or cycle guard: a circular error object would
  have thrown `RangeError: Maximum call stack size exceeded` from inside the
  redaction path. Nothing called it, so it is gone along with `SECRET_ENV`.

### Added — tests
- Unloading the plugin closes its pooled connections and the plugin keeps
  working afterwards.
- A command that hits its deadline leaves the connection healthy for the next
  call (three deadlines in a row).
- The file and workspace tools answer through their schemas even when SFTP and
  the workspace registry are unavailable.
- An oversized request to the credential page is refused without writing
  anything.

## 0.7.5 — 2026-10-31

### Fixed
- **An enormous `timeoutMs` aborted the command instantly.** `setTimeout` clamps
  any delay above 2^31-1 to 1 ms, so `ssh_exec { timeoutMs: 10000000000 }`
  returned "timed out" after 12 ms. Deadlines are clamped to the timer range for
  exec and for the SFTP transfers.
- **Two dead helpers removed.** `readEnv` in credentials.js and
  `dpapiDescription` in dpapi.js were defined and never called; a future reader
  would have taken `readEnv` for the code that reads credentials from the
  environment, which it never was.

### Added — tests
- Relative paths containing `..` are refused for the stated reason.
- Ten commands run at once on one connection; a dropped connection is noticed
  and re-established on the next call; `maxConnections: 0` means no ceiling; the
  drain window lets an in-flight command finish.
- Two credential-page saves issued together both survive.

## 0.7.4 — 2026-10-31

Found by driving the guard against a real host and by building a loopback SSH
server so the pool and the tool bodies are exercised without one.

### Fixed — the guard
- **`cd / && rm -rf *` was not refused, and it ran.** The root rule only looked
  at the target of the `rm`; here the slash belongs to the `cd`, so nothing
  matched. A second rule now refuses `cd /`/`cd ~`/`cd $HOME` followed by a
  recursive `rm` of a glob, including the `/bin/rm`, `sudo -u …`, `env` and
  `nohup` spellings.
- **`rm -rf //` slipped through** the same rule: the pattern wanted whitespace,
  end-of-string or `*` directly after a single slash. Multiple slashes, `/.`
  and `/..` are covered now.
- **`rm -rf ~` / `rm -rf $HOME` are refused**, at the top of the home directory
  only — `rm -rf ~/build` still works.
- **`find / -delete` and `find / -exec rm`** are refused; subdirectory finds are
  untouched.
- **The shutdown rule refused the bare word anywhere.** `grep -c shutdown
  /var/log/syslog` and `echo reboot` were blocked. It now matches only at a
  command position, with `sudo`/`doas`/`nohup`/`nice`/`timeout`/`systemctl`
  prefixes.

### Fixed — credentials
- **`set-password --alias prod-1` stored the password under `prod1`.** The
  script stripped `-` and `.` while the plugin and the GUI kept them, so the
  password was written and then never found ("no credentials"). All three now
  use the same rule.

### Fixed — the credential page
- A malformed JSON body answered 500 and an oversized one answered 500; they are
  the caller's mistake, so they answer 400 and 413.

### Changed
- `ssh_close` says `Closed: <alias>` in both the single and the all form.

### Added — tests
- A loopback SSH server (ssh2 `Server`) drives the real client: auth, host-key
  change rejection, cooldown, timeout, signal, output cap, busy close and LRU
  eviction (11 tests), plus the twelve tool bodies end to end including the
  audit trail (15 tests).
- The credential page's endpoints: Host-header refusal, save/delete, alias and
  port validation, 404/400 (5 tests).
- `set-password` rotation and alias handling (3 tests).

## 0.7.3 — 2026-10-31

### Fixed
- **A command killed by a signal reported `[exit unknown]`.** ssh2's close
  event carries `(code, signal)`; only the code was read, so `kill -9 $$`
  looked like lost information instead of a killed process. The result now
  carries the signal and renders `[signal SIGKILL]` / `[signal SIGTERM]`.
- **A relative path that does not exist now says what it is relative to.**
  sshd resolves it against the login user's home directory, not against the
  previous call's path, and the bare `No such file: tmp/x` gave the caller no
  way to tell. The hint appears only for missing relative paths, so absolute
  paths and permission errors are unchanged.

## 0.7.2 — 2026-10-31

Found by driving the twelve tools against a live host on 0.2.1-rc.5.

### Fixed
- **A long single-line output took 33 seconds to return.** Every result passes
  through `redact()` before it reaches the model. Its key rule started with an
  unanchored lazy `[A-Za-z0-9_]*?` and its URL rule with an unanchored
  unbounded scheme run, so both were retried from every position of a line made
  of word characters — quadratic in the line length. `cat` of a 100 KB file
  with no newline took 8.3 s; 200 KB hit the 30 s command timeout. Both rules
  now anchor on a non-word character (or the start of the text), and a 400 KB
  line redacts in 2 ms. Verified live: the same command dropped to 0.35 s.
- **"No such file" for a path that exists.** `ssh_list` on a regular file
  repeated sshd's ENOENT, which reads as "the path is gone". `ssh_read` of a
  directory and `ssh_write` onto one said only `Failure`. All three now stat
  the path on the error path and say `not a directory: … (it is a file)` or
  `not a file: … (it is a directory)`.

### Changed
- **Nested calls run in parallel again.** Without an `isConcurrencySafe`
  declaration the harness treats every tool as exclusive, so a 3-second command
  blocked an unrelated 200 ms one — measured 3.4 s where 0.2 s was expected.
  Each call owns its own SSH channel and the pool keys state per alias, so all
  twelve tools now declare it safe.

## 0.7.1 — 2026-10-30

### Fixed — the plugin did not activate on DSH 0.2.1
- **Every tool disappeared on 0.2.1.** That release replaced the
  `ctx.tools.defineTool` service method with `ctx.tools.register` and moved the
  definition compiler to the `@deepseek-ai/dsh-tools` export. Activation threw
  `TypeError: ctx.tools.defineTool is not a function` at the first registration,
  the harness logged `warning: 1 entry did not activate`, and the plugin
  contributed nothing — the worst failure shape for a security tool, because it
  fails quietly.
- Registration now picks the entry point the running harness offers:
  `ctx.tools.register(defineTool(definition))` on 0.2.1+, the older
  `ctx.tools.defineTool(definition)` on 0.1.x, and a version-naming error when
  neither exists.
- `test/tools-registration.test.js` asserts the shape `register` demands
  (`parameters.type === 'object'`, `output.render`, `output.schema`) so a
  silent "did not activate" cannot ship again; the tool tests now register
  through the same compiled path the host uses.
- Verified against 0.2.1-rc.5: the "did not activate" warning is gone and all
  twelve tools register.

## 0.7.0 — 2026-10-30

### Added — remote workspaces
- `ssh_workspace` creates a sidebar workspace bound to one SSH machine. A DSH
  workspace is a local directory, so a remote host gets a placeholder directory
  (`~/.dsh/dsh-ssh-safe/remotes/<alias>`) registered through
  `ctx.workspaceRegistry`; it appears in the sidebar as `远程 · <alias>`.
- The placeholder carries an `AGENTS.md` that the harness loads as project
  instructions: this directory only points at the remote host, and every file or
  command operation goes through `ssh_*` with `machine: "<alias>"`. Re-running
  `create` refreshes it after an endpoint change.
- `remove` unregisters without deleting the directory; `deleteFiles: true` also
  removes it. Files on the remote host are never touched.
- The instructions never carry a credential: they name the environment variable
  and the DPAPI store instead.

## 0.6.1 — 2026-10-30

### Fixed
- `AuditLog.write` trusted its callers to summarise first: a raw 5,000
  character command produced a 5,102 byte record, and rotation only checks the
  size before appending, so a handful of records could land past the cap. Every
  string field is clamped to 300 characters, objects are replaced with
  `[object]` instead of being serialised, and a record cannot rewrite its own
  timestamp.

## 0.6.0 — 2026-10-30

Everything below was found by driving the eleven tools against a live host and
by fuzzing the guard and the redactor, then kept by a test.

### Fixed — the plugin did not actually connect
- **A stored password was never sent to ssh2.** `SshPool#open` mapped credential
  kinds with an if/else chain that named four of them; the kinds produced by the
  settings form and the credential file fell through, so the connection carried
  no authentication and failed with the bare "All configured authentication
  methods failed". The DPAPI password path — the whole point of the settings
  page — had never worked. The mapping now keys on the resolved value and lives
  in one place (`src/connect.js`), shared with the page.
- **SFTP sessions leaked until the server refused new channels.** Each
  read/write/list opened a session and never closed it; sshd counts sessions per
  connection (10 by default), so the eleventh operation failed with
  "(SSH) Channel open failure".
- **Closing a session could kill the process.** ssh2 reports an abandoned
  request on the stream, so removing the stream's listeners before closing made
  it an unhandled `error` event. Reading a missing file crashed DSH.
- **`maxOutputChars` bounded a string nobody rendered.** The accumulators obeyed
  the cap while the timeline `ssh_exec` prints collected every chunk: with a
  4,000 character cap, 337,842 characters came back.

### Fixed — silent misconfiguration
- **A misspelled setting was ignored.** `execGurad: confirm` parsed, appeared in
  the config, and governed nothing. A key within edit distance 2 of a real one
  now fails the load and names the intended spelling.
- **A shadowed session password said nothing.** A session password is the last
  resort, so passing one while a stored credential exists has no effect. The
  call now prints a `[note]` saying so.
- **`ssh_machines` printed `auth: NONE`** for a machine whose password was
  sitting in the credential file.
- **A dead second resolver.** `credentials.resolveAuth()` was called by nothing
  but its own tests, so the agent fallback was "covered" in code no user could
  reach.

### Fixed — safety rails
- `rm -rf /;` slipped past the guard: the canonical form ended at the slash and
  the pattern required whitespace after it.
- `mkfs.ext4 ./disk.img` was refused: the pattern asked for the word mkfs, not
  for a device.
- Redaction missed JSON (`{"password": "hunter2"}`) and flag-style secrets
  (`curl -u admin:hunter2`), and over-matched prose (`secretary: hello`).
- The page compared its token with `===` and accepted the query-string token on
  every API route; the API now requires the header and the comparison is
  constant-time.
- The page accepted `__proto__` as an alias, answered `{"ok":true}`, and saved
  nothing.

### Added
- `ssh_write` takes `createDirs: true`; without it a missing parent is an error
  that names the path instead of the bare "No such file".
- `maxListEntries` (default 2,000) caps `ssh_list`; the omitted count is shown.
  Control characters in names are escaped so one entry cannot forge a row.
- `ssh_read` only claims to have masked secrets when redaction changed
  something.
- `test/guard-corpus.test.js` (62 cases against the shipped defaults),
  `test/connect.test.js`, `test/format.test.js`, `test/auth-wiring.test.js`,
  `test/sftp-cleanup.test.js`.

### Tests
325 tests (320 pass, 5 skip on this platform), typecheck clean.

## 0.5.0 — 2026-10-28

### Added
- `scripts/gui.mjs` + `scripts/gui.html`: an on-demand local page for machines
  and credentials. Lists every alias from all three sources, edits host / port /
  user / key path, stores a password DPAPI encrypted immediately, and runs a real
  connection test that reports 配置 / TCP / 主机密钥 / 认证 / 命令通道 in order.
- `npm run gui`.

### Why a separate process

The plugin keeps no listening socket. The page runs only while the command runs,
binds 127.0.0.1 on a random port, requires a per-start token in the URL, and exits
on close or after ten idle minutes. No CDN, no telemetry, one local file.

### Deliberate limits
- The connection test reports the host-key fingerprint but does not record it: a
  test must not move the trust state.
- If a machine's host or user is defined in the DSH settings form, editing it here
  warns instead of silently losing to the settings form's precedence.
- No endpoint returns a password. Tests assert this for the state call and the
  save response.
## 0.4.0 — 2026-10-28

### Changed
- Passwords are stored DPAPI encrypted, never as readable text. The credential
  file holds ciphertext bound to the Windows account that wrote it: another
  machine, or another user on this one, decrypts nothing.
- A plaintext password in the settings form or the credential file is refused by
  default, with an explanation rather than a silent failure. The refusal falls
  through to the next source, so a machine that also has a usable key keeps
  working. `allowPlaintextPassword: true` opts back in.
- `scripts/set-password.mjs` encrypts by default. `--plaintext` still writes a
  readable value for the rare case that needs one, and says so.

### Added
- `ssh_credentials` reports the encryption state and warns when a readable
  password is being ignored; `ssh_doctor` reports the same as `[warn]`.

### Notes
- DPAPI is a Windows feature. On other platforms use an environment variable (in
  memory only) or an SSH agent.
- Verified that DPAPI's HMAC rejects a modified payload instead of decrypting to
  a wrong password; a change outside the protected region cannot alter the
  secret either.
## 0.3.0 — 2026-10-28

### Added
- `machines` config: define hosts in the DSH settings form instead of
  environment variables. DSH renders the schema as a form, so host, port, user,
  key path and host-key policy are editable without touching the environment.
- `<DSH_HOME>/dsh-ssh-safe/credentials.json`, read on every connection. A rotated
  password takes effect on the next command with no restart — which is the whole
  point, since passwords are what change most often.
- `ssh_credentials`: reports which source supplies each machine's password or
  key. Never prints the value.
- `scripts/set-password.mjs`: prompts for a password without echoing it and
  writes the credential file with an owner-only ACL. A Node script rather than
  PowerShell because this machine's execution policy rejects unsigned scripts.
- `ssh_machines` now lists machines from all three sources and shows which one
  supplied each field.

### Fixed
- The global `hostKeyPolicy` setting was unreachable: `machineFromEnv` defaulted
  to `'strict'`, and `effectivePolicy(global, machine)` lets the machine win when
  it holds a valid value, so the machine default always overrode the global
  setting. An unset per-machine policy is now empty and the global one applies.
- A test asserted the old behaviour (`'strict' is the default policy`), so the
  bug was encoded in the suite. It now asserts the fallback.
## 0.2.0 — 2026-10-28

### Fixed
- `ssh_config` now lists every setting, including `pipeToShell` and
  `healthCheckTimeoutMs`, and warns if a setting is ever omitted again.
- A pipeline refusal names `pipeToShell` rather than `denyPatterns`, which
  cannot affect it.
- The audit renderer shows `error`, `path`, `bytes`, `entries`, `truncated`,
  `redacted` and `ms`; a failed operation previously showed only "error".
- `ssh_doctor` verifies a key file exists, is non-empty and looks like a key,
  and that an agent socket exists, instead of reporting ok for a declared kind.
- Relative paths containing `..` are refused: the remote base directory is not
  knowable, so the path would resolve somewhere unpredictable.
- README documents the three settings it was missing.

### Added
- `test/tools.test.js`: drives all eleven registered tools through a fake ctx and
  asserts on their output. The defects above all lived where no test looked.
- `test/sftp.test.js`: 15 tests for the transfer module, including the error and
  deadline branches that had never executed.

### Fixed (this release)
- `apply()` validated nothing: it spread the defaults and overwrote them with the
  user's config, so the enum schemas only ran when the host called `Config()`
  itself. An invalid value now fails the load and names the setting.
- Tool arguments were documented in `parameters` but never checked. A shared set
  of validators rejects wrong types and negative numbers before any network work,
  instead of surfacing them as ECONNREFUSED or hiding them behind the cooldown.
- `ssh_write` silently wrote the string "null" when content was null.
- One sftp error path skipped redaction while the other three applied it.
- SPDX headers on every source file; compatibility requirements and known
  limitations documented in both README halves, not just the Chinese one.
- `package.json` now declares `engines.node` (`>=20`), so the Node floor the
  README states is enforced by npm instead of being prose only.

## 0.1.0

- `ssh_machines`, `ssh_connect`, `ssh_exec`, `ssh_read`, `ssh_write`,
  `ssh_list`, `ssh_close` as a parallel tool set; local fs/shell untouched.
- Credentials from `DSH_SSH_<ALIAS>_*` environment variables by default.
- Host-key pinning with `strict` / `tofu` / `off`, stored 0600.
- Bounded output and files, deadlines on every network wait.
- LRU cap on live connections, in-flight aware shutdown.
- Command guard that normalises before matching and inspects shell wrappers.
- Diagnostics (`ssh_doctor`), auditing (`ssh_audit`), config inspection
  (`ssh_config`), SSH agent support, timing-safe fingerprint comparison.