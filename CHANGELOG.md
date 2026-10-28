# Changelog

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
- `test/tools.test.js`: drives all ten registered tools through a fake ctx and
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