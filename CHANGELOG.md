# Changelog

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