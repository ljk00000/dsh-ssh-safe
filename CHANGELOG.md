# Changelog

## Unreleased

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