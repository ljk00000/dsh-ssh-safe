# Changelog

## 0.1.0

First release.

- `ssh_machines`, `ssh_connect`, `ssh_exec`, `ssh_read`, `ssh_write`,
  `ssh_list`, `ssh_close` as a parallel tool set; local fs/shell untouched.
- Credentials from `DSH_SSH_<ALIAS>_*` environment variables by default.
- Host-key pinning with `strict` / `tofu` / `off`, stored 0600.
- Bounded output (`maxOutputChars`, shared across stdout and stderr), bounded
  files (`maxFileBytes`), and deadlines on every network wait.
- LRU cap on live connections (`maxConnections`).
- Command guard that normalises before matching and inspects shell wrappers.
