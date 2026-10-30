# Changelog

## 0.7.26 — 2026-10-31

### Fixed
- **A misspelled argument was accepted and silently ignored.** DSH compiles a
  tool's parameters into an *open* object schema, so `timeout: 500` ran with the
  configured 30 seconds, `maxByte: 5` read up to a megabyte, and
  `createDir: true` created nothing -- each looking like it had worked. Every
  tool now rejects undeclared arguments and names the near miss:
  `Unknown argument(s) for ssh_exec: "timeout" (did you mean "timeoutMs"?) ...`.

### Added — tests
- Three typo shapes: a near miss with a suggestion, another with a suggestion,
  and one with nothing close enough to suggest.

## 0.7.25 — 2026-10-31

### Fixed
- **A command too large for one SSH request failed as "Unable to exec".**
  RFC 4253 caps a transport packet at 35000 bytes; measured against the test
  server, 34900 works and 35000 does not. ssh2 refuses the request before
  sending and says nothing about the size, so a 100 KB command looked like a
  server refusal. Commands over 34000 bytes are now refused up front, before a
  connection is opened, with the size, the limit and the way out (write the
  script with `ssh_write` and run it from there).

### Fixed — tests
- The test SSH server attached no `error` listener to its client, so a
  malformed packet (the oversized command above) crashed the whole test process
  instead of ending that connection.

### Added — tests
- An oversized command is refused with the message and no connection attempt; a
  command just under the limit still runs.

## 0.7.24 — 2026-10-31

### Fixed
- **A write that never opened claimed the file was damaged.** The
  "may be truncated or partially written" note from 0.7.16 was added to every
  write error, including open failures where nothing was sent. It is now added
  only when bytes actually went out (`stream.bytesWritten > 0`).
- **`createDirs` failures suggested the wrong fix.** With `createDirs: true`
  and a path component that is a file, the answer was still "the parent
  directory does not exist. Pass createDirs: true" -- advice the caller had
  already taken. That case now says `createDirs could not create the parent
  path; is part of it a file?`.
- **An unreadable private key surfaced as a bare ENOENT.** It now reads
  `Machine "x" cannot use its credential: ENOENT: ... open '<path>'`, and -- like
  the other configuration errors -- does not start the reconnect cooldown.

### Added — tests
- Four write-error shapes: no partial-write note when nothing was written, and
  the createDirs wording.
- The unreadable-key message, twice in a row, without a cooldown.

## 0.7.23 — 2026-10-31

### Fixed
- **The page misread quoted YAML values with a trailing comment.**
  `host: "10.0.0.5"   # quoted` arrived as `10.0.0.5"   # quoted`: the leading
  quote was stripped, the trailing one and the comment were kept. The page then
  showed -- and the test button tried -- a host the plugin would never use.
  Scalars are parsed properly now: matching quotes, \"-escapes, YAML's doubled
  single quote, and `#` comments only where YAML allows them. `port: "2222"`
  is still a number.
- **The output cap could end on half of a surrogate pair.** A 200k-emoji command
  cut at an odd character count left a lone surrogate, which survives
  JSON.stringify but renders as a replacement character downstream.

### Added — tests
- Quoted values, comments, an escaped quote and a quoted port, through
  `/api/state`.
- Four caps that land mid-pair, none of which may leave a lone high surrogate.

## 0.7.22 — 2026-10-31

### Fixed
- **A configuration error armed the reconnect cooldown.** Connecting to a
  machine with no host set threw "not configured", and that also started the
  15-second retry cooldown -- so after filling in the setting, the next attempt
  answered "Refusing to retry ghost for another 15s" instead of connecting. The
  cooldown is for network failures; "missing DSH_SSH_X_HOST" and "no credentials"
  no longer start one.
- **An unknown `ssh_workspace` action blamed the machine.** `action: "nope"`
  fell through to the machine check and answered "action \"nope\" needs machine",
  sending the caller to the wrong argument. The action is validated first.

### Added — tests
- Two consecutive connects to an unconfigured machine both report "not
  configured" and never the cooldown.
- The unknown-action message.

## 0.7.21 — 2026-10-31

### Fixed — privacy
- **`machineInventory: "alias"` did not cover `ssh_credentials`.** That tool
  printed `deploy@10.1.2.3:22` for every machine, and its output goes into the
  same conversation the setting exists to keep free of topology. It now shows
  `<host hidden>` like `ssh_machines`, and still reports which credential source
  each machine uses.

### Added — tests
- The alias/full pair for `ssh_credentials`, so the two tools cannot drift apart
  again.

## 0.7.20 — 2026-10-31

### Fixed
- **Closing during a handshake closed nothing and leaked the connection.**
  `ssh_close` (or `closeAll` at unload) landing while a connect was in flight
  found no client, answered "No live connection", and the socket that completed
  a moment later stayed open for the life of the process. `closeOne` now
  reports `pending`, and a forcing close arranges for the arriving connection to
  be closed; `closeAll` attaches the same cleanup before it drops entries.
- **The caller then got a bare "Not connected".** A close or eviction between
  `connect()` and the first use surfaced ssh2's wording, which reads like a
  plugin bug. It now says which machine's connection went away, that the close
  (or eviction, or dropped channel) caused it, and that the operation did not
  complete.

### Added — tests
- Forced close during a handshake: `pending`, the command rejects with the new
  message, the landing socket is closed and the server sees zero clients.
- `closeAll` during a handshake: same, and the next command reconnects.
- A non-forcing close during a handshake leaves the other call's connection
  alone (that call's command still completes).

## 0.7.19 — 2026-10-31

### Fixed
- **`ssh_doctor` could sever a command it did not start.** The doctor connects,
  probes, and closes what it opened -- with `force: true`, which also closes a
  connection that a command started *while the diagnosis was running* had just
  taken over. That command came back as "connection closed before the command
  reported an exit status" with nothing pointing at the doctor. The cleanup now
  uses the non-forcing close, which refuses while an operation is in flight; the
  command that owns the connection keeps it.
  The test fails against the old code with exactly that message, which is how
  the race was confirmed rather than assumed.

### Verified
- Installing 0.7.10 into an isolated profile and then re-adding the working tree
  upgrades cleanly: one dependency, one bundles entry, the new version on disk.
  The temporary worktree was removed afterwards.

## 0.7.18 — 2026-10-31

### Fixed
- **The page rewrote aliases without saying so.** Saving `prod/x` stored
  `prodx`, and `a b` stored `ab`; a name written entirely in non-ASCII was
  refused as "empty". The page then listed a machine the caller never typed, and
  `machine: "prod/x"` answered "not configured". Aliases outside
  `[a-z0-9._-]` are now refused with the offending input named, which is what
  `set-password` already did. `Prod ` still normalises to `prod`.

### Docs
- The alias character set, and the fact that letters become upper case in
  environment variables (`prod.x` reads `DSH_SSH_PROD_X_HOST`).
- `allowPlaintextPassword` added to the defaults table (it was only mentioned
  in prose).

### Verified — real runtime
- `dsh plugin --profile <name> add` in an isolated home produces a profile whose
  composed config contains the plugin, and `remove` drops both the dependency
  and the bundles entry (no dangling bundle).
- The page escapes `& < > " '` in every value it interpolates, including
  `data-alias` attributes.

## 0.7.17 — 2026-10-31

### Fixed
- **A failed connection said only "read ECONNRESET".** With several machines
  configured that names neither the machine nor the likely cause, and the
  difference between "the password is wrong" and "that port is not sshd" is what
  decides the next step. Handshake failures now read
  `Could not connect to root@host:22: <reason> (<likely cause>)`, with hints for
  a refused port, a closed connection, an unresolvable name, a missing SSH
  banner, rejected credentials, and an untrusted host key.
  Errors the host key store wrote itself are left alone: they already name the
  host, the fingerprint and the way out, and ssh_doctor prints the target on the
  line above.

### Added — tests
- The four shapes above, including a port that is not sshd, a wrong password,
  a closed port and a strict-policy host key.
- A directory of ten thousand entries is cut at `maxListEntries` (2000) with
  "8000 more entries not shown", in well under the deadline.
- Filenames containing a newline, a tab, a bell or 300 characters cannot forge
  an extra listing row: control characters are escaped.

### Fixed — tests
- The SFTP test server answered READDIR with every entry in one packet, which
  stalls at ten thousand entries (the client never finishes parsing). It now
  chunks 32 at a time like a real server -- the large-listing path had never
  actually run before.

## 0.7.16 — 2026-10-31

### Fixed
- **A write that fails part-way now says the file is damaged.** The SFTP write
  stream truncates on open, so a timeout or a dropped channel leaves less than
  the caller asked for -- and the error only said "did not complete". It now
  ends "the file may be truncated or partially written", on both the deadline
  and the error path. (A path that turns out to be a directory still says so and
  carries no such warning: nothing was written.)

### Added — tests
- Permission denied from the server reaches the caller with the path attached,
  for `ssh_list`, `ssh_read` and `ssh_write`; the test server can now deny a
  path the way sshd does.
- Deleting the audit log -- or its whole directory -- while the plugin runs is
  recovered on the next write, and does not count as a failure.
- Disconnecting mid-command settles that command at once (with the partial-output
  warning) instead of waiting out its deadline -- at the pool and at the tool.
- Two commands on one machine overlap instead of queueing: one connection
  carries several channels.
- 300 KB of output is cut at `maxOutputChars` and the cut is announced.
- 75 ordinary commands (`rm -rf build`, `find . -name "*.tmp" -delete`,
  `systemctl status`, `cd / && du -sh *` ...) pass the default deny patterns
  unblocked: the rail must not cry wolf.

## 0.7.15 — 2026-10-31

### Fixed
- **Saving from the page could make a concurrent connection fail.** The
  credential file was rewritten in place, which truncates it first; the plugin
  reads that file on every connection, from another process, so a connection
  that landed in the window read an empty file, fell back to "no machines", and
  answered "not configured" -- while the page reported the save as successful.
  Saves now write a sibling temp file and rename it over the target.

### Added — tests
- Twenty saves leave no temporary files behind and a parseable file.

## 0.7.14 — 2026-10-31

### Fixed
- **A settings-form alias written in any case was unusable.** The alias is
  lower-cased before it reaches the settings lookup, so a machine keyed `BOX`
  or `mixedCase` was reported by `ssh_machines` as `box` with no host at all,
  and every command answered "not configured". The lookup is case-insensitive
  now (still own-property only: `constructor` and `toString` remain
  non-machines).

### Added — tests
- A settings-form machine in three spellings runs from all of them, and the
  listing shows a real host.
- `ssh_doctor` ignores a disabled credential file too.
- A command killed at its deadline keeps the stdout and stderr it had already
  printed, and does not show the tail that never arrived.
- The alias that was evicted mid-command reconnects on its next call.
- A per-machine host key policy overrides the global one in both directions,
  checked against a host that is genuinely unrecorded ('localhost' is a
  different known_hosts id from '127.0.0.1', which is what made the first
  version of this test pass for the wrong reason).

## 0.7.13 — 2026-10-31

### Fixed — security
- **`useCredentialFile: false` did not stop the plugin reading the credential
  file.** The setting was honoured by `ssh_credentials` -- the tool that reports
  where credentials come from -- and by nothing else: a connection still
  authenticated from the file, and the machine's host, port and user still came
  from it. Turning the file off is exactly what someone does when they think a
  stored password is compromised, and the plugin kept using it.
  One decision now feeds every reader: the pool (for both `describe` and the
  connect path), `ssh_doctor`, `ssh_machines`, the workspace tools, and the
  credential page's test button. The known_hosts store still uses the real home.

### Fixed — tests
- The loopback server generated an ed25519 host key per start and ssh2's own
  server parser occasionally rejected one ("Malformed OpenSSH private key"),
  which surfaced as a flaky GUI test. One RSA key is generated per process.
- That caching broke the two changed-host-key tests, because a "replacement"
  server then presented the same key. They now ask for `alternateHostKey()`,
  and the failure is what pointed at the shared key in the first place.

### Added — tests
- The credential file end to end: a password stored by the page authenticates
  the plugin; rotation takes effect on the next connection; `useCredentialFile:
  false` makes the file invisible, and the page's test button says so instead of
  reporting a connection the plugin cannot make.
- `ssh_read` masked vs `raw`, and `maxBytes` that can only tighten the ceiling;
  `ssh_write` at exactly `maxFileBytes`; 60 concurrent execs leave 60 readable
  audit lines; `dsh plugin add` into a throwaway profile produces a profile
  whose composed config contains the plugin.

## 0.7.12 — 2026-10-31

### Fixed
- **A failing workspace service took the whole answer with it.**
  `ssh_workspace { action: "list" }` threw "registry unavailable" and lost the
  machine list and its placeholder directories, none of which had anything to
  do with the registry. The listing now reports the service error as one line
  and still shows everything it can read.
- **`action: "remove"` could report "no record" for a registry it could not
  read.** "Not registered" and "cannot ask" are different answers; the second
  used to leave a stale workspace in the sidebar while saying it was gone. It
  now refuses to act and says nothing was changed.

### Added — tests
- A failing registry: listing survives, removal refuses, and `findWorkspace`
  returns null instead of throwing.

## 0.7.11 — 2026-10-31

### Added
- **`npm run test:loopback`.** `test/integration.test.js` — the four cases that
  talk to a real sshd — now also run against the in-memory SSH/SFTP server, so
  the "can this client still speak to a server" check no longer waits for a
  machine to be available. The real-host form still works:
  `DSH_SSH_TEST_TARGET=<alias> npm test`.
- That runner was written with `spawnSync` first: the server lives in the same
  process, so blocking the event loop stopped it answering the child it had just
  started, and every case timed out at the connect deadline. `spawn` with an
  awaited exit fixed it; the comment in the file says why.

### Added — tests
- The idle health probe: a live connection is reused, a connection the server
  dropped is replaced, both with the probe enabled rather than disabled.

## 0.7.10 — 2026-10-31

### Fixed
- **A refused command's audit record did not say which machine it targeted.**
  The record carried the command, the matched pattern and the reason, and the
  operator's first question — "on which box?" — had no answer. It does now.
- **`set-password --port abc` stored `null`.** JSON turns `NaN` into `null`, the
  resolver falls back to 22, and the account ends up trying a port nobody asked
  for. `70000`, `-5`, `22.5` and `0` were stored verbatim. The helper now
  refuses anything that is not an integer in 1–65535, the way the page already
  did.

### Added — tests
- `test/doctor-live.test.js`: the seven failure stages of `ssh_doctor` (missing
  host, no credential, missing key file, unreachable port, wrong password,
  unknown host key, changed host key) were only checked by grepping the source;
  they now run against the loopback server.
- The credential page reads machines out of the profile's
  `cordis.patch.yml`: covered, including an empty host and the warning that the
  settings form outranks the file.

## 0.7.9 — 2026-10-31

### Fixed
- **"Wrote 1 bytes" and "[truncated at 1 bytes]".** Writing a one-character file
  is ordinary work, and the message made the whole result look careless. One
  byte now reads "1 byte"; the audit trail's count says "1 entry" for a single
  entry too.

## 0.7.8 — 2026-10-31

### Fixed
- **A command whose channel died mid-flight looked like one that printed
  nothing.** ssh2 reports an exit status or a signal when a command ends; when
  the connection drops there is neither, and the old code turned that into
  "no output, `[exit unknown]`". The pool now marks the result `dropped` and
  `ssh_exec` prints "connection closed before the command reported an exit
  status — the output above is partial"; the audit record says `incomplete`.
  This also covers the plugin's own eviction: with `maxConnections` reached, a
  running command's connection can be closed to honour the ceiling, and the
  caller now knows why it stopped.

### Added
- `test/exec-incomplete.test.js` drives that path through the tool.
- The loopback pool test asserts the evicted call settles (never hangs) and is
  marked incomplete.

## 0.7.7 — 2026-10-31

### Fixed
- **The guard could be made to hang.** Two of the default rules have the shape
  "keyword … later-token", which costs one scan per start position: a 400 KB
  command made of `find / ` repeated took **19.5 seconds** to check. A command
  made of `sudo ` repeated never finished at all, because every token unwrapped
  one wrapper level and re-scanned the remainder — 80,000 levels of recursion.
  Patterns now run against the first and last 8 KB of a candidate, and wrapper
  unwrapping stops at four levels. Real commands are far shorter than that
  window, and a dangerous command at either end of a huge line is still caught
  (there is a test for both ends). A command long enough to hide something in
  the middle of 400 KB can also spell the same thing differently.

### Added — tests
- The guard takes under 500 ms on a megabyte of spaces, 400 KB of `find /`,
  and 400 KB of `sudo` tokens.

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