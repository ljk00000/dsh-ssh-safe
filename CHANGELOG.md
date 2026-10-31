# Changelog

## 0.7.61 — 2026-10-31

### Fixed
- **A file path ending in "/" overwrote the file instead of being refused.**
  `ssh_write { path: "/etc/passwd/", content: "x" }` replaced the file and reported
  success: the normaliser dropped the trailing slash, so the server never saw the
  form POSIX reserves for a directory (a real sshd answers ENOTDIR). Reading had
  the same shape. File operations now refuse it:
  `path ends with "/" — that names a directory, not a file (received: /etc/passwd/).
  If you meant the file, drop the trailing slash to use /etc/passwd; if you meant
  the directory, use ssh_list.` `ssh_list` still accepts the spelling.

### Verified, no change needed
- The other odd paths already say the right thing: `~` (SFTP does not expand it),
  `C:\Users\...` and `relative/path` (must be absolute), empty (required),
  and a directory handed to a file operation (`not a file: /tmp (it is a
  directory; use ssh_list)`).

### Added — tests
- The normaliser's file mode, and a write that must leave the target untouched.

## 0.7.60 — 2026-10-31

### Fixed
- **A cancelled write claimed damage that did not exist, or hid damage that did.**
  Every cancel said `the file may be truncated or partially written`, including one
  that had not opened the file yet -- the caller went looking for a damaged file
  that was never touched. The message is composed at abort time now and matches
  what actually happened:
  - nothing opened: `the file was not touched`;
  - opened, nothing sent: `the file was opened (which truncates it) but no data
    was sent, so its previous content is gone` (measured: a 16-byte file became
    0 bytes -- the old wording did not say the content was already lost);
  - some bytes sent: `sent N bytes before it stopped; the file is partial`.
  The deadline message for a stalled write uses the same phrasing.
- The abort message was built when the listener was registered, i.e. before the
  stream existed, so it could never report the real state.

### Note
- The "some bytes sent" branch could not be reproduced in the test rig: the VFS
  stalls all writes or none, so a cancel lands either before the first chunk or
  after the last. The wording is shared with the deadline path, which is covered.

### Added — tests
- A cancel before the file is opened leaves nothing behind and says so.

## 0.7.59 — 2026-10-31

### Fixed
- **Two writes to the same remote file interleaved into a file that was neither
  content, and both reported success.** Measured: 300 kB of A written at the same
  time as 1 kB of B left a 300 kB file that began with B. SFTP has no locking and
  the two streams shared chunk offsets. Writes to one target are queued now, so
  the later one waits and the file is exactly one of the two contents. Writes to
  different files still run in parallel.

### Added — tests
- The 300 kB / 1 kB race, asserting the result equals one of the two inputs, and
  a check that different targets are not serialized against each other.

## 0.7.58 — 2026-10-31

### Fixed
- **"Output truncated" did not say how much was lost, or what to do.** The note was
  `[output truncated at maxOutputChars]`; the budget now counts what it discarded:
  `[output truncated at maxOutputChars: 3987 more characters were dropped — raise
  maxOutputChars, or send the output to a file and read it with ssh_read]`.
- **A truncated read said where it stopped but not that the file was larger.** It
  read `[truncated at 1024 bytes]`, which is also what a file of exactly 1024
  bytes would look like. Now: `[truncated: the first 1024 bytes of a larger file —
  raise maxFileBytes in the plugin config to read more]`. `maxBytes` can only
  tighten the ceiling, so pointing at `maxFileBytes` is the advice that works.
- **A refused oversized write gave no way forward.** `Refusing to write 3000 bytes
  (maxFileBytes = 1024)` now adds: raise `maxFileBytes`, or split the content
  across several writes — a partial write would leave a broken file behind.

### Verified, no change needed
- `ssh_list` already reports `… 3 more entries not shown (maxListEntries = 3)`.

### Added — tests
- The dropped-character count and the remedy, and the read header's "larger file"
  wording; the prefix-only assertion now counts the returned bytes instead of
  measuring the whole message.

## 0.7.57 — 2026-10-31

### Fixed
- **A port that answers with something other than SSH was reported as
  `Connection lost before handshake`.** That is what ssh2 says when the peer is
  an HTTP or proxy service -- the classic wrong-port mistake (80 or 443 instead of
  22). It now carries the reason: `the port answered but not with SSH — check the
  port number; an HTTP or proxy service answers like this`.

### Verified, no change needed
- The health check that started working in 0.7.56 does not churn: 20 idle/probe
  cycles on a real connection, zero reconnects, 1.1 ms per connect-with-probe.
  A probe timeout below the schema's 100 ms minimum can only be produced by
  constructing the pool by hand, not through the config.
- The published package contains every file the plugin needs (24 entries), packs,
  installs from the tarball with `npm install`, and loads with `apply`,
  `Config` and the shipped defaults intact.
- A server that accepts and immediately closes is explained (`ECONNRESET ...
  the port may not be sshd`) and the retry is held by the cooldown rather than
  retried in a loop.

### Added — tests
- The non-SSH-port hint, next to the ECONNRESET one.

## 0.7.56 — 2026-10-31

### Fixed
- **The idle health check never ran.** `entry(alias)` set `lastUsedAt = Date.now()`
  on every access, and `connect()` asks `entry()` for the slot before reading
  that clock: the idle time was 0 on every call, so `healthCheckIdleMs` never
  fired. A connection dropped by a NAT timeout or a firewall stayed in the pool
  and the user found out when a command hit the 30 s timeout -- the exact failure
  the probe was added to prevent (its comment says so). `lastUsedAt` is now set
  when an operation is handed a connection, not when the slot is read.
- **A probe could close a connection that was carrying work.** If the probe
  failed for an unrelated reason (the server at its `MaxSessions` limit, or slow
  to open a channel), the forced close took the running command with it -- the
  same mistake the eviction ceiling made in 0.7.55. A busy alias is not probed
  now; a dead connection announces itself to the operation using it.
- **Every probe left a pending timer** for up to `healthCheckTimeoutMs`
  (`Promise.race` does not clear the loser), which kept the event loop alive
  after the answer was known.

### Note
- The existing test for the probe passed vacuously: reusing a connection looks
  the same whether or not it was probed. The new tests count the probe's
  `exec` calls instead.

### Added — tests
- Reading a pool slot does not mark it used, and the probe really runs before a
  connection is reused.

## 0.7.55 — 2026-10-31

### Changed
- **The connection ceiling no longer aborts a command that is running.** With
  `maxConnections` reached, touching one more machine closed the oldest
  connection -- even a busy one. Measured: `sleep 2; echo done` on machine A came
  back as `[connection closed before the command reported an exit status]`
  because machine B was used meanwhile. Eviction now closes idle connections
  only; a busy one is left alone and the ceiling is enforced on the next acquire,
  when it is idle. The overflow is bounded by how many operations run at once and
  `ssh_config` says so out loud:
  `Live connections: 2 / 1 max  (over the limit: the extra ones are running a command)`.

  This reverses a deliberate earlier decision ("a ceiling, not a preference"):
  that fix was itself a fix for eviction that did nothing while reporting
  success. The result is the same accounting -- what is closed is what is
  reported -- without killing work the user asked for.

### Added — tests
- A busy connection is not evicted and the overflow is reported; an idle one is
  still evicted next to it; the ceiling is enforced once the busy one drains.
- The two "output is incomplete when the connection dies" tests now close the
  connection explicitly instead of relying on eviction to kill it.

## 0.7.54 — 2026-10-31

### Fixed
- **`recent(-5)` returned everything but the five oldest records.**
  `Array.prototype.slice(-(-5))` is `slice(5)`. `ssh_audit` clamps its argument,
  so no user saw this, but the log must not depend on its caller remembering to.
  A non-finite limit falls back to the default and a negative one to 1.
- **A command truncated at the character limit could end on half an emoji.** The
  audit record is NDJSON and a lone surrogate renders as a replacement character
  in the column people scan; the cut now steps back one code unit.

### Verified, no change needed
- Rotation under four concurrent writer processes: 1600 records, no torn line, no
  unparsable record, four generations plus the live file.
- A full 20 MB log (4 MB live + four generations, the enforced cap) is read in
  39 ms for either 20 or 200 records, so `ssh_audit` does not need a streaming
  reader.

### Added — tests
- The non-positive limits and the surrogate-safe truncation.

## 0.7.53 — 2026-10-31

### Fixed
- **A typo in `denyPatterns` turned that rule off without saying so.**
  `checkCommand` skips a pattern it cannot compile -- right for one call, wrong
  for a configuration: `"dd if=.*("` stayed visible in the settings while never
  matching anything, so the protection the user believed in was not there. The
  plugin now refuses to load and names the entry:
  `denyPatterns[1] is not a valid regular expression (Unterminated group): dd if=.*(`.
  This matches how the plugin already treats an unknown setting that looks like a
  typo.

### Added — tests
- An invalid pattern refuses to load, with the index and the pattern in the
  message; a valid custom pattern still loads.

## 0.7.52 — 2026-10-31

### Fixed
- **A refusal pasted the regular expression at the user.** `ssh_exec` said
  `Command refused: (?:^|[\s;&|()`])rm\s+-[rf]{1,2}\s+/+(?:\*|\.{1,2})?...` --
  something matched, but not something a person can act on. Each shipped rule has
  a name now: `Command refused: it deletes the filesystem root (rm -rf / and its
  spellings //, /*, /., /..). Adjust denyPatterns in the plugin config if this is
  intentional.` A rule added by the user has no name here and is quoted instead.
- **The rule list lived in two places.** The patterns were in the Config default
  and the names would have been in guard.js, so renaming a rule or reordering the
  list could silently attach the wrong description. `DEFAULT_DENY_RULES` is the
  single definition, and the name is looked up by pattern -- the first cut looked
  it up by position, which shifted every label when a user rule was added in
  front of the defaults.

### Verified, no change needed
- Audit kinds correlate one-to-one with events: twelve calls (connect ok and
  failed, exec ok / non-zero / refused, read ok and missing, write ok and bad
  parent, list ok and missing, exec against an unreachable host) produced exactly
  twelve records with the right `kind` and `outcome`.

### Added — tests
- The refusal names the rule and never shows a regex; a pipeline refusal keeps its
  own wording.
- A user rule is quoted, and adding one before the defaults does not relabel them.

## 0.7.51 — 2026-10-31

### Fixed
- **`ssh_workspace` told the user to run a command that cannot work.** In a
  profile with no workspace service (headless, tui) the listing said
  `有占位目录，但未注册（用 action: "create" 注册）` -- while `create` itself says
  `当前 profile 没有 workspace 服务：目录已就绪`. The line now reports the
  service being absent instead of promising a registration that is impossible:
  `有占位目录（当前 profile 没有 workspace 服务，无法注册到侧栏）`.

### Verified, no change needed
- `ssh_close` distinguishes the three answers correctly: no connections at all,
  a machine with none, and one that was live (`Closed: t`, then
  `No live connection for t`).
- `ssh_workspace create` reports create vs refresh, and its registration failure
  is reported rather than swallowed.

### Added — tests
- The listing without a workspace service must not mention registering.

## 0.7.50 — 2026-10-31

### Fixed
- **A gated `ssh_read` told the caller to confirm a write.** Reads are gated
  under `execGuard: "confirm"` too -- a read can copy a private key or a config
  file off the host -- but the refusal was the write message:
  `pass confirm: true to write to the remote host. Writes can install scripts or
  change access`. It now says `to read from the remote host` and gives the
  reason that applies. The tool description mentions the gate as well.

### Verified, no change needed
- Every command class the guard's header and the README list was executed
  against the shipped patterns: 45 cases, no mismatch -- including
  `sudo -u root rm -rf /`, `env FOO=1 bash -c "rm -rf /"`, `sudo bash -c`,
  `nice`/`nohup`/`timeout`/`command`/`exec`/`doas` prefixes, the `//` `/*` `/.`
  `/..` spellings, and the near misses that must keep working
  (`cd /tmp && rm -rf *`, `rm -rf /var/log/myapp`, `grep -c shutdown syslog`).

### Added — tests
- The read gate says read and not write; `ssh_list` stays ungated.

## 0.7.49 — 2026-10-31

### Fixed
- **`R=rm; $R -rf /` was allowed.** The module header has listed that exact
  shape since the first version as one of the paths this closes, but nothing ever
  resolved the variable — the string contains no `rm` after a boundary. Leading
  `NAME=value` assignments on the same command line are substituted before
  matching now (so `R=rm; F=-rf; $R $F /` is refused too), and an unknown
  variable is left alone.
- **A backtick substitution hid the command.** `\`rm -rf /\`` was allowed while
  `$(rm -rf /)` was refused: the boundary set had `(` but not a backtick.
- **`rm -rf ~/*` was allowed** while `rm -rf ~` was refused — the same deletion
  of the home directory. `~/.*` (the dotfiles) is covered too; `~/build` and
  `~/.cache` still work.

### Note
- Still outside the rail by design (no pattern matches them): `chmod -R 777 /`,
  `mv /* /tmp/`, `kill -9 -1`, and deletions of a single top-level directory
  such as `/home` or `/etc`. The README calls the list a starting point; adding
  these is a matter of appending to `denyPatterns`.

### Added — tests
- The three shapes above plus `$HOME/*` and the two-variable form.
- The near misses that must keep working: `~/build`, `~/.cache`, `/tmp/build`,
  and an unassigned variable.

## 0.7.48 — 2026-10-31

### Fixed
- **Searching for a dangerous string was refused.** `grep 'rm -rf /' notes.md`,
  `git commit -m "fix rm -rf / crash"` and `echo 'shutdown -h now' >> todo.txt`
  all matched the deny patterns, because the text inside the quotes was treated
  as if it were the command. A rail that blocks searching for a string is one the
  user turns off, so the cost of a false positive is higher than the cost of a
  miss here. For commands that only read or print text (`grep`, `echo`, `git`,
  `cat`, `man`, `history`, ...) quoted spans are blanked before matching; the
  unquoted part is still checked, so `grep x && rm -rf /` is refused.
- **A pipeline inside quotes was a false positive too**: `grep 'a | bash' f` read
  as a pipe into an interpreter.

### Safety, kept
- Quoting the dangerous part does not launder anything: `rm -rf "/"`,
  `sh -c "rm -rf /"`, `sudo sh -c '...'`, `xargs sh -c '...'`,
  `find -exec sh -c '...'`, `echo "..." | bash` and `cd / && rm -rf *` are all
  still refused. Interpreters (`python3 -c`, `awk`, `ssh`, `docker`, editors)
  keep the old behaviour -- their quoted argument is code, not data.

### Added — tests
- Nine quoted-target forms that must still be refused.
- Five text-only mentions that must be allowed, plus the unquoted-part check.

## 0.7.47 — 2026-10-31

### Added — tests
- **The README's settings table is now checked against the code.** All 23
  documented defaults were correct when this test was written, which is exactly
  why nothing would have noticed the day one of them changed: someone tunes
  `maxFileBytes` to 2 MB because the README said 1 MB, and the README is the
  stale half. Proven by changing the Config default to 2097152 and watching the
  test fail with `README says maxFileBytes = 1048576, the code says 2097152`.
- Every registered tool is named in the README, and the README names no tool that
  does not exist.

### Verified, no change needed
- The three README rows that differ from `ssh_config` are display forms, not
  wrong values: `defaultMachine` `''` vs `(none)`, `machines` `{}` vs
  `0 defined`, `denyPatterns` `9 条` vs `9 pattern(s)`.

## 0.7.46 — 2026-10-31

### Fixed
- **The documented credential precedence was missing three sources.**
  `ssh_credentials` said `encrypted file > environment > SSH agent`, and the
  README said `settings form > credential file > environment > SSH agent`. The
  code uses seven steps -- settings password, encrypted file, plaintext file,
  environment, key file, session password, agent -- so a user checking why a key
  was not used had nothing to check against. Both now list all of them, and both
  say the surprising part out loud: **any usable password outranks a key**.
- **The header had a blank line in it** when the credential file was enabled
  (an empty array entry joined the block).

### Added — tests
- The three precedence steps that a user can hit: a settings password beats a
  key, an environment password beats a key, and without a password the key is
  used.
- The `ssh_credentials` header mentions all seven sources and the password-beats-key
  rule.

## 0.7.45 — 2026-10-31

### Fixed
- **`ssh_doctor` still named the port under `machineInventory: alias`.**
  `ssh_machines` promises "host, port and key paths are hidden", but the
  reachability stage printed `port 2299 accepts connections` /
  `no answer on port 2299`. It says `the configured port` now.

### Verified, no change needed
- Host and port sweeps over twelve surfaces on the failure path (unreachable
  host) and ten on the success path (real connection): no leak in either,
  including the audit file.

### Added — tests
- The port must not appear in the alias-mode outputs (the sweep that found it).
- The doctor's probe line under `alias`.

## 0.7.44 — 2026-10-31

### Fixed
- **`machineInventory: alias` leaked the address in every failure message.**
  The success paths were masked in 0.7.32, but a failed connection said
  `Could not connect to root@10.9.8.7:22: ...` -- and that sentence was written
  to the audit log too. A sweep of twelve tool surfaces found six leaks
  (`ssh_connect`, `ssh_exec`, `ssh_read`, `ssh_write`, `ssh_list`, `ssh_audit`).
  They now read `Could not connect to machine "box" (address hidden): ...`, and
  the address inside the socket error itself (`connect ECONNREFUSED
  127.0.0.1:1`) is replaced too.

### Added — tests
- The masked and unmasked `connectFailure` shapes.
- A live failure under `alias`: no address anywhere in the message.

## 0.7.43 — 2026-10-31

### Fixed
- **An unusable private key did not name the file.** `readFileSync`'s
  `EISDIR: illegal operation on a directory, read` carries no path, and ssh2's
  `Cannot parse privateKey: Unsupported key format` is thrown later with nothing
  to say which file it read, so a typo'd `keyPath` produced
  `Machine "box" cannot use its credential: EISDIR ...` with no way to tell
  which machine field to fix. The key is read and parsed once, up front, and both
  failures name the machine and the file.

### Added — tests
- A key path that is a directory, and one that holds junk: each message contains
  the path.
- A canary sweep: seven tools (machines, config, credentials, doctor, connect,
  exec, audit) and the audit file on disk must not contain the configured
  password. The failure paths (no credentials, wrong password, missing key) are
  covered by the same value.

## 0.7.42 — 2026-10-31

### Fixed
- **A user name with surrounding spaces could not authenticate, and the error
  blamed the password.** Every write path trims, but a hand-edited
  `credentials.json` or a pasted environment variable can carry `"  deploy  "`,
  and the failure reads `the server rejected the credentials`. Host, user and
  key path are trimmed when they are read, so the value used is the value shown.
- **`tester@host` in the user field also blamed the password.** The
  authentication failure now adds `the user contains "@" — put only the account
  name, without the host`.

### Added — tests
- Trimming for host, user and key path from the credential file.
- The user-shape hint on an authentication failure, and none for a normal name.

## 0.7.41 — 2026-10-31

### Fixed
- **An out-of-range port from the credential file or the environment produced a
  raw socket error.** Only the settings form is schema-validated, so
  `"port": 99999` (or `-1`, `22.5`, `"abc"`) reached `net.connect` and came
  back as `Port should be >= 0 and < 65536. Received type number (99999)` -- no
  machine, no source, nothing to fix. It is now a configuration error naming all
  three: `Machine "box" cannot be used: port 99999 from the file is not an
  integer between 1 and 65535`, without starting the reconnect cooldown.
  `ssh_machines` shows the value as configured with a `BAD PORT` line (it used
  to show the silent 22 fallback) and `ssh_doctor` fails the configuration
  stage.

### Note
- The first cut of the port check turned an *unset* port into 0 (`Number('')is
  0`); an existing test caught it before release.

### Added — tests
- The configuration-error shape, twice, without a cooldown; the inventory line
  and the doctor stage for the same machine.

## 0.7.40 — 2026-10-31

### Fixed
- **0.7.39 bracketed anything with a colon.** `host: "example.com:2222"` was
  printed `u@[example.com:2222]:22`, which is not an address at all. Brackets
  are now reserved for real IPv6 literals (`net.isIPv6`); a non-IPv6 value with
  a colon is quoted instead (`u@"example.com:2222":22`).
- **A host field holding a URL, `user@host` or `host:port` only said "the host
  name did not resolve".** That is true and useless. The connection error now
  adds what the value looks like: `the host looks like a URL — use the bare host
  name and put the port in the port setting`, `the host contains "@" — the user
  name belongs in the user field`, `the host ends with a port ...`, `the host
  has leading or trailing spaces`, `the host contains a path separator`.

### Added — tests
- `formatHost` for a host:port and a URL (quoted, not bracketed).
- Four host-shape hints, and no hint for a plain host name.

## 0.7.39 — 2026-10-31

### Fixed
- **An IPv6 host was printed without brackets, which made the port
  unreadable.** `Could not connect to root@::1:2222` reads as host `::1:2222`
  with no port. Every place that names a target -- `ssh_connect`, the connection
  error decoration, `ssh_machines`, `ssh_workspace` -- now prints
  `root@[::1]:2222`, and a host that already carries brackets is not doubled.

### Added — tests
- `formatHost`: bare, already-bracketed, link-local, IPv4 and hostname forms.

## 0.7.38 — 2026-10-31

### Fixed
- **Deleting a machine the settings form defines looked like it worked.** The row
  stayed on the page after "已删除" because the entry was never in the
  credential file: the page cannot edit `cordis.patch.yml`. `/api/delete` now
  reports `removed` and explains where the machine comes from -- settings only
  ("要从这里移除请改设置"), both sources ("已删除凭据文件里的记录；...仍然可用"),
  or nothing to delete.

### Verified, no change needed
- Workspace marker round trip: host names with spaces, quotes and CJK come back
  unchanged from both the marker and `AGENTS.md`; an empty machine writes an
  empty host rather than the string `undefined`; a string port is stored as a
  number.
- Cold-start concurrency: ten simultaneous first calls open exactly one
  connection (all ten succeed), and five concurrent `ssh_connect` calls share it.

### Added — tests
- The three delete outcomes, through `/api/state` afterwards.

## 0.7.37 — 2026-10-31

### Fixed
- **`set-password --alias prod/x` stored the password under `prodx`.** The
  script was still *stripping* characters the alias rule forbids, then reporting
  "Stored for prodx" -- a password written under a name nothing ever looks up.
  It now refuses the alias, names it, and says it will not be rewritten (the GUI
  and the tools already did this; this was the last entrance using the old rule).
- **An unknown option was ignored.** `--pasword secret` (typo) was dropped and
  the run then failed with "nothing to store", pointing at the wrong thing. All
  other options are refused by name, with the accepted list.
- **`--host "   "` stored an empty host.** It printed "host" with nothing after
  it, looking like a value had been saved. Whitespace-only host, user and key
  path are skipped now.

### Note
- The first version of the option check omitted `--plaintext`; the existing
  `--plaintext` test caught it before release.

### Added — tests
- A refused alias writes nothing; an unknown option is named; both exit 2.

## 0.7.36 — 2026-10-31

### Fixed
- **The page wrote non-text values into the credential file.** `String({a:1})`
  is `"[object Object]"`, and `/api/save` stored that as the host name -- the
  plugin then dialled a machine called `[object Object]`. `host`, `user`,
  `keyPath` and `password` must be strings now (400 with the field and the
  received type).
- **A boolean port saved as port 1.** `Number(true)` is `1`, a valid port, so
  `port: true` was accepted silently. Booleans, objects and arrays are refused.

### Added — tests
- Five rejected shapes (object, array, boolean, number in a text field), nothing
  written for any of them, and a valid save still trims and coerces to the
  documented shape.

## 0.7.35 — 2026-10-31

### Fixed
- **A JSON array in `credentials.json` invented a machine named "0".** The file
  is a map from alias to entry; `typeof []` is `"object"`, so the array's
  indices became aliases and `[{"host":"9.9.9.9"}]` looked like a connectable
  machine called "0". Array roots (and array entries) are ignored now, like any
  other malformed file.
- **Pasting the settings-form shape into the credential file was reported as a
  typo.** `{"machines": {"prod": {...}}}` produced
  `machine "machines" has an unknown field "prod" (did you mean "port"?)`, which
  points at the wrong problem. It now says the file has a `machines` key and
  should be keyed by alias directly.

### Added — tests
- Both shapes, through `ssh_machines`: no phantom machine, and the nested-map
  message instead of the misspelling one.

## 0.7.34 — 2026-10-31

### Fixed
- **One `null` line in `audit.ndjson` crashed `ssh_audit`.** The reader treated
  "parses as JSON" as "is a record": `null` parses, and the renderer then read
  `r.malformed` off `null` and threw a `TypeError` -- so a hand-edited or
  half-written line took the whole history view down. Non-object lines (`null`,
  `42`, `"text"`, `[1,2]`) are reported as `[unreadable record]` now, and the
  renderer refuses to assume a record is an object.

### Added — tests
- `recent()` keeps the real record and marks all four non-object shapes
  unreadable; `ssh_audit` renders them without throwing.

## 0.7.33 — 2026-10-31

### Fixed
- **A corrupt `known_hosts.json` entry raised the interception alarm.**
  An entry that exists but holds no usable fingerprint (`"garbage"`, `{}`,
  `{"fingerprint": 12345}`) made the plugin answer
  `HOST KEY CHANGED ... recorded undefined` -- the one message that must keep
  meaning "someone may be intercepting this connection", spent on a broken file.
  It now says
  `Host key verification failed: the recorded entry for host:port in <file> has
  no usable fingerprint (string), so nothing can be verified against it` and
  tells the user to remove the entry. It still refuses to connect.

### Verified, no change needed
- 400 randomised tool calls (mixed types, nested objects, NULs, 300-character
  strings): no `TypeError`, no non-`Error` throw, no malformed result.
- The workspace registry fuzzed with `list` throwing/returning `null`/strings,
  junk items, `create` returning `null`, `delete` throwing: every call answered
  without an exception escaping.
- Credential precedence inside the file matches the settings form: a key wins
  over a stored password, and a plaintext password in the file is refused with an
  explanation.

### Added — tests
- Three corrupt entry shapes: each refuses, none claims a changed key, all point
  at the file.

## 0.7.32 — 2026-10-31

### Fixed
- **`machineInventory: alias` leaked the host from three more tools.**
  `ssh_machines` and `ssh_credentials` hid it, but `ssh_workspace` (both list
  and create), `ssh_connect` and `ssh_doctor` printed
  `user@host:port` anyway -- so the setting's promise held only until someone
  called one of those. All of them now report `<host hidden>`, through one
  shared helper so a new tool cannot quietly reintroduce the leak.

### Added — tests
- With `machineInventory: alias`: none of the four output shapes contains the
  address, and `ssh_connect` still names the machine it connected to.

## 0.7.31 — 2026-10-31

### Fixed
- **The credential page listed machines the plugin would ignore.**
  `useCredentialFile: false` was honoured by the connection path and by the
  test button, but `/api/state` still read `credentials.json`, so the page
  showed machines from a disabled file -- and the test button then explained, one
  click later, that the file is off. The list now comes from the sources the
  plugin actually reads.
- **Saving from the page said nothing when the file is disabled.** The entry was
  written to a file the plugin never opens. The save response now warns, and the
  page shows a banner above the list.

### Added — tests
- `/api/state` with the file disabled: no machine from the file, the settings
  machine still listed, `fileEnabled: false`, and the save warning.

## 0.7.30 — 2026-10-31

### Fixed
- **`useCredentialFile: false` did not hide the file's machines.** The setting
  stopped the connection path from reading `credentials.json`, but
  `ssh_machines`, `ssh_audit` and `ssh_workspace` still listed every alias in
  it -- machines that could never connect, presented as if they were
  configured. They now come only from the sources that are actually read.
- **An empty credential home read a relative path.** `loadCredentialFile('')`
  joined to `dsh-ssh-safe/credentials.json` relative to the process working
  directory, so a stray directory there would have been read as configuration.
  It now returns nothing, which is what "the file is disabled" means.

### Added — tests
- With `useCredentialFile: false`: the file's machine is not listed, the
  settings machine is, and `ssh_credentials` marks the file disabled.

## 0.7.29 — 2026-10-31

### Fixed
- **The credential file had the same silent-typo hole as the settings form.**
  `credentials.json` is free-form JSON: `"keypath"` instead of `"keyPath"`
  parsed, was ignored, and left the machine looking like it had no credential.
  Both sources are now checked, and the message names which file:
  `machine "box" in the credential file has an unknown field "keypath"`.
  The file's own fields (`passwordDpapi`, `username`) are not flagged.

### Changed
- `ssh_machines` prints one `Configuration problems:` block covering both
  sources (it used to be `Settings form problems:`).

### Added — tests
- A credential-file typo is reported against that file, and the file-only fields
  stay accepted.

## 0.7.28 — 2026-10-31

### Fixed
- **A misspelled machine field looked like a machine with no credentials.**
  schemastery drops keys it does not know, so `keypath: ~/.ssh/id_ed25519`
  parsed fine and the machine then reported "no password, key or agent
  available" -- configured on paper, unconfigured in practice.
  `ssh_doctor` now warns (`machine "box" has an unknown field "keypath" (did you
  mean "keyPath"?)`) and `ssh_machines` adds a "Settings form problems" block.
  The doctor checks the machine it was asked about; the inventory checks them
  all.

### Verified, no change needed
- Plugin unload: the effect disposer really is collected and run (cordis calls
  the returned function), sockets close, a command running at unload settles
  with `connection closed before the command reported an exit status` instead of
  hanging, and the client count reaches zero.
- 60 sequential and 20 concurrent mixed calls on one connection: every result
  carried its own output and the connection count stayed at one.

### Added — tests
- The three warning shapes: a typo with a suggestion, another machine's typo
  staying out of this machine's diagnosis, and the inventory block.

## 0.7.27 — 2026-10-31

### Fixed
- **Stopping a turn did not stop the remote work.** DSH aborts `exec.signal`
  when the user cancels, and the plugin ignored it: `ssh_exec` kept running
  until its deadline (a real side effect on the remote host) and a stalled
  transfer kept its socket busy.
  `ssh_exec` now sends SIGTERM to the channel and returns what had already
  printed, with `[cancelled at the caller request ...]` and no bogus
  `[exit unknown]`; reads, writes and listings abort their SFTP session at once
  (a cancelled write says the file may be partially written). A signal that is
  already aborted refuses before anything starts.

### Added — tests
- Cancellation of a running command (prompt, partial output, connection still
  usable afterwards) and of an already-aborted call.
- Cancellation of a stalled read, write and listing, each against a server that
  never answers; the pool still works afterwards.

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