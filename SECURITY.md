# Security policy

## Reporting a vulnerability

Open a [private security advisory](https://github.com/ljk00000/dsh-ssh-safe/security/advisories/new)
or email the maintainer. Please do not file a public issue for anything that
could expose a credential, a host, or a file on someone's server.

Include the version, the platform, and the smallest reproduction you can.

## What this plugin handles

`dsh-ssh-safe` opens SSH connections using credentials you supply through
environment variables. That means it touches two classes of sensitive data:

1. **Credentials** — passwords, private keys, key passphrases.
2. **Host identity** — host names, ports, and server public-key fingerprints.

## Design commitments

These are enforced by the code and pinned by tests; a change to any of them is
a security regression, not a feature:

- **No telemetry.** The package contains no HTTP client. `grep -r 'fetch(' src/`
  matches a comment and nothing else. Nothing is reported anywhere.
- **No auto-update.** The plugin never fetches a version and never rewrites
  itself.
- **No host patching.** `cordis.patch.yml` inserts this plugin and nothing
  else. It does not disable the file or shell sandbox and does not modify
  DeepSeek Harness sources.
- **Credentials are not persisted.** They come from environment variables at
  call time. Passing a password through a tool argument requires an explicit
  `allowSessionPassword: true`, and even then it lives only for the call.
- **A changed host key is fatal.** Host verification never heals itself: if a
  server's key differs from the recorded one, the connection fails with an
  explanation. `trustHostKey` accepts a *first* contact only.
- **Secrets are redacted.** Every tool result passes through `redact()`, and
  `ssh_read` masks secrets unless the caller passes `raw: true`.

## What this plugin is not

The command guard (`denyPatterns`) is a safety rail against catastrophic typos,
not a security boundary. A shell is Turing-complete: anything permitted to run
arbitrary commands can reach anything eventually. Real isolation belongs in the
remote account's permissions, not in string matching.

## Supported versions

The latest published minor receives security fixes.
