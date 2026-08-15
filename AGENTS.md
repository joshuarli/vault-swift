# vault

`vault` is a macOS CLI that stores secrets in the native login Keychain and injects them into child processes. Think `env` but the values come from Keychain instead of arguments.

## Layout

```
Sources/VaultCore    — Keychain CRUD + env-spec parsing (testable logic)
Sources/vault        — CLI dispatch, terminal I/O, posix_spawn exec
Sources/CSystem      — C shims over Security.framework, spawn, and tty
Tests/VaultCoreTests — unit tests
```

The `vault` executable links only `CSystem`; it avoids Foundation and the Swift Darwin overlay to stay small. `VaultCore` exists so the logic is testable, but the executable does not use it — `main.swift` keeps a private copy of the env-spec parser and reaches the Keychain through the C shims.

## Modes

`args[1]` dispatches:

| args[1] | Mode | Example |
|---------|------|---------|
| `set`, `isset`, `get`, `rm`, `ls`, `purge` | Keychain management | `vault set OPENAI_API_KEY` |
| anything else | Exec mode | `vault OPENAI_API_KEY -- cargo run` |

No config, no daemon, no networking, no async.

## Keychain model

Generic-password items in the login Keychain:

- **Service:** `dev.joshuarli.vault`
- **Account:** the environment variable name
- **Password:** the secret value

New items use the modern item API, so macOS applies its normal application-scoped access policy; an ad-hoc-signed rebuild can require reauthorization. `make install` code-signs with a stable self-signed identity to avoid that.

## Exec mode

`--` separates env specs from the command. A spec with exactly one `=`, non-empty name, is a literal `NAME=VALUE`; anything else is a Keychain lookup. `posix_spawnp` runs the command directly — no shell, stdio inherited. Exit code is the child's; signal deaths become 128+signal.

## Terminal input

`vault set` disables echo via `tcsetattr` (ECHO/ECHONL/ICANON off) and reads a byte at a time; non-TTY stdin is read wholesale. The terminal is restored on the way out (`defer`), even on read failure. Output goes through raw `write`, never `print`.

## Build

- `swift test` — unit tests (Swift Testing)
- `swift build -c release` — optimized build
- `make install` — build, code-sign with the `Vault Signing` identity, install to `~/usr/bin/vault`

Requires macOS 26 / Swift 6.3. Package.swift enforces Swift 6 language mode, `NonisolatedNonsendingByDefault`, and strict memory safety; release builds use whole-module optimization and linker stripping.

## Style

- No banner comments; keep comments that explain *why*.
- Match the surrounding error pattern: `fail(...)` then `exit(1)`.
- Secrets never logged, debug-printed, or written to disk.
- macOS only. Linux/Windows are non-goals.
