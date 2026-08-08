# vault

`vault` stores secrets in the macOS login Keychain and injects them into
commands without invoking a shell.

```text
vault set   NAME
vault isset NAME
vault get   NAME
vault rm    NAME
vault ls
vault purge
vault NAME OTHER_NAME LOG_LEVEL=debug -- command arg...
```

Generic-password items use service `dev.joshuarli.vault`, with the environment
variable name as the account. New items use the legacy Keychain add API so a
rebuild does not lock the current binary out of its own secrets.

## Build

This package requires macOS 26 and Swift 6.3. The package enables Swift 6
language mode, `NonisolatedNonsendingByDefault`, and strict memory safety.

```bash
swift test
swift build -c release --arch arm64
```

The release executable is built with whole-module optimization and linker
stripping (`-S` and `-x`). The implementation avoids Foundation and the Swift
Darwin overlay in the executable path to keep this exec wrapper small.
