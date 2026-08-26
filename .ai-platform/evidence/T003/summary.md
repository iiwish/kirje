# T003: Account Runtime

## Result

The runtime persists versioned non-secret TOML account configuration with an
atomic same-directory replacement and mode `0600` on Unix. Credential values
use the native OS keyring under service `dev.kirje.mail`. Account config access,
credential presence, credential mutation, and remote reads have separate ports.

Secret set/delete require an existing account. Empty and oversized credentials
are rejected. Configuration, keyring, authentication, TLS, network, protocol,
lookup, and resource-limit failures retain stable error codes without backend
diagnostics or secret values.

## Verification

- 3 runtime tests passed using temporary files and an in-memory secret store.
- Missing-account, secret-presence, deletion, ordering, and non-serialization
  behavior are covered.
