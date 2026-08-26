# Plan: Read-Only Mailbox MVP

## Architecture

Add three internal layers while preserving the existing interface crates:

- `kirje-core`: stable public domain objects, references, limits, and errors.
- `kirje-runtime`: config, secret-store ports, account and mailbox use cases.
- `kirje-protocol`: a Pimalaya-backed IMAP adapter with no CLI/MCP knowledge.

`kirje-cli` and `kirje-mcp` depend on `kirje-runtime`. `kirje-runtime` depends on
ports expressed in `kirje-core`, while the binary composes concrete filesystem,
keyring, and IMAP implementations.

## Decisions

- Use `io-imap` and `io-sasl` directly rather than the Himalaya binary or the
  young unified `io-email` facade.
- Use implicit TLS and STARTTLS only; plaintext transport is rejected.
- Store account documents under the platform configuration directory and secret
  values in the OS credential store under service `dev.kirje.mail`.
- Use scoped references containing account, mailbox, and UID. A later indexed
  runtime will replace them with durable local IDs without exposing bare UIDs.
- Accept structured search fields rather than a free-form provider query.
- Run blocking Pimalaya clients in `spawn_blocking` from async runtime methods.

## Validation

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --locked
npx -y @modelcontextprotocol/inspector --cli ./target/debug/kirje mcp serve --method tools/list --format json
```

Live checks use dedicated provider accounts and are never required in public CI.

