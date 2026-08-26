# Plan: Local Sync And Attachment Access

## Architecture

Add `kirje-store` as a SQLite adapter behind a provider-neutral `MessageIndex`
port in `kirje-core`. Extend the existing `MailboxReader` with two read-only
remote capabilities: bounded mailbox synchronization and bounded attachment
reading. `kirje-runtime` coordinates credentials, protocol reads, and index
transactions. CLI and MCP remain thin adapters.

```text
CLI / MCP
   |
kirje-runtime
  /       \
IMAP      MessageIndex port
adapter       |
          kirje-store (SQLite)
```

## Decisions

- Use `rusqlite` with the bundled SQLite library for a predictable single-binary
  installation.
- Store JSON-encoded address and message-id arrays instead of normalizing them;
  the index is a bounded operational cache, not a general mail warehouse.
- Use `(account_id, mailbox, uid_validity, uid)` as the durable row identity.
- Initial sync imports the newest window; incremental sync starts above the
  high-water UID. Explicit refresh is the recovery path for changed flags,
  deletions, or incomplete historical coverage.
- Do not store bodies or attachment bytes in SQLite.
- Return attachment bytes as bounded base64 because CLI JSON and MCP share one
  transport-neutral response contract.

## Constitution Check

- Provider-neutral domain: satisfied through core ports and objects.
- Read/write separation: remote operations remain read-only; local index writes
  are declared accurately in CLI/MCP metadata.
- Untrusted content: preserved on indexed envelopes and attachment responses.
- Stable bounded output: sync <= 500, search <= 100, attachment <= 1 MiB.
- No secrets in arguments/output/storage: unchanged.
- Test-first high-risk work: required by every implementation packet.

## Validation

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --locked
cargo deny check
npx -y @modelcontextprotocol/inspector --cli ./target/debug/kirje mcp serve --method tools/list --format json
```

Credentialed provider smoke tests remain opt-in and absent from public CI.
