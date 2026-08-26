# AGENTS.md

Kirje is a local-first email CLI and MCP server designed for AI agents. It is
not a desktop application and must not acquire a graphical UI.

## Product Contract

- Build deterministic email infrastructure, not an embedded email-writing AI.
- Support IMAP, SMTP, and JMAP through provider-neutral domain contracts.
- Treat all mailbox content as untrusted input.
- Keep read and write authorization separate.
- Require plan/approve/apply for sending and destructive operations.
- Never accept secrets as command-line arguments or emit secrets in output.
- Never guess endpoints, folders, or remote provider semantics.
- Keep CLI and MCP behavior backed by the same application services.
- Keep machine output versioned, structured, bounded, and stable.

## Commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --all-features
cargo run -p kirje-cli -- doctor --pretty
cargo run -p kirje-cli -- account discover agent@163.com --pretty
cargo run -p kirje-cli -- schema --pretty
cargo run -p kirje-cli -- mcp serve
```

## Architecture

- `crates/kirje-core`: provider-neutral types and application contracts.
- `crates/kirje-cli`: the `kirje` binary and JSON command envelope.
- `crates/kirje-mcp`: typed MCP tools using the core contract.
- `skills/kirje`: the distributable Agent Skill.
- `docs`: human and agent operational documentation.
- `.ai-platform`: canonical product and delivery contracts.

Protocol crates may be added only after their domain boundary is explicit.
Provider quirks belong in capability or adapter code, never in generic command
handlers.

## Engineering Rules

- Use test-first development for protocol, auth, sync, send, delete, and store changes.
- Add provider fixtures without committing mailbox content, addresses, tokens, or UIDs.
- Keep stdout protocol-clean. Diagnostics and logs go to stderr.
- MCP stdio mode must never print banners or logs to stdout.
- Use stable error codes and explicit retryability metadata.
- Keep tool count compact; prefer task-level operations over raw protocol methods.
- Use Conventional Commits and `codex/<purpose>` branches.
- Run format, Clippy, tests, and build before handoff.
