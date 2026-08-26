# Spec: Agent-First Bootstrap

## Metadata

- Feature ID: `001-agent-first-bootstrap`
- Status: Confirmed
- Updated: 2026-08-26

## Requirements

- R1: The repository builds one `kirje` binary from a Rust workspace.
- R2: `kirje schema` reports the installed machine contract as JSON.
- R3: `kirje doctor` reports current runtime and write-tool status.
- R4: `kirje account discover <email>` validates input and returns explicit
  matched or unmatched provider discovery without credentials.
- R5: NetEase 163/126 and QQ/Foxmail discovery is covered by tests.
- R6: `kirje mcp serve` runs a typed stdio server using the official Rust SDK.
- R7: MCP exposes only read-only bootstrap tools backed by `kirje-core`.
- R8: An Agent Skill and agent guide describe only implemented operations.
- R9: CI enforces formatting, Clippy, tests, and locked builds.
- R10: Documentation identifies email as untrusted input and defines the future
  plan/approve/apply write boundary.

## Non-Requirements

- Live mailbox authentication or synchronization.
- Message read, search, draft, send, move, or delete operations.
- A graphical interface.
