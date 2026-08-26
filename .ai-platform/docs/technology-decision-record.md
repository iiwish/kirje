# Technology Decision Record

## Metadata

- Status: Confirmed
- Updated: 2026-08-26

## Decisions

### Rust Workspace

Kirje uses Rust for a portable single-binary distribution, protocol safety,
bounded resource handling, and reuse between CLI and MCP.

### CLI As Durable Contract

The CLI JSON contract is primary. MCP is a typed adapter over the same core
services. No interface may implement mailbox behavior independently.

### Official MCP SDK

Kirje uses the official `rmcp` Rust SDK and stdio transport. Stdout is reserved
for MCP protocol frames while diagnostics use stderr.

### Protocol-Neutral Core

IMAP, SMTP, JMAP, Gmail-specific, and provider-specific behavior stays behind
adapters and capability mapping. User-facing operations use stable concepts such
as message, thread, draft, plan, and account.

### No Desktop Compatibility Layer

The archived desktop repository is a source of protocol knowledge and sanitized
tests, not an architecture to preserve. React, Tauri, and desktop lifecycle code
are not migrated.
