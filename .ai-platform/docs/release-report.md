# Release Report

## Metadata

- Status: Complete
- Product: Kirje
- Contract: `2026-08-26.2`
- Updated: 2026-08-26

## Product State

Kirje is a local-first email CLI and MCP runtime for agents. Its remote mailbox
surface is read-only. The current release supports provider discovery, secure
account configuration, mailbox diagnostics, message search and sanitized read,
explicit bounded SQLite synchronization, credential-free offline envelope
search, and bounded attachment reads.

## Verification

- Workspace formatting and Clippy with warnings denied pass.
- 48 automated tests and the complete workspace build pass.
- Cargo deny reports advisories, bans, licenses, and sources as acceptable.
- MCP Inspector reports ten tools with accurate local-write and remote-read
  annotations.
- Manual CLI validation confirms contract `2026-08-26.2`, offline empty-state
  behavior, and Unix index mode `0600`.

Credentialed provider smoke remains opt-in because public CI contains no mailbox
secrets. The sanitized smoke script covers remote reads, a temporary sync index,
and offline search.
