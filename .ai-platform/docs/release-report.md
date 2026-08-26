# Release Report

## Metadata

- Status: Complete
- Product: Kirje
- Contract: `2026-08-26.3`
- Updated: 2026-08-26

## Product State

Kirje is a local-first email CLI and MCP runtime for agents. Its remote mailbox
surface is read-only. The current release supports provider discovery, secure
account configuration, mailbox diagnostics, message search and sanitized read,
explicit bounded SQLite synchronization, credential-free offline envelope
search, bounded attachment reads, and a validated embedded provider registry
with CLI inspection.

## Verification

- Workspace formatting and Clippy with warnings denied pass.
- 57 automated tests and the complete workspace build pass.
- Cargo deny reports advisories, bans, licenses, and sources as acceptable.
- MCP Inspector reports ten tools with accurate local-write and remote-read
  annotations.
- Manual CLI validation confirms contract `2026-08-26.3`, 13 provider profiles,
  secure 163 defaults, the corrected iCloud SMTP submission endpoint, offline
  empty-state behavior, and Unix index mode `0600`.

Credentialed provider smoke remains opt-in because public CI contains no mailbox
secrets. The available 163 check stopped before network access because the local
macOS login keychain was unavailable. Kirje refused an unsafe credential
fallback, and cleanup verified that neither a keychain entry nor temporary
configuration/index files remained. Live NetEase authentication and mailbox
compatibility therefore remain unverified.
