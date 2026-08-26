# Release Report

## Metadata

- Status: Complete
- Product: Kirje
- Contract: `2026-08-27.5`
- Updated: 2026-08-27

## Product State

Kirje is a local-first email CLI and MCP runtime for agents. It supports secure
provider discovery, bounded IMAP reads and sync, private local drafts with
deterministic reply/reply-all/forward composition, bounded attachment import
and summaries, multipart SMTP sending, and governed IMAP flag, move, archive,
and safe-delete operations. A private versioned operation ledger unifies draft,
send, and mailbox operation records with migration, audit events, at-most-once
claims, crash recovery, and terminal `ambiguous` states.

## Verification

- Workspace formatting, Clippy with warnings denied, locked tests, locked build,
  and Cargo deny pass.
- 90 automated tests cover composition, IMAP mutation command generation,
  attachment bounds, ledger migration/recovery, draft and operation commands,
  MCP stdio, and redirected approval rejection.
- MCP stdio contract tests report the task-level draft and operation tools with
  plan/status/apply and no approval or credential operation.
- Manual CLI validation confirms contract `2026-08-27.5`, secure provider SMTP
  defaults, bounded local drafts and attachments, operation metadata, and TTY
  rejection for redirected approval.
- SQLite tests prove private files, migration, immutable payloads, audit events,
  expiry, concurrent claim exclusion, successful receipts, and terminal
  ambiguous outcomes.

## Live Provider Result

Live verification is opt-in and uses dedicated self-addressed test data. The
read-only smoke path is `scripts/live-imap-smoke.sh`; governed SMTP is
`scripts/live-send-smoke.sh`; governed IMAP flag verification is
`scripts/live-operations-smoke.sh` and restores the initial star state. This
environment has no configured dedicated test account or OS-stored credential,
so authenticated IMAP, SMTP, and IMAP mutation smoke checks remain an explicit
environment blocker. No live script was allowed to fall back to an argument,
environment variable, pipe, or plaintext credential.

The keyring backend-detection field in `doctor` is explicitly advisory;
`secret set` and `account status` are the authoritative operation checks.
