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
- 91 automated tests cover composition, IMAP mutation command generation,
  attachment bounds, ledger migration/recovery, draft and operation commands,
  MCP stdio, redirected approval rejection, and Coremail authentication/session
  compatibility.
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
`scripts/live-operations-smoke.sh` and restores the initial star state.

The dedicated 163/Coremail check on 2026-08-27 authenticated through the OS
keyring over verified TLS. Read-only verification listed 9 mailboxes, sampled 1
remote envelope, synchronized 10 bounded envelopes, found 1 local result, and
completed a bounded body read. The governed self-addressed send reached `sent`
with a positive SMTP acceptance receipt; recipient-INBOX visibility remained
false during the bounded polling window and is not treated as equivalent to
SMTP acceptance. The governed star operation and its separately approved
restoration both reached `succeeded`, with the original flag state restored.
The evidence contains no address, UID, subject, credential, or mailbox content.

The keyring backend-detection field in `doctor` is explicitly advisory;
`secret set` and `account status` are the authoritative operation checks. No
live script may fall back to an argument, environment variable, pipe, or
plaintext credential.
