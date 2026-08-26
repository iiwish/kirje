# Analysis: Agent Mail Operations

## Decision Summary

The v0.3 slice uses one local SQLite operation ledger for private drafts, SMTP
send plans, and governed IMAP writes. The ledger stores immutable bounded JSON
snapshots, SHA-256 payload digests, receipts, and append-only events. Legacy
send rows migrate transactionally at schema version 2.

Draft composition is local and deterministic. Reply uses Reply-To when present;
reply-all removes the configured account and de-duplicates recipients; forward
requires explicit recipients. Imported regular files are copied into a bounded
send snapshot and summarized without an embedded or remote summarizer.

IMAP mutations are capability-aware and UID-scoped. Archive and safe delete use
server-declared special-use mailboxes or an explicit destination. Safe delete
never calls `EXPUNGE`. The runtime claims approved work before credential
lookup and treats post-invocation uncertainty, including stale claims, as
`ambiguous` without automatic retry.

## Boundary Review

- CLI and MCP call the same runtime service methods.
- MCP has no approval or credential entrypoint.
- Bodies, headers, attachment bytes, summaries, and provider responses remain
  untrusted and bounded.
- Credentials remain outside JSON, ledger payloads, audit events, receipts,
  logs, arguments, and MCP messages.
- Live mutation verification is opt-in, TTY-gated, dedicated-account-only, and
  restores the initial star state.

## Residual Scope

JMAP mailbox mutation, permanent deletion, bulk operations, background sync,
automatic ambiguous-state reconciliation, and semantic summarization remain
outside v0.3.
