# Plan: Agent Mail Operations

## Status

- Status: Complete
- Feature: `006-agent-mail-operations`
- Source: `spec.md`

## Architecture

`kirje-core` owns provider-neutral draft, attachment, remote-operation, and
ledger contracts. `kirje-store` owns the private SQLite operation ledger and
its transactional migration. `kirje-protocol` owns IMAP mutation and MIME
construction. `kirje-runtime` is the only orchestration layer. CLI and MCP are
adapters over that runtime; MCP never receives an approval capability.

## Technical Decisions

1. Preserve the existing outbox path as the migration entry point. Upgrade its
   schema in place to a ledger with operation records and append-only events.
2. Keep send-specific `SendPlan` compatibility at the public boundary while
   storing it as a typed ledger operation. New remote IMAP writes use the same
   state machine and audit model.
3. Use bounded imported attachment bytes in the immutable send snapshot. Never
   persist a filesystem path as the authority for later delivery.
4. Generate deterministic reply and forward content from bounded message
   metadata/body; never ask a model or provider to author content.
5. Resolve `\\Archive` and `\\Trash` from LIST special-use attributes. An
   explicit destination is accepted only as the user-approved operation input.
6. Prefer UID MOVE when the server advertises MOVE. Otherwise use UID COPY
   followed by a UID-scoped `\\Deleted` mark, and fail closed if the required
   capability or response certainty is unavailable.
7. Safe delete never invokes EXPUNGE. The destination Trash mailbox is the
   recovery boundary; permanent deletion requires a future separately approved
   feature.
8. Treat every post-claim protocol uncertainty as `ambiguous`. No automatic
   retry path is added for any remote operation.

## State Model

Local drafts use `draft`/`discarded` records and are never remote operations.
Send and IMAP mutations use:

```text
planned -> approved -> applying -> succeeded
planned|approved -> expired
applying -> failed       (certainly no remote mutation began)
applying -> ambiguous    (the remote result may exist)
```

Terminal records are immutable. A send result is presented as `sent` for
backward compatibility; the ledger records the generic terminal event as
well.

## Migration

- Schema version 1 remains readable as the legacy `send_plans` table.
- Schema version 2 creates `operations`, `operation_events`, and the typed
  payload tables or JSON payload columns in one transaction.
- Existing rows are copied with their exact request JSON, digest, timestamps,
  state, receipt, and error; one `migrated` event is appended per row.
- The migration is idempotent, rejects versions newer than 2, and never logs
  payload contents or secrets.

## Validation Commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --locked
cargo deny check
cargo run -p kirje-cli -- schema --pretty
cargo run -p kirje-cli -- doctor --pretty
```

Controlled live verification remains opt-in and self-addressed. The result is
recorded as a sanitized success or credential-store/environment blocker.

## Constitution Check

- Local-first and no GUI: satisfied.
- CLI/MCP shared services: required by T022/T023.
- Untrusted input and secret isolation: required by T019/T021/T022.
- Human approval for send/destructive writes: required by T020/T022/T023.
- Protocol adapters behind core contracts: required by T021.
- Test-first behavior and reproducible evidence: required by every task.
