# Requirements Checklist: Agent Mail Operations

## Contract Quality

- [x] Draft privacy and remote composition boundaries are explicit.
- [x] Reply, reply-all, and forward recipient derivation is deterministic.
- [x] Multipart body and attachment size/count bounds are measurable.
- [x] Attachment summaries do not introduce an embedded or remote summarizer.
- [x] Every remote mutation has an immutable payload and an approval boundary.
- [x] Safe delete cannot perform permanent EXPUNGE or affect unrelated UIDs.
- [x] Archive and trash folder resolution never guesses localized mailbox names.
- [x] UIDVALIDITY, capability, provider failure, and stale-claim behavior are
  covered by requirements.
- [x] Ledger migration, append-only audit history, and newer-schema rejection
  are explicit.
- [x] CLI/MCP parity and MCP approval/secret exclusion are testable.
- [x] Secret, mailbox-content, file-import, and stdout boundaries are explicit.
- [x] Full automated gates and a conditional controlled live test are named.

## Edge And Recovery Review

- [x] Empty body, duplicate recipients, missing Reply-To, and oversized input
  have defined outcomes.
- [x] Missing or ambiguous special-use folders fail before remote mutation.
- [x] Repeated apply, concurrent apply, expired approval, and UID reuse are
  rejected or made visible without retry.
- [x] A crash after an operation claim becomes `ambiguous` conservatively.
- [x] Existing v0.1 send plans remain readable after migration.

## Baseline Decision

The v0.3 implementation uses safe delete as a move to server-declared
`\\Trash` or an explicit destination. Permanent deletion is outside this
release.
