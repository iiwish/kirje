# Spec: Local Sync And Attachment Access

## Metadata

- Feature ID: `003-local-sync-index`
- Status: Confirmed
- Approved direction: 2026-08-26

## Goal

An agent can explicitly synchronize bounded mailbox metadata into a local
SQLite index, query that index without mailbox credentials or network access,
and read one explicitly selected attachment through a bounded, non-mutating
operation.

## User Stories

- US1: An agent synchronizes the newest mailbox window once, then fetches only
  messages newer than the stored high-water UID on later runs.
- US2: An agent inspects sync coverage and searches indexed envelope metadata
  while offline.
- US3: An agent reads a selected attachment by a scoped message reference and
  server-returned attachment id without marking the message as seen.
- US4: An operator can inspect where the local index lives and can refresh a
  mailbox after UIDVALIDITY or provider state changes.

## Functional Requirements

- FR-001: Store indexed envelope metadata and sync cursors in a versioned local
  SQLite database; never store credentials or attachment bytes.
- FR-002: Initialize and migrate the database transactionally without deleting
  an unrecognized or newer schema.
- FR-003: A first sync imports the newest bounded window. Later syncs request
  UIDs above the stored high-water mark. Each network batch is capped at 500
  messages.
- FR-004: A UIDVALIDITY change atomically replaces the indexed mailbox scope so
  stale UIDs cannot be returned.
- FR-005: Explicit refresh discards the mailbox cursor and rebuilds its newest
  bounded window. No background process or implicit network access is allowed.
- FR-006: Sync reports expose fetched count, stored count, cursor, reset state,
  remote total, truncation/backlog state, and timestamp.
- FR-007: Local search supports bounded subject, sender, recipient, and unread
  filters with deterministic newest-first ordering and no credential lookup.
- FR-008: Local search rejects body-text queries because bodies are not indexed.
- FR-009: Attachment reads require account, mailbox, UID, optional UIDVALIDITY,
  and a server-returned `attachment-N` id.
- FR-010: Attachment output is base64, marked untrusted, capped at a caller
  limit no greater than 1 MiB, and includes truncation metadata. It is never
  written to disk or executed by Kirje.
- FR-011: Attachment reads use IMAP `BODY.PEEK`; mailbox flags are not changed.
- FR-012: CLI and MCP use the same runtime services and stable domain objects.
- FR-013: MCP exposes task-level `mailbox_sync`, `index_status`,
  `message_search_local`, and `attachment_read` tools with accurate safety
  annotations.
- FR-014: Existing remote read commands and tools retain their behavior.

## Non-Functional Requirements

- NFR-001: SQLite writes are transactional and concurrent readers use a bounded
  busy timeout.
- NFR-002: Every public list, query, sync, body, and attachment response is
  bounded before serialization.
- NFR-003: Mail content remains untrusted. Logs, errors, config, and the index
  reveal no credential values.
- NFR-004: stdout and MCP stdio remain protocol-clean.
- NFR-005: Store, sync, attachment, CLI contract, and MCP surface changes are
  developed test-first and pass the workspace quality gates.

## Edge Cases

- An empty mailbox creates a valid cursor with no high-water UID.
- A server omitting UIDVALIDITY prevents durable indexing and returns a stable
  protocol error.
- A UIDVALIDITY mismatch resets only the selected account/mailbox scope.
- A missing or malformed attachment id returns stable invalid-input or
  not-found errors without returning other MIME parts.
- A database with a newer schema version is left untouched and rejected.

## Non-Requirements

- Background daemon, IMAP IDLE, push notifications, or scheduled sync.
- Full historical backfill orchestration, thread reconstruction, body indexing,
  FTS, semantic search, or vector embeddings.
- Attachment extraction, previewing, execution, conversion, or persistence.
- Flag changes, move, archive, delete, draft, SMTP send, or JMAP operations.

## Success Criteria

1. A second sync uses the stored UID cursor and stores no duplicate rows.
2. Indexed search works with a secret store that always fails.
3. UIDVALIDITY reset removes stale rows in the same transaction as new state.
4. No attachment response can exceed 1 MiB decoded or expose raw message data.
5. All local gates and GitHub CI pass with no write-capable remote operation.
