# Spec: Agent Mail Operations

## Metadata

- Feature ID: `006-agent-mail-operations`
- Status: Implemented
- Target release: `v0.3`
- Product: Kirje

## Goal

Kirje provides agents with a private local drafting workflow and a compact,
governed set of IMAP mailbox operations. Every remote write is represented by
one immutable, auditable operation record. The CLI and MCP use the same runtime
services; only an interactive human CLI can approve a remote write.

## Users And Success Path

An agent reads a message, creates or updates a local draft, optionally imports
bounded local attachments, and asks a human to review the exact resulting send
plan. For mailbox maintenance, the agent creates a bounded operation plan. A
human approves the exact operation in a TTY, after which the agent may apply it
once and inspect its receipt or ambiguous state.

## Functional Requirements

### Drafts And Composition

- FR-001: Drafts are private local records. Creating, editing, listing, showing,
  and discarding a draft never contacts a provider and never changes a remote
  mailbox.
- FR-002: A draft supports `new`, `reply`, `reply_all`, and `forward` modes.
  Reply modes require one scoped source message reference; forward preserves a
  bounded source summary and permits explicit recipients.
- FR-003: Reply uses the source Reply-To when present, otherwise the source
  From. Reply-all includes the source From, To, and Cc recipients, removes the
  configured account address, and de-duplicates addresses case-insensitively.
  Forward requires explicit recipients and uses a deterministic forwarded
  subject and quoted source header/body block.
- FR-004: Draft bodies support plain text, HTML, or both. When both are
  present, SMTP emits a standards-compliant `multipart/alternative` part.
  Draft and send validation keeps body, header, and total payload bounds.
- FR-005: A draft can import explicitly selected local files at planning time.
  The imported snapshot stores bounded bytes, filename, MIME type, byte size,
  SHA-256, and a deterministic bounded content summary. It never stores only a
  path and never follows symlinks outside the selected regular file.
- FR-006: Content summaries are deterministic metadata and, for recognized
  UTF-8 text, a bounded text preview. No embedded LLM, remote summarizer, or
  autonomous prose generation is introduced. Imported bytes are never
  executed, uploaded, or implicitly forwarded.
- FR-007: A send plan created from a draft covers the complete immutable
  snapshot: account, recipients, subject, text/HTML bodies, attachment
  metadata and bytes, generated Message-ID, content digest, and expiry.
  Changing any covered field requires a new plan and approval.

### Governed IMAP Operations

- FR-008: Kirje supports scoped `set_read`, `set_starred`, `move`, `archive`,
  and `delete` operations using account, mailbox, UIDVALIDITY, UID, and any
  destination mailbox as explicit inputs.
- FR-009: `archive` resolves only a server-reported `\\Archive` mailbox or an
  explicitly supplied destination. Kirje never guesses a localized folder
  name. Missing or ambiguous archive targets are rejected before network
  mutation.
- FR-010: `delete` is safe deletion: it moves the selected message to a
  server-reported `\\Trash` mailbox or an explicitly supplied destination.
  v0.3 never performs permanent `EXPUNGE` and never broadens a UID-scoped
  operation to unrelated messages.
- FR-011: Each remote write is planned locally, binds its exact operation
  payload and scope to a SHA-256 digest, and requires interactive CLI approval
  before apply. `set_read` and `set_starred` are governed even though they are
  reversible; `move`, `archive`, and `delete` are also destructive or
  user-visible mutations.
- FR-012: Apply validates account and UIDVALIDITY scope immediately before
  mutation. A stale reference, missing destination, unsupported capability, or
  provider rejection produces a bounded structured error and an auditable
  terminal failure without retrying a different operation.

### Unified Operation Ledger

- FR-013: The existing send outbox evolves in place into a versioned private
  SQLite operation ledger. Existing send plans remain readable and migrate
  transactionally without credentials or message duplication.
- FR-014: The ledger stores immutable operation payloads, payload digest,
  operation kind, account/scope, state timestamps, approval identity marker,
  attempt count, bounded error/receipt, and an append-only audit event history.
  Secrets, credentials, and unrestricted remote message bodies are excluded.
- FR-015: The ledger supports bounded list/show/status/audit reads and stable
  state transitions for drafts, sends, and IMAP writes. Terminal records cannot
  be approved, mutated, or applied again.
- FR-016: A transaction claims an approved remote operation before credential
  lookup or protocol invocation. Concurrent and repeated apply calls cannot
  invoke the same operation twice.
- FR-017: A crash or process loss after claim is conservative: stale
  `applying` remote operations reconcile to `ambiguous`, are never retried
  automatically, and remain visible for operator reconciliation. Provider
  errors before mutation are `failed`; any uncertainty after mutation begins is
  `ambiguous`.
- FR-018: SQLite migrations reject newer schemas, use transactions, preserve
  private file permissions, and are covered by upgrade, downgrade-rejection,
  crash-recovery, and audit-integrity tests.

### Interfaces, Security, And Operations

- FR-019: CLI convenience commands and MCP tools call the same runtime service
  methods and domain contracts. MCP exposes plan/status/apply and local draft
  operations but exposes no approval operation and no secret operation.
- FR-020: CLI JSON remains versioned, bounded, and stdout-clean. Mailbox
  content, imported files, attachment summaries, and provider responses remain
  explicitly marked untrusted where they are returned to an agent.
- FR-021: Credentials remain in the OS credential store and never appear in
  request JSON, ledger payloads, audit events, receipts, logs, arguments, or
  MCP payloads. TLS verification and existing provider endpoint safeguards
  remain mandatory.
- FR-022: The Agent Skill, architecture, security, agent guide, provider
  operation notes, live smoke scripts, and release evidence describe the exact
  v0.3 contract, including safe delete and ambiguous-state handling.
- FR-023: Full formatting, lint, tests, build, dependency-policy, CLI contract,
  MCP stdio, and controlled live-mailbox verification are run before release
  claims. Live verification uses a dedicated self-addressed test mailbox,
  never commits credentials, and records a sanitized blocker when the OS
  credential boundary is unavailable.

## Non-Requirements

- No graphical UI, Tauri app, hosted relay, embedded LLM, autonomous approval,
  or background mailbox daemon.
- No permanent deletion or `EXPUNGE` in v0.3.
- No unbounded body/attachment storage, semantic search, arbitrary filesystem
  traversal, bulk mutation, scheduled send, tracking, or automatic retry after
  protocol invocation.
- No guessed provider folders or provider-specific behavior in generic CLI
  handlers.

## Safety Invariants

1. A remote write cannot occur without an immutable ledger record and a human
   TTY approval bound to that record.
2. MCP cannot approve, enter, retrieve, or delete credentials.
3. A UIDVALIDITY mismatch rejects the operation before mutation.
4. Safe delete targets only `\\Trash` or an explicit destination and never
   expunges unrelated messages.
5. `ambiguous` means possibly applied and is never automatically retried.
6. The ledger digest and audit events make the approved payload reviewable and
   tamper-evident within the local store.

## Acceptance Criteria

1. Tests prove draft privacy, reply/reply-all/forward recipient rules,
   multipart MIME construction, bounded attachment import, deterministic
   summaries, immutable send approval, and secret exclusion.
2. Tests prove IMAP read/star/move/archive/safe-delete command generation,
   explicit destination rules, UIDVALIDITY protection, governed transitions,
   concurrency exclusion, migration, audit history, stale-claim recovery, and
   ambiguous outcomes.
3. CLI and MCP contract tests prove shared runtime behavior and prove that MCP
   has no approval or credential entry point.
4. All repository quality gates pass, and controlled live verification either
   self-sends through the governed path and confirms the message or records a
   sanitized credential-store/environment blocker.
5. A reviewed commit, PR, CI result, and merge state are recorded without
   claiming an unavailable external action.

## Release Baseline

The implementation baseline uses the safe-delete policy in FR-010: move to
server-declared `\\Trash` or an explicit destination, with no permanent
`EXPUNGE`. The CLI approval step represents human authorization for each
remote operation; MCP has no approval entrypoint.
