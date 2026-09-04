# Technology Decision Record

## Metadata

- Status: Confirmed
- Updated: 2026-08-30

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

### Pimalaya IMAP Adapter

Kirje uses Pimalaya `io-imap` and `io-sasl` behind a Kirje-owned port. Mailboxes
open with `EXAMINE`; bodies and attachments use bounded `BODY.PEEK`; provider
quirks remain inside the adapter.

### SQLite Operational Index

Kirje uses bundled SQLite through `rusqlite` for a portable local envelope
index. The `kirje-store` adapter implements a provider-neutral core port,
migrates transactionally, rejects newer schemas, and stores no credentials,
bodies, raw MIME, or attachment bytes.

### Explicit UID Synchronization

Synchronization is an explicit task-level operation. The first run imports the
newest bounded window; later runs fetch above a persisted UID high-water mark.
UIDVALIDITY changes replace one mailbox scope atomically. Background `IDLE`,
historical backfill, and reconciliation are separate future capabilities.

### Unified Transactional Operation Ledger

Kirje stores private drafts, immutable bounded send requests, and governed IMAP
mutations in the private SQLite outbox path as one versioned operation ledger.
Schema migration preserves legacy send rows and appends audit events. Immediate
transactions enforce approval and one-time claim transitions. SMTP or IMAP
uncertainty is terminal and non-retryable rather than hidden behind an
automatic retry. Stale applying records reconcile to `ambiguous`.

### Deterministic Draft Composition

Drafts are local records with new, reply, reply-all, and forward modes. Reply
uses Reply-To when present; reply-all removes the configured account and
de-duplicates recipients; forward requires explicit recipients. Source content
is a bounded caller-provided snapshot, and local attachment imports are regular
file snapshots with deterministic summaries.

### Governed IMAP Mutations

Mailbox flags and move/archive/safe-delete work use the same ledger and
plan/CLI-approval/apply state machine as send. The adapter validates
UIDVALIDITY immediately before mutation, uses UID MOVE when available, and
falls back to UID COPY plus UID-scoped `\\Deleted`. Safe delete never invokes
`EXPUNGE`; archive and Trash targets come from server special-use declarations
or explicit input.

### Lettre SMTP Adapter

Kirje uses Lettre 0.11 for typed MIME construction and SMTP transport with
implicit TLS or mandatory STARTTLS. The adapter remains behind Kirje's
provider-neutral `MailSender` port; the send state machine is independent of
the SMTP library.

### No Desktop Compatibility Layer

The archived desktop repository is a source of protocol knowledge and sanitized
tests, not an architecture to preserve. React, Tauri, and desktop lifecycle code
are not migrated.

### Incremental V1 Checkpoints

Kirje uses one confirmed 1.0 product contract and one program work graph.
Security, mailbox convergence, delivery reconciliation, policy, stable
contracts, distribution, hardening, and stable publication are incremental
checkpoints under that program rather than independent release-governance
stacks.

Implementation batches run focused RED/GREEN and changed-crate validation.
Complete workspace, dependency, migration, CI, conformance, platform, and
artifact gates run at their checkpoint boundary. Every batch produces a
reviewed commit; every tagged checkpoint produces usable artifacts and an
evidence summary. Same-attempt validation can be reused only while exact
content hashes prove that relevant code, tests, fixtures, schema, dependencies,
toolchain, and configuration are unchanged.

The current account-create diff is preserved as review input. It is not
discarded or expanded during governance. The unchanged yanked transitive
`chacha20 0.10.1` dependency is a named Security Alpha remediation and cannot
be hidden by the checkpoint model.
