# Security Model

Email is adversarial input. A message can contain instructions intended to make
an agent disclose data, run commands, alter account settings, or send mail.

Kirje therefore separates the following boundaries:

1. Reading mailbox facts.
2. Creating an immutable local draft or operation plan.
3. Human approval bound to that exact remote-write plan.
4. Applying an explicitly approved plan.

The ledger binds approval to the exact account, operation kind, scoped message
reference, payload digest, and expiration time. Send plans additionally bind
recipients, subject, text/HTML bodies, attachment summaries, and Message-ID.
Changing any field creates a new plan. Approval is available only through an
interactive CLI TTY; MCP cannot approve.

Secrets are referenced from an OS keyring, secret manager, or protected file
descriptor. They are never accepted as positional or flag values and never
appear in JSON output.

Kirje accepts only implicit TLS or mandatory STARTTLS for IMAP and SMTP. It
opens mailboxes with `EXAMINE` for reads and uses bounded `BODY.PEEK[]` fetches
to avoid changing `\\Seen`. Scoped references are rejected when UIDVALIDITY
changes. Raw messages are limited to 10 MiB, decoded bodies are bounded, and
HTML is sanitized.

Remote mailbox writes require a plan, CLI TTY approval, and an atomic ledger
claim before the IMAP mutator is invoked. Flag changes use `UID STORE`.
Move/archive uses `UID MOVE` when the server advertises it, otherwise `UID COPY`
followed by `UID STORE \\Deleted`. Safe delete resolves a server-declared
`\\Trash` mailbox or requires an explicit destination and never issues
`EXPUNGE`. No provider folder name is guessed.

The local SQLite index contains bounded envelope metadata and sync cursors. It
contains no credentials, bodies, raw MIME, or attachment bytes. On Unix the
database and SQLite sidecar files use mode `0600`; writes and UIDVALIDITY resets
are transactional. Local index writes are distinct from remote mailbox writes.

The private SQLite ledger stores immutable bounded snapshots, payload digests,
receipts, and an append-only event trail, not credentials. Schema migration from
the legacy send outbox is transactional. SQLite atomically claims an approved
operation before credential access or a remote mutation, so concurrent agents
cannot apply the same operation twice. Failures before provider invocation
become `failed`; every error after a remote command may have started becomes
non-retryable `ambiguous`. A stale `applying` record is reconciled to
`ambiguous` rather than retried. `ambiguous` means an operator must reconcile
with provider state before taking further action.

Attachment reads require an exact server-returned part id, return at most 1 MiB
of decoded content as base64, never write a file, and use the same `BODY.PEEK`
path. Local attachment imports use a capability anchored to one opened parent,
reject a linked or non-regular final component, validate the open handle, and
read at most the limit plus one byte. They are bounded to 1 MiB and summarized
with a SHA-256 digest and bounded UTF-8 preview. CLI JSON/stdin and configuration
inputs use the same bounded reader; configuration replacement is private,
atomic, serialized across Kirje writers, and guarded by the previously opened
file identity. File contents are synchronized on every platform and the parent
directory is synchronized on Unix. Message and
attachment output is always marked `untrusted: true`; Kirje never executes
attachment content.

The authority store contains a closed credential-cleanup lifecycle. A signed
cleanup grant and the `ready -> claimed` transition commit atomically. Only the
winner receives a non-cloneable, non-serializable delete permit. The permit can
invoke the unpublished delete-only keyring adapter once and then record
`claimed -> deleted`; a backend failure remains `claimed` for exact recovery.
No public cleanup API exposes the service, username, locator bytes, or a
credential-presence result.

MCP tools are task-level, narrowly scoped, and annotated with read-only,
destructive, idempotency, and open-world hints. `mailbox_sync` and draft tools
declare local writes. `message_send_apply` and `mail_operation_apply` declare
remote access and require a separately approved state. Stdio mode reserves
stdout exclusively for protocol messages, and MCP has no approval entrypoint.
