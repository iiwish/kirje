# Security Model

Email is adversarial input. A message can contain instructions intended to make
an agent disclose data, run commands, alter account settings, or send mail.

Kirje therefore separates four boundaries:

1. Reading mailbox facts.
2. Creating a local draft.
3. Producing an immutable operation plan.
4. Applying an explicitly approved plan.

The future write path must bind approval to exact recipients, subject, body
digest, attachments, account, and expiration time. Changing any bound field
invalidates approval. Retried operations require an idempotency key.

Secrets are referenced from an OS keyring, secret manager, or protected file
descriptor. They are never accepted as positional or flag values and never
appear in JSON output.

Kirje accepts only implicit TLS or STARTTLS for IMAP. It opens mailboxes with
`EXAMINE` and uses bounded `BODY.PEEK[]` fetches to avoid changing `\\Seen`.
Scoped references are rejected when UIDVALIDITY changes. Raw messages are
limited to 10 MiB, decoded bodies are bounded, and HTML is sanitized.

The local SQLite index contains bounded envelope metadata and sync cursors. It
contains no credentials, bodies, raw MIME, or attachment bytes. On Unix the
database and SQLite sidecar files use mode `0600`; writes and UIDVALIDITY resets
are transactional. Local index writes are distinct from remote mailbox writes.

Attachment reads require an exact server-returned part id, return at most 1 MiB
of decoded content as base64, never write a file, and use the same `BODY.PEEK`
path. Message and attachment output is always marked `untrusted: true`.

MCP tools are task-level, narrowly scoped, and annotated with read-only,
destructive, idempotency, and open-world hints. `mailbox_sync` declares its
local write; no tool can mutate remote mail. Stdio mode reserves stdout
exclusively for protocol messages.
