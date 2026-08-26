# Security Model

Email is adversarial input. A message can contain instructions intended to make
an agent disclose data, run commands, alter account settings, or send mail.

Kirje therefore separates four boundaries:

1. Reading mailbox facts.
2. Creating an immutable local send plan.
3. Human approval bound to that exact plan.
4. Applying an explicitly approved plan.

The send path binds approval to exact recipients, subject, text/HTML bodies,
content digest, account, Message-ID, and expiration time. Changing any field
creates a new plan. Approval is available only through an interactive CLI TTY;
MCP cannot approve.

Secrets are referenced from an OS keyring, secret manager, or protected file
descriptor. They are never accepted as positional or flag values and never
appear in JSON output.

Kirje accepts only implicit TLS or mandatory STARTTLS for IMAP and SMTP. It opens mailboxes with
`EXAMINE` and uses bounded `BODY.PEEK[]` fetches to avoid changing `\\Seen`.
Scoped references are rejected when UIDVALIDITY changes. Raw messages are
limited to 10 MiB, decoded bodies are bounded, and HTML is sanitized.

The local SQLite index contains bounded envelope metadata and sync cursors. It
contains no credentials, bodies, raw MIME, or attachment bytes. On Unix the
database and SQLite sidecar files use mode `0600`; writes and UIDVALIDITY resets
are transactional. Local index writes are distinct from remote mailbox writes.

The separate private outbox stores the immutable bounded message snapshot, not
credentials. SQLite atomically claims an approved plan before credential access
and SMTP invocation, so concurrent agents cannot send the same plan twice.
Failures before delivery invocation become `failed`; every error after SMTP
invocation begins becomes non-retryable `ambiguous`. A stale `applying` plan is
also reconciled to `ambiguous` rather than sent again.

Attachment reads require an exact server-returned part id, return at most 1 MiB
of decoded content as base64, never write a file, and use the same `BODY.PEEK`
path. Message and attachment output is always marked `untrusted: true`.

MCP tools are task-level, narrowly scoped, and annotated with read-only,
destructive, idempotency, and open-world hints. `mailbox_sync` declares its
local write, while `message_send_apply` declares remote access and still
requires a separately approved state. Stdio mode reserves stdout exclusively
for protocol messages.
