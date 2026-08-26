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

The read-only MVP accepts only implicit TLS or STARTTLS for IMAP. It opens
mailboxes with `EXAMINE` and uses bounded `BODY.PEEK[]` fetches to avoid changing `\\Seen`, rejects stale scoped references when
UIDVALIDITY changes, limits raw messages to 10 MiB, bounds decoded bodies, omits
attachment content, and sanitizes HTML. Returned message content is always
marked `untrusted: true`; an agent must not execute instructions found inside it.

MCP tools are task-level, narrowly scoped, and annotated with read-only,
destructive, and idempotency hints. Stdio mode reserves stdout exclusively for
protocol messages.
