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

MCP tools are task-level, narrowly scoped, and annotated with read-only,
destructive, and idempotency hints. Stdio mode reserves stdout exclusively for
protocol messages.
