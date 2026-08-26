# Security Policy

Do not report vulnerabilities in public issues. Use GitHub private vulnerability
reporting for this repository.

Never include real mailbox credentials, OAuth tokens, message bodies, email
addresses, attachment contents, or provider UIDs in a report. Use synthetic
fixtures and redact paths that reveal local usernames.

Kirje connects through verified TLS. Remote reads are non-mutating; SMTP apply
requires an immutable plan and separate human TTY approval. The local index
contains envelope metadata, while the separate outbox contains the exact
bounded message snapshot covered by approval. Neither contains credentials.
Reports involving IMAP, sync, or SMTP should use a dedicated test account and
the sanitized evidence format in `docs/conformance.md`. The full security model
is documented in `docs/security.md`.
