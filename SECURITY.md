# Security Policy

Do not report vulnerabilities in public issues. Use GitHub private vulnerability
reporting for this repository.

Never include real mailbox credentials, OAuth tokens, message bodies, email
addresses, attachment contents, or provider UIDs in a report. Use synthetic
fixtures and redact paths that reveal local usernames.

Kirje connects to mailboxes through verified TLS and exposes no remote write
tools. The local SQLite index contains envelope metadata but no credentials,
bodies, raw MIME, or attachments. Reports involving IMAP or sync behavior
should use a dedicated test account and the sanitized evidence format in
`docs/conformance.md`. The full security model is documented in
`docs/security.md`.
