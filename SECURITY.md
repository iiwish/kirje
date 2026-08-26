# Security Policy

Do not report vulnerabilities in public issues. Use GitHub private vulnerability
reporting for this repository.

Never include real mailbox credentials, OAuth tokens, message bodies, email
addresses, attachment contents, or provider UIDs in a report. Use synthetic
fixtures and redact paths that reveal local usernames.

Kirje's current bootstrap release does not connect to mailboxes or expose write
tools. The intended security model is documented in `docs/security.md`.
