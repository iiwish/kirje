# T016 Evidence: SMTP Adapter

## Result

Complete. Kirje reuses Lettre 0.11.23 for MIME construction and synchronous
SMTP submission behind the provider-neutral `MailSender` port.

## TDD Evidence

- RED: the adapter contract test failed because `MailSender` and
  `LettreSmtpSender` did not exist.
- GREEN: `cargo test -p kirje-protocol --all-features` passed 15 tests.

## Review

Implicit TLS uses Lettre's secure relay builder and STARTTLS uses its mandatory
upgrade builder; no plaintext or opportunistic mode is reachable. MIME tests
cover stable Message-ID, Unicode headers, multipart bodies, Bcc envelope
delivery without a Bcc header, and bounded sanitized SMTP responses. Adapter
errors explicitly report whether SMTP delivery invocation began.
