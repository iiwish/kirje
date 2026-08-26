# Analysis: Read-Only Mailbox MVP

## Result

No blocking requirement conflict was found.

## Risks And Controls

- Pimalaya APIs are young: isolate them behind `kirje-protocol` and pin the
  resolved versions in `Cargo.lock`.
- Credential-store availability varies on headless Linux: expose a stable
  `secret_store_unavailable` error and test the runtime through an in-memory
  implementation.
- IMAP implementations differ: port sanitized compatibility cases from the
  archived desktop project and add opt-in live conformance checks.
- Message bodies may be hostile or very large: use `BODY.PEEK[]`, parse MIME,
  strip active rendering, bound returned text, and retain truncation metadata.
- IMAP UIDs are scoped: encode account and mailbox in every public reference.

