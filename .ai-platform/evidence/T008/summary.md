# T008 Evidence

- Result: complete
- Scope: bounded initial and incremental IMAP metadata synchronization
- RED: `cargo test -p kirje-runtime --all-features` failed with the expected
  missing `sync_mailbox` adapter method.
- GREEN: protocol tests cover newest-window selection, oldest-first incremental
  batches, UID range construction, and a raw `UID SEARCH UID 42:*` transcript.
- Review: mailboxes use `EXAMINE`, FETCH batches are capped at 500, UIDVALIDITY
  is mandatory, and no remote flag or mailbox mutation is issued.
- Residual risk: a large provider SEARCH response can contain many UID numbers;
  ESEARCH partial-result optimization is future conformance work.
