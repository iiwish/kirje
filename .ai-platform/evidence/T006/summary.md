# T006 Evidence

- Result: complete
- Scope: provider-neutral index contracts and `kirje-store` SQLite adapter
- RED: `cargo test -p kirje-core -p kirje-store --all-features` failed because
  `SqliteMessageIndex` was intentionally absent.
- GREEN: core/store tests pass, including schema migration, future-schema
  rejection, idempotent upsert, UIDVALIDITY reset, filtering, ordering, and Unix
  file/directory permissions.
- Review: no credentials, bodies, raw MIME, or attachment bytes enter SQLite;
  migrations and mailbox reset are transactional.
- Residual risk: SQLite corruption recovery is fail-closed but repair tooling is
  outside this phase.
