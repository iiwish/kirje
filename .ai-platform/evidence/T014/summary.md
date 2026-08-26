# T014 Evidence: Send Contract And Account Configuration

## Result

Complete. Kirje has bounded immutable send-plan contracts and account
configuration can carry a secure optional SMTP endpoint. Known providers fill
the endpoint from the validated registry; legacy IMAP-only TOML remains valid.

## TDD Evidence

- RED: targeted tests failed because `outgoing`, `SendRequest`, and `SendPlan`
  did not exist.
- GREEN: `cargo test -p kirje-core -p kirje-cli --all-features` passed 31 tests.

## Changed Surface

- Workspace dependencies: UUID and SHA-256.
- Core: request bounds, plan identity/hash/expiry, status and receipt contracts.
- CLI: provider-backed SMTP defaults and explicit SMTP overrides.

## Review

No secret field or insecure transport was added. Message content is bounded;
recipient and subject headers reject control characters. Legacy account files
deserialize with no outgoing endpoint and remain read-capable.
