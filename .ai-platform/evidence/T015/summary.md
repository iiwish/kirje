# T015 Evidence: Transactional Outbox

## Result

Complete. A private SQLite outbox persists immutable requests and enforces the
governed lifecycle with immediate transactions and compare-and-transition
guards.

## TDD Evidence

- RED: the outbox integration suite failed because the port, adapter, and stable
  state errors did not exist.
- GREEN: `cargo test -p kirje-store --test outbox --all-features` passed six
  lifecycle, expiry, concurrency, ambiguous, and receipt tests.

## Review

Plans cannot be inserted after approval or mutation. Only one concurrent claim
can enter `applying`; terminal and ambiguous plans cannot be reclaimed. Stale
applying work is conservatively reconciled to `ambiguous` after 15 minutes. DB,
WAL, and shared-memory files use mode 0600 on Unix.
