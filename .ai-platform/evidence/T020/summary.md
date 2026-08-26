# T020 Evidence: Unified Operation Ledger

Implemented schema version 2 in the private SQLite outbox path. Legacy send
rows migrate into generic operation records; transitions, payload digests,
append-only events, concurrent claims, expiry, stale-claim reconciliation, and
ambiguous outcomes are covered by store tests.
