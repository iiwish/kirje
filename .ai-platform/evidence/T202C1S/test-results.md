# T202C1S Test Results

## Test-First Attempt

- T202C1S-A001 baseline: branch `codex/v1-roadmap-governance`, HEAD `843bd6d`,
  clean worktree, and all four packet baseline hashes matched.
- RED command:
  `cargo test -p kirje-store --test authority_schema --test authority_registry --all-features --locked`.
  Registry exited 101 with 6 passing and 10 failing targets because the three
  immutable parent tables did not exist. The isolated schema RED had 22 passing
  and 8 failing targets for the old digest/inventory and absent relationships.
  The fault-matrix RED also failed because
  `AuthorityFaultPoint::RegisteredStoreVersionInserted` was absent.
- GREEN/refactor: the joint target reached 47/47; schema reached 31/31,
  registry 16/16, authorization 33/33, kirje-store all-features 99/99,
  no-default-features 19/19, and the workspace 208/208.
- Initial Clippy found two test-only lint violations. The worker refactored only
  those tests and reran the complete green and validation loops successfully.

## Final Gates

The orchestrator independently reran the accepted production tree:

```text
cargo test -p kirje-store --test authority_schema --test authority_registry \
  --test authority_authorization --all-features --locked                    PASS 80/80
cargo test -p kirje-store --no-default-features --locked                    PASS 19/19
cargo test --workspace --all-features --locked                              PASS 208/208
cargo +1.88.0 test -p kirje-store --all-features --locked                   PASS 99/99
cargo fmt --all --check                                                     PASS
cargo clippy --workspace --all-targets --all-features --locked \
  -- -D warnings                                                             PASS
cargo build --workspace --all-features --locked                             PASS
cargo deny check licenses bans sources                                      PASS
feature-wide delivery artifact validator                                    PASS
canonical DDL SHA-256 gate                                                   PASS
git diff --check and allowed-file scope                                      PASS
```

`cargo deny check advisories` reports only the packet-recorded yanked
`chacha20 0.10.1` dependency in the unchanged
`io-imap -> imap-codec -> imap-types -> rand` chain.

## Schema And Relationship Matrix

- Canonical inventory: 20 tables, 15 explicit indexes, 3 triggers,
  application ID 1263096394, user version 1.
- Canonical DDL SHA-256:
  `5d01739b89246a5f495a965e57e416eee9fd0b5016995add41c6edee7f3e970d`.
- Valid complete graphs return zero rows from `PRAGMA foreign_key_check` and
  exactly `ok` from `PRAGMA integrity_check`.
- Remote store and account effect parents are immutable versions. Updating a
  current store config or current account binding leaves history valid.
- Store versions enforce exact receipt XOR transition origin. Credential and
  account versions enforce exact account/store/transition composites. Cross-
  origin and mutable-current-only probes are rejected by SQLite.
- The old 17-table developer inventory is rejected without migration, repair,
  rename, fallback, or partial bootstrap.

## Enrollment, Restart, And Privacy

- First success inserts one initial version after current-store insertion and
  before the existing enrollment event and commit. It emits no new event and
  consumes no entropy.
- Ordinary retry, restart, response loss, and exact concurrency recover one
  immutable version. Changed or corrupted retry fails with stable existing
  errors and writes nothing.
- Every pre-commit fault rolls back grant, current store, initial version,
  events, and paired clock. The post-commit loss path retains one recoverable
  graph.
- T202A/T202B require all new parents empty; T202C1 requires one receipt-origin
  store version per store and no credential/account-version rows.
- The 128-row restart path records four registry streams and 3,584 bounded keyed
  lookups. Query plans use primary/unique keys and no temporary B-tree.
- Changed files are exactly the four packet-owned files. Cargo, core, runtime,
  protocol, CLI, MCP, public APIs, event codes, errors, docs, and dependencies
  did not change. Source, diff, and output scans found no real account, mailbox,
  endpoint, UID, credential, password, token, private signing material, or
  authorization artifact.

## Review

- Packet review A001: 1 High, 3 Medium, 1 Low; no pass.
- Packet review A002: 0 Critical, 0 High, 0 Medium, 0 Low;
  `T202C1S_A002_PACKET_REVIEW_PASS`.
- Implementation review A001: 0 Critical, 0 High, 0 Medium, 1 accepted Low;
  `T202C1S_A001_CODE_REVIEW_PASS`.
