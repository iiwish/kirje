# T202C3 Test Results

## A001 RED

After correcting a test-harness compile error, the focused command exited 101:

```text
cargo test -p kirje-store --test authority_registry \
  remaining_account_and_credential_challenges_are_exact \
  --all-features --locked
```

The first valid `account_update` request reached the intended missing
capability and returned `authorization_context_stale`.

## A001 GREEN

- Focused T202C3-A001 test: 1 passed, 0 failed.
- Authority registry suite: 36 passed, 0 failed.
- `cargo test -p kirje-store --all-features --locked`:
  - crate unit tests: 8 passed;
  - authority authorization: 33 passed;
  - authority registry: 36 passed;
  - authority schema: 31 passed;
  - outbox: 11 passed;
  - doc tests: passed.
- `cargo test -p kirje-store --no-default-features --locked`: passed.
- `cargo clippy -p kirje-store --all-targets --all-features --locked -- -D warnings`:
  passed.
- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.

The final package test ran after production commit `daf22a0`. The exact focused
test additionally proves four successful/reusable action challenges, four
intrinsic-shape failures, stale generation, busy store, zero challenge effects,
no new lifecycle rows, zero entropy on rejection, and unchanged rejection
fingerprints.

## Integrity

- Authority SQLite v1 schema SHA-256 remains
  `5d01739b89246a5f495a965e57e416eee9fd0b5016995add41c6edee7f3e970d`.
- `Cargo.lock` SHA-256 remains
  `596ddb0071ecb38b0b9429c5d91cdbb83abe6a25bc760cf9588b2764274ff850`.
- Commit scope contains only the two packet-authorized store files.
- Added-line scan found no address, endpoint, password, secret, token, or
  private-key literal.

## A002 RED

The focused command exited 101 at the intended create-only transition gate:

```text
cargo test -p kirje-store --test authority_registry \
  account_update_transition_lifecycle_is_exact \
  --all-features --locked
```

The valid authorized update returned `authorization_context_stale` and its
rejection fingerprint proved zero grant, transition, credential, cleanup,
event, or clock writes.

During review, the same command supplied a second negative control for an
authorized update expiring before prepare. The operation returned the correct
`authorization_expired`, then restart failed the Ready assertion. This proved
the persisted expiry event used the wrong transition-kind intent. The focused
test passed after the action-specific fix.

## A002 Final GREEN

- Focused account-update lifecycle: 1 passed, 0 failed.
- Authority registry suite: 37 passed, 0 failed.
- `cargo test -p kirje-store --all-features --locked`:
  - crate unit tests: 8 passed;
  - authority authorization: 33 passed;
  - authority registry: 37 passed;
  - authority schema: 31 passed;
  - outbox: 11 passed;
  - doc tests: passed.
- `cargo test -p kirje-store --no-default-features --locked`: 19 passed across
  the enabled unit and outbox targets; feature-gated authority suites compiled
  and selected zero tests.
- `cargo clippy -p kirje-store --all-targets --all-features --locked -- -D warnings`:
  passed.
- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- Delivery artifact validator: passed.

The database-backed lifecycle test covers success, exact retry, immutable
versions, abort restoration, unsafe recovery, expiry restart, cleanup material
mismatch, prepare/finalize fault rollback, and private-material tamper recovery.
The registry suite additionally covers concurrency, successor retry scoping,
event order, query slope, restart corruption, and privacy compile gates.

## A002 Integrity

- Production commit: `2c00f32`.
- Authority SQLite v1 schema SHA-256 remains
  `5d01739b89246a5f495a965e57e416eee9fd0b5016995add41c6edee7f3e970d`.
- `Cargo.lock` SHA-256 remains
  `596ddb0071ecb38b0b9429c5d91cdbb83abe6a25bc760cf9588b2764274ff850`.
- Production scope contains only the packet-authorized authority source,
  registry test, and synthetic public-signature fixture.
- Privacy scan found no private key, seed, proof, nonce, locator material,
  address, endpoint, mailbox content, or provider data in the fixture or
  evidence.
