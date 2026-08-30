# T202C3 Test Results

## RED

After correcting a test-harness compile error, the focused command exited 101:

```text
cargo test -p kirje-store --test authority_registry \
  remaining_account_and_credential_challenges_are_exact \
  --all-features --locked
```

The first valid `account_update` request reached the intended missing
capability and returned `authorization_context_stale`.

## Final GREEN

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
