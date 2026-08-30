# T202C2 Test Results

## Status

Review fixes and all required local gates passed. The user accepted the
checkpoint on 2026-08-30.

## Review RED/GREEN

All three review findings were reproduced before their fixes:

- `finalized_account_history_rejects_a_tampered_current_store_pair` exited 101
  because the tampered current pair reopened as Ready; it passes after history
  reconstruction was added.
- `account_create_challenge_requires_the_reentry_state_reason` exited 101
  because issuance reached entropy and returned `Internal`; it passes after
  intrinsic state-reason validation was added.
- `unsafe_config_pairs_take_precedence_over_a_stale_method_state` exited 101
  with `AccountUpdateConflict`; it passes after unsafe-pair precedence and
  convergent terminal recovery were fixed.

## Fresh Passed Gates

- `cargo fmt --all --check`
- `cargo test -p kirje-store --test authority_registry --all-features --locked`
  - 35 passed, 0 failed.
- `cargo clippy -p kirje-store --all-targets --all-features --locked -- -D warnings`
- `cargo test -p kirje-store --no-default-features --locked`
- `cargo +1.88.0 test -p kirje-store --all-features --locked`
  - Authority registry: 35 passed.
  - Authority authorization: 33 passed.
  - Authority schema: 31 passed.
- `cargo test --workspace --all-features --locked`
  - All workspace unit, integration, and doc-test targets passed.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo build --workspace --all-features --locked`
- `git diff --check`

The focused suite also retained its affine query-count, indexed query-plan,
128-history, concurrency, restart, privacy, no-external-call, and schema-hash
assertions.

## Known Baseline Failure

`cargo deny check` exits 1 only for yanked `chacha20 0.10.1` in the unchanged
dependency chain:

```text
io-imap -> imap-codec -> imap-types -> rand -> chacha20
```

The same command reports bans, licenses, and sources as passing. `Cargo.lock`
remains at SHA-256
`596ddb0071ecb38b0b9429c5d91cdbb83abe6a25bc760cf9588b2764274ff850`.
T111 owns remediation.

## Evidence Boundary

The final tested hashes are recorded in `summary.md`. Any later source, test,
fixture, schema, dependency, relevant configuration, or toolchain change
invalidates the affected result.
