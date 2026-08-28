# T202A Test Results

## Test-First Attempts

- T202A-A001: valid missing-contract RED, followed by 14 core and 11 authority
  GREEN tests. Independent review found four High and one Medium invariant gap;
  the attempt was not accepted.
- T202A-A002: five deterministic RED failures covered confirmation state,
  active bundle equality, canonical event history, stale database identity, and
  unaccounted history. The final 20 authority tests passed. Independent review
  found one High stale-regeneration path and one Medium inconsistent-read path;
  the attempt was not accepted.
- T202A-A003: three deterministic RED failures covered stale authority loss,
  open/confirm snapshot interleaving, and exact-retry identity TOCTOU. The final
  23 authority tests passed. Independent review found one Medium regression in
  existing-connection WAL enforcement; the attempt was not accepted.
- T202A-A004: three deterministic RED failures proved that valid existing
  databases remained in DELETE mode, stale write paths omitted WAL restoration,
  and foreign preflight could mutate journal mode. The final 26 authority tests
  passed and independent review found no remaining issue.

## Packet Gates

The orchestrator independently reran the final tree:

```text
cargo fmt --all --check                                                    PASS
cargo test -p kirje-core --test authorization_contract --all-features --locked
                                                                            PASS 14/14
cargo test -p kirje-store --test authority_schema --all-features --locked   PASS 26/26
cargo test -p kirje-core -p kirje-store --all-features --locked             PASS
cargo test -p kirje-store --no-default-features --locked                    PASS
cargo clippy -p kirje-core -p kirje-store --all-targets --all-features \
  --locked -- -D warnings                                                    PASS
cargo +1.88 check -p kirje-core -p kirje-store --all-features --locked      PASS
```

## Repository Gates

```text
cargo test --workspace --all-features --locked                              PASS
cargo clippy --workspace --all-targets --all-features --locked \
  -- -D warnings                                                             PASS
cargo build --workspace --all-features --locked                             PASS
cargo deny check licenses bans sources                                      PASS
git diff HEAD --check excluding canonical DDL and generated diff evidence    PASS
```

On source/governance files, full `git diff HEAD --check` reports only the
canonical DDL's required final blank line. Removing it would change the frozen
schema digest; the exact-byte contract is retained and the lint mismatch is
recorded as a Low watch item. The generated `diff.patch` is excluded because
standard unified-diff context markers are not source whitespace.

`cargo deny check advisories` reports the pre-existing yanked `chacha20 0.10.1`
through the unchanged `io-imap -> imap-codec -> imap-types -> rand` chain. T202A
does not add or use that chain. Its removal remains owned by the protocol and
release dependency work; license, ban, and source policy checks pass.

## Schema And Security Matrix

- DDL: exact SHA-256, 17 tables, 14 declared indexes, 3 triggers, no top-level
  transaction control or PRAGMA.
- SQLite identity: application ID `1263096394`, schema version 1, strict
  inventory comparison, foreign-key check, integrity check, WAL, FULL
  synchronous mode, and 5000 ms busy timeout.
- Raw SQL: every table rejects all-NULL rows; storage class, length, numeric,
  enum, relation, partial-unique, role/epoch, and composite-FK cross-link
  negatives execute; valid relationship chains pass integrity and FK checks.
- Bootstrap: malformed/equal role keys fail before entropy or files; the outer
  transaction rollback leaves no user objects, rows, application ID, or version;
  deterministic entropy exhaustion restarts cleanly; concurrent bootstrap has
  one committed identity.
- Recovery: wrong/missing/replaced/newer/partial/corrupt state fails closed;
  stale non-Unconfigured stores never regenerate identities; exact retry and
  confirmation revalidate inside `BEGIN IMMEDIATE` before writing.
- Concurrency: open validates one deferred read snapshot across a concurrent
  confirmation; event rows, sequence high-water, trust bundle, row shape, and
  current state are exact.
- Existing database preflight: no-create and non-mutating for foreign, newer,
  nonempty zero-ID, and stale pristine databases; only valid KIRJ v1 or a real
  first initialization may enable and verify WAL/FULL before a fresh full
  transaction validation.

## API, Dependency, And Privacy Review

- `OwnerPublicKey` accepts only exact non-weak Ed25519 public keys and exposes no
  serde, default, private-key, key-generation, signing, or unchecked API.
- Production construction has no caller-selected path or entropy source.
  Isolated homes, deterministic entropy, and deterministic pause hooks are
  available only under the non-default `test-support` feature.
- Added direct dependencies are exactly `fs4 1.1.0` and `getrandom 0.4.3`;
  existing `directories 6.0.0` and `rusqlite 0.37.0` are reused. Rust 1.88 and
  dependency policy checks pass. Kirje source remains unsafe-free.
- Exact supplied mailbox-identifier and credential-pattern scans are clean.
  Fixtures contain no live address, endpoint, UID, mailbox content, private key,
  signature, proof, nonce, or provider response.

## Residual Ownership

T202B-T202E own challenge/proof/receipt, registry/transition,
claim/invocation/observation, and rotation/recovery/audit APIs on this exact
schema. T203 owns stronger same-user filesystem and anchor I/O hardening. The
pre-existing yanked protocol dependency remains visible for T209/T211 and is not
hidden by this acceptance.
