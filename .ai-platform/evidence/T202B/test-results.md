# T202B Test Results

## Test-First Attempts

- T202B-A001: core and store targets exited 101 because the sealed snapshot,
  proof codec, challenge, proof, receipt, nonce, and fault APIs did not exist.
  Initial GREEN reached 16 core and 16 authority tests. Independent review found
  three Medium gaps in inclusive reuse, replacement-event causality, and the
  security QA matrix, so the attempt was not accepted.
- T202B-A002: contract REDs reproduced exact-expiry reuse rejection, missing
  cross-challenge event ordering, and missing proof/expiry clock fault points.
  GREEN expanded authority coverage to 26 tests. Independent review found two
  Medium gaps: authorized-predecessor causality and a history-quadratic correlated
  validator query, so the attempt was not accepted.
- T202B-A003: schema RED passed 23 and failed 4 tests; lifecycle RED passed 24
  and failed 8 tests. Failures were exactly the missing created-event link,
  lifecycle index/inventory/hash, and causal validation. GREEN reached 27 schema
  and 32 authority tests with indexed streaming validation. Independent review
  found one Medium corruption-classification gap and one Low unproven crash
  boundary, so the attempt was not accepted.
- T202B-A004: a stale-handle orphan-event RED returned
  `authorization_malformed` instead of `owner_recovery_required`; a second RED
  proved the append-before-link fault point was absent. Both exited 101. Final
  GREEN reached 33 authority tests, and independent review found zero Critical,
  High, Medium, or Low issue.

## Packet Gates

The orchestrator independently reran the final tree:

```text
cargo fmt --all --check                                                    PASS
cargo test -p kirje-core --test authorization_contract --all-features --locked
                                                                            PASS 16/16
cargo test -p kirje-store --test authority_authorization --all-features --locked
                                                                            PASS 33/33
cargo test -p kirje-store --test authority_schema --all-features --locked   PASS 27/27
cargo test -p kirje-core -p kirje-store --all-features --locked             PASS 142/142
cargo test -p kirje-store --no-default-features --locked                    PASS 19/19
cargo clippy -p kirje-core -p kirje-store --all-targets --all-features \
  --locked -- -D warnings                                                    PASS
cargo +1.88 check -p kirje-core -p kirje-store --all-features --locked      PASS
canonical DDL SHA-256 gate                                                  PASS
```

## Repository Gates

```text
cargo test --workspace --all-features --locked                              PASS
cargo clippy --workspace --all-targets --all-features --locked \
  -- -D warnings                                                             PASS
cargo build --workspace --all-features --locked                             PASS
cargo deny check licenses bans sources                                      PASS
feature delivery artifact validator                                         PASS
tracked and untracked diff whitespace checks                                PASS
```

`cargo deny check advisories` reports the pre-existing yanked
`chacha20 0.10.1` in the unchanged
`io-imap -> imap-codec -> imap-types -> rand` chain. No Cargo or lockfile byte
changed in T202B.

## Authorization And Persistence Matrix

- Stage support is exactly `store_enroll`, `owner_rotate`, `recovery_rotate`,
  and `owner_recover`; deferred actions, stale manifests, and rejected actions
  consume no entropy and write nothing.
- A committed challenge consumes 48 random bytes; a first valid proof consumes
  16. Exhaustion, grant/nonce/receipt collisions, reuse, replay, expiry,
  deterministic rejection, and concurrency loser paths have exact tested
  entropy accounting and atomic rollback.
- Exact receipt replay retains immutable identity and may update only the paired
  authority clock. Changed replay fails. Expired pending proof commits one exact
  expiry event before returning the stable error and cannot be revived.
- Created-event linkage, authorized/expired lifecycle ordering, legal trailing
  pending state, orphan events, invalidated state, conflicting terminal events,
  bounded SQL classes/lengths, every later-stage table, and recomputed proof or
  receipt mutation fail closed.
- Query plans use
  `authorization_challenges_context_created_sequence` and
  `authority_events_entity_sequence`, with no correlated full scan or temporary
  history collection.
- Fault points cover challenge insert, clock, event append, link update, event
  completion, before/after commit, receipt, nonce, authorized/expired state,
  proof/expiry clock, and terminal events. Response-loss retries recover exact
  durable state.

## API, Privacy, And Review

- Core owns manifest, payload, proof, target, effect, policy, and transcript
  interpretation. Store contains no second parser or caller-selected trust
  context.
- `AuthorizationProof` fields are private and have no signature-bearing Debug.
  Ordinary receipt, status, error, and log surfaces omit proof, signature,
  nonce, manifest, signing bytes, realm, key bytes, SQL, and path data. The
  bounded owner challenge export is the only explicit signing-artifact output.
- Scans found no supplied mailbox identifier, credential, private key or seed,
  provider response, logging macro, or Kirje `unsafe` block in changed scope.
- Independent packet feasibility review and final code review both ended with
  zero Critical, High, or Medium issue; the final A004 review also found zero
  Low issue.
