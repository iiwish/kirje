# T202C1 Test Results

## Test-First Attempts

- T202C1-A001: the initial registry target exited 101 because the request,
  projection, ten fault points, and `enroll_store` API were absent. A later
  focused RED reproduced pending-reuse rejection after sibling enrollment.
  GREEN reached 10 registry tests. Independent review found three Medium gaps:
  repeated full-table preflights caused quadratic restart work, one StoreRead
  error was mapped to stale context, and required security counterexamples were
  incomplete. The attempt was not accepted.
- T202C1-A002: M1 REDs exited 101 for the absent real-path query counter and
  then failed `2304 != 2560`; GREEN proved six preflights once, four streams,
  and `20 * 128` bounded indexed lookups. M2 RED exited 101 because the shared
  challenge-read fault was absent; GREEN retained StoreRead code/retryability.
  M3 RED exited 101 because post-commit expiry response loss was absent; GREEN
  added exact recovery and the missing lifecycle, corruption, alias-concurrency,
  and trait matrices. Independent review found two Medium test-discrimination
  gaps and one Low trait-scan gap. The attempt was not accepted.
- T202C1-A003: a structural RED proved the challenge-read fault bypassed the
  classifier; an old-mapping mutation then failed with stale instead of
  StoreRead. An occupancy-check mutation made a fresh alias request succeed and
  failed the zero-write test. A synthetic manual `Debug` implementation was not
  detected by the old trait gate. GREEN routed real and injected read results
  through one classifier, added fresh store-only/location-only issuance tests,
  and added a token-aware derive/manual trait scanner. Independent final review
  returned zero Critical, High, or Medium finding and one nonblocking Low item.

## Final Packet Gates

The orchestrator independently reran the final production tree:

```text
cargo fmt --all --check                                                    PASS
cargo test -p kirje-store --test authority_registry --all-features --locked
                                                                            PASS 15/15
cargo test -p kirje-store --test authority_authorization --all-features --locked
                                                                            PASS 33/33
cargo test -p kirje-store --test authority_schema --all-features --locked   PASS 27/27
cargo test -p kirje-store --all-features --locked                           PASS 94/94
cargo test -p kirje-store --no-default-features --locked                    PASS 19/19
cargo clippy -p kirje-store --all-targets --all-features --locked \
  -- -D warnings                                                             PASS
cargo +1.88 check -p kirje-store --all-features --locked                    PASS
canonical DDL SHA-256 gate                                                  PASS
```

## Repository Gates

```text
cargo test --workspace --all-features --locked                              PASS 203/203
cargo clippy --workspace --all-targets --all-features --locked \
  -- -D warnings                                                             PASS
cargo build --workspace --all-features --locked                             PASS
cargo deny check licenses bans sources                                      PASS
feature delivery artifact validator                                         PASS
tracked and untracked whitespace, scope, privacy, and secret checks          PASS
```

`cargo deny check advisories` reports only the pre-existing yanked
`chacha20 0.10.1` in the unchanged
`io-imap -> imap-codec -> imap-types -> rand` chain. No Cargo manifest,
lockfile, core contract, or DDL byte changed.

## Authorization And Transaction Matrix

- First use binds exact grant, receipt, action, target, manifest, store,
  canonical location digest, generation, and config digest. Raw observation
  time is absent from immutable identity and durable event time.
- Exact durable grant recovery precedes fresh expiry/current-context checks.
  Changed six-field replay fails, Used outranks later expiry, and no authority
  is refreshed.
- Authorized-unclaimed expiry commits one intent-bound event and paired clock
  before returning. Later observation advances only the clock pair; rollback,
  restart, concurrency, response loss, and changed-intent cases are covered.
- Six enrollment pre-commit and three expiry pre-commit faults roll back all
  rows, events, and clock changes. Both post-commit response-loss paths recover
  exact state. Enrollment consumes zero entropy on every path.
- Exact concurrency returns one durable state. Distinct receipts, store-ID-only,
  and location-only contenders have one winner; every loser is stable and has
  no grant.
- Fresh store/location occupancy is checked only when no exact pending challenge
  is reusable. Historical same- and different-context siblings remain valid.

## Restart, Performance, And Privacy

- Grant and store SQL class, length, range, digest, cross-link, current-config,
  duplicate/orphan event, event order, and every later-stage-table corruption
  fail closed without repair.
- `authorize A -> create B -> expire A` is legal at equal effective time;
  swapped, duplicate, omitted, or pre-authorization final-expiry events fail.
- The complete 128-row path records six preflights at one each, four registry
  streams, and 2,560 bounded keyed queries. The final worker run took 38.77s,
  40.82s wall, and 265,273,344 bytes maximum RSS; the validator retains no
  history-proportional collection.
- The synthetic fixture has SHA-256
  `8d71f00425d2d659dd7504bc79961387dacb2f7866545f501ac6e8af021f6a60`.
  It contains 132 clearly marked RFC8032 detached signatures and no signer,
  private seed, credential, account, endpoint, mailbox, UID, or real location.
- Request/projection scans and the token-aware trait gate found no Debug,
  Display, Serialize, JsonSchema, private material, SQL/path, logging, or unsafe
  exposure in the production surface.

## Review

- Packet rereview: `T202C1_A002_PACKET_REVIEW_PASS`.
- A001 code review: 0 Critical, 0 High, 3 Medium; no pass.
- A002 code review: 0 Critical, 0 High, 2 Medium, 1 Low; no pass.
- Final A003 code review: 0 Critical, 0 High, 0 Medium, 1 accepted Low;
  `T202C1_A003_CODE_REVIEW_PASS`.
