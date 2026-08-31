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

## A003 RED

The focused command was:

```text
cargo test -p kirje-store --test authority_registry \
  account_remove_transition_lifecycle_is_exact \
  --all-features --locked
```

The first run exited 101 at the cleanup-reservation builder's update-only
boundary. After admitting the sealed remove descriptor there, the second run
exited 101 at the intended create/update-only transition gate with
`authorization_context_stale`. The rejection fingerprint proved zero grant,
transition, cleanup, event, or clock writes.

## A003 Final GREEN

- Focused account-remove lifecycle: 1 passed, 0 failed after final review
  additions.
- Authority registry suite: 38 passed, 0 failed.
- `cargo test -p kirje-store --all-features --locked`:
  - crate unit tests: 8 passed;
  - authority authorization: 33 passed;
  - authority registry: 38 passed;
  - authority schema: 31 passed;
  - outbox: 11 passed;
  - doc tests: passed.
- `cargo test -p kirje-store --no-default-features --locked`: 19 passed across
  the enabled unit and outbox targets; feature-gated authority suites compiled
  and selected zero tests.
- `cargo clippy -p kirje-store --all-targets --all-features --locked -- -D warnings`:
  passed after final review additions.
- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.

The package test included the create-update-remove chain. Review then added one
more negative assertion for historical credential-ID reuse; the final focused
test and all-target Clippy run passed after that test-only addition.

The lifecycle covers prepare, exact retry, store-only config versioning,
finalize removal, abort receipt restoration, unsafe recovery, expiry restart,
cleanup material mismatch, prepare/commit/finalize fault rollback, display
reuse with fresh identities, old account and credential identity rejection,
valid removal after update, and cleanup tamper recovery.

## A003 Integrity

- Production commit: `703b5a1`.
- Authority SQLite v1 schema SHA-256 remains
  `5d01739b89246a5f495a965e57e416eee9fd0b5016995add41c6edee7f3e970d`.
- `Cargo.lock` SHA-256 remains
  `596ddb0071ecb38b0b9429c5d91cdbb83abe6a25bc760cf9588b2764274ff850`.
- Production scope contains only the packet-authorized authority source,
  registry test, and synthetic public-signature fixture.
- Privacy scan found no private key, seed, proof, nonce, real account data,
  address, endpoint, mailbox content, or provider data in the fixture or
  evidence.

## A004 RED

The focused command exited 101 at the intended account-only transition gate:

```text
cargo test -p kirje-store --test authority_registry \
  credential_set_transition_lifecycle_is_exact \
  --all-features --locked
```

The valid authorized credential-set prepare returned
`authorization_context_stale`. Its rejection fingerprint proved zero grant,
transition, credential, cleanup, version, event, or clock changes.

## A004 Final GREEN

- Focused credential-set lifecycle: 1 passed, 0 failed after final review
  replay assertions.
- `cargo test -p kirje-store --all-features --locked`:
  - crate unit tests: 8 passed;
  - authority authorization: 33 passed;
  - authority registry: 39 passed;
  - authority schema: 31 passed;
  - outbox: 11 passed;
  - doc tests: passed.
- `cargo test -p kirje-store --no-default-features --locked`: 19 passed across
  the enabled unit and outbox targets; feature-gated authority suites compiled
  and selected zero tests.
- `cargo clippy -p kirje-store --all-targets --all-features --locked -- -D warnings`:
  passed after final review assertions.
- `cargo fmt --all --check`: passed.
- `git diff --check`: passed.
- Delivery artifact validator: passed.

The package test included the production implementation and complete
credential-set lifecycle. Review then added exact abort and recovery terminal
replay assertions; the final focused test and all-target Clippy run passed after
that test-only addition.

The lifecycle covers prepare, config commit, finalize, exact retry, abort
receipt restoration, unsafe recovery, expiry restart, credential target
mismatch, prepare/commit/finalize fault rollback, existing credential history,
immutable account/store versions, no cleanup row, and transition-kind tamper.

## A004 Integrity

- Production commit: `1c6d7cb`.
- Authority SQLite v1 schema SHA-256 remains
  `5d01739b89246a5f495a965e57e416eee9fd0b5016995add41c6edee7f3e970d`.
- `Cargo.lock` SHA-256 remains
  `596ddb0071ecb38b0b9429c5d91cdbb83abe6a25bc760cf9588b2764274ff850`.
- Production scope contains only the packet-authorized authority source,
  registry test, and synthetic public-signature fixture.
- Privacy scan found no private key, seed, proof, nonce, credential bytes,
  locator material, real account data, address, endpoint, mailbox content, or
  provider data in the fixture or evidence.

## A005 RED

The valid focused command exited 101 at the intended unsupported transition
gate:

```text
cargo test -p kirje-store --test authority_registry \
  credential_delete_transition_lifecycle_is_exact \
  --all-features --locked
```

The authorized credential-delete prepare returned
`authorization_context_stale`. Its rejection fingerprint proved zero grant,
transition, credential, cleanup, version, event, or clock changes.

## A005 Final GREEN

- Focused credential-delete lifecycle: 1 passed, 0 failed.
- `cargo test -p kirje-store --all-features --locked`:
  - crate unit tests: 8 passed;
  - authority authorization: 33 passed;
  - authority registry: 40 passed;
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

The lifecycle covers the exact create-set-delete predecessor chain, prepare,
config commit, finalize, terminal replay, abort receipt restoration, unsafe
recovery, expiry restart, credential target mismatch, prepare/commit/finalize
fault rollback, permanent credential history, immutable account/store versions,
no cleanup row, and transition-kind tamper.

## A005 Integrity

- Production commit: `316dae0`.
- Authority SQLite v1 schema SHA-256 remains
  `5d01739b89246a5f495a965e57e416eee9fd0b5016995add41c6edee7f3e970d`.
- `Cargo.lock` SHA-256 remains
  `596ddb0071ecb38b0b9429c5d91cdbb83abe6a25bc760cf9588b2764274ff850`.
- Production scope contains only the packet-authorized authority source,
  registry test, and synthetic public-signature fixture.
- Privacy scan found no private key, seed, proof, nonce, credential bytes,
  locator material, real account data, address, endpoint, mailbox content, or
  provider data in the fixture or evidence.

## A006 RED

The focused command exited 101 at the intended unsupported cleanup gate:

```text
cargo test -p kirje-store --test authority_registry \
  credential_cleanup_challenge_is_exact \
  --all-features --locked
```

The valid request returned `authorization_context_stale` before cleanup
challenge support existed.

## A006 GREEN And Validation

- Focused cleanup challenge test: 1 passed, 0 failed, 44 filtered out.
- `cargo test -p kirje-store --all-features --locked`: unit 8,
  authorization 33, authority registry 45, schema 31, outbox 11, and doc tests
  passed.
- `cargo test -p kirje-store --no-default-features --locked`: 8 unit and 11
  outbox tests passed; feature-gated suites selected zero tests.
- All-target, all-feature Clippy with `-D warnings`: passed.
- `cargo fmt --all --check`: passed.
- Schema and `Cargo.lock` hashes remained unchanged.

## A006 Review Failure

Engineering passed with zero finding and noted residual missing legacy full-flow
proof. Spec compliance failed with 1 High and 1 Medium. QA failed with 4 Medium
findings. The High is an error-precedence/privacy defect: mixed invalid target
plus blocked/recovery state exposes target validity by returning
`credential_cleanup_invalid` before the required eligibility error. The five
Medium findings cover locator/legacy mutation discrimination, invalid expired-
replacement rollback, immutable clock/entropy/concurrency/response-loss
assertions, historical/restart-corruption matrices, and effect/external-call/
privacy proof.

A006 is Returned/Needs Fix at
`2241a946c399ba9c61e67e808a85f777c0d2b402`; passing commands do not override
the failed reviews. Autonomous execution stopped at that gate. The user
explicitly resumed A006 repair on 2026-08-31; F001 was submitted for independent
fix-packet review without code or fixture permission and has no new production
test result. That packet review returned engineering PASS
C0/H0/M0/L0, QA PASS C0/H0/M0/L0, and spec FAIL C0/H1/M2/L0. No implementation
attempt or production test followed; F001 is blocked for contract clarification
and the heartbeat is paused.

The user approved the F002 contract revision on 2026-08-31. F002 has no new
production RED/GREEN or validation result. Its packet review at `38ca4273`
returned QA PASS C0/H0/M0/L0, spec FAIL C0/H0/M1/L0, and engineering FAIL
C0/H1/M2/L0. The High is an internal call-order contradiction: complete global
history validation reads every cleanup/origin/locator graph, so a literal no-
private-read promise cannot follow that validation. A successor must preserve
step 2 and prove no request-directed private lookup or request-dependent private
branch after global validation. The Mediums are stale unreachable replacement
text in `data-model.md`, unresolved `transition_id=None` error/preflight
ownership, and a stale F001 review gate. F002 is blocked, the heartbeat is
paused, and production, test, and fixture permissions are none.

F003 was governance-only and had no production RED/GREEN or implementation.
Its packet review failed engineering C0/H1/M0/L0, spec C0/H0/M1/L0, and QA
C0/H0/M1/L0. No pass token or execution permission exists.

F004 was governance-only and had no production RED/GREEN result. Its packet
review failed on the cleanup-challenge phase-ordering High and supporting matrix,
effect, complete-gate, stale-authority-audit, and wording defects. No aggregate
severity counts were supplied and none are inferred. No implementation started.

F005 was governance-only and had no production RED/GREEN result. Its review
failed on public-row ambiguity, audit lifecycle/enumeration/parsing, workspace
handoff gates, and plan grammar. No aggregate counts are inferred.

F006 was governance-only and had no production RED/GREEN result. It gives
unrelated existing matched blocked and recovery-store pairs independent
`account_update_conflict` and `owner_recovery_required` results, with each
crossed against all six private-invalid cells. The pre-review audit requires the
21-path PENDING/none state; post-authorization requires normalized final tokens
without attempt evidence; post-integration requires 22 paths and structured
attempt/summary/test linkage, including execution authorization and governance
follow-up. Workspace test/Clippy/build join the gate. Cargo
deny remains the T111 baseline blocker and is not reported as passing. Existing
phase, preflight, numeric, fault, effect, privacy, and scope contracts remain.

F006 audit review failed on independently sourced path truth, exact-token self-
trapping, strict duplicate/contradiction parsing, phase permission/linkage, and
deterministic negative controls. No aggregate severity counts are inferred and
no production attempt started.

F007 is governance-only and has no production RED/GREEN result. It leaves every
substantive F006 contract and workspace gate unchanged. Its audit script owns
the attempted 21/22-path allowlists. Review failed/refused with exact counts:
spec C0/H0/M2/L1, engineering/security C0/H3/M2/L0, and QA C0/H4/M2/L1. No
execution authority or production attempt exists.

F008 is governance-only and has no production RED/GREEN result. It preserves
the substantive F006 contract, TDD matrix, workspace gates, and exact future
code scope. Review failed/refused with exact counts spec C0/H2/M2/L0,
engineering/security C0/H4/M1/L0, and QA C0/H4/M2/L0. No production attempt or
authorization exists.

F009 is governance-only and has no production RED/GREEN result. It retires the
bespoke A006 audit script and defines an immutable append-only P-A-C-I Git DAG.
Historical tokens and Markdown are inert evidence. The F006 contract, exact
three-file future scope, TDD matrix, complete workspace gates, and cargo-deny
T111 blocker remain unchanged. Production, test, and fixture permissions remain
none pending three packet reviews and a standalone authorization record.
