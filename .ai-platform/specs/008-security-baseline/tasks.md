# Work Graph: Security Baseline

## Metadata

- Feature ID: `008-security-baseline`
- Status: Confirmed
- Target checkpoint: `v1.0.0-alpha.1`
- Source: `spec.md`, `plan.md`, `research.md`, `data-model.md`, `contracts/**`
- Updated: 2026-08-30
- Review authority: delegated project owner

## Scheduling Rules

- Accepted tasks T201, T202A, T202B, T202C1, and T202C1S retain their exact
  commit and evidence identity.
- The v1 program work graph in `../007-stable-v1-program/tasks.md` owns
  executable batching, checkpoint output, and Git handoff. Remaining task
  blocks in this document are binding security acceptance coverage and may be
  satisfied by one of the bounded T101 batches without an independent release
  program or PR per block.
- Read-only research and independent review may run in parallel.
- Every executable production batch needs a self-contained packet and verified
  RED evidence before implementation.
- A worker executes one task/attempt, edits only allowed files, does not delegate,
  and does not mark the task Accepted.
- The orchestrator performs scope, spec, engineering, and QA review and writes
  evidence after each attempt.
- No task may expose credentials, owner private keys, signatures, mailbox
  content, account addresses, endpoints, UIDs, or raw provider responses in
  committed fixtures/evidence.
- T202 is an acceptance umbrella, not an implementation packet. Its remaining
  acceptance coverage is mapped into T109-T112. The umbrella becomes
  Accepted only after its complete contract, review, and evidence pass.
- T204-T212 each require the T202 umbrella to be Accepted, in addition to their
  direct predecessor dependencies.
- T212 begins only after T201-T211 have no blocking findings.

## T201: Core Security Contracts

Status: Accepted
Priority: P0
Story / Requirement: US-001, US-003, US-005; FR-001, FR-002, FR-013-FR-015,
FR-017, FR-022, FR-024, FR-027-FR-030; NFR-001, NFR-002, NFR-004, NFR-006, NFR-007
Depends on: Confirmed 008 spec, plan, checklist, and analysis
Blocks: T202-T212
Parallel: No
Conflicts with: Every task changing core public models, error codes, limits, or
workspace cryptographic dependencies

Goal:
Define stable typed identities, account-binding transcript, exhaustive sensitive
action map, canonical manifest/authorization transcripts, proof/receipt
projections, bounded untrusted values, authorization-aware operation states,
stable security error codes, and bounded typed deserialization for shared mail
and authorization requests.

Allowed files:
- `Cargo.toml`
- `Cargo.lock`
- `crates/kirje-core/Cargo.toml`
- `crates/kirje-core/src/lib.rs`
- `crates/kirje-core/src/account.rs`
- `crates/kirje-core/src/authorization.rs`
- `crates/kirje-core/src/bounded.rs`
- `crates/kirje-core/src/input.rs`
- `crates/kirje-core/src/mail.rs`
- `crates/kirje-core/src/operation.rs`
- `crates/kirje-core/src/send.rs`
- `crates/kirje-core/tests/**`

Forbidden changes:
- Filesystem, SQLite, keyring, CLI, MCP, or network behavior
- Production signing-key generation or private-key parsing
- Permissive Ed25519 verification or generic JSON/TOML signing
- New mailbox effects

Test targets:
- Golden account-binding bytes/digests, host/IP equivalence, and every-field
  mutation
- Golden action manifests/signing transcripts and parser rejection matrix
- RFC8032/strict Ed25519 verification vectors, wrong key/signature, and
  malleability cases
- Exhaustive action policy and future-unmapped fail-closed compile/contract test
- Proof/status schema privacy and bounded untrusted-value semantics
- Typed JSON depth/string/list/Base64/decoded-total N/N+1 and allocation tests
- Sealed typed `parse_bounded_json` coverage for SendRequest,
  DraftInput/MessageContent, mailbox/search/sync/read requests, and
  AuthorizationProof; config/file/MCP adapters remain later tasks
- Stable error-code/retryability snapshot
- Pure `PlatformLocationMaterial -> KIRJE-CONFIG-LOCATION-V1` byte/digest
  goldens; no filesystem access in core

Deliverables:
- Core identity/account/authorization/bounded modules, sealed typed manifest
  payloads, bounded request deserializers, and golden contract tests
- Locked strict-verifier/randomness dependencies and public schema snapshots

Acceptance criteria:
- Every mapped core requirement has an executable passing contract test.
- No core API can sign, access local state, authorize an unmapped action, or
  construct a manifest for an explicitly unsupported action.
- `ManifestSupport::UnsupportedCapability` has no payload/encoder/parser path
  and returns stable `unsupported_capability`.

TDD plan:
- RED: Add golden and mutation tests that fail because v0.3 has no stable
  identities, transcripts, strict signature verifier, or closed action map.
- GREEN: Implement the minimum provider-neutral contracts and strict parsers.
- REFACTOR: Consolidate tagged transcript helpers only after all byte-golden and
  tamper tests remain green.

Validation commands:
```bash
cargo test -p kirje-core --all-features --locked
cargo clippy -p kirje-core --all-targets --all-features --locked -- -D warnings
```

Definition of Done:
- Core compiles without filesystem/network dependencies.
- Every transcript is byte-for-byte golden and independently parsable.
- Shared mail/authorization JSON cannot allocate collections or decoded content
  beyond its typed field and total budgets before rejection.
- `verify_strict` is the only production signature verification path.
- Every sensitive action maps exhaustively; supported encoders are sealed and
  unsupported/unrecognized serialized values fail.
- Public security outputs omit proof/signature/locator/private material.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T201.yaml`

Evidence required:
- `.ai-platform/evidence/T201/summary.md`
- RED/GREEN command results, changed-file list, dependency feature/MSRV review,
  spec and engineering reviews

## T202: Pinned Authority Store Umbrella

Status: Draft
Priority: P0
Story / Requirement: US-003; FR-012-FR-019; NFR-001-NFR-003, NFR-006,
NFR-007
Depends on: T201 Accepted; T202A-T202E Accepted for umbrella acceptance
Blocks: T204-T212
Parallel: No
Conflicts with: Every authority schema, bootstrap, trust, receipt, nonce,
registry, transition, grant, claim, invocation, observation, rotation, recovery,
or authority-event change

Goal:
Aggregate the strictly serial T202A-T202E implementation and evidence into one
accepted pinned-authority-store boundary. The umbrella performs no direct code
change and grants no dependency release until all child tasks pass review and
receive evidence-based acceptance from the delegated project owner.

Allowed files:
- No direct implementation files; each child owns its exact allowed files.
- Status/evidence integration uses this `tasks.md` block and the declared T202
  evidence path only in the acceptance attempt.

Test targets:
- Combined schema/bootstrap, proof/replay, registry/transition, claim/invocation/
  observation, rotation/recovery/audit, restart, concurrency, and privacy gates
- Child evidence completeness and same-schema compatibility across T202A-T202E

Deliverables:
- One reviewed authority SQLite v1 implementation and aggregate acceptance record

Acceptance criteria:
- T202A-T202E are Accepted with no unresolved Critical/High finding.
- Fresh combined store/core validation uses the bootstrap structure created by
  T202A and the sole pre-release lifecycle column/index amendment owned by T202B.

TDD plan:
- RED: Child tasks own behavior RED evidence; umbrella review fails while any
  child evidence or combined gate is missing.
- GREEN: Integrate only accepted child evidence and run the complete validation.
- REFACTOR: None; fixes return to the owning child attempt.

Validation commands:
```bash
cargo test -p kirje-core -p kirje-store --all-features --locked
cargo clippy -p kirje-core -p kirje-store --all-targets --all-features --locked -- -D warnings
```

Definition of Done:
- T202E completes the aggregate review, the orchestrator records delegated
  project-owner acceptance from passing evidence, and T204-T212 may observe
  `T202 Accepted`.
- The umbrella is not Accepted from child status inference alone.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T202.yaml`

Evidence required:
- `.ai-platform/evidence/T202/summary.md`
- Child evidence links, combined command results, schema identity, privacy scan,
  spec/security/engineering/QA reviews, and residual risk

### T202A: Schema And Bootstrap

Status: Accepted
Priority: P0
Story / Requirement: US-003; FR-012, FR-018; NFR-001-NFR-003, NFR-006,
NFR-007
Depends on: T201 Accepted
Blocks: T202B; T202 umbrella acceptance
Parallel: No
Conflicts with: T202B-T202E and every authority schema/home/bootstrap/entropy
change

Goal:
Add the minimal validated core `OwnerPublicKey`, create the complete executable
authority SQLite v1 schema transaction body, and implement only the fixed
production home, isolated `test-support` home, application/version preflight,
CSPRNG boundary, typed anchor/location input, DB-first `prepare_bootstrap`, exact
`confirm_anchor`, clock high-water, and T202A open match matrix. Any staged row or
staged anchor is recovery-required in A. Later canonical tables exist but have no
operational APIs.

Allowed files:
- `Cargo.toml`
- `Cargo.lock`
- `crates/kirje-core/src/authorization.rs`
- `crates/kirje-core/tests/authorization_contract.rs`
- `crates/kirje-store/Cargo.toml`
- `crates/kirje-store/src/lib.rs`
- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/src/authority/schema_v1.sql`
- `crates/kirje-store/tests/authority_schema.rs`
- `crates/kirje-store/tests/fixtures/authority/schema/**`

Test targets:
- `OwnerPublicKey` exact-32-byte parse/non-weak construction, borrowed public
  bytes/equality, malformed/weak rejection, and absence of default/serde/private-
  key/signing APIs; malformed/weak/equal role keys return non-retryable
  `authorization_malformed` before side effects
- `application_id=0x4B49524A`, user version 1, pristine zero-ID initialization,
  foreign/nonzero/zero-nonempty/newer rejection, all required pragmas
- Executable full-schema body/digest and raw-SQL NULL/storage-class/length/range/
  enum/FK/ordinal/field-relation/partial-index negatives for every table
- One outer `BEGIN IMMEDIATE` owns schema, initial keys/epoch/meta/event,
  application ID/version, and commit; injected rollback leaves zero user objects,
  rows, application ID, and user version
- Valid minimal relationship chains plus receipt, nonce use, grant use,
  challenge-effect/remote-effect, effect-claim, invocation, and observation
  cross-link negatives; foreign-key/integrity checks and declared-index inventory
- Unique public keys, distinct owner/recovery identities, exact role/mask checks,
  epoch-to-stored-role cross-reference rejection, exact active initial keys/epoch
  1, initial-staged key or epoch rejection, and checked exact successor plus
  epoch-gap rejection
- Production home has no path/env/CLI-capable constructor; complete isolated
  home and deterministic entropy require non-default `test-support`
- OS CSPRNG identity generation, commit stability, restart and concurrent
  bootstrap winner reuse
- `prepare_bootstrap`/create-only-anchor/`confirm_anchor` crash points and every
  absent/pending/ready/active/third-state matrix row; every staged row or staged
  anchor maps to `recovery_required`, never `staged_finalize_required`
- Trust-bundle and journal-location digest goldens, key role/hash, minimum epoch,
  clock rollback 30s/N+1 and high-water max behavior

Deliverables:
- Minimal core `OwnerPublicKey`; complete authority v1 DDL transaction body;
  schema/open validation, authority-home types, typed bootstrap/anchor snapshots,
  entropy and clock boundaries
- Schema/bootstrap fixtures with no later proof/registry/effect implementation

Acceptance criteria:
- A pristine DB can reach `pending_anchor` then `ready` only through the exact
  two-phase protocol; crash recovery never regenerates committed identities.
- Every invalid application/schema/anchor/location/epoch/type relationship fails
  before credential or network access.
- SQLite rejects cross-linked durable chains without relying on application-only
  comparisons, and T202A fails closed on every staged state.

TDD plan:
- RED: Add core public-key contract tests, schema-body/digest/object tests,
  raw-SQL invalid-row and cross-link tests, outer-transaction rollback,
  constructor-surface, bootstrap crash, staged fail-closed, mismatch, entropy,
  restart, concurrency, and clock tests against the missing authority store.
- GREEN: Implement schema/preflight and one bootstrap transaction at a time; do
  not add challenge, registry, claim, or rotation APIs.
- REFACTOR: Extract checked row/pragma codecs only after schema and crash matrix
  remain green.

Validation commands:
```bash
cargo test -p kirje-core --test authorization_contract --all-features --locked
cargo test -p kirje-store --test authority_schema --all-features --locked
cargo test -p kirje-core -p kirje-store --all-features --locked
cargo clippy -p kirje-core -p kirje-store --all-targets --all-features --locked -- -D warnings
```

Definition of Done:
- The checked-in schema dump equals the canonical DDL and is complete for B-E.
- The DDL contains no transaction control/PRAGMA, one outer bootstrap transaction
  rolls back to zero objects/rows/version, and composite-FK cross-link negatives
  plus valid chains, foreign-key check, integrity check, and index inventory pass.
- `OwnerPublicKey` rejects malformed/weak values, bootstrap rejects equal keys,
  all with `authorization_malformed`; SQL rejects equal public keys, wrong
  epoch-to-stored-role references, initial staged keys/epoch, and epoch gaps
  without a core Cargo change.
- Production API accepts no ordinary path or entropy injection; test support is
  explicit, non-default, and requires a complete isolated home.
- RED/GREEN, restart/concurrency, bootstrap matrix, schema privacy, and review
  evidence have no blocking finding.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T202A.yaml`

Evidence required:
- `.ai-platform/evidence/T202A/summary.md`
- RED/GREEN logs, schema dump/digest, raw-SQL constraint matrix, bootstrap fault
  matrix, constructor/API review, privacy scan, and residual risk

### T202B: Challenges, Proofs, And Receipts

Status: Accepted
Priority: P0
Story / Requirement: US-003; FR-013-FR-015, FR-018; NFR-001-NFR-003,
NFR-006, NFR-007
Depends on: T202A Accepted
Blocks: T202C; T202 umbrella acceptance
Parallel: No
Conflicts with: T202A/T202C-T202E and core/store authorization payload,
challenge, proof, receipt, nonce, or replay behavior

Goal:
Add the read-only typed core authorization projection, then implement challenge
creation, pending-context uniqueness, strict proof verification, canonical proof
and receipt transcripts, nonce consumption, exact replay, clock/expiry behavior,
and bounded private/public projections without a store-local parser. In B,
challenge issuance is limited to store enrollment and the three trust actions;
T202C expands registry-backed account, credential, cleanup, send, and mailbox
issuance, T202D adds `ambiguous_close` issuance, and T202E owns replay after
finalized rotation/invalidation.

Allowed files:
- `crates/kirje-core/src/authorization.rs`
- `crates/kirje-core/tests/authorization_contract.rs`
- `crates/kirje-store/src/lib.rs`
- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/src/authority/schema_v1.sql`
- `crates/kirje-store/tests/authority_schema.rs`
- `crates/kirje-store/tests/authority_authorization.rs`
- `crates/kirje-store/tests/fixtures/authority/authorization/**`

Test targets:
- `AuthorizationPayloadSnapshot`, optional `AuthorizationEffectSnapshot`, target
  kind/canonical bytes/closed display, sealed manifest payload access, borrowed
  private bytes, core proof codec, no second parser
- Stage support matrix: store enrollment and three trust actions succeed only
  against exact current/absence state; registry/effect actions fail context-stale
  with zero entropy/write; policy/assurance remain unsupported
- Challenge context transcript/digest and partial pending uniqueness under NULL-
  shaped optional context, exact action/effect/ordinal matrix, 48-byte entropy,
  duplicate reuse, expiry-and-recreate, restart and concurrent winner
- Proof/receipt byte goldens and every field mutation, malformed/wrong role/key/
  signature/manifest/payload/epoch/bundle/anchor/time case
- First proof, exact replay after restart/expiry, changed replay, clock-only
  replay high-water, nonce/challenge corruption, concurrent proof winner
- Effective-time inclusive expiry, 30s/N+1 rollback/issuance skew, monotonic
  high-water pair, committed-expiry exact retry/response-loss recovery, no TTL
  extension or revival
- Exact ready-bootstrap prefix, B causal row graphs, fixed event numeric/detail
  mapping, persisted created-event linkage, non-overlapping same-context
  lifecycle intervals, contiguous sequence/high-water, corruption and bounded
  BLOB loading
- Explicit bounded owner challenge export, receipt target/state projection
  (`Unclaimed`/`Expired` in B), and ordinary output omission of proof/signature/
  nonce/manifest/realm/location material

Deliverables:
- Typed core read-only projection and challenge/proof/receipt/nonce store APIs
- Canonical transcript, event, replay, fault, concurrency, and projection fixtures

Acceptance criteria:
- Store persistence consumes the core snapshot and cannot duplicate or reinterpret
  authorization tags/action policy.
- One first proof creates exactly one immutable receipt/nonce use; historical
  exact replay returns it without fresh authority.
- Restart-open validates every B row/event causally while retaining the exact
  initial trust-root constraints and the canonical lifecycle index.

TDD plan:
- RED: Add accessor/sealing compile tests, transcript mutations, stage-support,
  full replay/effective-time matrix, restart/concurrency/fault, causal corruption,
  bounded-load, event, and output-privacy failures.
- GREEN: Expose the minimum read-only core projection and implement one proof
  transaction against the canonical v1 schema with exact created-event linkage.
- REFACTOR: Consolidate transcript builders only after independent byte goldens
  and parser-nonduplication review pass.

Validation commands:
```bash
cargo test -p kirje-core --test authorization_contract --all-features --locked
cargo test -p kirje-store --test authority_authorization --all-features --locked
cargo test -p kirje-store --test authority_schema --all-features --locked
cargo test -p kirje-core -p kirje-store --all-features --locked
cargo test -p kirje-store --no-default-features --locked
cargo clippy -p kirje-core -p kirje-store --all-targets --all-features --locked -- -D warnings
cargo +1.88 check -p kirje-core -p kirje-store --all-features --locked
test "$(shasum -a 256 crates/kirje-store/src/authority/schema_v1.sql | cut -d ' ' -f1)" = "572a73ba5fa83c763188d804ce9767a3c21373410d8b170f6d97b49be0a86454"
```

Definition of Done:
- Projection ownership, proof/receipt bytes, exact replay truth table, nonce
  uniqueness, stage support, effective clock bounds, event/causal validation,
  crash recovery, and public omission are executable and reviewed.
- The canonical v1 schema has exactly one additive challenge lifecycle column
  and one declared lifecycle index, with unchanged application ID/user version,
  tables, triggers, and trust-root semantics.
- Real post-rotation/invalidation replay remains explicitly assigned to T202E.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T202B.yaml`

Evidence required:
- `.ai-platform/evidence/T202B/summary.md`
- RED/GREEN logs, byte goldens, replay/concurrency matrix, core API review,
  private-output scan, and residual risk

### T202C: Store/Account Registry And Transitions Umbrella

Status: Draft
Priority: P0
Story / Requirement: US-001, US-003; FR-003-FR-009, FR-016; NFR-001-NFR-003,
NFR-006, NFR-007
Depends on: T202B Accepted; T202C1, T202C1S, and T202C2-T202C4 Accepted
Blocks: T202D; T202 umbrella acceptance
Parallel: No
Conflicts with: T202A-T202B/T202D-T202E and every registry, transition, cleanup,
location, generation, credential, display-identity, or registry-backed challenge
rule

Goal:
Accept the complete T202C security slice only after five strict serial production
tasks prove grant consumption and store enrollment, immutable registry-version
parentage, account creation, remaining
account/credential/cleanup transitions, and remote challenge issuance against
the corrected pre-release canonical Authority SQLite v1 schema.

Acceptance criteria:
- Store/location/account/credential/display mappings cannot alias or be replaced
  by changed retry, restart, crash, or concurrency.
- Every transition resolves only to the exact before or after snapshot, or enters
  recovery; removed history and cleanup evidence remain immutable.
- Every T202C control action has registry-backed challenge issuance and every
  remote action has exactly one planner-owned ordinal-zero challenge effect.
- T202C1, T202C1S, and T202C2-T202C4 evidence, independent reviews, aggregate
  registry/event restart validation, privacy review, canonical DDL hash, and
  package gates are green.

Packet path:
- None; T202C is an acceptance umbrella and has no production packet.

Evidence required:
- `.ai-platform/evidence/T202C/summary.md`
- Child evidence index, aggregate schema/event/privacy/gate review, and residual
  risk handoff to T202D

### T202C1: Grant Use And Store Enrollment

Status: Accepted
Priority: P0
Story / Requirement: US-003; FR-003, FR-016, FR-018; NFR-001-NFR-003,
NFR-006, NFR-007
Depends on: T202B Accepted at production commit `43f0788`
Accepted at: production commit `aa53efb`; evidence in `.ai-platform/evidence/T202C1/`
Blocks: T202C1S; T202C umbrella acceptance
Parallel: No
Conflicts with: T202C2-T202C4/T202D-T202E and every grant-use, store registry,
authority clock, authority event, or restart-validator rule

Goal:
Implement the exact canonical grant-use substrate and owner-authorized config
store enrollment in one transaction. Consume the existing T202B `store_enroll`
receipt, bind one store ID to one bounded private location identity and exact
config generation/digest, preserve immutable use/enrollment evidence, and expand
the restart validator only for these two row kinds and events.

Allowed files:
- `crates/kirje-store/src/lib.rs`
- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/tests/authority_registry.rs`
- `crates/kirje-store/tests/fixtures/authority/registry/store_enrollment/**`

Test targets:
- Grant-use transcript byte golden, parse/recompute, exact first use, exact
  committed recovery after expiry/restart, changed retry, and first-use expiry
- Store-derived effective use time under tolerated raw clock rollback and an
  exact time-independent enrollment-intent digest for no-grant expiry recovery
- Store-enroll first/retry, both-direction store/location uniqueness, changed
  config/receipt/location retries, bounded location material, and exact receipt,
  target, manifest, anchor, key, epoch, bundle, clock, and config linkage
- One transaction and one fixed apply lock across grant row/event, store row/event,
  clock update, commit-before-response loss, deterministic fault points, and
  concurrent/stale-handle winner behavior
- Streaming bounded restart validation for grant/store rows and event graph;
  every account/effect/transition/cleanup/rotation row remains rejected
- Same/different-context authorized/pending siblings after one enrollment,
  replacement-terminal versus final-expiry ordering, and 128-or-more complete
  legal histories with indexed EXPLAIN plans and O(1) additional memory
- Public projection, stable-error, ordinary-output, log, SQL/path, location,
  manifest/proof/signature/nonce, and real-account privacy scans

Deliverables:
- Typed `GrantUseRequest` and `EnrollStoreRequest` plus a bounded public store
  projection with no private location or authorization bytes
- Canonical `KIRJE-GRANT-USE-V1` durable transcript and exact immutable row checks
- Atomic enrollment API, fault hooks, event insertion, and restart validator

Acceptance criteria:
- No first use succeeds after immutable receipt expiry or against stale/mismatched
  authority context; an exact committed retry returns the historical same use and
  store projection without refreshing authority.
- Store ID and location digest are globally one-to-one and immutable; neither a
  changed retry nor a concurrent contender can claim either identity.
- T202B behavior remains green and canonical schema bytes do not change.

TDD plan:
- RED: Add missing API/transcript, expiry/replay, uniqueness, crash, concurrency,
  event, corruption, bounded-load, and privacy tests; confirm contract-relevant
  failures before production edits.
- GREEN: Add the minimum typed transaction and incremental validator/event support.
- REFACTOR: Share exact row/transcript helpers only after all RED targets pass.

Validation commands:
```bash
cargo test -p kirje-store --test authority_registry --all-features --locked
cargo test -p kirje-store --test authority_authorization --all-features --locked
cargo test -p kirje-store --test authority_schema --all-features --locked
cargo test -p kirje-store --all-features --locked
cargo test -p kirje-store --no-default-features --locked
cargo clippy -p kirje-store --all-targets --all-features --locked -- -D warnings
cargo +1.88 check -p kirje-store --all-features --locked
test "$(shasum -a 256 crates/kirje-store/src/authority/schema_v1.sql | cut -d ' ' -f1)" = "572a73ba5fa83c763188d804ce9767a3c21373410d8b170f6d97b49be0a86454"
```

Definition of Done:
- Grant use, store enrollment, exact recovery, concurrency, fault, event, restart,
  corruption, boundedness, privacy, no-default-features, MSRV, and schema-hash
  gates pass with no Cargo, core, runtime, CLI, MCP, protocol, or DDL change.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T202C1.yaml`

Evidence required:
- `.ai-platform/evidence/T202C1/summary.md`
- RED/GREEN logs, byte golden, replay/expiry/uniqueness/fault/concurrency/event/
  restart matrices, privacy scan, and residual risk

### T202C1S: Immutable Registry Version Schema Correction

Status: Accepted
Priority: P0
Story / Requirement: US-001, US-003; FR-003-FR-006, FR-016, FR-018;
NFR-001-NFR-003, NFR-006, NFR-007
Depends on: T202C1 Accepted at production commit `aa53efb`
Accepted at: production commit `8eceaff`; evidence in `.ai-platform/evidence/T202C1S/`
Blocks: T202C2; T202C umbrella acceptance; T202D
Parallel: No
Conflicts with: T202C2-T202E and every authority schema, store enrollment,
registry identity, remote-effect relationship, or restart-validator rule

Goal:
Correct the unreleased canonical Authority SQLite v1 before account mutations
exist. Add immutable credential, store-version, and account-version parents;
point historical remote effects at immutable versions rather than mutable
current projections; and evolve accepted store enrollment to create and recover
its initial store version atomically. Keep the application ID and user version
at v1 and fail closed on every earlier developer-only inventory.

Allowed files:
- `crates/kirje-store/src/authority/schema_v1.sql`
- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/tests/authority_schema.rs`
- `crates/kirje-store/tests/authority_registry.rs`

Test targets:
- RED demonstrating that a remote effect linked to immutable version parents
  remains valid while legal current store/account tuples advance, whereas the
  old current-parent shape would reject those updates
- Exact 20-table canonical object inventory, unchanged explicit index/trigger,
  application-ID/user-version/bootstrap semantics, and noncanonical old-shape
  fail-closed behavior with no migration or repair
- Credential global identity/account/store/creating-transition linkage;
  store-version exact receipt-or-transition origin and generation order;
  account-version exact credential/account/transition linkage
- Missing, duplicate, cross-store, cross-account, cross-credential,
  cross-transition, and mutable-current-only remote-effect parent rejection
- Initial store version inserted in the enrollment transaction, every fault and
  response-loss boundary, exact retry after restart/concurrency, and no second
  immutable row/event/clock timestamp
- T202A/T202B empty-stage regressions and T202C1 store/version/grant/event
  restart validation, bounded row loading, affine query count, and query plans
  using store-version primary-key order with no temporary B-tree
- Public/API/privacy scan proving no new authority mutation surface, output,
  migration, secret, address, endpoint, mailbox, or signing material

Validation commands:
```bash
cargo test -p kirje-store --test authority_schema --all-features --locked
cargo test -p kirje-store --test authority_registry --all-features --locked
cargo test -p kirje-store --test authority_authorization --all-features --locked
cargo test -p kirje-store --all-features --locked
cargo test -p kirje-store --no-default-features --locked
cargo +1.88.0 test -p kirje-store --all-features --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --locked
test "$(shasum -a 256 crates/kirje-store/src/authority/schema_v1.sql | cut -d ' ' -f1)" = "5d01739b89246a5f495a965e57e416eee9fd0b5016995add41c6edee7f3e970d"
```

Definition of Done:
- Historical remote-effect FKs terminate only at immutable version rows and no
  longer block current registry evolution.
- Accepted enrollment atomically creates and exactly recovers one initial store
  version; restart validates all new parents and preserves T202A-T202C1 behavior.
- Canonical DDL bytes, object inventory, query plans, RED/GREEN evidence, full
  gates, independent zero-finding review, and the pre-release no-migration
  boundary are recorded.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T202C1S.yaml`

Evidence required:
- `.ai-platform/evidence/T202C1S/summary.md`
- RED/GREEN logs, canonical DDL digest/inventory, relationship and current-row
  evolution matrix, enrollment crash/retry matrix, query plans, privacy review,
  and residual risk

### T202C2: Account Creation Transition

Status: Accepted
Execution state: T109 review and fresh validation completed with three scoped
RED/GREEN fixes and no unresolved Critical or High finding. The user accepted
production commit `94f3495` on 2026-08-30.
Packet review: `T202C2_A006_PACKET_REVIEW_PASS` with zero Critical, High,
Medium, or Low findings
Priority: P0
Story / Requirement: US-001, US-003; FR-003-FR-006, FR-016; NFR-001-NFR-003,
NFR-006, NFR-007
Depends on: T202C1S Accepted
Blocks: T202C3; T202C umbrella acceptance
Parallel: No
Conflicts with: T202C1-T202C1S/T202C3-T202C4/T202D-T202E and every account-create,
account registry, display identity, transition, or registry challenge rule

Goal:
Expand challenge issuance for exact registry-backed `account_create`, then
implement create prepare/config-committed/finalize/abort/recovery transitions
that reserve account, credential, and active display identities before config or
keyring work and recover only from exact before/after config snapshots.

Allowed files:
- `crates/kirje-store/src/lib.rs`
- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/tests/authority_registry.rs`
- `crates/kirje-store/tests/fixtures/authority/registry/account_create/**`

Test targets:
- Registry-backed create challenge exact context, pending reuse/restart/
  concurrency, stale store/config/binding rejection, and zero challenge effects
- Global account/credential uniqueness, active display partial-index behavior,
  exact display/transition/intent/recovery bytes and digests, exact next
  generation, one active store transition, and exact retry
- Prepare-before-config blocking, config-committed/finalize/abort/recovery fault
  boundaries, before/after/third digest restart matrix, and no external calls
- Deferred cyclic-FK closure, expiry response loss, event graph, corruption,
  immutable enrollment retry after current-state evolution, 128-history
  affine-query streaming restart validation, query plans, and privacy

Validation commands:
```bash
cargo test -p kirje-store --test authority_registry --all-features --locked
cargo test -p kirje-store --test authority_authorization --all-features --locked
cargo test -p kirje-store --test authority_schema --all-features --locked
cargo test -p kirje-store --all-features --locked
cargo test -p kirje-store --no-default-features --locked
cargo clippy -p kirje-store --all-targets --all-features --locked -- -D warnings
cargo fmt --all --check
cargo test --workspace --all-features --locked
cargo +1.88.0 test -p kirje-store --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --all-features --locked
```

Definition of Done:
- Account-create issuance and transition lifecycle are exact, crash-safe,
  idempotent, private, and schema-preserving.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T202C2.yaml`

Evidence required:
- `.ai-platform/evidence/T202C2/summary.md`
- RED/GREEN logs, canonical byte goldens, identity/concurrency/expiry and
  transition fault matrices, schema/hash and no-default/MSRV regressions,
  restart/query-plan/event/privacy review, and residual risk

### T202C3: Account Credential And Cleanup Lifecycles

Status: Running
Execution state: `T202C3-A001` completed review at production commit `daf22a0`.
It owns effect-free challenge issuance for account update/remove and credential
set/delete. `T202C3-A002` is accepted at production commit `2c00f32` and owns
the exact account-update transition plus provisional-to-ready cleanup rows.
Account remove is the active bounded attempt; credential transitions and
cleanup claim/delete remain later serial attempts.
Priority: P0
Story / Requirement: US-001, US-003; FR-003-FR-009, FR-016; NFR-001-NFR-003,
NFR-006, NFR-007
Depends on: T202C2 Accepted
Blocks: T202C4; T202C umbrella acceptance
Parallel: No
Conflicts with: T202C1-T202C2/T202C4/T202D-T202E and every account update/remove,
credential, cleanup, transition, removed-history, or challenge rule

Goal:
Expand exact challenge issuance and transition execution for account update,
account remove, credential set, credential delete, and credential cleanup. Retain
all removed identities and bind private locator tombstones to a closed delete-only
cleanup lifecycle with no read/probe/copy/export/set capability.

Allowed files:
- `crates/kirje-store/src/lib.rs`
- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/tests/authority_registry.rs`
- `crates/kirje-store/tests/fixtures/authority/registry/account_credential_cleanup/**`

Test targets:
- Per-action exact current/proposed registry challenge context and zero effects
- Update/remove/set/delete transition first/retry/crash/concurrency/recovery and
  immutable removed account/credential identity history
- Removed display recreation only with new account and credential identities
- Provisional/ready/claimed/deleted cleanup; active-v2/legacy-v1 exact enum;
  delete-only projection/API compile review and capability-escalation negatives
- Event/corruption/restart/boundedness/privacy and no-external-call-before-claim

Validation commands:
```bash
cargo test -p kirje-store --test authority_registry --all-features --locked
cargo test -p kirje-store --all-features --locked
cargo clippy -p kirje-store --all-targets --all-features --locked -- -D warnings
```

Definition of Done:
- Every remaining control lifecycle is exact, immutable, crash-safe, delete-only
  where required, private, and schema-preserving.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T202C3.yaml`

Evidence required:
- `.ai-platform/evidence/T202C3/summary.md`
- RED/GREEN logs, transition/removed-history/cleanup capability matrices,
  restart/event/privacy review, and residual risk

### T202C4: Remote Challenge Registry Binding

Status: Draft
Priority: P0
Story / Requirement: US-002, US-003; FR-013, FR-016-FR-018; NFR-001-NFR-003,
NFR-006, NFR-007
Depends on: T202C3 Accepted
Blocks: T202C umbrella acceptance
Parallel: No
Conflicts with: T202C1-T202C3/T202D-T202E and every remote challenge, policy,
effect registration, registry validation, or event/restart rule

Goal:
Expand challenge issuance for send and the five governed mailbox actions against
one exact active store/account/binding/config/policy snapshot, atomically persist
exactly one planner-owned ordinal-zero `challenge_effects` row, and complete the
aggregate T202C streaming restart validator without claiming or invoking effects.

Allowed files:
- `crates/kirje-store/src/lib.rs`
- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/tests/authority_registry.rs`
- `crates/kirje-store/tests/fixtures/authority/registry/remote_challenges/**`

Test targets:
- Send/seen/starred/move/archive/safe-delete exact registry, policy, manifest,
  account, credential, binding, location, generation, capability, and effect checks
- One and only one ordinal-zero effect row, globally unique planner-owned effect,
  exact pending reuse/restart/concurrency, stale/changed retry rejection, and no
  remote effect/claim/invocation/observation row
- Aggregate T202C grant/store/account/transition/cleanup/challenge-effect event
  and streaming bounded restart validation plus corruption/FK/privacy matrices

Validation commands:
```bash
cargo test -p kirje-store --test authority_registry --all-features --locked
cargo test -p kirje-store --all-features --locked
cargo clippy -p kirje-store --all-targets --all-features --locked -- -D warnings
```

Definition of Done:
- All T202C challenge actions and registry histories validate exactly after
  restart with no claim/invocation/network capability and unchanged canonical DDL.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T202C4.yaml`

Evidence required:
- `.ai-platform/evidence/T202C4/summary.md`
- RED/GREEN logs, six-action/effect/stale-context/concurrency/event/restart/
  privacy matrices, T202C aggregate gates, and residual risk

### T202D: Effect Claim Invocation And Observation

Status: Draft
Priority: P0
Story / Requirement: US-002, US-003; FR-016-FR-018; NFR-001-NFR-003,
NFR-006, NFR-007
Depends on: T202C Accepted
Blocks: T202E; T202 umbrella acceptance
Parallel: No
Conflicts with: T202A-T202C/T202E and grant-use integration, remote-effect, claim,
invocation-permit, observation, or apply-boundary behavior

Goal:
Reuse T202C1's exact grant-use substrate inside typed same-transaction remote
current-context revalidation, then implement canonical effect claim/invocation
start/observation transcripts, global effect claim, single adapter-entry permit,
exact recovery, and crash-to-ambiguous observation. Expand challenge issuance
for `ambiguous_close` only after its referenced effect, claim, invocation, and
observation history validates exactly.

Allowed files:
- `crates/kirje-core/src/account.rs`
- `crates/kirje-core/src/lib.rs`
- `crates/kirje-core/tests/account_security_contract.rs`
- `crates/kirje-store/src/lib.rs`
- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/tests/authority_effects.rs`
- `crates/kirje-store/tests/fixtures/authority/effects/**`

Test targets:
- `EffectClaimId`/`AuthoritySessionId` UUIDv4 BLOB16 and `OperationId` BLOB16
  storage/text boundary; production CSPRNG/test entropy rules
- Byte goldens and every-field mutations for grant use, claim, invocation, and
  observation; result 1/16MiB/N+1 and hash match
- Typed request recheck of receipt/grant/expiry/anchor/meta/key/epoch/bundle,
  store location/config generation+digest, account generation/credential/
  binding/state, policy, manifest, effect/ordinal/operation
- Exact committed use/claim/invocation/observation recovery after later context
  expiry; changed retry failures; first-boundary current-context failures
- Concurrent global claim/invocation winners; only inserter receives non-Clone/
  non-Serialize/no-byte-export `InvocationPermit`
- Crash before invocation has zero adapter entry; invocation without observation
  becomes one ambiguous recovery observation and never reinvokes
- `ambiguous_close` challenge issuance accepts only the exact durable effect and
  observation history and rejects missing, changed, or cross-linked history
- Authority-first observation and normal projection privacy

Deliverables:
- Typed request/projection APIs, durable transcript codecs, claim/invocation/
  observation transactions, and invocation permit
- History-bound `ambiguous_close` challenge issuance and fixtures
- Concurrency/restart/fault/privacy fixtures

Acceptance criteria:
- One effect has at most one claim, invocation, and first observation globally,
  including copied/rolled-back caller ledgers.
- No credential lookup/network entry can occur without the inserting-process
  permit; recovery never manufactures a second permit.

TDD plan:
- RED: Add transcript mutation, stale-context, changed-retry, concurrency,
  permit trait/ownership, crash-window, and result-bound tests.
- GREEN: Implement grant use, claim, invocation, and observation in boundary
  order, returning a permit only from the insert winner.
- REFACTOR: Extract shared current-context comparisons only after fault and
  concurrency tests remain deterministic.

Validation commands:
```bash
cargo test -p kirje-core --test account_security_contract --all-features --locked
cargo test -p kirje-store --test authority_effects --all-features --locked
cargo test -p kirje-core -p kirje-store --all-features --locked
cargo clippy -p kirje-core -p kirje-store --all-targets --all-features --locked -- -D warnings
```

Definition of Done:
- All six durable transcript domains, typed rechecks, exact recovery, global
  uniqueness, permit ownership, result bounds, crash ambiguity, and projection
  privacy are executable and reviewed.
- The canonical T202C1S Authority SQLite v1 schema remains unchanged and no
  adapter implementation enters store.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T202D.yaml`

Evidence required:
- `.ai-platform/evidence/T202D/summary.md`
- RED/GREEN logs, byte goldens, recheck matrix, concurrency/fault traces,
  permit/API review, privacy scan, and residual risk

### T202E: Rotation/Recovery/Audit And Umbrella Acceptance

Status: Draft
Priority: P0
Story / Requirement: US-003; FR-018, FR-019; NFR-001-NFR-003, NFR-006,
NFR-007
Depends on: T202D Accepted
Blocks: T202 umbrella acceptance; T204-T212 through the umbrella
Parallel: No
Conflicts with: T202A-T202D and trust key/epoch, anchor matching, invalidation,
recovery blocking, event/audit, or aggregate authority acceptance behavior

Goal:
Implement staged rotation/recovery/finalization and the verified
`staged_finalize_required` classifier using T202B's core snapshot plus exact
transition-receipt and role-required POP verification; enforce strict
key/role/mask/epoch row shapes, anchor crash matching, old-context invalidation,
recovery blocking/re-enrollment requirements, private event integrity, bounded
public audit, historical re-verification, and the complete T202 umbrella
acceptance gate.

Allowed files:
- `crates/kirje-store/src/lib.rs`
- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/tests/authority_rotation.rs`
- `crates/kirje-store/tests/authority_audit.rs`
- `crates/kirje-store/tests/authority_acceptance.rs`
- `crates/kirje-store/tests/fixtures/authority/rotation/**`
- `crates/kirje-store/tests/fixtures/authority/audit/**`

Test targets:
- Initial/staged/active/retired exact row shapes, one active/one staged successor,
  exact +1 epoch, owner/recovery role+mask+key ID, POP byte goldens/mutations
- Owner rotation, recovery-key rotation, owner recovery, concurrent stage/finalize,
  and active/staged/anchor crash matrix
- T202A staged inputs remain recovery-required; T202E returns
  `staged_finalize_required` only after the exact T202B core snapshot,
  transition receipt, role/mask, key, epoch/bundle, and required POPs all verify
- Matching fully verified signed staged anchor finalizes after restart; every
  lower/unrecognized/second/unsigned/location/bundle/key/receipt/POP mismatch is
  recovery-required
- Finalize retirement and invalidation of pending plus authorized-unclaimed old
  challenges; used/claimed history and old keys/receipts remain re-verifiable
- Recovery blocks all nonremoved stores/accounts and requires re-enrollment,
  binding authorization, and credential re-entry
- Event/detail digest and closed enum/cross-row corruption, append-only behavior,
  keyset sequence page limit 0/1/100/101, no private bytes in normal projection
- Full T202A-T202E restart/concurrency/privacy/schema compatibility suite

Deliverables:
- Rotation/recovery/finalization and audit APIs/fixtures
- Historical verification, invalidation/blocking, crash matrix, and aggregate
  T202 acceptance evidence

Acceptance criteria:
- Only the active anchor or its one fully signed and receipt/POP-verified staged
  successor can reach ready, `staged_finalize_required`, or finalize; all other
  staged/mismatch states fail before authority use.
- Recovery leaves no store/account ready and loses no historical evidence.
- Aggregate T202 review has no unresolved Critical/High finding.

TDD plan:
- RED: Add T202A-to-T202E staged-classification transition, core-snapshot,
  receipt/POP verification, row-shape/index, POP mutation, crash/mismatch,
  invalidation, recovery blocking, historical reverify, audit-bound/privacy, and
  aggregate gate failures.
- GREEN: Implement stage/finalize/recover and keyset audit one transaction at a
  time; preserve all historical rows.
- REFACTOR: Consolidate trust/event codecs only after crash and historical
  verification matrices remain green.

Validation commands:
```bash
cargo test -p kirje-store --test authority_rotation --all-features --locked
cargo test -p kirje-store --test authority_audit --all-features --locked
cargo test -p kirje-store --test authority_acceptance --all-features --locked
cargo test -p kirje-core -p kirje-store --all-features --locked
cargo clippy -p kirje-core -p kirje-store --all-targets --all-features --locked -- -D warnings
```

Definition of Done:
- Rotation/recovery/audit behavior and the combined authority suite pass against
  the unchanged canonical T202C1S Authority SQLite v1 schema with private
  history retained.
- Independent spec/security/engineering/QA reviews find no blocking issue.
- T202 remains non-Accepted until its aggregate evidence receives recorded
  acceptance from the delegated project owner.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T202E.yaml`

Evidence required:
- `.ai-platform/evidence/T202E/summary.md`
- RED/GREEN logs, POP/epoch goldens, crash/invalidation/recovery matrices,
  historical reverify, audit/privacy results, aggregate gate and review reports

## T203: Cross-Platform Safe Local I/O

Status: Draft
Priority: P0
Story / Requirement: US-004; FR-021-FR-024; NFR-002, NFR-004, NFR-005,
NFR-007
Depends on: T201 Accepted
Blocks: T204, T207, T208, T212
Parallel: No
Conflicts with: Workspace membership/dependency changes, local file open/read/
replace code, platform test matrix changes

Goal:
Create `kirje-local-io` with opened-parent capability semantics,
final-component no-follow/nonblocking regular-file validation, exact
limit-plus-one readers, stable platform object identity, private same-parent
replacement, and equivalent Linux/macOS/Windows tests.

Allowed files:
- `Cargo.toml`
- `Cargo.lock`
- `crates/kirje-local-io/**`
- `.github/workflows/ci.yml`

Forbidden changes:
- Mail, config parsing, authorization, CLI command, MCP, keyring, or protocol
  behavior in the new crate
- Project-owned unsafe code
- Path-based metadata/read fallback after a secure-open failure
- Platform test skip that reports success on the target platform

Test targets:
- Zero, exact limit/EOF, plus one, endless/short/interrupted reads
- Metadata over/under-report, growth, shrink, replacement, rename, unlink
- Same-handle object identity, directory, hard link, final symlink/reparse
- Unix FIFO nonblocking rejection, socket, device
- Windows pre-open namespace/reserved-device rejection, symlink,
  junction/reparse, and named pipe
- Allocation failure mapping and maximum scratch/retained bytes
- Private temp file, collision resistance, Unix atomic replacement, Windows
  journaled two-rename recovery, and parent durability behavior
- Domain-neutral `PlatformLocationMaterial` Unix and Windows forms; canonical
  Kirje transcript encoding remains in core/T201 and integration is T204

Deliverables:
- New `kirje-local-io` crate with portable API and platform tests
- Linux/macOS/Windows CI test/build matrix, runnable before T212 through branch
  push and `workflow_dispatch`/pull-request CI

Acceptance criteria:
- Target tests prove equivalent final-component and limit semantics without
  project unsafe code or a weaker fallback.
- The crate remains domain-neutral and reusable by CLI/runtime.
- The crate returns bounded opaque platform material and does not know the
  `KIRJE-CONFIG-LOCATION-V1` domain string or store registry.

TDD plan:
- RED: Add portable and target-specific tests against a missing crate.
- GREEN: Implement with cap-std/cap-fs-ext/fs4 and no unsafe Kirje code.
- REFACTOR: Share reader and error mapping only after every target fixture is
  green.

Validation commands:
```bash
cargo test -p kirje-local-io --all-features --locked
cargo clippy -p kirje-local-io --all-targets --all-features --locked -- -D warnings
cargo +1.88 check -p kirje-local-io --all-features --locked
cargo deny check
```

Definition of Done:
- No selected final link/reparse/special object can be imported.
- Accepted bytes always come from the validated opened handle.
- No reader retains or consumes beyond the documented limit plus one.
- T203 evidence includes a pushed-branch Linux/macOS/Windows CI run; local
  acceptance alone cannot claim platform equivalence.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T203.yaml`

Evidence required:
- `.ai-platform/evidence/T203/summary.md`
- Platform test table, RED/GREEN output, dependency/source review, memory-bound
  assertions, CI matrix evidence

## T204: Config V2, Stable Accounts, And Bound Credentials

Status: Draft
Priority: P0
Story / Requirement: US-001, US-002; FR-001-FR-011, FR-021-FR-024;
NFR-001-NFR-007
Depends on: T202 Accepted, T203 Accepted
Blocks: T205-T212
Parallel: No
Conflicts with: Account repository, config migration, keyring, stable account
references, message-index account schema, or account status changes

Goal:
Replace display-ID upsert and credential addressing with strict config v2,
stable store/account/credential IDs, v1 quarantine migration, locked CAS writes,
pinned store/account registry transitions, active/delete-only keyring ports, and
stable account references in the local message index. It also constructs the
immutable `LedgerV3MigrationContext` consumed by T205.

Allowed files:
- `crates/kirje-core/src/account.rs`
- `crates/kirje-core/src/lib.rs`
- `crates/kirje-core/src/mail.rs`
- `crates/kirje-core/tests/account_contract.rs`
- `crates/kirje-runtime/Cargo.toml`
- `crates/kirje-runtime/src/lib.rs`
- `crates/kirje-runtime/src/account_config.rs`
- `crates/kirje-runtime/src/account_service.rs`
- `crates/kirje-runtime/src/credential.rs`
- `crates/kirje-runtime/tests/**`
- `crates/kirje-store/src/lib.rs`
- `crates/kirje-store/tests/**`

Forbidden changes:
- CLI/MCP mutation handlers or remote apply behavior
- Legacy credential get/contains/copy/probe
- Display-ID upsert or mutation
- Credential bytes in config, manifest, arguments, output, logs, tests, or
  evidence

Test targets:
- Strict config v2 parsing/state/duplicates/unrecognized fields/size/newer version
- Fresh `initialize_if_absent`, concurrent winner reuse, and zero authority/
  keyring/network calls
- v1 migration, IDs stable only after commit, every crash boundary, idempotent
  restart, permissions
- Two-process create/update/CAS/lost-update behavior
- Store/location copy/alias/identity conflict with zero keyring calls
- Create-only duplicate display ID and immutable display ID
- Binding change, new credential ID, re-entry, account generation
- Active locator digest and zero active use of legacy locator
- Set/delete/binding-change crash order and delete-only cleanup capability
- Status orthogonal states/privacy
- Message-index migration to stable account ID and same-display-ID recreation
  isolation
- Canonical ConfigCas/AccountCas/AccountSnapshot goldens and deterministic
  `LegacyAccountMap` construction

Deliverables:
- Config v2 repository/migration, account service, bound secret ports, registry
  integration, and stable message-index migration
- Config/account/status and fake-keyring contract fixtures

Acceptance criteria:
- Every legacy account is quarantined with zero legacy read/presence calls.
- Only one matching pinned snapshot can construct an active credential locator.

TDD plan:
- RED: Reproduce display-ID replacement, copied-config credential namespace,
  legacy presence probing, unbounded config, CAS loss, and stale-index reuse.
- GREEN: Implement v2 projection, registry transition, typed secret ports, and
  index migration minimally.
- REFACTOR: Split monolithic runtime only after migration/crash/keyring fake
  tests pass.

Validation commands:
```bash
cargo test -p kirje-core -p kirje-runtime -p kirje-store --all-features --locked
cargo clippy -p kirje-core -p kirje-runtime -p kirje-store --all-targets --all-features --locked -- -D warnings
```

Definition of Done:
- Existing v1 accounts migrate to stable, quarantined v2 identities without a
  keyring probe.
- Duplicate create and stale update cannot replace another account.
- Active credentials resolve only through matching realm/store/account/
  credential/binding context.
- Removal/recreation cannot inherit indexed or credential state.
- T204 can produce one bounded duplicate-free ledger migration context without
  letting the store reopen config.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T204.yaml`

Evidence required:
- `.ai-platform/evidence/T204/summary.md`
- Migration/crash matrix, fake keyring call log, concurrency results, schema
  diff, privacy scan, reviews

## T205: Operation Ledger V3 Migration

Status: Draft
Priority: P0
Story / Requirement: US-002, US-003; FR-010, FR-011, FR-013-FR-018;
NFR-001-NFR-003, NFR-006, NFR-007
Depends on: T202 Accepted, T204 Accepted
Blocks: T206-T212
Parallel: No
Conflicts with: Core operation/send state, outbox schema/migrations, ledger
events, or account-reference migration

Goal:
Migrate the unified operation ledger to schema v3 with stable account/store
references, canonical manifests, authorization state, receipt/claim/invocation/
observation projections, legacy approval provenance, and conservative state
migration from one immutable `LedgerV3MigrationContext`.

Allowed files:
- `crates/kirje-core/src/operation.rs`
- `crates/kirje-core/src/send.rs`
- `crates/kirje-core/src/lib.rs`
- `crates/kirje-core/tests/**`
- `crates/kirje-store/src/outbox.rs`
- `crates/kirje-store/src/lib.rs`
- `crates/kirje-store/tests/outbox.rs`
- `crates/kirje-store/tests/fixtures/outbox/**`

Forbidden changes:
- Direct ledger-local approval authority
- Credential or network access
- Retroactive authority for a legacy approved record
- Deletion/editing of terminal legacy events

Test targets:
- v1->v2->v3 and v2->v3 migration in one transaction
- Draft/planned/approved/applying/expired/failed/ambiguous/succeeded/sent matrix
- Legacy TTY provenance and replan-required account mapping
- Duplicate/missing `LegacyAccountMap`, stable-account/store/realm plus
  legacy-terminal/replan-required scope constraints, and no config reload
  inside store migration
- Newer schema, duplicate/invalid fields, interrupted/repeated migration
- Authorization/effect projection state constraints and append-only events
- Account removal/recreate operation reference isolation
- Bounded audit/list/receipt details

Deliverables:
- Ledger schema v3, migration code/fixtures, state/event codecs, and projections
- Complete legacy-state migration and account-reference evidence

Acceptance criteria:
- Every supported legacy state has one deterministic tested v3 outcome.
- No ledger row or event can independently create owner authority.

TDD plan:
- RED: Add migration fixtures proving v2 approved/applying states remain unsafe
  under current schema.
- GREEN: Add v3 columns/state codecs and conservative migration.
- REFACTOR: Remove compatibility duplication only after all v1/v2 fixtures and
  terminal invariants pass.

Validation commands:
```bash
cargo test -p kirje-core -p kirje-store --all-features --locked
cargo clippy -p kirje-core -p kirje-store --all-targets --all-features --locked -- -D warnings
```

Definition of Done:
- Legacy TTY approval cannot invoke work after migration.
- Legacy applying becomes ambiguous; terminal outcomes remain immutable/readable.
- New operations bind stable identities and exact manifest digest.
- Only scope-valid stable account/store/realm rows can authorize or apply;
  legacy-terminal/replan-required rows cannot. T206 owns runtime context wiring.
- The ledger is a recoverable projection, never the authority source.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T205.yaml`

Evidence required:
- `.ai-platform/evidence/T205/summary.md`
- Migration matrix/results, schema snapshot, RED/GREEN tests, append-only review

## T206: Shared Authorization And Crash-Recovery Runtime

Status: Draft
Priority: P0
Story / Requirement: US-001-US-003; FR-003, FR-005, FR-006, FR-012-FR-020;
NFR-001-NFR-003, NFR-006, NFR-007
Depends on: T202 Accepted, T205 Accepted
Blocks: T207-T212
Parallel: No
Conflicts with: Runtime account snapshot, authorization, approve/apply, keyring,
adapter invocation, or fault-injection behavior

Goal:
Make one runtime service the only path for challenge creation, proof submission,
grant use, account/control apply, remote effect claim, invocation permit,
credential lookup, adapter call, authority observation, and ledger projection.

Allowed files:
- `crates/kirje-runtime/Cargo.toml`
- `crates/kirje-runtime/src/lib.rs`
- `crates/kirje-runtime/src/authority.rs`
- `crates/kirje-runtime/src/operation_service.rs`
- `crates/kirje-runtime/src/account_service.rs`
- `crates/kirje-runtime/src/credential.rs`
- `crates/kirje-runtime/tests/**`

Forbidden changes:
- CLI/MCP-specific authorization rules
- Network or keyring access before authority claim/invocation boundary
- Automatic retry after invocation uncertainty
- Serializable/cloneable invocation permit
- Caller override of production anchor/journal/apply-lock paths

Test targets:
- Missing anchor/trust/store registration/context fails before keyring/network
- Challenge manifest immutability and proof submit idempotency through service
- Expiry, epoch/key rotation, binding/policy/config changes between receipt/apply
- Eight crash boundaries: claim, ledger projection, invocation, keyring lookup,
  adapter entry, observation, ledger result, lock release
- Copied/rolled-back outbox before/after receipt/claim/invocation
- Two-process apply and adapter call count at most one
- Known pre-network failure consumes effect; post-invocation missing observation
  becomes ambiguous
- TTY approval API has no mutating runtime path

Deliverables:
- Shared authorization/control/apply runtime services and production fixed-path
  authority wiring
- Deterministic crash injector and multiprocess no-replay test suite

Acceptance criteria:
- Fault and concurrency tests observe at most one adapter entry per effect.
- Every failure before invocation observes zero credential/network calls.

TDD plan:
- RED: Use fake authority, ledger, secret store, adapter, and crash injector to
  demonstrate duplicate/unsafe current apply behavior.
- GREEN: Implement fixed ordered protocol and non-serializable permit.
- REFACTOR: Share send/mailbox/control orchestration after call-count and crash
  tests remain green.

Validation commands:
```bash
cargo test -p kirje-runtime --all-features --locked
cargo clippy -p kirje-runtime --all-targets --all-features --locked -- -D warnings
```

Definition of Done:
- Every covered action uses the exhaustive shared verifier.
- Authority claim and invocation precede keyring/network.
- No copied/rolled-back ledger or process crash can enter an adapter twice.
- Runtime production authority paths ignore normal data-path overrides.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T206.yaml`

Evidence required:
- `.ai-platform/evidence/T206/summary.md`
- Fault matrix, adapter/keyring call counts, multiprocess results, path override
  tests, reviews

## T207: CLI Owner, Account, And Credential Workflow

Status: Draft
Priority: P0
Story / Requirement: US-001-US-005; FR-004-FR-006, FR-009, FR-012-FR-024,
FR-030, FR-031; NFR-001, NFR-002, NFR-006, NFR-007
Depends on: T202 Accepted, T206 Accepted
Blocks: T208, T210-T212
Parallel: No
Conflicts with: CLI command/schema/error envelopes, TTY handling, file input,
doctor/schema/capability output

Goal:
Expose trusted bootstrap/status, bounded challenge/export/proof/audit, store
init/status/enrollment, planned account/credential controls, hidden credential
entry after grant claim, and non-mutating compatibility errors for legacy
approve commands.

Allowed files:
- `crates/kirje-cli/Cargo.toml`
- `crates/kirje-cli/src/main.rs`
- `crates/kirje-cli/tests/cli_contract.rs`
- `crates/kirje-cli/tests/fixtures/**`
- `crates/kirje-runtime/src/lib.rs`
- `crates/kirje-runtime/tests/**`

Forbidden changes:
- Credential or private key in arguments, stdin JSON, environment, output,
  logs, fixtures, or evidence
- Inline proof/signature on account/secret/apply commands
- TTY retyping as authorization
- Production authority path override
- MCP tool changes

Test targets:
- Bootstrap create-once, owner status/recovery, no path override
- Challenge create/show/export and proof submit exact/N+1/no-link inputs
- PTY automation cannot authorize without detached proof
- Store init/status/enroll-plan/apply, exact retry, and both identity conflicts
- Account create/update/remove plan/apply and duplicate conflict
- Secret set/delete/cleanup plan/apply, hidden prompt ordering, no secret echo
- Legacy approve stable error and zero state change
- Account/authorization status privacy and stable error JSON
- Doctor/schema honest password/app-password and unsupported protocol claims
- CLI file/stdin shared bounded parser for every document type

Deliverables:
- Versioned owner/authorization/store/account/credential CLI commands and
  golden JSON
- PTY, hidden-prompt, file/stdin, schema, and doctor contract tests

Acceptance criteria:
- A detached current receipt is necessary for every sensitive CLI mutation.
- CLI contracts contain no secret/private key/proof leakage or TTY approval.

TDD plan:
- RED: Add CLI/PTY/golden tests proving current direct writes and approve paths
  violate the contract.
- GREEN: Route commands to shared services and local-io input.
- REFACTOR: Consolidate command output only after stdout/secret/status tests pass.

Validation commands:
```bash
cargo test -p kirje-cli -p kirje-runtime --all-features --locked
cargo clippy -p kirje-cli -p kirje-runtime --all-targets --all-features --locked -- -D warnings
cargo run -p kirje-cli -- schema --pretty
cargo run -p kirje-cli -- doctor --pretty
```

Definition of Done:
- CLI supports the complete owner workflow without possessing private keys.
- A fresh or migrated store has an executable owner-authorized enrollment path.
- Every sensitive account/credential action is planned and owner-authorized.
- Credential bytes enter only through the hidden post-claim prompt.
- Legacy TTY approval has no mutating behavior.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T207.yaml`

Evidence required:
- `.ai-platform/evidence/T207/summary.md`
- CLI/schema golden diff, PTY results, secret scan, input-boundary tests, reviews

## T208: Bounded MCP Transport And Exact Deny Surface

Status: Draft
Priority: P0
Story / Requirement: US-003-US-005; FR-020, FR-024-FR-026, FR-030;
NFR-001, NFR-002, NFR-004, NFR-006, NFR-007
Depends on: T202 Accepted, T207 Accepted
Blocks: T209-T212
Parallel: No
Conflicts with: MCP tools/schemas/stdio transport, Tokio features, CLI MCP exit
and stdout behavior

Goal:
Replace unbounded rmcp stdio with exact limit-plus-one framing, four request
handlers plus one control lane, two-phase handler/active-ID/output lifecycle,
method-aware structural preflight, bounded queues/writer, backpressure,
redacted tracing, terminal overflow behavior, exact tool allowlist, and
recursive proof/control deny schema.

Allowed files:
- `Cargo.toml`
- `Cargo.lock`
- `crates/kirje-mcp/Cargo.toml`
- `crates/kirje-mcp/src/lib.rs`
- `crates/kirje-mcp/src/stdio_transport.rs`
- `crates/kirje-mcp/src/preflight.rs`
- `crates/kirje-mcp/src/lifecycle.rs`
- `crates/kirje-mcp/src/output.rs`
- `crates/kirje-mcp/tests/**`
- `crates/kirje-cli/Cargo.toml`
- `crates/kirje-cli/src/main.rs`
- `crates/kirje-cli/tests/mcp_stdio.rs`
- `crates/kirje-cli/tests/fixtures/mcp/**`

Forbidden changes:
- Challenge/proof/owner/account/credential/policy/cleanup/ambiguous-close MCP
  mutation
- Raw request/result tracing
- Reading another frame without task/writer capacity
- Draining an oversized attacker frame
- Normal CLI JSON envelope on MCP stdout

Test targets:
- Frame N/N+1, exact no-newline, incomplete EOF, one null-ID error, nonzero exit
- Generated maximum-valid-request budget inequality
- Four blocked handlers, one control task, fifth normal request busy, and
  blocked writer/queue/reservation byte caps
- Duplicate/oversized IDs, method bound, initialized/cancel notification rules
- Handler completion retains active-ID/output state through transport send;
  cancel/error/panic/disconnect terminal release
- Cancellation before response claim reaches worker-aware TerminalNoResponse;
  cancellation after claim completes send and never waits for handoff timeout
- 24 MiB service document plus 4 KiB input envelope, 16 MiB result plus 4 KiB
  output envelope, and stdout protocol purity
- Method-aware preflight rejects depth/count/string/Base64 N+1 before rmcp
  constructs `serde_json::Value`
- Fixed task accounting remains at or below 16 and tool results serialize
  structured content exactly once
- Exact current tool allowlist and golden schemas
- Recursive prohibited authorization/control names and aliases
- Shared apply services still recheck authority; no adapter-specific bypass

Deliverables:
- Custom bounded rmcp stdio transport and lifecycle tests
- Exact MCP tool/schema golden allowlist and recursive deny checker

Acceptance criteria:
- Blocked/flooded sessions stay within every task/ID/queue/byte budget.
- MCP stdout remains pure and exposes no owner or control mutation path.

TDD plan:
- RED: Reproduce unbounded line, task/ID growth, raw schema gap, and stdout
  contamination on v0.3.
- GREEN: Implement the custom role-server transport and exact contract tests.
- REFACTOR: Isolate frame/session/writer state only after blocked-stream tests are
  deterministic.

Validation commands:
```bash
cargo test -p kirje-mcp -p kirje-cli --all-features --locked
cargo clippy -p kirje-mcp -p kirje-cli --all-targets --all-features --locked -- -D warnings
```

Definition of Done:
- MCP retains at most frame N+1, four active request IDs/handlers, one control
  task, and bounded queued plus reserved output bytes.
- Overflow is one terminal MCP error with clean stdout and nonzero exit.
- Exact allowlist/schemas expose no authorization or sensitive control mutation.
- Valid shared requests fit the MCP frame by generated proof.
- The T208 commit SHA passes the existing Linux/macOS/Windows CI matrix before
  acceptance.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T208.yaml`

Evidence required:
- `.ai-platform/evidence/T208/summary.md`
- Memory/task/queue assertions, stdio transcripts, tool/schema snapshots,
  tracing/stdout scan, same-SHA three-platform CI, reviews

## T209: Bounded Protocol Responses And Capabilities

Status: Draft
Priority: P0
Story / Requirement: US-005; FR-027-FR-031; NFR-001, NFR-002, NFR-004-
NFR-007
Depends on: T202 Accepted, T208 Accepted
Blocks: T210-T212
Parallel: No
Conflicts with: IMAP connection/session/capability behavior, SMTP receipt,
bounded core response models

Goal:
Enforce the IMAP bound from the first server byte, parse complete typed
capabilities under count/item/total budgets, unify mailbox/special-use/result
bounds, and emit byte-bounded metadata-rich SMTP receipts.

Allowed files:
- `Cargo.toml`
- `Cargo.lock`
- `crates/kirje-core/src/bounded.rs`
- `crates/kirje-core/src/mail.rs`
- `crates/kirje-core/src/send.rs`
- `crates/kirje-core/src/lib.rs`
- `crates/kirje-core/tests/**`
- `crates/kirje-protocol/Cargo.toml`
- `crates/kirje-protocol/src/lib.rs`
- `crates/kirje-protocol/src/imap.rs`
- `crates/kirje-protocol/src/smtp.rs`
- `crates/kirje-protocol/tests/**`
- `crates/kirje-store/src/outbox.rs`
- `crates/kirje-store/tests/outbox.rs`
- `crates/kirje-runtime/src/lib.rs`
- `crates/kirje-runtime/tests/**`
- `crates/kirje-cli/src/main.rs`
- `crates/kirje-cli/tests/**`
- `crates/kirje-mcp/src/lib.rs`
- `crates/kirje-mcp/tests/**`

Forbidden changes:
- Post-parse display truncation represented as wire bound
- Security decisions from `Debug` strings or incomplete/truncated capability
  displays
- Raw provider response in receipt/error/log/evidence
- New authentication protocol or mailbox effect

Test targets:
- IMAP initial fragment 12 MiB/N+1 across greeting/capability/auth
- Capability 128/129, item 256/257, total 16 KiB/N+1, duplicates/unrecognized/UTF-8
- Complete/incomplete typed capability decisions including MOVE
- Mailbox 1,000/1,001 and special-use duplicate/total result behavior
- Remote value/control/identifier and 16 MiB result/8 MiB untrusted totals
- SMTP source-limit assertion and 256/257 multibyte/control receipt metadata
- Stable resource errors without rejected provider text

Deliverables:
- Bounded IMAP connection pump, typed capability model, total-result enforcement,
  and bounded SMTP receipt
- Protocol fixture and serialization-bound evidence

Acceptance criteria:
- The first IMAP server byte and every emitted remote value have executable
  bounds.
- Incomplete/truncated capability display cannot authorize protocol behavior.

TDD plan:
- RED: Add adapter fixtures that exceed current initial/capability/receipt
  boundaries.
- GREEN: Add bounded connect pump, typed sets, total budgets, and receipt model.
- REFACTOR: Share bounded text conversion only after raw-byte and capability
  completeness tests pass.

Validation commands:
```bash
cargo test -p kirje-core -p kirje-protocol --all-features --locked
cargo clippy -p kirje-core -p kirje-protocol --all-targets --all-features --locked -- -D warnings
cargo test -p kirje-store -p kirje-runtime -p kirje-cli -p kirje-mcp --all-features --locked
cargo clippy -p kirje-store -p kirje-runtime -p kirje-cli -p kirje-mcp --all-targets --all-features --locked -- -D warnings
```

Definition of Done:
- No effective io-imap 100 MiB initial boundary remains.
- Capability-dependent behavior requires a complete typed set.
- Every remote value/result has item/count/total disposition metadata, and
  store/runtime/CLI/MCP integration tests prove that metadata survives each
  projection without raw provider content.
- SMTP receipt is byte-bounded, untrusted, and never raw.
- The T209 commit SHA passes the existing Linux/macOS/Windows CI matrix before
  acceptance.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T209.yaml`

Evidence required:
- `.ai-platform/evidence/T209/summary.md`
- Protocol fixture matrix, source-limit review, serialized-result measurements,
  same-SHA three-platform CI, reviews

## T210: Canonical Security And Operations Documentation

Status: Draft
Priority: P0
Story / Requirement: US-005; FR-031-FR-034; NFR-002, NFR-005-NFR-008
Depends on: T202 Accepted, T209 Accepted
Blocks: T211, T212
Parallel: No
Conflicts with: Product/security/provider/operation claims, Agent Skill, release
and architecture documentation

Goal:
Make every canonical product and operator surface accurately describe Security Alpha
authentication, trust, storage, migration, backup/restore, retention/erasure,
authorization, ambiguous outcomes, bounded input, and MCP boundaries.

Allowed files:
- `README.md`
- `docs/**`
- `skills/kirje/**`
- `.ai-platform/docs/**`
- `.ai-platform/memory/**`
- `.ai-platform/specs/008-security-baseline/**`
- `scripts/**`

Forbidden changes:
- Production Rust behavior
- Historical before/after narrative in canonical docs except explicit migration,
  ADR, release, or evidence records
- OAuth2/JMAP/Gmail API/Graph runtime support claims
- Encryption-at-rest, recipient-delivery, or tamper-proof audit claims
- Real account/credential/signature/content examples

Test targets:
- README/Skill/architecture/security/operations/provider/conformance parity
- Runtime schema/doctor capability claim parity
- Data locations, private permissions, backup/restore pairing, retention, erasure
- Bootstrap/rotation/recovery and legacy quarantine runbooks
- SMTP acceptance/mailbox mutation/authorization/local audit distinctions
- Secret/content/address/endpoint/UID/signature scan
- Delivery artifact validator

Deliverables:
- Canonical README, Agent Skill, architecture, security, operations, provider,
  conformance, migration, and release documentation
- Claim parity, privacy scan, and operator-runbook evidence

Acceptance criteria:
- Runtime and every canonical document make identical support/security claims.
- An operator can bootstrap, migrate, recover, back up, restore, retain, and
  erase state without undocumented authority assumptions.

TDD plan:
- RED: Run claim/parity/secret scans and capture stale or missing statements.
- GREEN: Rewrite canonical present-tense documents to the shipped contract.
- REFACTOR: Deduplicate through links only where each operator workflow remains
  self-contained.

Validation commands:
```bash
cargo run -p kirje-cli -- schema --pretty
cargo run -p kirje-cli -- doctor --pretty
python /Users/iiwish/.codex/skills/ai-delivery-governor/scripts/validate_delivery_artifacts.py --root /Users/iiwish/self/kirje --task-id T210
```

Definition of Done:
- Every canonical surface states IMAP/SMTP password/app-password only.
- Trust and same-user attacker limits are direct and consistent.
- Storage is documented as private but neither encrypted nor tamper-proof.
- Backup/restore and erase procedures preserve or deliberately retire anchor/
  journal/config/ledger/keyring relationships.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T210.yaml`

Evidence required:
- `.ai-platform/evidence/T210/summary.md`
- Claim matrix, docs paths, scan output, schema/doctor snapshots, review

## T211: Security Review And Cross-Platform Release Candidate

Status: Draft
Priority: P0
Story / Requirement: All FR/NFR and SC-001-SC-008
Depends on: T202 Accepted, T210 Accepted
Blocks: T212
Parallel: No
Conflicts with: Any concurrent production, migration, workflow, or release
metadata change

Goal:
Run complete migration/replay/fault/platform/privacy gates, independent security
reviews, controlled read-only real-account verification, version/release
preparation, and produce a clean Security Alpha release candidate.

Allowed files:
- `Cargo.toml`
- `Cargo.lock`
- `crates/**/Cargo.toml`
- `.github/**`
- `scripts/**`
- `docs/**`
- `skills/**`
- `.ai-platform/**`
- Test/fixture files needed only to close review findings; production fixes
  require a scoped T201-T210 fix attempt and their original allowed files.

Forbidden changes:
- Bypassing, deleting, weakening, or skipping a failing gate
- Committing real account, endpoint, UID, mail content, credential, signature,
  raw provider response, or private evidence
- Remote write in live verification without a separate signed packet
- Expanding authentication/protocol scope

Test targets:
- Every success criterion and acceptance matrix
- Three-platform CI, Rust 1.88, dependency deny/advisory/license
- Full fault/replay/copy/rollback/concurrency and input/MCP/protocol suites
- Secret/privacy and golden external-contract scans
- Controlled real-account read-only auth/capability check
- Independent spec/security/engineering/QA reviews with zero blocking findings

Deliverables:
- Fresh local and three-platform release-candidate test evidence
- Sanitized controlled-account result, independent reviews, release/version diff

Acceptance criteria:
- Every SC-001-SC-008 gate is green or the task remains unaccepted.
- Security/privacy scans find no real credential, account, content, UID,
  signature, or raw provider evidence.

TDD plan:
- RED: No new behavior is expected; any failing acceptance gate creates a scoped
  fix attempt in its owning task and must reproduce before the fix.
- GREEN: Close only confirmed release-blocking findings in owning scope.
- REFACTOR: None during final RC except required deterministic fixture cleanup.

Validation commands:
```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --locked
cargo deny check
cargo run -p kirje-cli -- schema --pretty
cargo run -p kirje-cli -- doctor --pretty
```

Definition of Done:
- All local/full/platform/CI gates are green and fresh.
- Independent reviews have no Critical/High/blocking finding.
- Controlled evidence is credential/content-free and accurately read-only or a
  sanitized environment blocker.
- Workspace/package version and release notes identify `v1.0.0-alpha.1`.
- Branch is ready for one reviewed release commit and PR.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T211.yaml`

Evidence required:
- `.ai-platform/evidence/T211/summary.md`
- Full command logs/summaries, cross-platform CI links, review reports, live
  sanitized result, secret scan, release diff

## T212: Commit, PR, CI, Merge, Tag, And Post-Merge Evidence

Status: Draft
Priority: P0
Story / Requirement: NFR-008, SC-008, release acceptance
Depends on: T202 Accepted, T211 Accepted
Blocks: 007 T102 and every Mailbox Alpha production change
Parallel: No
Conflicts with: Any concurrent branch/release/PR/version change

Goal:
Create the Conventional Commit, push the governed branch, open and review the
PR, obtain green required CI, merge, verify post-merge main CI, tag/publish the
Security Alpha checkpoint when repository policy supports it, and update sanitized release
evidence and parent-program status.

Allowed files:
- `.ai-platform/evidence/T212/**`
- `.ai-platform/specs/008-security-baseline/**`
- `.ai-platform/specs/007-stable-v1-program/tasks.md`
- `.ai-platform/docs/tasks.md`
- Release metadata required by confirmed repository policy
- Git commit/branch/tag/PR/CI remote state

Forbidden changes:
- Production behavior after T211 acceptance without a new owning fix attempt
- Merge with failed/skipped required CI or unresolved blocking review
- Force push, history rewrite, destructive reset, or unreviewed tag
- Claiming an external PR/CI/merge/tag action completed without observed evidence

Test targets:
- Clean scoped diff and conventional commit
- PR diff equals accepted local diff
- Required CI green on PR and post-merge main
- Release artifact/tag identity and version consistency
- Parent T101 status/evidence link and Mailbox Alpha gate

Deliverables:
- Reviewed commit/PR/merge/tag chain and post-merge CI evidence
- Final T212 evidence plus parent-program and project-task status updates

Acceptance criteria:
- Remote Git/CI/release states are observed and recorded without inference.
- Mailbox Alpha remains blocked until merged Security Alpha CI is green.

TDD plan:
- RED/GREEN does not apply to remote metadata; every state claim uses observed
  Git/GitHub/CI evidence and any code failure returns to its owning task.

Validation commands:
```bash
git diff --check
git status --short
git log -1 --oneline
gh pr checks --watch
```

Definition of Done:
- Accepted Security Alpha changes are committed, reviewed, merged, tagged, and
  green on main.
- Tag/release is published and verified when enabled, or an exact external
  blocker is recorded without false closure.
- T101 becomes Accepted only after this evidence exists.
- No Mailbox Alpha production task starts earlier.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/T212.yaml`

Evidence required:
- `.ai-platform/evidence/T212/summary.md`
- Commit SHA, PR URL/number, checks, merge SHA, main CI, tag/release evidence or
  exact blocker, final secret scan

## Requirement Coverage Summary

- FR-001-FR-011: T201-T205, T207
- FR-012-FR-020: T201, T202A-T202E, T205-T208
- FR-021-FR-024: T201, T203, T204, T207, T208
- FR-025-FR-026: T208
- FR-027-FR-030: T201, T208, T209
- FR-031-FR-034: T207, T209, T210
- NFR-001-NFR-007: production tasks plus T211
- NFR-008 and SC-001-SC-008: T211-T212

## User Review Gate

Confirmed on 2026-08-28 under the user's explicit standing project-owner
delegation and instruction to continue without per-step approval. T202A is
Accepted, and T202B is Accepted at `43f0788` from four test-first attempts and
independent final review. T202C-T202E and T203-T212 are Draft; no production
task is Ready. The T202
umbrella is Draft and cannot become Accepted before T202E evidence and recorded
delegated acceptance. Individual task acceptance remains evidence-based rather
than inferred from this graph confirmation; a failed or missing gate still stops
execution.
