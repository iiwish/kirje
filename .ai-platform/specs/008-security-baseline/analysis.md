# Analysis: Security Baseline

## Metadata

- Feature ID: `008-security-baseline`
- Status: T202C3_A006_F011_Ready_For_Packet_Review_No_Execution_Permission
- Updated: 2026-08-31
- Inputs: `spec.md`, `checklists/requirements.md`, `plan.md`, `research.md`,
  `data-model.md`, `contracts/**`, `tasks.md`, project constitution and AGENTS
- Review basis: local code/dependency inspection plus independent packet,
  security, implementation, and QA read-only audits

## Gate Result

- Critical findings: 0 unresolved.
- High findings: the A006 production-review High remains open. F006 resolves the
  F002 packet-review High at the contract layer. Cleanup validates
  origin/locator/tombstone before blocked/recovery eligibility, so mixed invalid
  target plus blocked/recovery state returns `credential_cleanup_invalid`
  instead of `account_update_conflict` or `owner_recovery_required` and leaks
  target validity. Candidate `2241a946` remains Returned/Needs Fix. The user
  explicitly resumed A006 repair on 2026-08-31, but F001 failed spec review
  C0/H1/M2/L0 while engineering and QA each passed C0/H0/M0/L0. The packet
  wrongly treated caller-supplied common IDs as signed and did not close absent,
  pair-mismatched, or unrelated-row classification. The user explicitly
  approved the F002 contract revision on 2026-08-31. Its packet review failed
  because a literal no-private-read claim contradicted mandatory global graph
  validation. Under the user's delegated existing-boundary clarification
  authority, F008 review failed/refused with exact counts spec C0/H2/M2/L0,
  engineering/security C0/H4/M1/L0, and QA C0/H4/M2/L0. F009 review failed with
  spec C0/H1/M0/L0, engineering/security C0/H1/M2/L0, and QA C0/H1/M1/L0. The
  F010 review returned spec PASS C0/H0/M0/L0, engineering/security BLOCK
  C0/H3/M3/L0, and QA BLOCK C0/H1/M2/L0. The orchestrator approved F011's
  trusted-local procedural clarification. F011 leaves the substantive F006
  cleanup contract unchanged. Complete request-independent step-2
  validation remains intact and may stream all private graphs. After the request-
  independent global validation pass, source/call-order proof must show no
  request-directed pending/private lookup or request-dependent private branch
  before closed public pair classification. Same-context expired pending plus
  later blocked/recovery performs no pending-row lookup-dependent interaction;
  active eligible rollback uses the two existing expiration fault hooks. No
  generic projection sample is accepted: absent store, absent account, pair
  mismatch, matched recovery, matched blocked store/account, unrelated matched
  proposed, unrelated existing matched blocked returning `account_update_conflict`,
  unrelated existing matched recovery-store returning `owner_recovery_required`,
  active/active, and active/removed
  are each crossed independently with wrong origin, locator kind, locator
  digest, tombstone, lifecycle, and descriptor.
  Challenge issuance orders preflight, lock/transaction, global validation,
  checked effective time/time shape without pending access, public classification,
  private validation, pending lookup, reuse/replacement, and successor commit;
  no pending expiry is durable before eligibility. Claim/delete proof-expiry
  ordering remains unchanged. Same-origin proposed is corruption; only an
  unrelated matched proposed pair is a reachable public projection.
  No implementation started; F011 awaits three reviews with permissions closed. The first A006 packet
  review rejected the current-binding contradiction, incomplete clock-only
  recovery rule, and non-implementable cross-crate delete capability. The
  revised amendment makes cleanup the explicit historical-before exception,
  limits exact pending/claimed recovery to the paired clock, hardens
  reservation/prepare canonicality, and adds complete replacement/race and
  synthetic-vector contracts. Repeat review found one remaining High: the
  shared public constructor/deletion surface still allowed runtime to bypass
  authority. The focused revision makes the unpublished low-level crate a
  direct dependency of store only, removes the trait/plugin surface, and makes
  the combined store apply method the sole production call site. Final QA
  accepted that boundary but found one Medium in its literal call-site proof.
  The final independent three-pass review at governance HEAD `3533054` accepted
  the AST-proof repair with zero finding and issued
  `T202C3_A006_PACKET_REVIEW_PASS`; that historical packet pass does not
  override the later failed production review. A007/A008 remain non-executable
  JIT outlines.
  F011 keeps bespoke authority auditors retired and defines governance as a
  trusted-local procedural trace, not a product-security credential. Real scope,
  TDD, validation, and independent review evidence establish delivery. Cargo deny
  remains an explicit T111 baseline blocker rather than an A006 pass claim.
  The 3 A001 T202C1 findings are closed by A002
  and `T202C1_A002_PACKET_REVIEW_PASS`. Historical challenge validation is now
  intrinsic, lifecycle replacement and final-state terminals are distinct, and
  durable grant/event time is store-derived effective authority time with a
  time-independent enrollment-intent digest. The nine T202 authority-store packetization
  findings and four focused T202A artifact-review findings are resolved by the
  canonical authority-store contract, transaction-body DDL, composite SQLite
  relationships, minimal validated core public-key prerequisite, fail-closed
  staged ownership, exact durable transcripts/replay tables, closed transaction
  requests, and rotation/recovery state machine. The first independent T202C2
  packet review found mutable remote-effect parents; accepted T202C1S replaces
  them with immutable version parents and closes that High finding. T202C2 A006
  independently passed with zero findings.
- Medium findings: 5 unresolved in A006 production review: incomplete
  legacy/locator bound and mutation discrimination; unexercised invalid
  expired-replacement rollback; incomplete immutable projection/clock/entropy/
  concurrency/response-loss assertions; missing historical later-state and
  durable restart-corruption matrices; and incomplete effect observation,
  external-call, and privacy proof. F001 additionally failed on two Medium
  packet defects: its same-context invalid-target expired-replacement case is
  unreachable except as step-2 persisted corruption, and closed locator shapes
  cannot prove generic parser bounds at the integration surface. F006 requires
  same-context expired pending plus later blocked to return
  `account_update_conflict` and later recovery store to return
  `owner_recovery_required`, each without pending lookup-dependent interaction and with predecessor/event/
  clocks unchanged. It moves rollback proof to an active eligible valid-target
  path using `OldChallengeExpiredState` and `OldChallengeExpiredEvent`; a
  different-context invalid target has zero predecessor interaction and
  persisted corruption remains step 2. It retains the
  private numeric classifier with numeric-only unit tests; no public/test-support
  API is added and closed-form bytes stay in `authority_registry.rs`. F006 also
  replaces the stale data-model branch, fixes the execution gate, and chooses a pure exact-
  scope manifest preflight for `transition_id=None` without a core change. The
  earlier literal sole-call scan can be bypassed by aliases, wildcards, re-
  exports, macros,
  function pointers, or indirect bindings. A008 now owns a dedicated exhaustive
  AST allowlist over every production store Rust file, composed with Cargo
  direct-dependency, no-re-export, and runtime compile-fail proofs. The test is
  specified but not implemented as future A008 work; the packet-level finding
  is closed by `T202C3_A006_PACKET_REVIEW_PASS`. A007/A008 remain non-executable.
  The 1 A001 T202C1 finding is closed by A002
  and `T202C1_A002_PACKET_REVIEW_PASS`. A 128-or-more complete legal-history RED
  plus indexed EXPLAIN plans and O(1) memory review is now mandatory. Canonical schema ownership
  is assigned to T202B and propagated through T202C-T202E, the unreleased T202A
  development fence has an explicit fail-closed disposal boundary, and the
  schema target/hash gates are present at task and packet level. T202C2 A002
  review found four Medium packet gaps: config-commit ordering/timestamps/faults,
  cross-transition historical projection recovery, executable event-stream SQL,
  and stale analysis status. A003 closed those items but exposed two further
  Medium gaps: terminal recovery raw-pair provenance and a synthetic-fixture stop
  contradiction. A004 closed the recovery reconstruction but left predecessor
  synthetic-vector scope ambiguous. A005 grandfathers exact hash-pinned
  predecessor vectors, restricts task-new vectors, freezes recovery-store
  immutability through T202E, but its generic cross-transition retry rule still
  included the terminal recovery state. A006 limits cross-transition retry to
  finalized/aborted transitions and requires recovery retry to prove the
  unchanged terminal current row with no successor. Independent review confirmed
  the complete packet with zero Critical, High, Medium, or Low findings and issued
  `T202C2_A006_PACKET_REVIEW_PASS`.
- Low findings: 4 accepted watch items: future policy/assurance snapshot schemas
  remain executable fail-closed unsupported; the generic artifact validator
  cannot select letter-suffixed child IDs independently. The generated unified-diff
evidence is excluded from whitespace lint because its context lines use the
standard single-space patch marker. The T202C1 test-only token scanner may
false-positive on a future raw string containing code-like text; current
production source has no raw string and independent source review confirms no
prohibited trait implementation. The T202C1S registry-parent preflight is
currently called once but has no dedicated test-support query counter; T202C2
must preserve that placement or add an explicit counter before loop expansion.
- Execution decision: T201, T202A, T202B, T202C1, T202C1S, and T202C2 are
  Accepted. T202C3 remains non-Accepted after the user's
  acceptance of `T202C3-A005` at production commit `316dae0` and approval of the
  cleanup security-contract amendment on 2026-08-30. The orchestrator approved
  the material unpublished store-only credential-crate architecture under
  delegated authority on 2026-08-31, superseding the flawed shared formulation.
  T202C3-A006 candidate `2241a946` is Returned/Needs Fix. The user explicitly
  resumed A006 repair on 2026-08-31 and fixed the path as A006 repair/re-review,
  A007 claim, A008 delete, then T202C3/T110 closure. F001 failed spec review; the
  user approved F002 on 2026-08-31. F002 packet review returned QA PASS
  C0/H0/M0/L0, spec FAIL C0/H0/M1/L0, and engineering FAIL C0/H1/M2/L0 at
  `38ca4273`. Under the user's delegated existing-boundary clarification
  authority, F008 and F009 reviews failed, F010 review blocked, and the
  orchestrator approved F011's trusted-local clarification. It is ready for three independent packet
  reviews under the packet's severity/disposition rule; permissions remain none,
  and A007/A008 remain closed.
  T202C4, T202D-T202E, and T203-T212 remain dependency-gated Draft work. T204
  and every later task directly require the T202 umbrella to be Accepted.

The product requirements remain confirmed and do not add a remote mailbox
effect or broaden authentication/protocol scope. T202A owns accepted bootstrap
behavior, T202B owns authorization receipts, and T202C1 owns enrollment.
T202C1S owns the sole remaining pre-release Authority SQLite v1 correction:
immutable credential/store-version/account-version parents and initial
store-version enrollment. Later tasks reuse that one canonical v1 format and
cannot invent a second authority database.

## Artifact Consistency

### Product And Constitution

- Kirje remains a local-first CLI/MCP server with no GUI or hosted control plane.
- Core owns provider-neutral types; runtime owns shared services; protocol quirks
  stay in adapters.
- Mailbox content, local paths, protocol responses, and MCP input remain
  untrusted.
- Read-only access and write authorization are separate.
- Every remote/sensitive action uses plan/owner-authorize/apply.
- MCP has no owner authorization or sensitive control mutation.
- Credentials and owner private keys remain outside arguments/output/persistent
  Kirje data respectively.
- Stable bounded JSON/errors and stdout purity are explicit task contracts.

No constitution exception exists.

### Trust Boundary

The spec, plan, data model, and contracts all state the same guarantee:

- asymmetric authorization protects supported Kirje transitions when OS
  permissions/sandboxing protect the installed binary, fixed anchor/journal,
  keyring, and external signer
- a same-user attacker that can replace the binary, rewrite protected databases,
  or read the owner private key is outside the claim
- SQLite/config are private by OS permission but not encrypted or tamper-proof
- append-only means supported application paths, not cryptographic transparency

### Authority And Ledger

- Fixed authority path is independent of normal config/index/outbox flags.
- SQLite application ID is `0x4B49524A` (`KIRJ`), schema version is exactly 1,
  and every table has executable storage-class/length/range/enum/FK/index checks.
- Production home comes only from `ProjectDirs::from("", "", "kirje")`; isolated home and
  deterministic entropy exist only under non-default `test-support`.
- Bootstrap is database-first `pending_anchor -> ready`; anchor I/O is external
  to the store and every third-state mismatch is recovery-required.
- T202A maps every staged row or staged anchor to recovery-required. T202E alone
  may classify a staged finalize after T202B snapshot plus receipt/POP verification.
- The schema is a transaction body under one bootstrap-owned `BEGIN IMMEDIATE`;
  rollback before the sole commit leaves no user object, row, or version marker.
- Composite SQLite keys bind copied receipt/use/effect/claim/invocation/
  observation context and reject cross-linked durable chains.
- Authority owns nonce use, immutable receipt, grant use, global effect claim,
  unique invocation, and first outcome observation.
- Operation, effect-claim, invocation, and authority-session UUIDs are BLOB16;
  observation identity is the exact transcript SHA-256/BLOB32.
- Caller-selected ledger stores a recoverable projection and append-only
  workflow history.
- Apply lock plus unique invocation distinguishes a crashed process from a live
  concurrent invocation without replay.
- Legacy approval is preserved as provenance but grants no authority.

### Account And Credential

- Realm is 32 random bytes; store/account/credential/grant/effect identities are
  independent.
- Display ID is immutable and not a durable operation/keyring reference.
- Config location binds open parent identity and final native component.
- Authority registry provides store/location and account/binding uniqueness.
- Keyring locator binds realm/store/account/credential/binding.
- The credential capability boundary is enforceable: unpublished lower
  `kirje-credential` is a direct dependency of `kirje-store` only and owns the
  opaque locator plus concrete delete-only backend. Store owns the lock-holding
  permit, sole production low-level call site, and combined terminal method.
  A008 proves exclusivity with an exhaustive production-source AST allowlist;
  literal source matching is not acceptance evidence.
  Runtime calls only that high-level method and never imports, receives, or
  re-exports low-level APIs. A007 owns the crate/type/store-only dependency and
  store-private fake hook; A008 owns the real backend and sole call site; T204
  owns only high-level runtime/CLI integration and legacy-path removal.
- Legacy entries are never read/tested/copied; cleanup has delete-only typing.
- Config v1 migration is locked, bounded, idempotent, quarantined, and
  crash-recoverable on every supported platform without claiming Windows
  overwrite atomicity.

### Bounded Boundaries

- cap-std/cap-fs-ext/fs4 satisfy safe same-parent, no-follow/reparse, nonblocking,
  and cooperative lock requirements without project unsafe code.
- Exact limit-plus-one and EOF rules are identical for file/stdin.
- Typed visitors and transcript decoders enforce structure before post-hoc
  semantic validation.
- MCP framing, active handlers/IDs, queues, bytes, notifications, writer, and
  tracing are all bounded.
- IMAP initial connection gets a Kirje-owned 12 MiB pump; SMTP preserves
  lettre's transport bounds and adds a bounded receipt.
- Complete typed capabilities, not display truncation, drive security behavior.

## Requirement Traceability

| Requirement | Plan/contract decision | Task(s) | Primary evidence |
|---|---|---|---|
| FR-001 | D-001/D-002, config v2 identities | T201, T204 | binding/config/index migration tests |
| FR-002 | account-binding V1 transcript | T201 | byte golden and field mutation matrix |
| FR-003 | pinned registry + locator V2 | T202C, T204, T206 | copied-config and zero-keyring-call tests |
| FR-004 | create-only, immutable display ID | T204, T207 | sequential/concurrent conflict tests |
| FR-005 | explicit update/new credential snapshot | T204, T206 | update/CAS/snapshot tests |
| FR-006 | governed account/credential lifecycle | T202C, T204, T206, T207 | control manifest and crash-order tests |
| FR-007 | locked restart-safe v1 migration | T203, T204 | interruption/idempotency/permission matrix |
| FR-008 | legacy quarantine/delete-only cleanup | T202C3, T204 | store-private fake deletion log, low-level boundary, and integration tests |
| FR-009 | orthogonal private status | T204, T207 | status golden/privacy scan |
| FR-010 | legacy ledger state migration | T205 | all-state v1/v2/v3 fixtures |
| FR-011 | strict config/ledger migration bounds | T203-T205 | newer/duplicate/malformed/N+1 tests |
| FR-012 | create-once fixed owner realm | T202A, T206, T207 | bootstrap/path/mismatch/recovery tests |
| FR-013 | complete persisted challenge | T201, T202B, T206 | transcript/schema/context tests |
| FR-014 | exact independent signer manifest | T201, T207 | golden export and tamper tests |
| FR-015 | strict detached proof/replay | T201, T202B, T206 | RFC8032, expiry, replay, concurrency tests |
| FR-016 | receipts/global claims/recovery | T202B-T202D, T205, T206 | copy/rollback/crash/invocation matrix |
| FR-017 | exhaustive action map/apply recheck | T201, T206 | action golden and stale-context tests |
| FR-018 | private re-verifiable evidence | T202B, T202E, T207 | rotation reverify and output privacy tests |
| FR-019 | rotation/recovery/epoch invalidation | T202E, T206, T207 | dual-proof, staged crash, recovery tests |
| FR-020 | CLI workflow and MCP deny surface | T207, T208 | CLI golden + exact MCP allowlist/schema |
| FR-021 | same-handle no-link regular file | T203, T204, T207 | Linux/macOS/Windows object tests |
| FR-022 | N+1/read/parser/allocation bounds | T201, T203, T207, T208 | exact-limit and visitor tests |
| FR-023 | metadata non-authority/object stability | T203 | grow/shrink/replace/unlink tests |
| FR-024 | shared input service/error mapping | T201, T203, T204, T207, T208 | typed parser and adapter parity tests |
| FR-025 | terminal bounded MCP frame | T208 | N/N+1/EOF/stdout/nonzero tests |
| FR-026 | derived budget/tasks/queues/backpressure | T208 | generated inequality and blocked-stream tests |
| FR-027 | protocol item/count/total boundaries | T209 | IMAP/SMTP raw fixture matrix |
| FR-028 | complete typed capabilities | T201, T209 | overflow/incomplete/MOVE decision tests |
| FR-029 | explicit disposition metadata | T201, T209 | core/ledger/CLI/MCP serialization tests |
| FR-030 | bounded status/audit/machine output | T201, T207-T209 | output-size, privacy, stdout tests |
| FR-031 | honest IMAP/SMTP auth claims | T207, T209, T210 | schema/doctor/docs parity matrix |
| FR-032 | honest local storage/audit boundary | T210 | security/operations review |
| FR-033 | location/backup/retention/erasure | T210 | operator runbook review |
| FR-034 | receipt/finality distinctions | T210 | terminology/claim matrix |
| NFR-001 | fail closed before keyring/network | T202A-T202E, T204, T206, T209 | call-count and TLS/protocol tests |
| NFR-002 | secret/private/untrusted exclusion | T201-T212 | source/output/evidence scans |
| NFR-003 | atomic restart-safe transitions | T202A-T202E, T204-T206 | fault/restart/copy/rollback matrix |
| NFR-004 | first-boundary boundedness | T201, T203, T208, T209 | memory/count/item/total tests |
| NFR-005 | Linux/macOS/Windows equivalence | T203, T209, T211 | target CI matrix |
| NFR-006 | shared services/versioned migration | T201, T204-T209 | golden CLI/MCP/schema fixtures |
| NFR-007 | stable redacted observability | T201-T210 | error/tracing/stdout/privacy tests |
| NFR-008 | TDD/review/release discipline | T201-T212 | per-task evidence and release chain |

## Success-Criteria Traceability

| Criterion | Tasks | Gate |
|---|---|---|
| SC-001 credential redirection/canonical binding | T201, T204, T206 | field/copy/update call-count matrix |
| SC-002 unconditional legacy quarantine | T204 | migration + zero legacy probe evidence |
| SC-003 PTY cannot authorize | T206, T207, T208 | PTY and MCP negative contracts |
| SC-004 signature/replay/copy/rollback protection | T201, T202A-T202E, T205, T206 | proof/fault/multiprocess matrix |
| SC-005 cross-platform file/MCP bounds | T203, T208, T211 | target tests + blocked-stream memory gates |
| SC-006 bounded remote/results/evidence | T201, T209-T211 | protocol/output/evidence size gates |
| SC-007 honest runtime/docs boundary | T207, T209, T210 | capability claim parity |
| SC-008 full gates/live/review/merge | T211, T212 | release evidence chain |

## Data And State Checks

### Config

- Config v2 has one store ID/generation and strict account records.
- Store/account/credential identities are unique and validated as UUIDv4.
- Binding digest is recomputed; invalid combinations fail on load.
- Migration IDs are generated once in the committed replacement.
- Authority transition digest recovery resolves before/after/third-state cases.

### Authority

- Full v1 DDL is executable and checks required/nullable storage classes,
  lengths, ranges, closed enums, action/target shapes, foreign keys, ordinal
  bounds, composite cross-chain relationships, and partial uniqueness.
  `context_sha256` closes pending NULL semantics.
- Immutable credential, store-version, and account-version rows preserve exact
  registry history. Remote effects reference those version rows rather than
  mutable current projections, so later legal registry transitions remain
  possible without weakening historical foreign keys.
- Bootstrap meta has exact `pending_anchor`/`ready` shapes and a complete
  database/anchor matrix; every staged state is recovery-required in T202A.
- Proof, receipt, grant use, effect claim, invocation start, observation,
  transition, trust POP, and event details use serializer-independent transcripts.
- Exact committed replay returns immutable history; every first use/claim/
  invocation boundary requires current context in the same `BEGIN IMMEDIATE`.
- Last observed wall-clock high-water detects significant rollback; inclusive
  expiry and 30-second issuance tolerance never extend authority.
- Rotation/recovery has exact staged/active/retired shapes, one staged successor,
  and T202E-owned receipt/POP-verified anchor finalize, invalidation, and registry
  blocking behavior.
- Historical key/receipt/use/claim/invocation/observation data remains; private
  key and normal-output private bytes never appear.

### Operation

- Authorization state is distinct from operation outcome and effect phase.
- Legacy TTY approval becomes provenance only.
- Applying migration becomes ambiguous.
- Terminal outcomes/events remain immutable.
- Authority observation precedes ledger projection.

## Interface Checks

### CLI

- Owner bootstrap/status/rotation/recovery and authorization create/export/
  submit/audit are explicit.
- Account/credential changes are planned control operations.
- Apply takes target operation ID, not inline proof or secret.
- Credential entry follows grant claim through hidden prompt.
- Existing approve commands do not mutate.

### MCP

- Exact allowlist replaces substring policy.
- Recursive schema deny prevents proof/trust/policy override smuggling.
- Apply remains a shared runtime service and can only consume an already stored
  owner receipt.
- Frame/session/output errors remain MCP JSON-RPC only; normal CLI envelope is
  disabled after MCP mode begins.

## Dependency And Portability Checks

- `ed25519-dalek 3.0.0` MSRV 1.85 fits Rust 1.88; strict verifier is available.
- `getrandom 0.4.3` MSRV 1.85 fits Rust 1.88.
- `cap-std/cap-fs-ext 4.0.2` expose safe directory-relative no-follow and
  platform metadata APIs.
- `fs4 1.1.0` MSRV 1.75 fits and provides sync cross-platform locks.
- Workspace keeps `unsafe_code = "forbid"`; target unsafe stays in dependencies.
- T203 and T211 require Rust 1.88 and three-platform evidence plus cargo deny.

## Independent Review Synthesis

### Authority/Ledger Audit

The audit confirmed that current approval/claim lives only in outbox and
recommended fixed anchor/journal/apply lock, strict Ed25519 transcripts,
transactional receipts/nonces, unique claim/invocation, authority-first
observation, v3 migration, and exact MCP deny. All are present in plan/contracts/
T201-T208.

### Account/Keyring Audit

The audit confirmed v1 unbounded config, display-ID upsert, cross-config keyring
namespace, and snapshot absence. It recommended strict config v2, parent object
location identity, registry transitions, locator V2, active/delete-only ports,
quarantine migration, CAS/recovery, and stable account references. All are
present in plan/data model/T201/T202/T204/T205/T207.

### Input/MCP/Protocol Audit

The audit confirmed file TOCTOU, post-allocation validation, rmcp unbounded
frame/task/tracing paths, io-imap's 100 MiB initial bound, and incomplete SMTP
metadata. It recommended a shared local-I/O crate, typed visitors, custom rmcp
transport with task gating, bounded IMAP connect pump, typed capabilities, and
three-platform CI. All are present in T203/T208/T209/T211.

### Executable-Boundary Review

The first post-packet review found no Critical issue and nine High gaps across
canonical enum/action bytes, bounded deserialization ownership, rmcp response
lifecycle/cancellation admission, transport envelope arithmetic, Windows
pre-open/replace behavior, account remove/recreate history, store enrollment,
and cross-layer disposition evidence. T201-A001 stopped after RED rather than
inventing protocol. The canonical contracts now define fixed codes and typed
manifest tags, core/MCP parser ownership, separate domain/envelope budgets, a
four-handler plus one-control lifecycle, pre-open Windows rejection, journaled
Windows replacement, a live-row account index, explicit store enrollment, SQL
BLOB nullability/type checks, exact control-manifest field encodings, and
corrected task/CI ownership.

The final independent reviews report:

- canonical-byte/cryptographic contract: 0 Critical, 0 High; the required A002
  packetization state is satisfied and one future-schema Low remains fail-closed
- bounded-I/O/MCP/protocol contract: 0 Critical, 0 High, 0 Medium
- account/config/migration contract after focused SQL nullability recheck:
  0 Critical, 0 High, 0 Medium, 0 Low

Structural artifact validation and `git diff --check` also pass. No review
authorized production shortcuts, broader file ownership, or weakened tests.

### T202 Authority-Store Packetization Audit

The post-T201 authority audit found no Critical issue and nine High plus one
Medium packetization gaps:

- private core payload fields forced a second transcript parser in store
- symbolic application ID and TEXT operation IDs left DB/identity semantics open
- authority-home, bootstrap, anchor, bundle, and location input ownership was not
  executable
- SQL admitted NULL/wrong storage classes and open enum values
- nullable pending-context uniqueness, foreign keys, ordinals, and partial
  indexes were incomplete
- proof/receipt/use/claim/start/observation exact transcripts were undefined
- rotation/recovery row shapes, transitions, invalidation, and crash matching
  were incomplete
- grant/claim/invocation APIs could not prove same-transaction current-context
  comparison
- expiry, rollback, exact historical replay, and first-boundary recovery were
  ambiguous
- public target/state/audit projection was underdefined

`contracts/authority-store.md`, the complete Authority SQLite V1 DDL, the
authorization replay/rotation additions, and T202A-T202E serial graph resolve
those artifact gaps without modifying production code. T202A owns only its
minimal public `kirje_core::OwnerPublicKey` prerequisite plus schema/bootstrap;
it does not invent later operations. T202B has the full core projection
prerequisite; T202C-T202E each have closed API, validation, packet, and evidence
ownership.

### T202A Focused Artifact Remediation

The independent post-packet DDL/open review found four High governance defects:

- the canonical DDL contained its own transaction, so an outer bootstrap
  transaction failed with `cannot start a transaction within a transaction` and
  schema objects could commit outside the intended crash boundary
- individually valid receipt, nonce, grant, effect, claim, invocation, and
  observation identifiers could be cross-linked because SQL did not bind copied
  parent context as a composite relationship
- T202A classified a staged anchor as `staged_finalize_required` before it owned
  receipt/POP verification
- bootstrap accepted raw 32-byte keys and SQL admitted equal public keys,
  swapped roles, an initial staged epoch, and epoch gaps

The canonical remediation makes the SQL fence a pure transaction body, gives
`prepare_bootstrap` one outer `BEGIN IMMEDIATE` and sole commit, adds exact parent
composite uniqueness and child composite foreign keys with `ON DELETE RESTRICT`,
defers staged-finalize classification to T202E after T202B snapshot and exact
receipt/POP verification, and adds T202A's minimal core `OwnerPublicKey` plus
SQLite key/role/epoch constraints. T202A does not acquire the full T202B payload
snapshot or any staged mutation API.

Executable SQLite validation of the accepted T202B fence reported SHA-256
`572a73ba5fa83c763188d804ce9767a3c21373410d8b170f6d97b49be0a86454`, 17 user
tables, 15 declared indexes, and 3 triggers. The body parses with foreign keys
enabled; valid receipt/nonce/grant and two complete remote-effect through
observation chains insert successfully; `PRAGMA foreign_key_check` returns zero
rows and `PRAGMA integrity_check` returns `ok`. Cross-linked receipt, nonce use,
grant use, challenge-effect/remote-effect, effect claim, invocation, and
observation inserts each fail with `FOREIGN KEY constraint failed` and leave zero
invalid child rows. Equal public keys fail the unique constraint, swapped roles
fail the role trigger, and initial-staged plus epoch-gap rows fail checks.

The later T202C2 preflight proved that this fence's remote-effect parent choice
was not mutation-safe: exact effects referenced current store/account tuples.
T202C1S replaces only that unreleased relationship shape with three immutable
version parents, evolves T202C1 enrollment to insert the initial store version,
and records the resulting canonical digest after GREEN. Application ID and user
version remain unchanged; older developer inventories fail exact schema
classification and are not migrated.

The challenge table carries the exact created-event sequence and a declared
`(context_sha256, created_event_sequence, challenge_id)` lifecycle index. The
restart validator can therefore stream same-context histories in causal order
with O(1) application memory and indexed event lookups; it does not execute a
history-quadratic correlated scan or rely on timestamp ordering.

The outer-transaction rollback probe observes 35 user objects and five initial
rows with application ID `1263096394` and user version `1` before rollback; after
rollback it observed zero user objects, application ID `0`, and user version `0`.
This closes the reproduced nested-transaction/crash counterexample.

Ruby safely parses the remediated T202A packet with 18 root keys and seven
validation commands. Feature-wide artifact validation reports zero errors and
258 legacy warnings outside this T202A contract; the prior T202A missing-root-
`validation_loop` warning is absent. `cargo test -p kirje-core --all-features
--locked` passes all 60 baseline tests without a production-code or Cargo change,
and `git diff --check` passes.

## Resolved Technical Questions

- Signing algorithm: Ed25519 strict verification, direct typed transcript.
- Signing bytes: `KIRJE-AUTHORIZATION-V1` strict tagged binary.
- Owner entropy: 32-byte OS-random realm and nonce.
- Owner public key: exact 32-byte parsed non-weak `OwnerPublicKey`, distinct
  owner/recovery values, no serde/default/private/signing surface in T202A.
- Fixed authority: platform anchor/journal/apply-lock paths, no normal override.
- Authority DB identity: `application_id=0x4B49524A` (`KIRJ`), user version 1;
  T202A owns bootstrap structure, T202B owns authorization lifecycle, and
  T202C1S owns the final pre-release immutable registry-version correction.
  T202C2-T202E reuse that exact canonical fence unchanged.
- Bootstrap: one outer transaction owns schema body, initial rows, application
  ID/version, and commit; create-only external anchor write then exact confirm.
  Anchor-present/DB-missing, every third-state mismatch, and every T202A staged
  state require recovery.
- Trust bundle: exact seven-field `KIRJE-TRUST-BUNDLE-V1` transcript; journal
  location is a separate typed digest pin.
- Authority IDs: every UUID is BLOB16 including operation/effect-claim/session;
  observation identity is transcript SHA-256/BLOB32.
- Exact retry: immutable proof/receipt/use/claim/start/observation transcripts,
  historical replay without refreshed authority, and current context at every
  first use/claim/invocation boundary.
- Rotation: exact one-active/one-staged-successor state machine; T202E classifies
  and finalizes only after core-snapshot receipt/POP verification, with historical
  retention and recovery registry blocking.
- Config location: exact platform-tagged TLV from opened parent identity and a
  Unix-native final-component byte sequence or exact Windows native UTF-16LE
  final-component code units.
- No-link API: cap-std/cap-fs-ext behind `kirje-local-io`.
- Config coordination: fs4 lock plus generation/content/location CAS.
- MCP frame: 24 MiB canonical request plus a separately proven 4 KiB JSON-RPC
  envelope; output uses 16 MiB plus 4 KiB.
- MCP capacity: four handlers/active IDs, one control task, five writer items,
  two maximum queued wire frames, four output reservations, and sixteen total
  session tasks.
- IMAP initial response: Kirje-owned 12 MiB pump from first server byte.
- Capability security: complete bounded typed set; display metadata separate.

T202B packetization fixes its stage boundary explicitly. B issues only store
enrollment and trust-action challenges. T202C owns registry-backed account,
credential, cleanup, send, and mailbox issuance plus challenge-effect rows;
T202D owns `ambiguous_close` issuance after effect history exists; T202E owns
post-rotation/invalidation replay. Core owns borrowed payload/target/effect
projection and canonical proof bytes. Effective authority time closes rollback
revival, including paired-meta clock-only pending reuse, exact replay, and
already-expired response-loss recovery. The fixed event numeric/detail table
plus causal B validator replaces T202A's initial-empty rule without weakening
the bootstrap prefix or exact later-table zero-row boundary.

The first independent T202C1 packet review found three High and one Medium
execution-contract gap: historical siblings depended on current store absence,
authorized-to-expired was conflated with the replacement terminal, caller use
time conflicted with effective authority time and no-grant recovery identity,
and O(1) validation lacked executable high-cardinality/query-plan proof. The
A002 amendment resolves these in the canonical authority-store contract and
packet, and `T202C1_A002_PACKET_REVIEW_PASS` closes the execution-packet gate.
T202C is an acceptance umbrella rather than a single production patch:
T202C1 owns generic grant consumption plus store enrollment; T202C1S owns the
unreleased immutable-version schema correction and initial store-version row;
T202C2 owns account-create issuance and transitions; T202C3 owns remaining account,
credential, and delete-only cleanup lifecycles; T202C4 owns six remote challenge
effects and aggregate T202C validation. These tasks are strict serial because
they share the authority transaction, validator, event stream, and fixture
surface. T202C2 is Accepted. T202C3-A006 passed its packet review at `3533054`,
but candidate `2241a946` failed production spec/QA review and is Returned/Needs
Fix. A007/A008 remain non-executable outlines. T202C4 plus
T202D-T202E remain dependency-gated Draft tasks, and T202 remains a Draft
acceptance umbrella.

The first T202C2 packet review issued no pass. Its mutable-parent remote-effect
finding is closed by accepted T202C1S. A002 closed the synthetic-fixture and
transition-ID timing findings, but independent review found four remaining
Medium gaps. A003 freezes version-before-projection config-commit order and
timestamps, three missing fault hooks, transition-scoped historical projections
across later independent transitions, valid authority-event SQL, and consistent
governance status. A003 then found the canonical-v1 recovery raw-pair exception
and a fixture stop-condition conflict. A004 permits a terminal store-pair read
only after exact recovery graph proof and narrows the stop condition to real or
private material and misplaced task-new synthetic bytes. A005 additionally
grandfathers unchanged accepted predecessor vectors and makes the account-
transition recovery store row immutable for every canonical-v1 path through
T202E, but its generic T1-after-T2 retry matrix still included recovery. A006
limits cross-transition retry to finalized/aborted terminals and gives
RecoveryRequired only an unchanged-current-row, no-successor retry case. That
T202C2 gate is closed by `T202C2_A006_PACKET_REVIEW_PASS`.

## Watch Items

### L-001 Dependency API Drift

The exact cap-std/cap-fs-ext and rmcp APIs are current at planning time. T201/
T203/T208 lock versions through Cargo.lock and run Rust 1.88 plus cargo-deny
checks. An API mismatch is an implementation issue within those task packets,
not permission to weaken no-follow or capacity semantics.

### L-002 Protocol Upstream Boundary

The io-imap bounded connection pump relies on public session/stream primitives.
T209 must prove the first-byte 12 MiB bound in executable fixtures. If upstream
APIs cannot support it, T209 is blocked until the adapter is replaced or the
affected runtime capability is explicitly disabled. Post-connect truncation is
not an accepted fallback.

### L-003 Suffixed Task Validator Selection

The shared artifact validator recognizes numeric `T###` headings but cannot
select `T202A`-`T202E`, `T202C1S`, or `T202C1`-`T202C4` through `--task-id`. Feature-wide
validation still checks the confirmed work graph and scans every packet file
once present. Child packet review must therefore use feature-wide validation
plus the declared packet and evidence paths until the validator is extended in
a separately allowed tooling task. This is a smoke-tool limitation, not
permission to merge child evidence or relax the strict serial gates.

## Execution Gate

`T202C3_A006_F011_READY_FOR_PACKET_REVIEW_NO_EXECUTION_PERMISSION`

T202A is accepted from four test-first attempts, independent security and QA
review, its bootstrap-schema digest, and fresh packet/workspace gates. A003
retains the A001/A002 RED evidence and implementation as a hash-pinned baseline,
then adds only lifecycle linkage/schema REDs and their minimum implementation.
Its amended packet received `T202B_A003_PACKET_REVIEW_PASS`. Four test-first
attempts, fresh packet/workspace gates, and `T202B_A004_CODE_REVIEW_PASS`
support evidence-based T202B acceptance at `43f0788`. T202C1 A001 received no
pass (`0 Critical / 3 High / 1 Medium`); A002 closes those findings and received
`T202C1_A002_PACKET_REVIEW_PASS` with zero Critical, High, Medium, or Low
findings. Three test-first implementation attempts, fresh packet/workspace
gates, and `T202C1_A003_CODE_REVIEW_PASS` support evidence-based T202C1
acceptance at production commit `aa53efb`. T202C2 received no packet pass
because its schema parent relationship was not executable. T202C1S is the next
serial task. Its A001 packet review received no pass (`1 High / 3 Medium / 1
Low`): transition origins lacked exact composite FKs, abort wording conflicted,
credential mutations did not freeze account-generation advancement, legal-
successor enrollment retry was assigned to a stage that could not construct it,
and the target DDL hash was not pinned. A002 closes those findings with exact
transition/account/store parents, remove-not-delete semantics, one-step account
generation rules, T202C2 ownership of successor retry, and target digest
`5d01739b89246a5f495a965e57e416eee9fd0b5016995add41c6edee7f3e970d`.
Independent A002 re-review verified every prior finding fixed, reproduced the
exact FK/cycle/current-evolution/query-plan properties, reported zero Critical,
High, Medium, or Low, and issued `T202C1S_A002_PACKET_REVIEW_PASS`. T202C1S is
Accepted at production commit `8eceaff` after one delegated test-first attempt,
fresh package/workspace gates, and independent
`T202C1S_A001_CODE_REVIEW_PASS` with zero Critical, High, or Medium finding.
The accepted Low watch item records that the one-time registry-parent preflight
lacks a dedicated test counter. T202C2 A001 received no pass with three High and
two Medium findings. A002 closed the immutable-parent, synthetic-fixture,
transition-ID timing, and same-transition monotonic-retry gaps but received no
pass with four Medium findings. A003 closed config-commit order/time/fault,
cross-transition projection, executable SQL, and analysis consistency gaps but
received no pass with two Medium findings. A004 closed terminal recovery pair
provenance but received no pass with one Medium and two Low findings. A005
grandfathers unchanged predecessor synthetic vectors, restricts task-new bytes,
freezes recovery-store immutability, and aligns all status artifacts, but
received no pass with one Medium finding because its generic T1-after-T2 retry
rule still contradicted recovery terminality. A006 limits that rule to
finalized/aborted transitions and freezes RecoveryRequired retry to the unchanged
terminal current row with no successor. Independent A006 review replayed the
prior findings, reported zero Critical, High, Medium, or Low, and issued
`T202C2_A006_PACKET_REVIEW_PASS`. T202C2 is Accepted. Returned candidate
`T202C3-A006` retains one High and five Medium findings. The user resumed repair,
F001 failed spec review C0/H1/M2/L0, and the user approved the F002 contract
revision. F002-F005 then failed packet review. F006 resolves the F005
findings by splitting exact public rows, defining three-stage authority audits,
adding workspace handoff gates, preserving cleanup-challenge precedence,
complete request-independent step-2 validation, prohibiting request-directed
pending/private lookup and durable expiry before public eligibility, separating
same-origin proposed corruption from unrelated proposed public conflict,
retaining active-pair fault rollback, and completing effect/gate/audit proof.
F006 audit review then failed without reopening that substantive contract. F007
and F008 reviews also failed/refused. F009 review failed and F010 review blocked.
F011 keeps bespoke authority auditors retired and defines a trusted-local
procedural delivery trace. No implementation started. F011 requires three
independent packet reviews before A11 dispatch; the T202C and T202
umbrellas remain non-Accepted.
