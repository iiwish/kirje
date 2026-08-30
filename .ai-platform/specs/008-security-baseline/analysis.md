# Analysis: Security Baseline

## Metadata

- Feature ID: `008-security-baseline`
- Status: T202A_T202B_Accepted_T202C_Packetization
- Updated: 2026-08-30
- Inputs: `spec.md`, `checklists/requirements.md`, `plan.md`, `research.md`,
  `data-model.md`, `contracts/**`, `tasks.md`, project constitution and AGENTS
- Review basis: local code/dependency inspection plus five independent
  scope-specific read-only audits

## Gate Result

- Critical findings: 0 unresolved
- High findings: 0 unresolved. The A003 packet accepts the
  current A002 implementation as its immutable baseline and narrows execution
  to lifecycle/schema REDs; its stop conditions permit only the declared
  additive amendment. Independent packet re-review confirms both findings are
  resolved. The nine T202 authority-store packetization
  findings and four focused T202A artifact-review findings are resolved by the
  canonical authority-store contract, transaction-body DDL, composite SQLite
  relationships, minimal validated core public-key prerequisite, fail-closed
  staged ownership, exact durable transcripts/replay tables, closed transaction
  requests, and rotation/recovery state machine.
- Medium findings: 0 unresolved. Canonical schema ownership
  is assigned to T202B and propagated through T202C-T202E, the unreleased T202A
  development fence has an explicit fail-closed disposal boundary, and the
  schema target/hash gates are present at task and packet level. Independent
  packet re-review confirms all three findings are resolved.
- Low findings: 3 accepted watch items: future policy/assurance snapshot schemas
  remain executable fail-closed unsupported; the generic artifact validator
  cannot select letter-suffixed child IDs independently; and the frozen
  canonical DDL includes one final blank line that `git diff HEAD --check`
reports even though its exact byte hash is required. The generated unified-diff
evidence is excluded from whitespace lint because its context lines use the
standard single-space patch marker.
- Execution decision: T201 and T202A are Accepted. T202 remains a Draft
  acceptance umbrella split into strict serial T202A-T202E. T202B is Accepted
  at production commit `43f0788`; T202C-T202E and T203-T212 remain Draft, so no
  production task is Ready. T204 and every
  later task directly require the T202 umbrella to be Accepted.

The product requirements remain confirmed and do not add a remote mailbox
effect or broaden authentication/protocol scope. T202A owns the accepted
bootstrap behavior and relationship structure; T202B owns the sole pre-release
lifecycle column/index amendment. T202C-T202E reuse the canonical T202B schema
and cannot invent a second authority format.

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
| FR-008 | legacy quarantine/delete-only cleanup | T204 | fake keyring call log and janitor tests |
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

Executable SQLite validation of the canonical fence reports SHA-256
`572a73ba5fa83c763188d804ce9767a3c21373410d8b170f6d97b49be0a86454`, 17 user
tables, 15 declared indexes, and 3 triggers. The body parses with foreign keys
enabled; valid receipt/nonce/grant and two complete remote-effect through
observation chains insert successfully; `PRAGMA foreign_key_check` returns zero
rows and `PRAGMA integrity_check` returns `ok`. Cross-linked receipt, nonce use,
grant use, challenge-effect/remote-effect, effect claim, invocation, and
observation inserts each fail with `FOREIGN KEY constraint failed` and leave zero
invalid child rows. Equal public keys fail the unique constraint, swapped roles
fail the role trigger, and initial-staged plus epoch-gap rows fail checks.

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
  T202A owns bootstrap structure and T202B owns the sole pre-release lifecycle
  column/index amendment. T202C-T202E reuse the canonical T202B fence unchanged.
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

No product-spec or executable-contract question blocks T202B packetization.
T202C-T202E remain dependency-gated Draft tasks and T202 remains a Draft
acceptance umbrella.

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
select `T202A`-`T202E` through `--task-id`. Feature-wide validation still checks
the confirmed work graph and scans every packet file once present. Child packet
review must therefore use feature-wide validation plus the declared packet and
evidence paths until the validator is extended in a separately allowed tooling
task. This is a smoke-tool limitation, not permission to merge child evidence or
relax the strict serial gates.

### L-004 Canonical DDL Diff Lint

The accepted authority v1 DDL ends with one empty line and its exact SHA-256 is
part of the reviewed contract. `git diff HEAD --check` therefore reports a new
blank line at EOF when the schema first enters Git. All source and governance
diffs other than that canonical file pass the same check; generated
`evidence/T202A/diff.patch` is excluded because unified-diff context markers are
not source whitespace. The fixed v1 bytes take precedence over normalization; a
future schema version may normalize its own canonical source before freezing
its digest.

## Execution Gate

`APPROVED_FOR_T202C_PACKETIZATION`

T202A is accepted from four test-first attempts, independent security and QA
review, its bootstrap-schema digest, and fresh packet/workspace gates. A003
retains the A001/A002 RED evidence and implementation as a hash-pinned baseline,
then adds only lifecycle linkage/schema REDs and their minimum implementation.
Its amended packet received `T202B_A003_PACKET_REVIEW_PASS`. Four test-first
attempts, fresh packet/workspace gates, and `T202B_A004_CODE_REVIEW_PASS`
support evidence-based T202B acceptance at `43f0788`. T202C may be packetized
but remains Draft until its own independent packet review. The T202 umbrella
remains non-Accepted.
