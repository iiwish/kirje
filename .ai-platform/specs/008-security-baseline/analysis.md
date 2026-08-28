# Analysis: Security Baseline

## Metadata

- Feature ID: `008-security-baseline`
- Status: T201_Accepted_T202_Ready
- Updated: 2026-08-28
- Inputs: `spec.md`, `checklists/requirements.md`, `plan.md`, `research.md`,
  `data-model.md`, `contracts/**`, `tasks.md`, project constitution and AGENTS
- Review basis: local code/dependency inspection plus three independent
  scope-specific read-only audits

## Gate Result

- Critical findings: 0 unresolved
- High findings: 0 unresolved; all nine executable-boundary findings were
  remediated and independently re-reviewed
- Medium findings: 0 unresolved; the replacement-attempt packetization finding
  is satisfied by T201-A002
- Low findings: 1 accepted watch item for future policy/assurance snapshot
  schemas; those actions remain executable fail-closed unsupported
- Execution decision: T201-A001 remains stopped after valid RED evidence and
  T201-A002 remains review-failed. T201-A003 passed fresh RED/GREEN, all core
  gates, cargo-deny, privacy/dependency review, and independent spec,
  cryptographic, engineering, and QA review. T201 is Accepted and T202 is the
  only Ready production task.

The product requirements remain confirmed and do not add a remote mailbox
effect or broaden authentication/protocol scope. A003 repaired direct
violations of existing executable contracts without changing the signed byte
goldens. T202 may proceed; T203-T212 remain governed by their declared
dependencies.

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
- Authority owns nonce use, immutable receipt, grant use, global effect claim,
  unique invocation, and first outcome observation.
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
| FR-003 | pinned registry + locator V2 | T202, T204, T206 | copied-config and zero-keyring-call tests |
| FR-004 | create-only, immutable display ID | T204, T207 | sequential/concurrent conflict tests |
| FR-005 | explicit update/new credential snapshot | T204, T206 | update/CAS/snapshot tests |
| FR-006 | governed account/credential lifecycle | T202, T204, T206, T207 | control manifest and crash-order tests |
| FR-007 | locked restart-safe v1 migration | T203, T204 | interruption/idempotency/permission matrix |
| FR-008 | legacy quarantine/delete-only cleanup | T204 | fake keyring call log and janitor tests |
| FR-009 | orthogonal private status | T204, T207 | status golden/privacy scan |
| FR-010 | legacy ledger state migration | T205 | all-state v1/v2/v3 fixtures |
| FR-011 | strict config/ledger migration bounds | T203-T205 | newer/duplicate/malformed/N+1 tests |
| FR-012 | create-once fixed owner realm | T202, T206, T207 | bootstrap/path/mismatch/recovery tests |
| FR-013 | complete persisted challenge | T201, T202, T206 | transcript/schema/context tests |
| FR-014 | exact independent signer manifest | T201, T207 | golden export and tamper tests |
| FR-015 | strict detached proof/replay | T201, T202, T206 | RFC8032, expiry, replay, concurrency tests |
| FR-016 | receipts/global claims/recovery | T202, T205, T206 | copy/rollback/crash/invocation matrix |
| FR-017 | exhaustive action map/apply recheck | T201, T206 | action golden and stale-context tests |
| FR-018 | private re-verifiable evidence | T202, T207 | rotation reverify and output privacy tests |
| FR-019 | rotation/recovery/epoch invalidation | T202, T206, T207 | dual-proof, staged crash, recovery tests |
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
| NFR-001 | fail closed before keyring/network | T202, T204, T206, T209 | call-count and TLS/protocol tests |
| NFR-002 | secret/private/untrusted exclusion | T201-T212 | source/output/evidence scans |
| NFR-003 | atomic restart-safe transitions | T202, T204-T206 | fault/restart/copy/rollback matrix |
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
| SC-004 signature/replay/copy/rollback protection | T201, T202, T205, T206 | proof/fault/multiprocess matrix |
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

- Exact-length SQL constraints mirror typed Rust validation.
- Receipt, nonce, grant use, effect claim, and invocation each have a durable
  unique boundary.
- Last observed wall-clock high-water detects significant rollback; 30-second
  issuance tolerance never extends expiry.
- Rotation stages journal, updates anchor, and finalizes one epoch with a
  recoverable matching transition.
- Historical key/receipt data remains; private key never appears.

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

## Resolved Technical Questions

- Signing algorithm: Ed25519 strict verification, direct typed transcript.
- Signing bytes: `KIRJE-AUTHORIZATION-V1` strict tagged binary.
- Owner entropy: 32-byte OS-random realm and nonce.
- Fixed authority: platform anchor/journal/apply-lock paths, no normal override.
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

No product-spec or executable-contract question blocks T202 packetization.

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

## Execution Gate

`APPROVED_FOR_T202_PACKETIZATION`

T201-A001 is preserved as a stopped attempt and T201-A002 as a GREEN but
review-failed attempt. T201-A003 may edit only the narrowed core/test scope,
must first add failing invariant tests, and may not weaken canonical bytes,
strict verification, first-boundary limits, or privacy constraints.
