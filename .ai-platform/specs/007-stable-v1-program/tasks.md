# Work Graph: Stable 1.0 Program

## Metadata

- Feature ID: `007-stable-v1-program`
- Status: Confirmed
- Source: `spec.md`, `plan.md`
- Updated: 2026-08-30
- Target release: `v1.0.0`

## Scheduling Rules

- T101 through T108 are sequential user-visible checkpoints.
- Each implementation task ends in a reviewed commit. Each checkpoint ends in
  a PR/merge decision and, except T109, a prerelease or stable tag.
- Focused RED/GREEN and changed-crate gates run per task. Full workspace,
  dependency, migration, CI, and checkpoint-specific gates run once per tag.
- Future packets are generated just in time after their predecessor is
  Accepted. Only T109 is packetized in this governance round.
- Existing accepted T201-T202C1S commits and evidence remain immutable.
- The preserved T202C2 implementation is not modified during governance. After
  plan approval, T109 moves directly to review because implementation and
  test evidence already exist.
- Production tasks are serial when their state, migration, or public contracts
  conflict. Read-only review and CI jobs may run concurrently.
- A failed gate remains visible and gets a named remediation owner. It is not
  converted into a passing checkpoint claim.

## Checkpoint Summary

| Checkpoint | Tasks | Output |
| --- | --- | --- |
| Current branch | T109 | reviewed checkpoint commit and PR/merge decision |
| Security Alpha | T110-T112 | `v1.0.0-alpha.1` |
| Mailbox Alpha | T113-T114 | `v1.0.0-alpha.2` |
| Delivery Beta | T115-T116 | `v1.0.0-beta.1` |
| Policy Beta | T117 | `v1.0.0-beta.2` |
| Contract RC | T118-T119 | `v1.0.0-rc.1` |
| Hardening RC | T120 | `v1.0.0-rc.2` |
| Stable | T121 | `v1.0.0` |

## T109: Recover And Review The Current Account-Create Checkpoint

Status: Accepted
Implementation state: accepted by the user on 2026-08-30 at reviewed production
commit `94f3495`; governance/evidence commit `c8208f6`
Priority: P0
Depends on: T202C1S Accepted at commit `8eceaff`
Blocks: T110
Story / Requirement: US-001, US-003; SFR-001-SFR-003; NFR-001-NFR-003,
NFR-006-NFR-008
Parallel: No
Conflicts with: Any concurrent authority store or account-registry edit

Goal:
Preserve the interrupted T202C2 account-create implementation, integrate its
real RED/GREEN evidence, perform adversarial spec and engineering review, close
only review findings in the original scope, and produce one checkpoint commit.

Allowed files:
- `crates/kirje-store/src/lib.rs`
- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/tests/authority_registry.rs`
- `crates/kirje-store/tests/fixtures/authority/registry/account_create/**`
- `.ai-platform/evidence/T202C2/**`
- `.ai-platform/specs/008-security-baseline/tasks.md` for reviewed status only

Test targets:
- Account-create challenge, prepare, config-committed, finalize, abort,
  recovery, concurrency, corruption, restart, and bounded-history tests.
- Exact schema, predecessor fixture, privacy, query-count, and query-plan gates.

Deliverables:
- Reviewed account-create diff.
- Complete T202C2 evidence summary and test results.
- One production commit plus one evidence/status commit, or one combined
  checkpoint commit when review makes no production change.
- Explicit record of the unchanged baseline `cargo deny` finding.

Acceptance criteria:
- Exact source/test/fixture hashes match the interrupted attempt unless review
  records and validates a scoped fix.
- The account-create lifecycle is crash-safe, idempotent, bounded, private, and
  schema-preserving.
- No new account-create scope, dependency, schema, runtime, CLI, MCP, keyring,
  protocol, or network behavior is introduced.
- Review has no unresolved Critical or High finding.

Definition of Done:
- Attempt evidence is integrated.
- Focused verification is fresh; unchanged-hash full-suite evidence is valid.
- Review findings and the yanked dependency baseline are explicit.
- Diff is committed and ready for checkpoint PR/merge acceptance.

Validation commands:
```bash
cargo fmt --all --check
cargo test -p kirje-store --test authority_registry --all-features --locked
cargo clippy -p kirje-store --all-targets --all-features --locked -- -D warnings
git diff --check
```

TDD plan:
- RED: Reuse the recorded missing-surface and unsupported-capability failures
  from T202C2-A001 only when exact content hashes match.
- GREEN: Reuse recorded focused/package/workspace/MSRV results only under the
  same hash rule.
- REFACTOR: Make no refactor unless review identifies a concrete defect; any
  fix receives a new focused RED.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T109.yaml`

Evidence required:
- `.ai-platform/evidence/T202C2/attempts/T202C2-A001.md`
- `.ai-platform/evidence/T202C2/summary.md`
- `.ai-platform/evidence/T202C2/test-results.md`
- Changed-file hashes, review findings, validation results, and residual risk.

## T110: Complete Authority Lifecycles

Status: Running
Execution state: T109 is Accepted. T110 runs as four strict serial security
batches. T202C3-A001 challenge issuance is reviewed at commit `daf22a0`; the
T202C3-A002 account-update transition is accepted at commit `2c00f32`.
`T202C3-A003` account-remove transition is accepted at commit `703b5a1`.
`T202C3-A004` credential-set transition is accepted at commit `1c6d7cb`.
Credential delete is the next bounded attempt pending packet review. No later
attempt or security batch is Ready until its predecessor is reviewed and
accepted.
Priority: P0
Depends on: T109 Accepted
Blocks: T111
Story / Requirement: US-001, US-003; SFR-001-SFR-003; NFR-001-NFR-003,
NFR-006-NFR-008
Parallel: No
Conflicts with: Authority schema, registry, authorization, claim, event, and
restart validation work

Goal:
Complete account update/remove, credential set/delete/cleanup, registry-bound
remote challenges, effect claims, owner rotation/recovery, audit export, and
their fail-closed restart contracts.

Allowed files:
- `crates/kirje-core/src/account.rs`
- `crates/kirje-core/src/authorization.rs`
- `crates/kirje-core/src/operation.rs`
- `crates/kirje-core/tests/**`
- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/src/authority/schema_v1.sql`
- `crates/kirje-store/tests/authority_*.rs`
- `crates/kirje-store/tests/fixtures/authority/**`

Test targets:
- T202C3-T202E acceptance matrices in `008-security-baseline/tasks.md`.

Deliverables:
- Reviewed, independently revertible authority-lifecycle commits and evidence
  summaries for T202C3, T202C4, T202D, and T202E.

Acceptance criteria:
- Remaining authority lifecycles are exact, immutable, crash-safe, bounded, and
  free of generic signing, credential, or remote-effect surfaces.

Definition of Done:
- Focused RED/GREEN, changed-crate gates, review, evidence, and commit pass.

Validation commands:
- `cargo test -p kirje-core --all-features --locked`
- `cargo test -p kirje-store --all-features --locked`
- `cargo clippy -p kirje-store --all-targets --all-features --locked -- -D warnings`

TDD plan:
- RED: Add exact lifecycle, crash, corruption, and capability negatives.
- GREEN: Implement the minimum authority behavior.
- REFACTOR: Consolidate only after lifecycle matrices are green.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T110.yaml`

Evidence required:
- RED/GREEN commands, state/fault matrix, hashes, review, and residual risk.

### Execution Batches

1. `T202C3`: account update/remove, credential set/delete/cleanup. The first
   bounded attempt, `T202C3-A001`, enables exact effect-free challenge issuance
   only. `T202C3-A002` delivers reviewed account-update prepare through terminal
   transition, immutable versioning, and provisional-to-ready cleanup only at
   commit `2c00f32`; claim/delete and other transition kinds remain later
   attempts. `T202C3-A003` delivers reviewed account-remove prepare through
   terminal state, removed-history preservation, store-only after versioning,
   and cleanup readiness at commit `703b5a1`. `T202C3-A004` delivers reviewed
   credential-targeted prepare through terminal state, existing credential
   identity, immutable account/store versioning, and the no-cleanup/no-keyring
   boundary at commit `1c6d7cb`; the user explicitly accepted A004 on
   2026-08-30. Credential delete is the next bounded attempt pending packet
   review.
2. `T202C4`: remote challenge registry binding and planner-owned effect row.
3. `T202D`: effect claim, invocation permit, observation, and ambiguity.
4. `T202E`: owner rotation/recovery, audit, and aggregate authority acceptance.

Each batch and each high-risk attempt starts from a self-contained packet,
records discriminating RED/GREEN evidence, and produces a reviewable commit.
T110 becomes `Needs_Review` only after all four security batches pass.

## T111: Integrate Safe Local State And Runtime Authorization

Status: Draft
Priority: P0
Depends on: T110 Accepted
Blocks: T112
Story / Requirement: US-001, US-003, US-005; SFR-001-SFR-006;
NFR-001-NFR-008
Parallel: No
Conflicts with: Config, credential, ledger, runtime authorization, local input,
protocol capability, and public error changes

Goal:
Deliver bounded no-follow local I/O, config v2 and credential binding, ledger v3
migration, shared authorization and crash recovery, and bounded protocol
responses through one validated account snapshot.

Allowed files:
- `Cargo.toml`
- `Cargo.lock`
- `crates/kirje-local-io/**`
- `crates/kirje-core/**`
- `crates/kirje-store/**`
- `crates/kirje-runtime/**`
- `crates/kirje-protocol/**`

Test targets:
- T203-T206 and T209 acceptance coverage in `008-security-baseline/tasks.md`.

Deliverables:
- Reviewed local-state/runtime integration commits.
- Removal of the yanked `chacha20 0.10.1` dependency or an upstream-safe
  dependency graph that makes `cargo deny check` green.

Acceptance criteria:
- Legacy credentials cannot be redirected.
- File/stdin and protocol inputs are bounded before allocation or effect.
- Pending legacy operations cannot invoke remote work without new authority.
- `cargo deny check` passes.

Definition of Done:
- Focused RED/GREEN, migrations, no-default/MSRV where relevant, dependency
  gate, review, evidence, and commits pass.

Validation commands:
- `cargo test -p kirje-runtime --all-features --locked`
- `cargo test -p kirje-store --all-features --locked`
- `cargo test -p kirje-protocol --all-features --locked`
- `cargo deny check`

TDD plan:
- RED: Reproduce redirect, path replacement, over-limit, migration, and crash
  boundaries.
- GREEN: Implement the smallest shared services and adapters.
- REFACTOR: Consolidate after migration and authorization tests pass.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T111.yaml`

Evidence required:
- Migration matrix, dependency result, RED/GREEN logs, review, and residual risk.

## T112: Deliver Security Alpha

Status: Draft
Priority: P0
Depends on: T111 Accepted
Blocks: T113
Story / Requirement: US-001, US-003, US-005; SFR-001-SFR-007;
NFR-001-NFR-008
Parallel: No
Conflicts with: CLI/MCP schemas, capability reporting, security docs, CI, and
release metadata

Goal:
Expose owner/account/credential workflows through CLI, preserve the MCP deny
surface, align capability and security documentation, run complete gates, and
publish `v1.0.0-alpha.1`.

Allowed files:
- `crates/kirje-cli/**`
- `crates/kirje-mcp/**`
- `crates/kirje-runtime/**`
- `skills/kirje/**`
- `docs/**`
- `README.md`
- `.github/workflows/**`
- `.ai-platform/docs/**`
- `.ai-platform/evidence/**`

Test targets:
- T207-T212 acceptance coverage and every `SFR-*`.

Deliverables:
- Usable CLI workflow, exact MCP exclusions, canonical docs, checkpoint
  evidence, PR/merge, and `v1.0.0-alpha.1`.

Acceptance criteria:
- Security alpha success path works without exposing secrets.
- Full local gates, CI, controlled account workflow, and dependency policy pass.

Definition of Done:
- Checkpoint review is accepted and the tag matches the published evidence.

Validation commands:
- Full tagged-checkpoint gate from `plan.md`.
- Controlled secret-free account workflow.

TDD plan:
- RED: CLI/MCP contract and capability snapshots expose missing or unsafe paths.
- GREEN: Wire shared services and exact deny surface.
- REFACTOR: Remove duplicate adapter logic only after parity tests pass.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T112.yaml`

Evidence required:
- CLI/MCP snapshots, full gates, CI, tag, and sanitized workflow results.

## T113: Deliver Mailbox Convergence Core

Status: Draft
Priority: P0
Depends on: T112 Accepted
Blocks: T114
Story / Requirement: US-001; FR-001-FR-003; NFR-001-NFR-008
Parallel: No
Conflicts with: Index schema, sync cursor, message reference, and IMAP query work

Goal:
Implement bounded resumable backfill, scoped reconciliation, coverage state,
tombstones, and transactional UIDVALIDITY rebuild.

Allowed files:
- `crates/kirje-core/**`
- `crates/kirje-store/**`
- `crates/kirje-runtime/**`
- `crates/kirje-protocol/**`

Test targets:
- Interruption, remote drift, missing coverage, UIDVALIDITY, migration, and
  bounded UID query fixtures.

Deliverables:
- Reviewed convergence core commit and evidence.

Acceptance criteria:
- Sync resumes without skipped coverage, false deletion, duplicate rows, or
  unbounded remote UID materialization.

Definition of Done:
- Focused RED/GREEN, migration, changed-crate gates, review, and commit pass.

Validation commands:
- Focused core/store/runtime/protocol sync suites.

TDD plan:
- RED: Reproduce interruption, drift, stale reference, and bound failures.
- GREEN: Implement transactional convergence services.
- REFACTOR: Consolidate after migration and interruption tests pass.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T113.yaml`

Evidence required:
- Coverage/migration matrix, RED/GREEN logs, review, and residual risk.

## T114: Deliver Thread Queries And Mailbox Alpha

Status: Draft
Priority: P0
Depends on: T113 Accepted
Blocks: T115
Story / Requirement: US-001, US-002; FR-004-FR-005; NFR-001-NFR-008
Parallel: No
Conflicts with: Thread schema, CLI/MCP sync/query contracts, and release metadata

Goal:
Deliver deterministic header-based thread graphs and bounded CLI/MCP
convergence, coverage, and thread services; publish `v1.0.0-alpha.2`.

Allowed files:
- `crates/kirje-core/**`
- `crates/kirje-store/**`
- `crates/kirje-runtime/**`
- `crates/kirje-cli/**`
- `crates/kirje-mcp/**`
- `docs/**`
- `.ai-platform/evidence/**`

Test targets:
- Cycle, duplicate, missing-parent, provisional-thread, parity, and controlled
  read-only mailbox scenarios.

Deliverables:
- Thread/query commits, checkpoint evidence, PR/merge, and alpha.2 tag.

Acceptance criteria:
- Thread identity is deterministic and never inferred authoritatively from
  subject alone; outputs are bounded and parity-tested.

Definition of Done:
- Full checkpoint gate, CI, live read-only validation, review, and tag pass.

Validation commands:
- Full tagged-checkpoint gate plus controlled read-only mailbox scripts.

TDD plan:
- RED: Header anomaly and adapter parity fixtures fail.
- GREEN: Implement thread and adapter services.
- REFACTOR: Optimize only with unchanged deterministic fixtures.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T114.yaml`

Evidence required:
- Thread fixtures, parity, full gates, CI, tag, and live summary.

## T115: Deliver Reconciled Send Core

Status: Draft
Priority: P0
Depends on: T114 Accepted
Blocks: T116
Story / Requirement: US-003; FR-006-FR-010; NFR-001-NFR-008
Parallel: No
Conflicts with: MIME, ledger, SMTP, IMAP APPEND, and reconciliation state work

Goal:
Persist canonical MIME, SMTP progress, Sent filing, certainty, claims, and
append-only owner reconciliation without automatic uncertain replay.

Allowed files:
- `crates/kirje-core/**`
- `crates/kirje-store/**`
- `crates/kirje-runtime/**`
- `crates/kirje-protocol/**`

Test targets:
- MIME golden, ledger migration, SMTP/APPEND crash matrix, filing destination,
  and no-replay reconciliation.

Deliverables:
- Reviewed delivery-core commits and evidence.

Acceptance criteria:
- SMTP and filing outcomes are independently inspectable and no uncertain
  remote effect is automatically repeated.

Definition of Done:
- Focused RED/GREEN, migration/fault gates, review, and commits pass.

Validation commands:
- Focused core/store/runtime/protocol delivery suites.

TDD plan:
- RED: Reproduce every remote-effect interruption boundary.
- GREEN: Extend the shared ledger and runtime minimally.
- REFACTOR: Preserve immutable MIME and certainty invariants.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T115.yaml`

Evidence required:
- State/fault matrix, migration, RED/GREEN logs, review, and residual risk.

## T116: Deliver Delivery Beta

Status: Draft
Priority: P0
Depends on: T115 Accepted
Blocks: T117
Story / Requirement: US-003; FR-006-FR-011; NFR-001-NFR-008
Parallel: No
Conflicts with: CLI/MCP send/reconciliation schemas and release metadata

Goal:
Expose bounded status/apply/reconciliation workflows, keep owner reconciliation
CLI-only, complete controlled self-send evidence, and publish
`v1.0.0-beta.1`.

Allowed files:
- `crates/kirje-cli/**`
- `crates/kirje-mcp/**`
- `crates/kirje-runtime/**`
- `scripts/**`
- `docs/**`
- `.ai-platform/evidence/**`

Test targets:
- CLI/MCP parity and deny surface, live self-send, Sent filing, and ambiguous
  operator workflow.

Deliverables:
- Adapter commits, checkpoint evidence, PR/merge, and beta.1 tag.

Acceptance criteria:
- MCP cannot approve, close, or retry uncertain effects; live evidence does not
  overclaim recipient delivery.

Definition of Done:
- Full checkpoint gate, CI, controlled send, review, and tag pass.

Validation commands:
- Full tagged-checkpoint gate plus controlled send scripts.

TDD plan:
- RED: Contract tests expose missing parity or unsafe owner operations.
- GREEN: Wire shared runtime behavior.
- REFACTOR: Keep command handlers free of business state logic.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T116.yaml`

Evidence required:
- Contract snapshots, full gates, CI, tag, and sanitized send results.

## T117: Deliver Policy And Provider Beta

Status: Draft
Priority: P0
Depends on: T116 Accepted
Blocks: T118
Story / Requirement: US-004; FR-012-FR-017; NFR-001-NFR-008
Parallel: No
Conflicts with: Account policy, planning/apply, provider registry, capability,
and compatibility documentation

Goal:
Enforce canonical account policy at plan and invocation, publish honest provider
tiers, complete sanitized conformance, and publish `v1.0.0-beta.2`.

Allowed files:
- `crates/kirje-core/**`
- `crates/kirje-runtime/**`
- `crates/kirje-protocol/**`
- `crates/kirje-cli/**`
- `crates/kirje-mcp/**`
- `registry/**`
- `docs/**`
- `.ai-platform/evidence/**`

Test targets:
- Policy canonicalization/races/scopes, provider tiers, capability reasons,
  secret scan, and sanitized conformance.

Deliverables:
- Policy/provider commits, checkpoint evidence, PR/merge, and beta.2 tag.

Acceptance criteria:
- Disallowed work fails before network mutation; provider claims match evidence.

Definition of Done:
- Full checkpoint gate, CI, conformance, review, and tag pass.

Validation commands:
- Full tagged-checkpoint gate plus policy and conformance suites.

TDD plan:
- RED: Reproduce missing policy, apply races, and inflated support claims.
- GREEN: Add canonical policy and capability mapping.
- REFACTOR: Keep policy and provider decisions outside adapters.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T117.yaml`

Evidence required:
- Policy matrix, provider report, full gates, CI, tag, and residual risk.

## T118: Freeze Stable Contracts And Migrations

Status: Draft
Priority: P0
Depends on: T117 Accepted
Blocks: T119
Story / Requirement: US-005; FR-018-FR-021; NFR-001-NFR-008
Parallel: No
Conflicts with: Public schemas, errors, operation states, database migrations,
version metadata, and compatibility documentation

Goal:
Freeze the supported 1.x machine and persistence contract with golden fixtures,
complete migrations, backup/restore, downgrade rejection, and capability
reason tests.

Allowed files:
- `crates/**`
- `docs/**`
- `README.md`
- `.ai-platform/evidence/**`

Test targets:
- CLI/MCP/schema/error goldens and every supported database migration path.

Deliverables:
- Reviewed contract/migration commits and compatibility matrix.

Acceptance criteria:
- One documented version matrix matches runtime behavior and fixtures.

Definition of Done:
- Golden, migration, backup/restore, full local gates, review, and commits pass.

Validation commands:
- Full tagged-checkpoint gate plus golden and migration suites.

TDD plan:
- RED: Golden fixtures detect unversioned or inconsistent behavior.
- GREEN: Add minimum stable versions and migration guarantees.
- REFACTOR: Remove duplicate metadata after goldens pass.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T118.yaml`

Evidence required:
- Compatibility matrix, migrations, backup/restore, review, and residual risk.

## T119: Publish Verifiable Release Candidate Artifacts

Status: Draft
Priority: P0
Depends on: T118 Accepted
Blocks: T120
Story / Requirement: US-006; FR-022-FR-025; NFR-001-NFR-008
Parallel: No
Conflicts with: Packaging, release CI, version metadata, permissions, and
platform support claims

Goal:
Build, verify, and publish preview artifacts with checksums, SBOM, provenance,
install/doctor checks, honest support tiers, and tag `v1.0.0-rc.1`.

Allowed files:
- `.github/workflows/**`
- `scripts/**`
- `Cargo.toml`
- `Cargo.lock`
- `crates/kirje-cli/**`
- `docs/**`
- `README.md`
- `.ai-platform/evidence/**`

Test targets:
- Target builds, archives, version identity, checksums, SBOM, provenance,
  install, keyring, permissions, locking, paths, and upgrades.

Deliverables:
- Target artifacts, verifier results, checkpoint evidence, and rc.1 tag.

Acceptance criteria:
- Published assets match the tag and contain no local account state or secrets.

Definition of Done:
- Target CI, artifact verification, review, PR/merge, and tag pass.

Validation commands:
- Full tagged-checkpoint gate plus target artifact verification.

TDD plan:
- RED: Verifier rejects missing or mismatched artifacts.
- GREEN: Add least-privilege build and publication workflow.
- REFACTOR: Deduplicate metadata only after target verification passes.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T119.yaml`

Evidence required:
- Artifact manifest, checksums, SBOM, provenance, CI, tag, and support tiers.

## T120: Harden And Accept The Release Candidate

Status: Draft
Priority: P0
Depends on: T119 Accepted
Blocks: T121
Story / Requirement: US-001-US-006; FR-026-FR-029; NFR-001-NFR-008
Parallel: No
Conflicts with: Unreviewed feature development or release workflow changes

Goal:
Complete fuzz, property, fault, migration, provider, security, privacy,
performance, documentation, and disaster-recovery acceptance; publish
`v1.0.0-rc.2`.

Allowed files:
- `crates/**`
- `fuzz/**`
- `scripts/**`
- `tests/**`
- `docs/**`
- `.github/workflows/**`
- `.ai-platform/evidence/**`

Test targets:
- Adversarial parser/state suites, every crash boundary, migration rehearsal,
  deterministic standards server, real provider, and release dry run.

Deliverables:
- Finding register, conformance report, fixes, dry-run manifest, and rc.2 tag.

Acceptance criteria:
- No unresolved P0/P1 finding remains and unavailable external checks are
  honest sanitized blockers.

Definition of Done:
- Hardening gates, review, PR/merge, evidence, and rc.2 tag pass.

Validation commands:
- Full tagged-checkpoint gate plus fuzz/fault/conformance/release dry run.

TDD plan:
- RED: Reproduce each accepted hardening finding.
- GREEN: Fix only release blockers.
- REFACTOR: No scope growth during RC.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T120.yaml`

Evidence required:
- Finding register, conformance, full gates, CI, dry run, tag, and residual risk.

## T121: Publish Kirje 1.0.0

Status: Draft
Priority: P0
Depends on: T120 Accepted
Blocks: None
Story / Requirement: US-001-US-006; FR-030-FR-032; NFR-001-NFR-008
Parallel: No
Conflicts with: Any unmerged production, contract, documentation, or release
workflow change

Goal:
Publish the exact clean, green, reviewed Kirje `v1.0.0` commit and verify its
artifacts and final release report.

Allowed files:
- Release version and notes paths declared in the packet.
- `.ai-platform/docs/release-report.md`
- `.ai-platform/evidence/**`

Test targets:
- Final versions/contracts, target CI, artifact download verification,
  installation, tag identity, GitHub Release, and post-release smoke.

Deliverables:
- Release commit, annotated tag, GitHub Release, verified assets, and canonical
  release report.

Acceptance criteria:
- FR-030-FR-032 and every program success criterion have accepted evidence.

Definition of Done:
- Final gates, user acceptance, clean commit, tag, publication, and post-release
  verification pass.

Validation commands:
- Final tagged-checkpoint and downloaded-artifact verification.

TDD plan:
- RED: Release verifier rejects missing or mismatched final assets.
- GREEN: Publish only the exact accepted commit and assets.
- REFACTOR: Not applicable after tag; corrections require a new release.

Packet path:
- `.ai-platform/specs/007-stable-v1-program/packets/T121.yaml`

Evidence required:
- Release commit, tag, URL, asset manifest, checksums, SBOM, provenance, CI,
  installation, smoke, and final report.

## Requirement Coverage

- SFR-001-SFR-003: T109-T112
- SFR-004-SFR-007: T111-T112
- FR-001-FR-003: T113
- FR-004-FR-005: T114
- FR-006-FR-010: T115
- FR-011: T116
- FR-012-FR-017: T117
- FR-018-FR-021: T118
- FR-022-FR-025: T119
- FR-026-FR-029: T120
- FR-030-FR-032: T121
- NFR-001-NFR-008: enforced at every relevant task and checkpoint.

## User Review Gate

This work graph is `Confirmed`. The user approved the accelerated plan and task
breakdown on 2026-08-30. T109 is executable and is in `Needs_Review` because
its interrupted implementation and test evidence already exist.
