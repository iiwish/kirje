# Work Graph: Stable 1.0 Program

## Metadata

- Feature ID: `007-stable-v1-program`
- Status: Confirmed
- Source: `spec.md`, `plan.md`
- Updated: 2026-08-27

## Scheduling Rules

- T101 through T108 are sequential release epics.
- Research and read-only review may run in parallel when file scopes do not
  conflict. Production implementation cannot merge out of sequence.
- Each epic must create a child feature task graph with executor-sized tasks,
  exact allowed files, RED/GREEN commands, packets, and evidence before code
  changes begin.
- A release epic becomes Accepted only after its child tasks, review, local
  gates, PR CI, merge, and post-merge main CI are complete.

## T101: Govern And Deliver v0.3.1 Security Baseline

Status: Running
Priority: P0
Depends on: v0.3 accepted baseline
Blocks: T102-T108
Story / Requirement: SFR-001-SFR-007, NFR-001-NFR-008
Parallel: No
Conflicts with: Any concurrent account, credential, approval, local-import, or
remote-write production change

Goal:
Eliminate credential redirection, distinguish terminal presence from strong
owner authorization, make local imports race-safe and bounded, and correct the
documented local threat boundary before adding new remote behavior.

Allowed files:
- `.ai-platform/specs/008-security-baseline/**`
- `.ai-platform/docs/tasks.md`
- Production and documentation paths must be narrowed by the confirmed child
  task graph before implementation.

Test targets:
- Credential identity/fingerprint migration, account replacement rejection,
  legacy quarantine, endpoint-change invalidation, trusted bootstrap, signed
  remote/control-plane authorization, nonce/expiry/replay rejection, MCP
  exclusion, same-handle bounded file import, bounded stdin, capability/response
  bounds, and corrected product/security documentation.

Deliverables:
- Confirmed `008-security-baseline` artifacts.
- Accepted child implementation tasks and v0.3.1 evidence.
- Merged security baseline commit and green post-merge CI.

Acceptance criteria:
- SFR-001 through SFR-007 and mapped NFRs have passing evidence.
- Existing credentials cannot be redirected by account ID reuse.
- TTY cannot create remote or security-sensitive authorization.
- Path replacement or oversized input cannot bypass import bounds.
- No prerelease retains the known OAuth2/JMAP/Gmail/Outlook runtime overclaim.

Definition of Done:
- Child artifacts, TDD, security review, full gates, PR, CI, merge, and release
  report are complete.

Validation commands:
- Program artifact validator for T101.
- Commands confirmed in the child feature task graph.
- Full workspace gates from `plan.md`.

TDD plan:
- RED: Reproduce endpoint credential reuse, account replacement, automated TTY
  authorization, signature replay/expiry, privileged config bypass,
  symlink/path replacement, oversized file/stream handling, and an unbounded
  MCP stdio JSON-RPC line.
- GREEN: Implement bound credential identities, explicit account updates,
  owner-signed authorization, bounded imports, and honest capability claims.
- REFACTOR: Consolidate only after secret exclusion and migration tests pass.

Packet path:
- `.ai-platform/specs/008-security-baseline/packets/`

Evidence required:
- Child task evidence, threat review, migration results, PR/CI/merge references,
  and a credential/content-free security summary.

## T102: Govern And Deliver v0.4 Mailbox Convergence

Status: Draft
Priority: P0
Depends on: T101 Accepted
Blocks: T103-T108
Story / Requirement: US-001, US-002, FR-001-FR-005, NFR-001-NFR-008
Parallel: No
Conflicts with: Any concurrent index, sync, message-reference, or thread-model
production change

Goal:
Deliver explicit resumable history backfill, scoped state reconciliation,
coverage semantics, and deterministic thread queries as v0.4.

Allowed files:
- `.ai-platform/specs/009-mailbox-convergence/**`
- `.ai-platform/docs/tasks.md`
- Production and documentation paths must be narrowed by the confirmed child
  task graph before implementation.

Test targets:
- Child-spec requirement checklist and analysis.
- Store migration, cursor interruption, reconciliation, thread graph, CLI/MCP
  contract, and controlled read-only mailbox tests.

Deliverables:
- Confirmed `009-mailbox-convergence` artifacts.
- Accepted child implementation tasks and v0.4 evidence.
- Merged v0.4 release commit and green post-merge CI.

Acceptance criteria:
- FR-001 through FR-005 and mapped NFRs have passing evidence.
- No false deletion is inferred outside reconciled coverage.
- Existing v0.3 references and ledgers remain valid or migrate explicitly.

Definition of Done:
- Child artifacts, TDD, reviews, full gates, PR, CI, merge, and release report
  are complete.

Validation commands:
- Program artifact validator for T102.
- Commands confirmed in the child feature task graph.
- Full workspace gates from `plan.md`.

TDD plan:
- RED: Child tasks prove interruption, remote drift, thread anomalies, and
  contract gaps fail on the v0.3 baseline.
- GREEN: Implement the minimum provider-neutral convergence services.
- REFACTOR: Consolidate only after all migration and contract tests pass.

Packet path:
- `.ai-platform/specs/009-mailbox-convergence/packets/`

Evidence required:
- Child task evidence, aggregate release evidence, PR/CI/merge references, and
  sanitized controlled-mailbox results.

## T103: Govern And Deliver v0.5 Delivery Reconciliation

Status: Draft
Priority: P0
Depends on: T102 Accepted
Blocks: T104-T108
Story / Requirement: US-003, FR-006-FR-011, NFR-001-NFR-008
Parallel: No
Conflicts with: Any concurrent ledger, send-state, SMTP, or IMAP APPEND change

Goal:
Deliver separately recorded SMTP acceptance and Sent filing plus append-only,
CLI-only operator reconciliation without automatic resend.

Allowed files:
- `.ai-platform/specs/010-delivery-reconciliation/**`
- `.ai-platform/docs/tasks.md`
- Production and documentation paths must be narrowed by the confirmed child
  task graph before implementation.

Test targets:
- Composite send state, ledger migration, SMTP/IMAP failure windows, no-replay
  crash recovery, CLI-only reconciliation, MCP exclusion, and live self-send.

Deliverables:
- Confirmed `010-delivery-reconciliation` artifacts.
- Accepted child implementation tasks and v0.5 evidence.
- Merged v0.5 release commit and green post-merge CI.

Acceptance criteria:
- FR-006 through FR-011 and mapped NFRs have passing evidence.
- No uncertain SMTP invocation can be replayed automatically.
- Sent destinations are provider-declared or explicitly approved.

Definition of Done:
- Child artifacts, TDD, reviews, full gates, PR, CI, merge, and release report
  are complete.

Validation commands:
- Program artifact validator for T103.
- Commands confirmed in the child feature task graph.
- Full workspace gates from `plan.md`.

TDD plan:
- RED: Child tasks model each SMTP and filing interruption boundary.
- GREEN: Extend the existing ledger and shared runtime services minimally.
- REFACTOR: Preserve terminal-state and migration invariants while simplifying.

Packet path:
- `.ai-platform/specs/010-delivery-reconciliation/packets/`

Evidence required:
- Child evidence, state-transition matrix, sanitized send results, and
  PR/CI/merge references.

## T104: Govern And Deliver v0.6 Policy And Provider Compatibility

Status: Draft
Priority: P0
Depends on: T103 Accepted
Blocks: T105-T108
Story / Requirement: US-004, FR-012-FR-017, NFR-001-NFR-008
Parallel: No
Conflicts with: Concurrent account-config, authorization, provider-registry, or
capability-reporting changes

Goal:
Enforce versioned local account policy and publish honest provider compatibility
tiers without expanding the 1.0 protocol/authentication boundary.

Allowed files:
- `.ai-platform/specs/011-policy-provider-compatibility/**`
- `.ai-platform/docs/tasks.md`
- Production and documentation paths must be narrowed by the confirmed child
  task graph before implementation.

Test targets:
- Policy canonicalization, migration, plan/apply races, recipient and mailbox
  scopes, capability reasons, fixtures, secret scans, and provider smoke tests.

Deliverables:
- Confirmed `011-policy-provider-compatibility` artifacts.
- Accepted child implementation tasks and v0.6 evidence.
- Merged v0.6 release commit and green post-merge CI.

Acceptance criteria:
- FR-012 through FR-017 and mapped NFRs have passing evidence.
- Legacy plans cannot bypass newly introduced policy.
- OAuth2/JMAP limitations and provider tiers are consistent everywhere.

Definition of Done:
- Child artifacts, TDD, reviews, full gates, PR, CI, merge, and release report
  are complete.

Validation commands:
- Program artifact validator for T104.
- Commands confirmed in the child feature task graph.
- Full workspace gates from `plan.md`.

TDD plan:
- RED: Child tasks prove missing policy, races, and claim inflation.
- GREEN: Add canonical policy and shared enforcement services.
- REFACTOR: Keep provider quirks and policy decisions out of CLI/MCP handlers.

Packet path:
- `.ai-platform/specs/011-policy-provider-compatibility/packets/`

Evidence required:
- Child evidence, policy matrix, compatibility report, secret scan, and
  PR/CI/merge references.

## T105: Govern And Deliver v0.7 Stable Contracts

Status: Draft
Priority: P0
Depends on: T104 Accepted
Blocks: T106-T108
Story / Requirement: US-005, FR-018-FR-021, NFR-001-NFR-008
Parallel: No
Conflicts with: Concurrent public schema, error, state, or migration changes

Goal:
Freeze and test the external and persisted compatibility contract that 1.x will
support.

Allowed files:
- `.ai-platform/specs/012-stable-contracts/**`
- `.ai-platform/docs/tasks.md`
- Production, golden-contract, and documentation paths must be narrowed by the
  confirmed child task graph before implementation.

Test targets:
- CLI/MCP/schema/error snapshots, capability reasons, database migrations,
  backup/restore, downgrade rejection, and deprecation checks.

Deliverables:
- Confirmed `012-stable-contracts` artifacts.
- Accepted child implementation tasks and v0.7 evidence.
- Merged v0.7 release commit and green post-merge CI.

Acceptance criteria:
- FR-018 through FR-021 and mapped NFRs have passing evidence.
- One documented version matrix matches runtime behavior and fixtures.

Definition of Done:
- Child artifacts, TDD, reviews, full gates, PR, CI, merge, and release report
  are complete.

Validation commands:
- Program artifact validator for T105.
- Commands confirmed in the child feature task graph.
- Full workspace gates from `plan.md`.

TDD plan:
- RED: Golden fixtures detect current unversioned or inconsistent behavior.
- GREEN: Add the minimum version and migration guarantees.
- REFACTOR: Remove duplicate interface metadata after snapshots pass.

Packet path:
- `.ai-platform/specs/012-stable-contracts/packets/`

Evidence required:
- Child evidence, compatibility matrix, migration receipts, and PR/CI/merge
  references.

## T106: Govern And Deliver v0.8 Distribution

Status: Draft
Priority: P0
Depends on: T105 Accepted
Blocks: T107-T108
Story / Requirement: US-006, FR-022-FR-025, NFR-001-NFR-008
Parallel: No
Conflicts with: Concurrent version, packaging, CI-permission, or release changes

Goal:
Ship installable, verifiable Kirje artifacts for every supported target without
weakening keyring or filesystem safety.

Allowed files:
- `.ai-platform/specs/013-distribution/**`
- `.ai-platform/docs/tasks.md`
- Workflow, packaging, platform-test, and documentation paths must be narrowed
  by the confirmed child task graph before implementation.

Test targets:
- Target builds/tests, archive contents, version identity, checksums, SBOM,
  provenance, install, doctor, keyring, paths, locking, and permissions.

Deliverables:
- Confirmed `013-distribution` artifacts.
- Accepted child implementation tasks and v0.8 evidence.
- Merged v0.8 release commit and green post-merge CI.

Acceptance criteria:
- FR-022 through FR-025 and mapped NFRs have passing evidence.
- Release artifacts contain no local account state or secrets.

Definition of Done:
- Child artifacts, TDD, reviews, full gates, PR, CI, merge, and release report
  are complete.

Validation commands:
- Program artifact validator for T106.
- Commands confirmed in the child feature task graph.
- Full workspace and target release gates from `plan.md`.

TDD plan:
- RED: Packaging verification fails on absent/mismatched platform artifacts.
- GREEN: Add least-privilege build and verification automation.
- REFACTOR: Deduplicate release metadata only after target verification passes.

Packet path:
- `.ai-platform/specs/013-distribution/packets/`

Evidence required:
- Child evidence, artifact manifests, verifier output, and PR/CI/merge references.

## T107: Govern And Deliver v0.9 Release Candidate

Status: Draft
Priority: P0
Depends on: T106 Accepted
Blocks: T108
Story / Requirement: US-001-US-006, FR-026-FR-029, NFR-001-NFR-008
Parallel: No
Conflicts with: Unreviewed feature development or release workflow changes

Goal:
Harden the complete 1.0 candidate under parser, state, crash, provider, security,
migration, and operational stress without adding new product scope.

Allowed files:
- `.ai-platform/specs/014-release-candidate/**`
- `.ai-platform/docs/tasks.md`
- Test, fixture, review, documentation, and narrowly justified bug-fix paths
  must be declared by the confirmed child task graph.

Test targets:
- Fuzz/property suites, fault injection, long-run tests, threat review,
  migration rehearsal, local standards server, real provider, and release dry
  run.

Deliverables:
- Confirmed `014-release-candidate` artifacts.
- Accepted hardening and fix tasks with v0.9 evidence.
- Merged release-candidate commit and green post-merge CI.

Acceptance criteria:
- FR-026 through FR-029 and every NFR have passing or explicitly accepted
  evidence.
- No unresolved P0 or P1 finding remains.

Definition of Done:
- Child artifacts, tests, reviews, full gates, PR, CI, merge, RC artifacts, and
  release report are complete.

Validation commands:
- Program artifact validator for T107.
- Commands confirmed in the child feature task graph.
- Full workspace, fuzz/fault, conformance, and release-dry-run gates.

TDD plan:
- RED: New adversarial and fault cases reproduce concrete failures or missing
  guarantees.
- GREEN: Fix only accepted RC blockers.
- REFACTOR: No scope growth; cleanup requires unchanged acceptance evidence.

Packet path:
- `.ai-platform/specs/014-release-candidate/packets/`

Evidence required:
- Child evidence, finding register, conformance summary, dry-run manifest, and
  PR/CI/merge references.

## T108: Publish v1.0.0

Status: Draft
Priority: P0
Depends on: T107 Accepted
Blocks: None
Story / Requirement: US-001-US-006, FR-030-FR-032, NFR-001-NFR-008
Parallel: No
Conflicts with: Any unmerged production or documentation change

Goal:
Create the exact clean, green, documented, tagged, verifiable Kirje v1.0.0
release and prove its published artifacts.

Allowed files:
- `.ai-platform/specs/015-v1-release/**`
- `.ai-platform/docs/release-report.md`
- Release version and notes paths declared by the confirmed child task graph.

Test targets:
- Final contract/version checks, target CI, artifact verification, install
  smoke, tag identity, GitHub Release contents, and post-release checks.

Deliverables:
- Confirmed `015-v1-release` artifacts.
- Accepted release task evidence.
- Annotated `v1.0.0` tag and published GitHub Release.

Acceptance criteria:
- FR-030 through FR-032 and all program success criteria are satisfied.
- Published assets match the tagged commit and documented support matrix.

Definition of Done:
- Final gates, user acceptance, clean release commit, tag, release, artifact
  verification, and release evidence are complete.

Validation commands:
- Program artifact validator for T108.
- Commands confirmed in the release child task graph.
- Tag, GitHub Release, checksum, SBOM, provenance, and install verification.

TDD plan:
- RED: Release dry-run verifier rejects missing or mismatched v1.0 assets.
- GREEN: Publish only the exact accepted release commit and assets.
- REFACTOR: Not applicable after tag; any correction requires a new release.

Packet path:
- `.ai-platform/specs/015-v1-release/packets/`

Evidence required:
- Release commit, tag, URL, asset manifest, verification output, CI runs,
  support matrix, and final release report.

## User Review Gate

Approval changes this work graph to Confirmed and allows T101 to enter child
security-baseline planning. It does not pre-approve later child specs or remote
mailbox mutations; those retain their own review and owner-signature gates.
