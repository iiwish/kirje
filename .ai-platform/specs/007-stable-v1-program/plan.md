# Plan: Stable 1.0 Program

## Metadata

- Feature ID: `007-stable-v1-program`
- Status: Confirmed
- Source spec: `spec.md`
- Updated: 2026-08-31
- Target release: `v1.0.0`

## Decision Summary

Kirje reaches 1.0 through one governed program and a sequence of usable
checkpoints. The checkpoints are integration and evidence boundaries, not
independent product programs. Each implementation batch is small enough to
review and commit; each tagged checkpoint runs the complete local gate and CI
matrix once.

The current `codex/v1-roadmap-governance` branch is the first checkpoint. Its
accepted commits and interrupted account-create implementation are preserved.
The account-create diff enters review from its recorded RED/GREEN evidence; it
is not discarded, regenerated, or expanded before review.

## Constitution Check

- Local-first and no GUI: satisfied. No checkpoint adds a hosted service or UI.
- Shared CLI/MCP services: satisfied. Runtime services remain the behavior
  owner; MCP keeps the exact deny surface for approval and owner mutations.
- Untrusted mailbox content: satisfied. Sync, thread, protocol, and evidence
  outputs remain bounded and marked untrusted.
- Secret exclusion: satisfied. Credentials remain in the OS keyring and owner
  private keys remain outside Kirje, fixtures, logs, and evidence.
- Plan/authorize/apply: satisfied. Send, mailbox mutation, account mutation,
  policy, and reconciliation retain immutable authorization boundaries.
- Protocol neutrality: satisfied. IMAP/SMTP behavior stays behind adapters.
- TDD and evidence: satisfied. Behavior batches require discriminating RED;
  checkpoint recovery may reuse same-attempt evidence only when exact content
  hashes prove that the tested code and fixtures are unchanged.
- Git and review: satisfied. Coherent batches commit independently; checkpoint
  integration receives spec, engineering, and QA review before merge or tag.

No constitution exception is proposed.

## Technical Decisions

### D-001 One V1 Governance Stack

`007-stable-v1-program` is the v1 product, plan, work-graph, analysis, and
checkpoint SSOT. Feature directories such as `008-security-baseline` provide
specialized contracts and accepted evidence. They do not create a second
release train or require a separate PR and post-merge cycle for every internal
contract unit.

### D-002 Incremental User-Visible Checkpoints

The delivery sequence is:

1. current branch checkpoint;
2. `v1.0.0-alpha.1` security foundation;
3. `v1.0.0-alpha.2` mailbox convergence;
4. `v1.0.0-beta.1` delivery reconciliation;
5. `v1.0.0-beta.2` policy and provider compatibility;
6. `v1.0.0-rc.1` stable contracts and distribution;
7. `v1.0.0-rc.2` hardening and acceptance;
8. `v1.0.0` stable release.

Every checkpoint ends with a concrete commit or tag, evidence summary, known
limitations, and the next executable batch. A checkpoint cannot remain Running
while producing only planning artifacts.

### D-003 Two Validation Cadences

Implementation batches run focused RED/GREEN tests, formatting, changed-crate
Clippy, and diff/privacy checks. Tagged checkpoints run the complete workspace
test, Clippy, build, dependency policy, migration, and checkpoint-specific
acceptance gates. CI owns cross-platform and release matrix work.

An unchanged content hash may reuse a successful command from the same
execution attempt. A code, test, fixture, schema, dependency, toolchain, or
relevant configuration change invalidates that evidence. Failed commands are
never hidden; a baseline dependency failure receives a named remediation task.

### D-004 Commit And Merge Cadence

Each executor-sized batch produces one coherent commit after review. A
checkpoint PR contains only reviewed batch commits and checkpoint evidence.
The branch does not accumulate another multi-thousand-line unreviewed diff.
Accepted history keeps its commit identity and is never rewritten to simplify
the plan.

### D-005 Current Branch Recovery

The current branch checkpoint starts at `ab9f059` plus the preserved
account-create diff in:

- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/tests/authority_registry.rs`
- `crates/kirje-store/tests/fixtures/authority/registry/account_create/**`

The interrupted attempt recorded real RED failures, focused GREEN, package and
workspace tests, MSRV tests, Clippy, build, schema hash, query-bound, and
privacy scans. The remaining work is evidence integration, adversarial review,
resolution or scheduling of the existing yanked transitive dependency, and Git
handoff. New account-create scope is not part of checkpoint recovery.

### D-006 Security Alpha Batching

The security checkpoint uses four bounded batches:

1. recover and review account-create;
2. complete account, credential, challenge, claim, rotation, and recovery
   authority lifecycles;
3. integrate safe local I/O, config v2, ledger v3, runtime authorization,
   adapters, capability bounds, and the dependency-policy remediation;
4. complete CLI/MCP workflows, canonical docs, security review, CI, and the
   `alpha.1` tag.

The detailed `008-security-baseline` contracts remain binding. Its remaining
task blocks are acceptance coverage for these batches, not mandatory one-PR
release units.

### D-007 Narrow 1.0 Boundary

IMAP and SMTP with password or provider-issued app-password authentication are
the 1.0 runtime boundary. OAuth2, Gmail API, Microsoft Graph, JMAP runtime,
resident sync, permanent delete, automatic uncertain replay, semantic search,
and embedded AI remain outside 1.0.

### D-008 Supported And Preview Targets

Release automation builds macOS arm64/x86_64, Linux arm64/x86_64, and Windows
x86_64 artifacts. A target is supported only when keyring, permissions, paths,
locking, installation, and upgrade behavior have platform evidence. Other
buildable artifacts remain preview quality and are labeled honestly.

## Checkpoint Plan

### Current Branch Checkpoint

Outcome: reviewed account-create implementation, integrated evidence, one clean
checkpoint commit, PR/merge decision, and no unexplained workspace changes.

Gate: account-create focused tests, exact content hashes, diff/privacy checks,
independent code review, and the already recorded unchanged-hash full-test
evidence. The yanked `chacha20` dependency is a visible baseline finding and
must be removed before `alpha.1` acceptance.

### Security Alpha

Outcome: owner-authorized account and credential workflows are usable through
CLI, forbidden through MCP where required, and enforced by shared runtime
services. Local imports, configuration, ledgers, protocol outputs, and stdio are
bounded. Runtime/docs report the exact IMAP/SMTP authentication boundary.

Gate: `SFR-001` through `SFR-007`, all `008` acceptance coverage, migration,
secret scan, full local gate, CI, controlled account workflow, and tag
`v1.0.0-alpha.1`.

### Mailbox Alpha

Outcome: explicit resumable backfill, scoped reconciliation, UIDVALIDITY
rebuild, coverage semantics, deterministic thread graph, and CLI/MCP parity.

Gate: interruption and drift fixtures, bounded protocol queries, migration,
thread anomalies, controlled read-only mailbox validation, full local gate,
CI, and tag `v1.0.0-alpha.2`.

### Delivery Beta

Outcome: one approved MIME artifact drives SMTP and optional Sent filing;
certainty is recorded per step; uncertain effects never resend automatically;
owner-signed CLI reconciliation is append-only.

Gate: SMTP/APPEND fault matrix, ledger migration, no-replay crash tests,
CLI/MCP deny surface, controlled self-send, full local gate, CI, and tag
`v1.0.0-beta.1`.

### Policy Beta

Outcome: canonical account policy is enforced at plan and invocation; provider
tiers distinguish reference, fixture-tested, and live-verified behavior.

Gate: policy race and scope matrix, capability fixtures, secret scan,
sanitized provider conformance, full local gate, CI, and tag
`v1.0.0-beta.2`.

### Contract And Distribution RC

Outcome: one documented stable compatibility matrix covers binary, JSON, CLI,
MCP, errors, operation states, and SQLite schemas. Verifiable artifacts are
published for buildable targets with honest support tiers.

Gate: golden contracts, every supported migration, backup/restore, target CI,
archives, checksums, SBOM, provenance, installation, `doctor`, full local gate,
and tag `v1.0.0-rc.1`.

### Hardening RC

Outcome: parser, MIME, state, migration, crash, provider, security, privacy,
performance, and recovery risks have no unresolved P0/P1 findings.

Gate: fuzz/property/fault suites, deterministic local server, at least one
credentialed provider, migration rehearsal, release dry run, and tag
`v1.0.0-rc.2`.

### Stable Release

Outcome: the accepted clean commit is tagged and published as `v1.0.0` with
matching artifacts and a canonical release report.

Gate: final contract/version checks, target CI, downloaded-artifact
reverification, annotated tag, GitHub Release, and post-release smoke.

## Standard Validation

Implementation batch:

```bash
cargo fmt --all --check
cargo clippy -p kirje-store --all-targets --all-features --locked -- -D warnings
cargo test -p kirje-store --test authority_registry --all-features --locked
git diff --check
```

Later packets replace the crate and focused target with exact commands for their
declared allowed files before the task can become Ready.

Tagged checkpoint:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --locked
cargo deny check
```

Checkpoint-specific migration, fault, conformance, platform, and artifact gates
are additive.

## Risks And Mitigations

- Large accepted branch delta: close the current checkpoint before starting new
  production scope; keep commits intact and review the uncommitted diff first.
- Hidden baseline dependency failure: keep `cargo deny` failure visible and
  remediate the yanked transitive dependency before `alpha.1`.
- Reduced process mistaken for reduced safety: preserve TDD, content-hash
  evidence, adversarial review, full checkpoint gates, and explicit blockers.
- Checkpoint scope growth: each batch has allowed paths, a packet, stop
  conditions, and a commit-sized Definition of Done.
- Cross-platform evidence arrives late: build preview targets continuously in
  CI and grant supported status only at `rc.1`.
- Real-provider access unavailable: deterministic local fixtures remain the
  baseline; unavailable live checks are sanitized blockers, never support
  claims.

## Supporting Artifacts

- Product contract: `spec.md`
- Requirement checklist: `checklists/requirements.md`
- Work graph: `tasks.md`
- Consistency analysis: `analysis.md`
- Security contracts: `../008-security-baseline/`
- First recovery packet: `packets/T109.yaml`
- Interrupted attempt evidence: `../../evidence/T202C2/attempts/T202C2-A001.md`

## User Review Gate

The product boundary and checkpoint direction were confirmed by the user on
2026-08-30. This technical plan and the work graph are `Confirmed`. T109 review
and fresh validation are complete at production commit `94f3495`, and the user
accepted the checkpoint on 2026-08-30. T110 is the next production task.
Within T110, returned A006 candidate `2241a946` remains unaccepted. The user
authorized orchestrator approval of existing-boundary clarifications on
2026-08-31. F003-F006 packet reviews failed. F006 preserves the substantive
cleanup contract but exposed authority-source, strict-parsing, phase-lifecycle,
and negative-control defects. F007 and F008 packet reviews also failed. F008's
exact counts are spec C0/H2/M2/L0, engineering/security C0/H4/M1/L0, and QA
C0/H4/M2/L0. F009 review failed with spec C0/H1/M0/L0,
engineering/security C0/H1/M2/L0, and QA C0/H1/M1/L0. Under delegated authority,
F010 review returned spec PASS C0/H0/M0/L0, engineering/security BLOCK
C0/H3/M3/L0, and QA BLOCK C0/H1/M2/L0. F011 review returned spec PASS
C0/H0/M0/L0, engineering/security BLOCK C0/H1/M1/L0, and QA PASS C0/H0/M0/L0.
F012 review returned spec BLOCK C0/H0/M1/L0, engineering/security BLOCK
C0/H1/M1/L0, and QA BLOCK C0/H0/M1/L0. The orchestrator approved F013's
non-self-referential integration clarification. The immutable F013 packet is ready for three
independent reviews; no authorization record exists and every code permission
is closed. The packet is the canonical execution detail. A007/A008 remain
non-executable.
