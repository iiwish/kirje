# Analysis: Stable 1.0 Program

## Metadata

- Feature ID: `007-stable-v1-program`
- Status: Completed
- Analyzed artifacts: `spec.md`, `plan.md`, `tasks.md`,
  `checklists/requirements.md`, project constitution, current product design,
  architecture, security model, v0.3 release evidence, and repository contracts
- Updated: 2026-08-27

## Result

The program artifacts are internally consistent and ready for explicit user
review. The current v0.3 baseline contains one Critical and several High
findings. Immediate credential, approval, input-boundary, and capability-claim
risks are covered by the dedicated v0.3.1 requirements and T101; contract and
release findings are scheduled behind that gate in T105-T107. No later
production task may execute until T101 is accepted. T101 remediation itself
remains blocked until the program artifacts and the security-baseline child
artifacts are user-approved.

## Constitution Compliance

- Local-first runtime: pass.
- No graphical or hosted control plane: pass.
- Shared CLI/MCP application services: pass.
- Mailbox content remains untrusted: pass.
- Secret exclusion: pass.
- Verified TLS and no provider guessing: pass.
- Immutable remote-write approval and no agent approval: pass.
- Reused protocol engines behind Kirje adapters: pass.
- TDD and reproducible evidence: pass.

No proposed requirement weakens a confirmed principle.

## Requirements To Work Graph Coverage

| Requirements | Program task | Coverage |
|---|---|---|
| SFR-001-SFR-007 | T101 | Epic mapped; child validation blocked |
| FR-001-FR-005 | T102 | Epic mapped; child validation blocked |
| FR-006-FR-011 | T103 | Epic mapped; child validation blocked |
| FR-012-FR-017 | T104 | Epic mapped; child validation blocked |
| FR-018-FR-021 | T105 | Epic mapped; child validation blocked |
| FR-022-FR-025 | T106 | Epic mapped; child validation blocked |
| FR-026-FR-029 | T107 | Epic mapped; child validation blocked |
| FR-030-FR-032 | T108 | Epic mapped; child validation blocked |
| NFR-001-NFR-008 | T101-T108 | Cumulative child mapping required |

Program tasks intentionally do not own broad production globs. Each task
requires a confirmed child graph with exact paths and validation before it can
be executed. This preserves the existing one-governed-task-at-a-time rule.

## Current Baseline Findings

1. Keyring credentials are currently addressed only by reusable account ID,
   while account creation silently replaces an existing account with the same
   ID. Endpoint or username replacement can therefore redirect an old
   credential to a new authenticated endpoint.
2. Current approval checks terminal presence and exact ID entry but does not
   prove an independent operator identity; an automated pseudo-terminal can
   satisfy the same check.
3. Local attachment import checks path metadata and then opens the path again
   with an unbounded read, allowing replacement between the check and read.
4. The current index advances only a newest-message high-water UID and cannot
   resume historical backfill toward older UIDs.
5. Current refresh behavior replaces one mailbox scope with another newest
   window and therefore is not state convergence.
6. Existing sync does not reconcile old flags, disappearance, or moves and has
   no tombstone or thread entity.
7. Initial IMAP sync can request all UIDs before truncating locally; v0.4 must
   move the bound into the protocol operation.
8. SMTP success currently ends the send operation before Sent-folder filing.
9. The current ledger cannot distinguish SMTP uncertainty from Sent APPEND
   uncertainty and has no append-only operator resolution.
10. MIME bytes are built inside the SMTP adapter, so an independent Sent writer
   cannot yet prove byte identity.
11. OAuth2 is explicitly unavailable and JMAP has reference metadata only, while
   top-level product wording currently implies broader runtime support.
12. Workspace package version remains `0.1.0`, no repository tag or GitHub
   Release exists, and CI currently tests only Ubuntu.

These findings are mapped to T101 through T106 and do not require broadening the
proposed 1.0 scope.

## Terminology Check

- `SMTP accepted` is consistently distinct from recipient delivery.
- `Sent filing` means client-managed APPEND or bounded verification under an
  explicitly approved policy, not guessing a localized folder.
- `ambiguous` remains possibly applied and non-retryable.
- `reconciled` or `closed` means an append-only operator assertion, not proof
  that Kirje observed a remote outcome.
- `provider preset`, `fixture-tested`, and `live verified` remain distinct.
- `supported platform` means a published and verified release target, not only
  a successful cross-compile.

No terminology conflict was found across the program artifacts.

## Findings

### Critical

1. Credential lookup is not bound to account endpoint and identity. T101 must
   resolve this before any later remote-operation feature merges.

### High

1. TTY presence is currently overstated as independent human approval. T101
   must require external owner signatures for every remote or
   security-sensitive action; TTY becomes review-only.
2. Local file import has a metadata-check/open race and unbounded `fs::read`.
   Explicit CLI JSON stdin already uses a limit-plus-one reader, but file JSON
   has the same check/open race and `rmcp` stdio currently accepts an unbounded
   JSON-RPC line. T101 must bind file validation/bytes to one handle and enforce
   a bound at every file, stream, and MCP transport entry point.
3. Product protocol/provider claims exceed runtime support. T101 must correct
   the known overclaim immediately; T104 later adds operation-level support
   tiers and conformance evidence.
4. Binary, machine-contract, error, state, and database versions are not one
   stable contract. T105 owns the compatibility freeze.
5. CI, branch/tag governance, dependency alerts, target evidence, and release
   automation are insufficient for a stable binary release. T106 and T107 own
   the release controls and verification.

### Medium

1. Child data models and exact state enums are not yet fixed. This is expected
   at program level; T101 through T103 cannot become Ready until their child plans
   define migrations and full transition tables.
2. Performance thresholds require a measured baseline. Each child spec must set
   a bounded fixture size and acceptance threshold for the path it changes.
3. Real-provider breadth depends on externally available dedicated accounts.
   The spec resolves the minimum with one real provider plus one deterministic
   standards-based server and forbids inflated claims.

### Low

1. The exact artifact attestation mechanism remains a v0.8 child-plan decision.
2. Release slice numbers may skip a public prerelease if a slice contains only
   contract work; repository semver and release notes must still identify the
   accepted slice consistently.

## Security Review

- Sent filing introduces a second remote effect but retains one immutable plan,
  durable claims, separate certainty, and no automatic resend.
- Operator close is a new authority and requires the same external owner
  signature as remote approval; it remains append-only and performs no remote
  write.
- Policy cannot substitute for approval and is checked again at apply.
- Policy, account identity, approval-trust, and owner-key changes require owner
  authorization and invalidate incompatible prior approvals.
- Legacy unbound credentials are quarantined and cannot be silently attached to
  current account endpoints.
- Release automation requires least privilege, tag identity, artifact
  verification, and no local state.

No new approval path is exposed to MCP.

## Execution Gate

Status: APPROVED_FOR_T101_CHILD_PLANNING

Required next steps:

1. Preserve the confirmed `spec.md`, `plan.md`, and `tasks.md` meaning.
2. Complete `008-security-baseline` planning, analysis, packets, and evidence
   gates before production code.
3. Execute only T101 remediation until its findings are accepted; then create
   `009-mailbox-convergence` artifacts for v0.4.
