# Requirements Checklist: Stable 1.0 Program

## Metadata

- Version: 1
- Status: Completed
- Source spec: `../spec.md`
- Updated: 2026-08-27

## Scope

This checklist tests whether the cross-release v0.4 through v1.0 requirements
are clear, complete, internally consistent, measurable, and safe enough to
decompose into feature-scoped specs. It does not claim implementation is
complete.

## Product Boundary

- [x] The production protocols included in 1.0 are explicit. [Clarity]
- [x] OAuth2, Gmail/Microsoft APIs, and JMAP runtime status are explicit.
  [Scope]
- [x] Background activity, permanent deletion, bulk mutation, semantic search,
  and autonomous approval are explicitly classified. [Non-goals]
- [x] The program distinguishes SMTP acceptance, Sent filing, and recipient
  delivery. [Consistency]
- [x] The program prevents presets from being interpreted as support claims.
  [Safety]

## User Outcomes

- [x] Each primary user outcome has a stable `US-*` identifier. [Traceability]
- [x] Mailbox completeness and partial coverage are user-observable outcomes.
  [Coverage]
- [x] Thread grouping defines authoritative and non-authoritative evidence.
  [Ambiguity]
- [x] Uncertain send and mailbox outcomes have a user-visible resolution path.
  [Error handling]
- [x] Installation and artifact verification are part of product acceptance.
  [Operational readiness]

## Mailbox Convergence

- [x] Backfill ordering, bounds, interruption, and resumability are defined.
  [Completeness]
- [x] Reconciliation cannot infer deletion outside known coverage. [Safety]
- [x] UIDVALIDITY invalidation behavior is retained. [Consistency]
- [x] Duplicate, missing-parent, cyclic, and truncated thread headers are named
  as edge cases. [Edge cases]
- [x] CLI/MCP parity is required for new query and sync services. [Interface]

## Security Baseline

- [x] Credentials are bound to immutable identity and endpoint configuration,
  not a reusable display ID. [Credential safety]
- [x] Account creation and endpoint-changing update have distinct behavior.
  [Authorization]
- [x] Terminal presence and independent owner authorization are not conflated.
  [Threat model]
- [x] Strong approval defines an external signature over the immutable digest
  and keeps signing authority outside MCP and the agent process. [Approval]
- [x] Owner signatures bind action, digest, nonce, and expiry; trusted bootstrap,
  replay rejection, rotation, and recovery are in scope. [Authorization]
- [x] Account changes, policy/assurance changes, owner-key rotation, and
  ambiguous closure require the same owner authorization. [Control plane]
- [x] Local file imports bind metadata and bytes to one bounded non-symlink
  handle. [TOCTOU]
- [x] Stdin and file inputs are bounded before allocation. [Resources]
- [x] SQLite append-only and encryption-at-rest limitations are stated
  accurately. [Threat boundary]
- [x] Known OAuth2/JMAP/Gmail/Outlook runtime overclaims are corrected in the
  security baseline rather than deferred. [Honest capability]

## Delivery Reconciliation

- [x] Sent destination resolution forbids localized-folder guessing. [Safety]
- [x] SMTP and IMAP filing have separate persisted outcomes. [Testability]
- [x] Every replay-permitted and replay-forbidden boundary is stated.
  [Reliability]
- [x] Operator reconciliation is CLI-only, append-only, and network-free.
  [Authorization]
- [x] The immutable approval covers the Sent-copy policy. [Integrity]

## Policy And Compatibility

- [x] Policy dimensions include operation, mailbox, recipient, and resources.
  [Coverage]
- [x] Policy is checked at both plan and apply. [Race handling]
- [x] Policy revision/digest invalidation is defined. [Integrity]
- [x] The migration behavior for pre-policy plans is explicit. [Migration]
- [x] Committed conformance evidence excludes identifiers and content.
  [Privacy]

## Contracts And Persistence

- [x] Binary, CLI, MCP, error, operation, and SQLite contracts share a version
  policy. [Consistency]
- [x] 1.x additive compatibility and deprecation expectations are stated.
  [Compatibility]
- [x] Migration, newer-schema rejection, backup, and restore are covered.
  [Data safety]
- [x] Capability output distinguishes unsupported, policy-disabled,
  provider-unavailable, and transient failure. [Error taxonomy]

## Distribution And Release

- [x] Supported target architectures are explicit. [Clarity]
- [x] Keyring behavior cannot silently degrade to plaintext. [Security]
- [x] Checksums, SBOM, provenance, and downloaded-artifact verification are
  required. [Supply chain]
- [x] The release archive contents are bounded and account-data-free. [Privacy]
- [x] The final tag and GitHub Release are bound to a clean green commit.
  [Release integrity]

## Non-Functional Requirements

- [x] Security and approval invariants remain non-negotiable. [Security]
- [x] Privacy requirements cover code, CI, fixtures, evidence, and artifacts.
  [Privacy]
- [x] Network, storage, output, and migration bounds are required. [Resources]
- [x] Crash and network uncertainty must map to persisted certainty states.
  [Reliability]
- [x] Target-specific behavior and limitations must be tested and documented.
  [Portability]
- [x] TDD, review, PR, CI, merge, and post-merge evidence are cumulative gates.
  [Delivery]

## Traceability And Acceptance

- [x] Every release slice maps to a feature-scoped spec before implementation.
  [Decomposition]
- [x] Every `SFR-*`, `FR-*`, and `NFR-*` maps to a release epic; each child
  feature must add executor-sized task and exact validation mapping before its
  execution gate opens. [Traceability]
- [x] Credentialed conformance has a minimum deterministic and real-provider
  family requirement. [Measurability]
- [x] External unavailability becomes a sanitized blocker, not fake evidence.
  [Honesty]
- [x] v1.0 cannot ship with unresolved P0/P1 findings. [Acceptance]

## Findings Summary

- Critical: 0
- High: 0
- Medium: 2
- Low: 1

### Medium Findings

1. Exact performance and database-size thresholds are intentionally delegated
   to child feature specs because the current repository has no accepted
   benchmark baseline. Every child spec must quantify the workload it changes
   before implementation.
2. Additional real-provider credentials are externally controlled. The program
   therefore requires one credentialed real provider plus a deterministic
   standards-based server and records other unavailable providers honestly.

### Low Finding

1. Artifact signing implementation may use GitHub artifact attestation or an
   equivalent verifiable mechanism. The distribution child plan must select one
   mechanism and document verifier commands.

## Resolution Notes

- No Critical or High issue blocks user review.
- Current implementation Critical/High risks are recorded separately in
  `../analysis.md` and mapped to the blocking T101 security-baseline epic.
- Medium findings are explicit child-spec obligations and do not alter the
  program boundary.
- The distribution plan must resolve the remaining signing implementation
  choice before its tasks become Ready.

## User Review Gate

The checklist is complete. The user confirmed the program spec, plan, work
graph, and autonomous project-owner mandate on 2026-08-27. Production execution
still requires the selected child feature's completed plan, task graph,
checklist, analysis, packets, and TDD evidence.
