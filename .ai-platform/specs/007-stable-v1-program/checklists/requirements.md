# Requirements Checklist: Stable 1.0 Program

## Metadata

- Feature ID: `007-stable-v1-program`
- Status: Completed
- Source spec: `../spec.md`
- Updated: 2026-08-30

## Checklist Scope

This checklist tests the confirmed 1.0 product contract and the incremental
checkpoint requirements. It does not test implementation. The detailed
security contracts under `008-security-baseline` remain supporting requirement
sources.

## Product Boundary

- [x] The 1.0 runtime protocol boundary is explicit: IMAP and SMTP.
- [x] The 1.0 authentication boundary is explicit: password or provider-issued
  app-password through the OS keyring.
- [x] OAuth2, Gmail API, Microsoft Graph, and JMAP runtime behavior are explicit
  non-requirements.
- [x] A resident daemon, permanent delete, unrestricted bulk mutation,
  automatic uncertain replay, semantic search, and embedded AI are excluded.
- [x] CLI and MCP share application services while owner approval and sensitive
  owner operations remain outside MCP.

## User Outcomes

- [x] US-001 defines current, partial, stale, invalidated, and converged mailbox
  outcomes.
- [x] US-002 defines deterministic thread relationships and provisional state.
- [x] US-003 separates SMTP acceptance, Sent filing, and recipient delivery.
- [x] US-004 defines owner-controlled account policy independently of prompts.
- [x] US-005 defines stable machine and persistence contracts.
- [x] US-006 defines verifiable installation and release artifacts.

## Functional Requirement Quality

- [x] SFR-001-SFR-007 define credential binding, account replacement,
  independent owner authorization, bounded imports, honest local security,
  bounded remote values, and truthful capability claims.
- [x] FR-001-FR-005 define bounded resumable convergence, scoped disappearance,
  UIDVALIDITY rebuild, thread anomalies, and CLI/MCP parity.
- [x] FR-006-FR-011 define immutable MIME, separate send/file progress,
  provider-declared Sent handling, no replay, append-only reconciliation, and
  MCP exclusions.
- [x] FR-012-FR-017 define policy scope, plan/apply recheck, read-only defaults,
  provider tiers, sanitized conformance, and deferred protocols.
- [x] FR-018-FR-021 define version, migration, compatibility, and capability
  reason contracts.
- [x] FR-022-FR-025 distinguish buildable, preview, and supported targets and
  define artifact contents and platform evidence.
- [x] FR-026-FR-029 define adversarial, crash, conformance, and release review
  acceptance.
- [x] FR-030-FR-032 define the final commit, tag, assets, and release report.

## Non-Functional Requirements

- [x] Security and privacy requirements exclude credentials, private signing
  material, unrestricted mailbox content, and fabricated provider evidence.
- [x] Every uncertain network boundary has an explicit persisted certainty and
  recovery requirement.
- [x] Boundedness covers network input, local input, query/output size,
  histories, and migration.
- [x] Portability distinguishes supported behavior from a merely buildable
  target.
- [x] Compatibility covers CLI, MCP, errors, operation states, and databases.
- [x] Observability preserves stderr diagnostics and protocol-clean MCP stdout.
- [x] TDD remains mandatory for protocol, auth, sync, persistence, policy, and
  remote-write behavior.

## Incremental Delivery Contract

- [x] One target release, `v1.0.0`, is unambiguous.
- [x] Every checkpoint has a user-visible artifact: commit/PR, prerelease tag,
  or stable release.
- [x] Every requirement maps to at least one stable task ID.
- [x] Focused batch gates and full checkpoint gates are distinct.
- [x] Content-hash evidence reuse is permitted only for unchanged code, tests,
  fixtures, schema, dependency graph, toolchain, and relevant configuration.
- [x] Failed gates remain blockers or named remediation work.
- [x] Future packets are generated just in time instead of before their codebase
  context is knowable.
- [x] The final release remains blocked on clean worktree, full local and CI
  gates, target artifacts, tag identity, and post-release verification.

## Edge And Recovery Cases

- [x] Interrupted account-create work has a preservation and review path.
- [x] Account/config/keyring crashes have deterministic before/after snapshot
  handling.
- [x] Sync interruption, drift, missing coverage, and UIDVALIDITY changes are
  covered.
- [x] SMTP and Sent-filing interruption cannot trigger automatic resend.
- [x] Policy changes between plan and invocation invalidate incompatible work.
- [x] Newer schemas and unsupported targets fail closed.
- [x] Unavailable live credentials create sanitized blockers, not support
  claims.
- [x] A release artifact mismatch blocks tag/release acceptance.

## Findings Summary

- Critical: 0
- High: 0
- Medium: 0
- Low: 0

The yanked transitive `chacha20 0.10.1` dependency is an implementation gate,
not a requirement ambiguity. T111 owns remediation before security-alpha
acceptance.

## Resolution Notes

- The product requirements remain unchanged.
- Intermediate version labels are checkpoint tags under the single 1.0 program.
- The work graph retains T101-T108 checkpoint lineage and uses executor-sized
  task IDs within each checkpoint.
- The current uncommitted implementation is review input, not discarded work.

## User Review Gate

The requirements checklist is complete. The technical plan and work graph are
Confirmed. T109 review is complete and awaits explicit checkpoint acceptance.
