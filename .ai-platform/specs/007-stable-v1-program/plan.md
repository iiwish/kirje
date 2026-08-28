# Plan: Stable 1.0 Program

## Metadata

- Feature ID: `007-stable-v1-program`
- Status: Confirmed
- Source spec: `spec.md`
- Updated: 2026-08-27

## Decision Summary

Kirje reaches 1.0 through sequential, independently releasable reliability
slices. Each slice receives its own feature spec and governed task graph. The
program does not batch multiple unfinished remote-write or persistence changes
into one release branch.

## Constitution Check

- Local-first and no GUI: satisfied. No release slice adds a hosted service or
  graphical client.
- Shared CLI/MCP services: satisfied. New interfaces remain runtime services
  with CLI and MCP adapters.
- Untrusted mailbox content: satisfied. Threads, reconciliation, fixtures, and
  diagnostics preserve untrusted markers and bounded output.
- Secret exclusion: satisfied. Policy, contracts, CI, artifacts, and evidence
  contain references and aggregate facts only.
- Verified TLS and honest providers: satisfied. Compatibility tiers prevent a
  preset from becoming an unsupported claim.
- Immutable approval and independent human authorization: satisfied. Sent
  filing and reconciliation extend the ledger without adding agent approval.
- Protocol reuse behind adapters: satisfied. IMAP/SMTP engines remain behind
  Kirje-owned ports.
- TDD and evidence: satisfied. Every production slice requires RED, GREEN,
  review, full gates, PR CI, merge, and post-merge CI.

No constitution exception is proposed.

## Technical Decisions

### D-000 Security Baseline Before New Remote Capability

Before v0.4 changes production behavior, Kirje binds each credential to an
immutable credential identity and normalized account endpoint fingerprint,
separates account creation from endpoint-changing updates, and replaces the
claim that TTY presence proves an independent human. Every remote effect and
security-sensitive control-plane action requires an external owner signature
bound to action, digest, nonce, and expiry; TTY is review-only and cannot create
authorization. Legacy unbound credentials are quarantined and re-entered rather
than silently attached to current endpoints. File and stdin imports are bounded
before allocation, and file metadata/bytes come from one non-symlink handle.
These changes ship as a v0.3.1 security baseline and block every later release
slice.

### D-001 Sequential Release Slices

Production work proceeds in order: convergence, delivery reconciliation,
policy/provider compatibility, stable contracts, distribution, release
candidate, stable release. Later slices may research in parallel but cannot
merge production behavior before the previous slice has accepted evidence.

### D-002 Explicit Convergence Sessions

Backfill and reconciliation are explicit bounded application operations with
transactional cursors. No resident daemon is introduced. The index represents
coverage and remote disappearance explicitly rather than treating local row
absence as a remote fact. Baseline protocol operations use bounded UID ranges
or exact bounded UID sets and cannot issue an unbounded `SEARCH ALL` before
truncating locally. Capability extensions may optimize but never weaken this
baseline.

### D-003 Header-Based Thread Graph

Thread identity is derived from normalized Message-ID relationships. A thread
graph stores deterministic parent/root relationships and bounded anomaly
metadata. Incomplete history produces provisional thread identity. Subject
heuristics may be reported separately but cannot create an authoritative reply
relationship.

### D-004 Composite Send Progress In The Existing Ledger

SMTP submission and optional Sent filing are child steps of one approved send
operation in the unified ledger. Migration extends existing records rather than
creating an unrelated queue. Each step has its own certainty and receipt while
the top-level state remains stable and bounded. Planning prepares one canonical
RFC822 artifact whose digest is approved and whose exact bytes are used by both
SMTP DATA and client-managed IMAP APPEND. A durable claim precedes each remote
effect. Legacy sent records remain auditable without retroactive filing; legacy
planned or approved sends require re-planning under the new policy.

### D-005 Append-Only Operator Reconciliation

External reconciliation adds a terminal assertion event and derived outcome;
it does not delete or edit the original ambiguous result. Only an owner-signed
CLI action can record or close the assertion. A separate bounded inspection
service may perform read-only Sent lookup, but the close command cannot invoke
SMTP, APPEND, or repeat an uncertain IMAP mutation.

### D-006 Versioned Account Policy

Policy is local configuration with a canonical serialized representation and
digest. Planning records the evaluated policy revision; apply re-evaluates the
current policy and rejects work that is no longer allowed. Policy never grants
approval, cannot be changed through MCP, and requires an external owner
signature to create or revise.

### D-007 One Compatibility Contract

The binary semver, JSON envelope version, schema snapshot, MCP server/tool
contract, stable error catalog, operation states, SQLite schemas, and provider
support tiers are documented together. Golden fixtures detect unreviewed drift.

### D-008 Verifiable GitHub Releases

GitHub Actions builds supported target archives from a tag, publishes SHA-256
checksums, an SPDX or CycloneDX SBOM, and GitHub build provenance/attestation,
then verifies the downloaded artifacts before the release is marked stable.
Secrets are limited to platform-provided release credentials.

## Alternatives Considered

- Ship 1.0 immediately from v0.3: rejected because synchronization does not yet
  converge deletions/flag drift, delivery lacks Sent filing, and no installable
  release exists.
- Include OAuth2 and JMAP in 1.0: rejected for the proposed narrow boundary;
  either would add a new authentication or protocol security surface before the
  current runtime is operationally stable.
- Add an always-running daemon for convergence: rejected. Explicit sync remains
  easier to authorize, test, stop, and audit.
- Automatically retry ambiguous sends: rejected because duplicate delivery is
  more harmful than requiring operator reconciliation.
- Store policy only in agent prompts: rejected because mailbox content and agent
  context cannot be trusted as an authorization boundary.
- Release only source code: rejected because keyring and platform behavior need
  tested binaries and users need verifiable artifacts.

## Feature Sequence

1. `008-security-baseline` targeting v0.3.1.
2. `009-mailbox-convergence` targeting v0.4.
3. `010-delivery-reconciliation` targeting v0.5.
4. `011-policy-provider-compatibility` targeting v0.6.
5. `012-stable-contracts` targeting v0.7.
6. `013-distribution` targeting v0.8.
7. `014-release-candidate` targeting v0.9.
8. `015-v1-release` targeting v1.0.0.

Each child feature must contain its own spec, requirement checklist, plan,
tasks, analysis, execution packets, and evidence. Child plans may refine data
models and exact file ownership but cannot broaden the program boundary without
new user approval.

## Cross-Release Validation

Every production slice runs:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --locked
cargo deny check
```

Additional gates accumulate rather than replace earlier gates:

- v0.3.1: credential endpoint binding, account replacement rejection, approval
  owner-signature enforcement, bounded same-handle file import, CLI/MCP
  exclusion, migration, and corrected threat-boundary documentation.
- v0.4: index migration, backfill interruption, reconciliation, thread graph,
  CLI/MCP parity, and controlled read-only mailbox checks.
- v0.5: SMTP/IMAP fault matrix, ledger migration, no-replay crash tests,
  owner-signed reconciliation tests, and controlled self-addressed send checks.
- v0.6: policy matrix, support-tier fixtures, secret scan, and sanitized
  provider conformance.
- v0.7: golden external contracts and every supported schema migration path.
- v0.8: target matrix builds, archive verification, SBOM, checksums,
  provenance, install, doctor, and keyring behavior.
- v0.9: fuzz/fault suites, long-run tests, threat review, release dry run, and
  sanitized real-provider checks.
- v1.0: clean release commit, full target CI, artifact re-verification,
  annotated tag, published release, and post-release smoke checks.

## Risks And Mitigations

- Remote deletion inference can erase valid local facts. Mitigation: coverage
  intervals, explicit tombstones, and no inference outside reconciled ranges.
- Account display-ID reuse can redirect an existing credential. Mitigation:
  random credential identity, endpoint fingerprint binding, explicit update,
  and mandatory interactive re-entry after identity changes.
- A pseudo-terminal can be automated and is not identity proof. Mitigation:
  mandatory external owner signatures for remote and security-sensitive
  actions; TTY cannot create authorization and MCP never receives a signing or
  approval operation.
- Attachment paths can change between metadata check and read. Mitigation:
  open once without symlink traversal, validate the opened handle, and read at
  most the configured bound plus one byte.
- Thread headers can be malicious or cyclic. Mitigation: bounded normalization,
  cycle detection, duplicate handling, and no subject-only authority.
- SMTP succeeds while Sent filing fails. Mitigation: separate persisted steps,
  no resend, provider-declared destination, and operator-visible certainty.
- Reconciliation can become a hidden approval bypass. Mitigation: CLI-only,
  no network invocation, explicit assertion text/category, append-only audit.
- Policy changes can race apply. Mitigation: canonical policy digest at plan and
  mandatory re-evaluation immediately before protocol invocation.
- Platform release automation can create unsigned or mismatched artifacts.
  Mitigation: tag-bound builds, least-privilege workflows, checksums, SBOM,
  provenance, and download verification.
- External provider credentials may be unavailable. Mitigation: deterministic
  local protocol fixtures plus sanitized blockers; no fabricated support claim.

## Supporting Artifacts

- Program requirements: `spec.md`
- Requirement quality gate: `checklists/requirements.md`
- Program work graph: `tasks.md`
- Consistency analysis: `analysis.md`
- Child feature artifacts under `.ai-platform/specs/008-*` through `015-*`

## User Review Gate

Confirmed on 2026-08-27 under the user's delegated project-owner authority. The
feature sequence, technical decisions, cumulative gates, and narrow 1.0
boundary govern autonomous execution.
