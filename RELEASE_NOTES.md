# Kirje v1.0.0-rc.1

This is the first Release Candidate for Kirje 1.0.0, finalizing the stable
machine, CLI, and MCP interface contracts for local-first email automation.

Highlights of this Release Candidate:
- **Frozen Machine Contracts**: Stable JSON command envelope (`2026-09-04.1`),
  exit codes (0, 1, 2), and comprehensive 25-tool MCP server without approval bypasses.
- **Transactional Schema Evolution**: Multi-tier SQLite storage (`authority` v1,
  `index` v2, `outbox` v3) with strict downgrade rejection, soft tombstones, and
  deterministic thread graph construction.
- **Two-Phase Policy Enforcement**: Read-only defaults for remote writes (FR-014)
  and transactional policy verification at plan and apply phases (FR-013).
- **Offline Delivery Reconciliation**: Governed `NeedsAttention` filing alerts,
  immutable audit events, and manual reconciliation via `kirje send reconcile`.
- **Honest Platform Support**: Distinct buildable, preview, and supported tiers;
  target builds for macOS (Apple Silicon & Intel), Linux (x86_64 & arm64), and Windows.
- **Verified Zero-Secret Distribution**: Release archives contain solely the
  binary, documentation, license, and notice without bundling private user data.

---

# Kirje v1.0.0-alpha.1

This is the first distributable Security Alpha of Kirje, a local-first email
CLI and MCP server for AI agents.

The release includes provider discovery, bounded IMAP reads and sync, a private
local envelope index, drafts and attachment snapshots, multipart SMTP sending,
governed IMAP operations, and a shared CLI/MCP runtime. Local file inputs are
opened without following their final component, validated from the open handle,
and consumed through strict byte budgets. The dependency policy gate is green.

The authority library also includes the signed credential-cleanup lifecycle:
grant use and claim are atomic, deletion requires an opaque permit, no-entry is
indistinguishable from deletion, and backend failures remain recoverable.

## Prerelease Boundaries

- CLI TTY approval remains the active user-facing approval mechanism. The
  owner-key authority workflow is not exposed through CLI or MCP; that product
  integration is the `v1.0.0-alpha.2` checkpoint.
- Account configuration remains the version 1 display-ID format. Stable
  internal account/config-v2 migration is scheduled before stable 1.0.
- JMAP, background watch, historical backfill, permanent deletion, and automatic
  ambiguous-result reconciliation are not included.
- Real-provider behavior varies. Use a dedicated test mailbox first and follow
  `docs/conformance.md`; no live mailbox action is part of the release gate.

Release archives contain `kirje`, `README.md`, `RELEASE_NOTES.md`,
`CHANGELOG.md`, `LICENSE`, and `NOTICE`. `SHA256SUMS` covers every uploaded
archive.
