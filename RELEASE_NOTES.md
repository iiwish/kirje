# Kirje v1.0.0: General Availability (GA)

Kirje 1.0.0 is the first production-ready, stable release of the local-first
email CLI and MCP server built for autonomous AI agents.

This release represents the complete execution and acceptance of the
program roadmap (T101 through T121), establishing a deterministic, safe,
and protocol-clean bridge between email systems and agent runtimes.

### Core Architecture & Delivery Highlights
- **Universal Local-First Infrastructure**: Unified runtime powering both CLI
  automation and Model Context Protocol (MCP stdio). Excludes graphical UI,
  in-memory relays, embedded LLMs, and hosted middleware.
- **Provider-Neutral Operations**: Native IMAP and SMTP support across NetEase
  (163/126/Yeah), Tencent (QQ/Foxmail), Aliyun, Fastmail, iCloud, and standard
  enterprise/self-hosted servers with source-backed provider presets.
- **Two-Phase Plan / Approve / Apply Engine**: Destructive operations and sending
  require explicit multi-phase execution. Sensitive actions require interactive
  human TTY approval. MCP stdio mode is architecturally barred from approval bypass.
- **Robust Outbox & Unambiguous Recovery**: SQLite outbox and unified operation
  ledger with deterministic crash recovery. Uncertain remote states enter terminal
  `Ambiguous` states and are never automatically replayed.
- **Offline Delivery Reconciliation**: Governed `NeedsAttention` filing alerts,
  immutable audit events, and manual offline reconciliation via `kirje send reconcile`.
- **Two-Phase Account Policy**: Default-deny read-only security model (FR-014)
  with transactional double-check policy validation during plan and apply phases (FR-013).
- **Transactional SQLite Index & Thread Reconstruction**: Local metadata index
  with incremental sync cursors, soft tombstones, and deterministic header-based
  conversation graph reconstruction.
- **25 Stable MCP Tools**: Compact, typed MCP toolset with explicit safety
  annotations and strict boundary budgets.
- **Zero-Secret Distribution**: Release archives contain solely the binary,
  documentation, license, and notice without bundling private user data. Full
  `cargo deny check` compliance across advisories, bans, licenses, and sources.

---

# Kirje v1.0.0-rc.2

This is the second Release Candidate for Kirje 1.0.0, completing deep hardening,
fault injection, crash recovery, and disaster recovery verification.

Highlights of this Hardening Release Candidate:
- **Comprehensive Crash and Fault Injection**: Full verification that uncertain
  SMTP and IMAP remote operations transition to terminal `Ambiguous` states and
  are never automatically replayed.
- **Downgrade Rejection & Disaster Recovery**: Verified multi-database migration
  paths (`authority`, `index`, `outbox`) with non-negotiable downgrade blocks and
  documented offline backup/restore procedures.
- **Rigorous Zero-Secret Audit**: Verified CLI, MCP, and error envelopes contain
  strictly zero leaked credentials, tokens, or plaintext keys.
- **Passing All Dependency & Security Gates**: `cargo deny check` completely clean
  (zero advisories, bans, license violations, or untrusted sources).

---

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
