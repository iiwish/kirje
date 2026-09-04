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
  owner-key authority workflow is not yet exposed through CLI or MCP.
- Account configuration remains the version 1 display-ID format. Stable
  internal account/config-v2 migration is scheduled before stable 1.0.
- JMAP, background watch, historical backfill, permanent deletion, and automatic
  ambiguous-result reconciliation are not included.
- Real-provider behavior varies. Use a dedicated test mailbox first and follow
  `docs/conformance.md`; no live mailbox action is part of the release gate.

Release archives contain `kirje`, `README.md`, `LICENSE`, and `NOTICE`.
`SHA256SUMS` covers every uploaded archive.
