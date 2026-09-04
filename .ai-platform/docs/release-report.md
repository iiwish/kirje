# Release Report

## Metadata

- Status: Release Candidate
- Product: Kirje
- Version: `1.0.0-alpha.1`
- Machine contract: `2026-09-04.1`
- Minimum Rust version: `1.95`
- Updated: 2026-09-04

## Product State

Kirje is a local-first email CLI and MCP runtime for agents. The Security Alpha
supports provider discovery, bounded IMAP reads and sync, a private local
envelope index, deterministic drafts, bounded attachment snapshots, multipart
SMTP sending, and governed IMAP flag/move/archive/safe-delete operations. CLI
and MCP use the same runtime and versioned machine envelope.

Local file input is capability-anchored: Kirje opens one parent, refuses to
follow the final component, validates metadata from the opened regular-file
handle, and retains no more than the declared limit plus one byte. Config reads
are capped at 1 MiB and config replacement is private, atomic, and conditioned
on the previously opened object identity. A private advisory lock serializes
Kirje writers before the identity check, preventing concurrent lost updates.
Account creation is create-only and cannot silently replace an existing display
ID.

The authority store contains the signed credential-cleanup lifecycle. Grant
consumption and `ready -> claimed` commit together, only the winner receives an
opaque delete permit, and the unpublished delete-only keyring adapter collapses
successful deletion and missing credentials to the same result. Backend failure
leaves `claimed` state for exact recovery; success records one terminal event.

## Verification

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked` (248 tests on macOS)
- `cargo test --workspace --all-features --release --locked` (248 tests on macOS)
- `cargo test --workspace --no-default-features --locked`
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked`
- `cargo build --workspace --all-features --locked`
- `cargo build --release --locked -p kirje-cli`
- `cargo deny check`
- Gitleaks scans the complete release branch history with only the exact
  deterministic public-signature fixture allowlisted.
- Actionlint validates both GitHub Actions workflows.
- `kirje --version` reports `kirje 1.0.0-alpha.1`.
- The release binary's `schema` and isolated `doctor` commands return contract
  `2026-09-04.1`; a local macOS arm64 archive contains only the binary and the
  five declared documents, and its SHA-256 checksum verifies.
- A clean `cargo install --path crates/kirje-cli --locked` smoke validates the
  installed binary, schema, isolated doctor, create-only duplicate rejection,
  private `0600` account config, archive manifest, and checksum.
- A deterministic two-writer regression test reproduces the stale-identity race
  without serialization and proves one successful compare-and-swap winner with
  the capability-relative lock. Unix coverage also rejects a linked lock file
  and verifies mode `0600`.
- CLI contract tests cover create-only account behavior, protocol-clean MCP
  startup, local attachment import, redirected secret/approval rejection, and
  the versioned JSON envelope.
- Authority tests cover cleanup grant claim, exact replay, adjacent grant/event
  order, terminal no-recall, idempotent delete simulation, and backend-failure
  recovery without exposing locator material.

The local gate runs on macOS arm64. CI is configured to run locked tests on
Linux, macOS, and Windows. Tagged release automation builds Linux and macOS
x86_64/arm64 plus Windows x86_64 archives and publishes `SHA256SUMS`. Remote CI,
tag creation, and GitHub release publication remain external handoff actions and
are not represented as completed local evidence.

## Prerelease Boundaries

- Interactive CLI confirmation remains the active public approval mechanism.
  Owner-key authority setup and account/credential workflows are library-only
  in this alpha and are excluded from MCP; their product integration is the
  `v1.0.0-alpha.2` checkpoint.
- Config v2 stable internal IDs, ledger v3 authority migration, bounded custom
  MCP framing, and bounded initial IMAP transport responses remain scheduled
  before stable 1.0.
- JMAP, background watching, historical backfill, permanent deletion, and
  automatic ambiguous-result reconciliation are outside this release.
- The 2026-08-27 dedicated Coremail verification remains historical
  compatibility evidence. No live mailbox or credential operation is part of
  this release-candidate gate.

## Release Assets

The tag must be exactly `v1.0.0-alpha.1`. The release workflow rejects a tag
that differs from the workspace version. Each archive contains the `kirje`
binary, `README.md`, `RELEASE_NOTES.md`, `CHANGELOG.md`, `LICENSE`, and `NOTICE`;
all archives are covered by the generated SHA-256 checksum file. Workspace
crates are unpublished so the release path cannot accidentally publish partial
internal APIs to crates.io.
