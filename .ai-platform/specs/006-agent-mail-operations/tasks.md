# Tasks: Agent Mail Operations

## T019 Core Contracts And Composition

- Status: Complete
- Requirements: FR-001 through FR-007
- Dependencies: `005-governed-send`
- Blocks: T020, T022, T023
- Allowed files: `crates/kirje-core/**`, `crates/kirje-protocol/src/smtp.rs`,
  `crates/kirje-protocol/Cargo.toml`, core/protocol tests
- TDD: add failing contract, composition, attachment, and MIME tests first.
- Validation: `cargo test -p kirje-core -p kirje-protocol --all-features`
- Definition of Done: drafts, composition, attachment snapshots, summaries,
  multipart mixed MIME, and immutable send payloads are typed and bounded.
- Evidence: `.ai-platform/evidence/T019/summary.md`

## T020 Unified Operation Ledger

- Status: Complete
- Requirements: FR-013 through FR-018
- Dependencies: T019
- Blocks: T022, T023
- Allowed files: `crates/kirje-core/src/operation.rs`,
  `crates/kirje-core/src/send.rs`, `crates/kirje-store/**`, store tests
- TDD: migration, audit, immutable payload, concurrency, and stale-recovery
  tests precede the schema implementation.
- Validation: `cargo test -p kirje-core -p kirje-store --all-features`
- Definition of Done: old outbox rows migrate in place, one ledger supports
  all operation kinds, transitions and event history are atomic, and stale
  claims become ambiguous.
- Evidence: `.ai-platform/evidence/T020/summary.md`

## T021 IMAP Mutation Adapter

- Status: Complete
- Requirements: FR-008 through FR-012
- Dependencies: T019
- Blocks: T022
- Allowed files: `crates/kirje-core/src/mail.rs`, `crates/kirje-protocol/src/imap.rs`,
  protocol tests
- TDD: fake-session command/capability tests precede adapter implementation.
- Validation: `cargo test -p kirje-core -p kirje-protocol --all-features`
- Definition of Done: UID-scoped flags, MOVE/COPY fallback, special-use folder
  resolution, safe delete, UIDVALIDITY checks, and bounded receipts work.
- Evidence: `.ai-platform/evidence/T021/summary.md`

## T022 Runtime And CLI Operations

- Status: Complete
- Requirements: FR-001 through FR-023
- Dependencies: T019, T020, T021
- Blocks: T023, T024
- Allowed files: `crates/kirje-runtime/**`, `crates/kirje-cli/**`, runtime/CLI tests
- TDD: service transition and CLI contract tests precede handlers.
- Validation: `cargo test -p kirje-runtime -p kirje-cli --all-features`
- Definition of Done: local draft commands, send-from-draft, generic operation
  plan/show/list/approve/apply, and safe scoped IMAP commands use one runtime.
- Evidence: `.ai-platform/evidence/T022/summary.md`

## T023 MCP Contract

- Status: Complete
- Requirements: FR-019 through FR-021
- Dependencies: T022
- Blocks: T024
- Allowed files: `crates/kirje-mcp/**`, MCP tests
- TDD: tool-list, schema, no-approval, and stdio-clean tests precede tools.
- Validation: `cargo test -p kirje-mcp -p kirje-cli --all-features`
- Definition of Done: MCP exposes local draft and plan/status/apply operations
  over shared runtime services without approval or secret entry tools.
- Evidence: `.ai-platform/evidence/T023/summary.md`

## T024 Documentation And Operational Scripts

- Status: Complete
- Requirements: FR-022, FR-023
- Dependencies: T022, T023
- Blocks: T025
- Allowed files: `README.md`, `docs/**`, `skills/**`, `scripts/**`,
  `.ai-platform/**`
- Validation: schema/doctor smoke plus delivery artifact validation.
- Definition of Done: agent workflow, security, architecture, Skill, live
  scripts, and release evidence reflect the shipped contract.
- Evidence: `.ai-platform/evidence/T024/summary.md`

## T025 Full QA, Commit, PR, CI, And Merge Handoff

- Status: Complete
- Requirements: all requirements and release acceptance
- Dependencies: T024
- Blocks: none
- Allowed files: `.ai-platform/**`, git metadata, remote PR state
- Validation: all commands in `plan.md`, controlled live smoke, PR checks.
- Definition of Done: fresh evidence exists, review has no blockers, commit and
  PR are created, CI is green, and merge is confirmed or accurately reported as
  externally pending.
- Evidence: `.ai-platform/evidence/T025/summary.md`
