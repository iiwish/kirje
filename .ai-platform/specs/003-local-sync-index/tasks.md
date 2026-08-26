# Tasks: Local Sync And Attachment Access

## T006 Store Contract And SQLite Adapter

- Status: Complete
- Priority: P0
- Story / Requirement: FR-001, FR-002, FR-004, FR-007, FR-008; NFR-001, NFR-003
- Dependencies: none
- Blocks: T007, T008, T010
- Parallel: false
- Conflicts with: T007-T011 while core/store contracts are changing
- Goal: create the durable local metadata persistence boundary.
- Allowed files: workspace manifests, `crates/kirje-core/**`, `crates/kirje-store/**`
- Test targets: store migrations, upsert/idempotency, reset, local filters, newer schema
- Deliverables: core index port and private transactional SQLite adapter
- Acceptance criteria: duplicate rows are impossible and UIDVALIDITY reset is scoped and atomic.
- Definition of Done: target tests and review pass with no sensitive payload storage.
- Validation commands: `cargo test -p kirje-core -p kirje-store --all-features`
- TDD plan: migration and behavior tests fail before adapter implementation.
- Packet path: `packets/T006.yaml`
- Evidence required: `.ai-platform/evidence/T006/summary.md`

## T007 Runtime Index Services

- Status: Complete
- Priority: P0
- Story / Requirement: FR-003 through FR-008, FR-012
- Dependencies: T006
- Blocks: T008, T010
- Parallel: false
- Conflicts with: T008 and T010 runtime composition changes
- Goal: coordinate explicit sync and credential-free local reads.
- Allowed files: `crates/kirje-runtime/**`, core/store integration adjustments
- Test targets: credential-free local query, cursor orchestration, refresh/reset
- Deliverables: shared runtime sync, status, and search services
- Acceptance criteria: repeat sync advances a persisted cursor and refresh replaces one scope.
- Definition of Done: runtime tests prove credential and network boundaries.
- Validation commands: `cargo test -p kirje-runtime --all-features`
- TDD plan: mock-port tests fail before runtime composition.
- Packet path: `packets/T007.yaml`
- Evidence required: `.ai-platform/evidence/T007/summary.md`

## T008 IMAP Incremental Sync

- Status: Complete
- Priority: P0
- Story / Requirement: FR-003 through FR-006, FR-011; NFR-002
- Dependencies: T006, T007
- Blocks: T010
- Parallel: false
- Conflicts with: T007 and T009 protocol adapter changes
- Goal: fetch bounded initial and high-water UID metadata batches.
- Allowed files: `crates/kirje-protocol/**`, protocol-facing core/runtime adjustments
- Test targets: initial/incremental range, limit, UIDVALIDITY reset, raw transcript
- Deliverables: Pimalaya-backed mailbox sync implementation
- Acceptance criteria: UID range and FETCH behavior are bounded and remotely read-only.
- Definition of Done: protocol and transcript tests pass.
- Validation commands: `cargo test -p kirje-protocol -p kirje-runtime --all-features`
- TDD plan: missing-port and transcript failures precede implementation.
- Packet path: `packets/T008.yaml`
- Evidence required: `.ai-platform/evidence/T008/summary.md`

## T009 Bounded Attachment Read

- Status: Complete
- Priority: P0
- Story / Requirement: FR-009 through FR-012; NFR-002, NFR-003
- Dependencies: T006
- Blocks: T010
- Parallel: false
- Conflicts with: T008 shared protocol adapter changes
- Goal: return one exact attachment as bounded untrusted base64.
- Allowed files: `crates/kirje-core/**`, `crates/kirje-protocol/**`, `crates/kirje-runtime/**`
- Test targets: validation, selection, base64, truncation, BODY.PEEK
- Deliverables: attachment domain contract, adapter, and runtime service
- Acceptance criteria: decoded output never exceeds 1 MiB or mutates the message.
- Definition of Done: MIME and safety tests pass.
- Validation commands: `cargo test -p kirje-core -p kirje-protocol -p kirje-runtime --all-features`
- TDD plan: validation and MIME-selection failures precede implementation.
- Packet path: `packets/T009.yaml`
- Evidence required: `.ai-platform/evidence/T009/summary.md`

## T010 CLI And MCP Surface

- Status: Complete
- Priority: P0
- Story / Requirement: FR-012 through FR-014; NFR-004
- Dependencies: T007, T008, T009
- Blocks: T011
- Parallel: false
- Conflicts with: interface files owned by release verification
- Goal: expose the shared services through stable CLI and MCP contracts.
- Allowed files: `crates/kirje-cli/**`, `crates/kirje-mcp/**`
- Test targets: CLI JSON contract, MCP names/schemas/annotations, stdout cleanliness
- Deliverables: sync, index, and attachment CLI/MCP operations
- Acceptance criteria: ten MCP tools expose accurate safety hints and object schemas.
- Definition of Done: interface tests and Inspector checks pass.
- Validation commands: `cargo test -p kirje-cli -p kirje-mcp --all-features`
- TDD plan: contract tests fail before new commands and tools exist.
- Packet path: `packets/T010.yaml`
- Evidence required: `.ai-platform/evidence/T010/summary.md`

## T011 Release Readiness

- Status: Complete
- Priority: P0
- Story / Requirement: all
- Dependencies: T006 through T010
- Blocks: none
- Parallel: false
- Conflicts with: any incomplete implementation task
- Goal: produce a reviewable and publishable second-stage release candidate.
- Allowed files: documentation, Skill, CI, evidence, delivery artifacts
- Test targets: full quality gates, cargo-deny, MCP Inspector, CLI quickstart
- Deliverables: canonical docs, Skill, smoke script, evidence, Git handoff
- Acceptance criteria: every local gate passes and credentialed smoke is represented honestly.
- Definition of Done: review has no blocking finding and main CI is green.
- Validation commands: complete commands from `plan.md`
- TDD plan: behavioral tests are owned by T006-T010; this task runs fresh release verification.
- Packet path: `packets/T011.yaml`
- Evidence required: `.ai-platform/evidence/T011/summary.md`
