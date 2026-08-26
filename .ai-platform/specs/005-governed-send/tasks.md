# Tasks: Governed Send

## T014 Send Contract And Account Configuration

- Status: Complete
- Priority: P0
- Requirements: FR-001, FR-002, FR-003, FR-011
- Dependencies: T013
- Blocks: T015, T016
- Goal: define bounded send contracts and secure SMTP account configuration.
- Allowed files: workspace manifests, `crates/kirje-core/**`, `crates/kirje-cli/**`
- Validation: `cargo test -p kirje-core -p kirje-cli --all-features`
- TDD: validation and configuration compatibility tests precede implementation.
- Packet: `packets/T014.yaml`
- Evidence: `.ai-platform/evidence/T014/summary.md`

## T015 Transactional Outbox

- Status: Complete
- Priority: P0
- Requirements: FR-003 through FR-008, FR-010
- Dependencies: T014
- Blocks: T017
- Goal: persist immutable plans and enforce atomic state transitions.
- Allowed files: `crates/kirje-core/**`, `crates/kirje-store/**`
- Validation: `cargo test -p kirje-core -p kirje-store --all-features`
- TDD: outbox lifecycle, expiry, conflict, and concurrency tests precede code.
- Packet: `packets/T015.yaml`
- Evidence: `.ai-platform/evidence/T015/summary.md`

## T016 SMTP Adapter

- Status: Complete
- Priority: P0
- Requirements: FR-007, FR-010, FR-011
- Dependencies: T014
- Blocks: T017
- Goal: construct bounded MIME and submit through encrypted SMTP.
- Allowed files: workspace manifests, `crates/kirje-protocol/**`
- Validation: `cargo test -p kirje-protocol --all-features`
- TDD: MIME, endpoint, and error-classification tests precede adapter code.
- Packet: `packets/T016.yaml`
- Evidence: `.ai-platform/evidence/T016/summary.md`

## T017 Runtime, CLI, And MCP Workflow

- Status: Complete
- Priority: P0
- Requirements: FR-005 through FR-010
- Dependencies: T015, T016
- Blocks: T018
- Goal: expose one shared governed-send service across CLI and MCP.
- Allowed files: `crates/kirje-runtime/**`, `crates/kirje-cli/**`, `crates/kirje-mcp/**`
- Validation: `cargo test -p kirje-runtime -p kirje-cli -p kirje-mcp --all-features`
- TDD: runtime transitions and interface contracts precede handlers.
- Packet: `packets/T017.yaml`
- Evidence: `.ai-platform/evidence/T017/summary.md`

## T018 Documentation, Live Verification, And Release

- Status: Complete
- Priority: P0
- Story / Requirement: FR-009 through FR-012 and all quality requirements
- Dependencies: T017
- Blocks: none
- Parallel: false
- Conflicts with: release documentation and live credential state
- Goal: document the agent workflow and complete release evidence.
- Allowed files: `README.md`, `docs/**`, `skills/**`, `scripts/**`, `.ai-platform/**`
- Test targets: full workspace gates, MCP stdio contract, isolated 163 smoke
- Deliverables: canonical docs, Agent Skill, smoke script, release evidence
- Acceptance criteria: agent instructions reflect the exact approval boundary;
  gates pass; live result or sanitized hard blocker is recorded.
- Definition of Done: review has no blocking finding and repository handoff is complete.
- Validation commands: all commands in `plan.md` plus isolated live smoke when safe
- TDD plan: behavioral coverage belongs to T014-T017; T018 performs fresh release QA.
- Packet path: `packets/T018.yaml`
- Evidence required: `.ai-platform/evidence/T018/summary.md`
