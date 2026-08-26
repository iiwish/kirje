# Tasks: Provider Preset Registry

## T012 Registry Contract And Discovery

- Status: Complete
- Priority: P0
- Story / Requirement: FR-001 through FR-007
- Dependencies: T011
- Blocks: T013
- Parallel: false
- Conflicts with: provider discovery and CLI contract changes
- Goal: make validated embedded JSON the only built-in provider preset source.
- Allowed files: workspace manifests, `crates/kirje-core/**`, `crates/kirje-cli/**`
- Test targets: registry invariants, discovery compatibility, provider CLI
- Deliverables: typed registry, JSON catalog, discovery migration, CLI inspection
- Acceptance criteria: secure endpoints and source evidence validate; 163 and
  iCloud port assertions pass; no POP3 endpoint enters account configuration.
- Definition of Done: target tests and review pass without secret material.
- Validation commands: `cargo test -p kirje-core -p kirje-cli --all-features`
- TDD plan: registry and CLI expectations fail before implementation.
- Packet path: `packets/T012.yaml`
- Evidence required: `.ai-platform/evidence/T012/summary.md`

## T013 Provider Verification And Release Readiness

- Status: Blocked
- Priority: P0
- Story / Requirement: FR-008, FR-009 and all quality requirements
- Dependencies: T012
- Blocks: none
- Parallel: false
- Conflicts with: credential store and release documentation
- Goal: run isolated 163 conformance and complete release evidence.
- Allowed files: `docs/**`, `scripts/**`, `.ai-platform/**`
- Test targets: live read-only smoke, full workspace quality gates
- Deliverables: sanitized smoke result, provider docs, release evidence
- Acceptance criteria: credentials and temporary files are removed after the
  check; full local gates pass.
- Definition of Done: review has no blocking finding and handoff is complete.
- Validation commands: complete commands from `plan.md` plus opt-in live smoke
- TDD plan: behavioral coverage belongs to T012; T013 performs fresh release QA.
- Packet path: `packets/T013.yaml`
- Evidence required: `.ai-platform/evidence/T013/summary.md`
