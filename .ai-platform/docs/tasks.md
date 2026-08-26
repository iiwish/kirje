# Product Work Graph

Feature-scoped implementation work is canonical under `.ai-platform/specs`.
Completed phases are `001-agent-first-bootstrap`, `002-read-only-mvp`,
`003-local-sync-index`, `004-provider-registry`, and `005-governed-send`. The
next feature phase has not been selected.

## T100: Govern The Next Product Phase

- Status: Complete
- Priority: P1
- Story / Requirement: Define the next approved vertical product slice.
- Dependencies: T011
- Blocks: implementation of the next phase
- Parallel: false
- Conflicts with: active release work
- Goal: keep product scope, security boundaries, and delivery evidence coherent.
- Allowed files: `.ai-platform/**`
- Test targets: requirement completeness and architecture consistency
- Deliverables: confirmed feature spec, plan, work graph, and packets under
  `.ai-platform/specs/004-provider-registry`
- Acceptance criteria: the user explicitly approves the next product contract.
- Definition of Done: the next feature is ready for test-first execution.
- Validation commands: delivery artifact validator for the selected feature
- TDD plan: requirements checklist and analysis precede implementation tests.
- Packet path: defined by the next feature work graph
- Evidence required: approval and analysis records
