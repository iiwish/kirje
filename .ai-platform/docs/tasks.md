# Product Work Graph

Feature-scoped implementation work is canonical under `.ai-platform/specs`.
Completed phases are `001-agent-first-bootstrap`, `002-read-only-mvp`,
`003-local-sync-index`, `004-provider-registry`, `005-governed-send`, and
`006-agent-mail-operations`.

## T100: Govern The Next Product Phase

- Status: Complete
- Priority: P1
- Story / Requirement: Govern and deliver the v0.3 Agent Mail Operations slice.
- Dependencies: T011
- Blocks: implementation of the v0.3 feature slice
- Parallel: false
- Conflicts with: active release work
- Goal: keep product scope, security boundaries, and delivery evidence coherent
  for `006-agent-mail-operations`.
- Allowed files: `.ai-platform/**`
- Test targets: requirement completeness and architecture consistency
- Deliverables: feature spec, plan, work graph, and evidence under
  `.ai-platform/specs/006-agent-mail-operations`
- Acceptance criteria: the v0.3 product contract and safe-delete baseline are
  recorded for implementation.
- Definition of Done: the v0.3 feature records, implementation, evidence, and
  delivery handoff are complete.
- Validation commands: delivery artifact validator for the selected feature
- TDD plan: requirements checklist and analysis precede implementation tests.
- Packet path: `.ai-platform/specs/006-agent-mail-operations`
- Evidence required: approval and analysis records
