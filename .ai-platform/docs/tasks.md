# Product Work Graph

Feature-scoped implementation work is canonical under `.ai-platform/specs`.
Completed phases are `001-agent-first-bootstrap`, `002-read-only-mvp`,
`003-local-sync-index`, `004-provider-registry`, `005-governed-send`, and
`006-agent-mail-operations`.

The active program is `007-stable-v1-program`. Its product boundary and
accelerated technical plan/work graph are Confirmed. T109 and its T202C2
account-create checkpoint are Accepted at production commit `94f3495`. The
current implementation checkpoint is T110 authority lifecycle completion.

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

## T101: Deliver Kirje 1.0 Through Incremental Checkpoints

- Status: Running
- Priority: P0
- Story / Requirement: US-001-US-006, SFR-001-SFR-007, FR-001-FR-032,
  NFR-001-NFR-008
- Dependencies: completed v0.3 baseline and accepted T201-T202C1S security work
- Blocks: `v1.0.0` publication
- Parallel: false for conflicting production state; CI and read-only review may
  run concurrently
- Conflicts with: any second v1 release train or concurrent writes to the same
  state/schema contracts
- Goal: deliver one narrow IMAP/SMTP 1.0 product through current-branch,
  alpha.1, alpha.2, beta.1, beta.2, rc.1, rc.2, and stable checkpoints.
- Allowed files: narrowed per executor task under
  `.ai-platform/specs/007-stable-v1-program/tasks.md`
- Test targets: focused RED/GREEN per batch; full local, CI, migration,
  conformance, platform, artifact, and release gates per checkpoint
- Deliverables: reviewed commits and tags culminating in `v1.0.0`
- Acceptance criteria: every checkpoint produces code or a verifiable release
  artifact and every FR/NFR has accepted evidence before stable publication
- Definition of Done: clean accepted release commit, annotated tag, matching
  published artifacts, and post-release verification
- Validation commands: checkpoint gates in
  `.ai-platform/specs/007-stable-v1-program/plan.md`
- TDD plan: high-risk behavior starts with discriminating RED; unchanged-hash
  evidence may be reused only within the same interrupted attempt
- Packet path:
  `.ai-platform/specs/007-stable-v1-program/packets/T109.yaml`
- Evidence required: checkpoint summaries, test results, reviews, CI, tags, and
  final release report
