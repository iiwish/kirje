# Analysis: Local Sync And Attachment Access

## Result

No blocking requirement, architecture, or constitution conflict was found.

## Coverage

- FR-001 through FR-008 map to T006 and T007.
- FR-003 through FR-006 and FR-011 map to T008.
- FR-009 through FR-011 map to T009.
- FR-012 through FR-014 map to T010.
- NFR-001 through NFR-005 map to task-local tests and T011 release gates.

## Risks And Controls

- UID sync is provider-sensitive: isolate IMAP range construction and verify raw
  commands with transcript tests.
- An initial newest-window sync is not a full archive: expose coverage and
  backlog state rather than implying completeness.
- Flags and deletions can change below the high-water UID: document explicit
  refresh and keep background reconciliation out of this phase.
- SQLite corruption or future schemas must not trigger data loss: fail closed
  with stable store errors and never auto-downgrade.
- Attachments are hostile binary input: require exact scoped references, cap
  decoded bytes to 1 MiB, base64 encode, mark untrusted, and never write or execute them.

## Execution Mode

Direct Execute is required because the active host policy does not permit
sub-agent delegation. Each task still uses a self-contained packet, TDD loop,
review, and evidence record.
