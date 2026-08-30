# T202C3-A006 Cleanup Contract Amendment

## Scope

This is governance evidence only. The user approved revision of the T202C3
cleanup security contract on 2026-08-30. No production code, test, schema,
dependency, core transcript, runtime, keyring, protocol, CLI, MCP, network, or
external provider behavior is changed.

## Decisions

- The private locator is one bounded canonical kind/service/username transcript;
  its digest covers the complete domain-prefixed bytes.
- The signed tombstone is one exact 14-field transcript derived from the realm,
  cleanup, finalized origin transition and manifest, historical-before account,
  private locator digest, and prepare time. Mutable claim/delete state and raw
  locator material are excluded.
- Every v1 cleanup, including `legacy_v1`, is transition-bound. A persisted NULL
  transition is corruption; schema and core transcript bytes remain unchanged.
- Challenge binds the origin-before account/binding and admits an active store
  plus active or removed historical account. Blocked and recovery states fail
  closed; later account changes cannot rebind the cleanup.
- A007 owns atomic grant use/claim, exact recovery, expiry/concurrency, opaque
  apply-lock permit, and event 16 immediately after event 7.
- A008 owns the combined consuming fake-janitor delete boundary, crash/backend
  recovery, terminal no-recall retry, and event 17 after event 16.
- Restart validates origin/transcript/grant/event/cardinality/privacy invariants
  under a closed error precedence. T204 owns real runtime/keyring integration.

## Governance Result

The eight recorded cleanup High findings and the canonical-locator High finding
are resolved in the proposed canonical SSOT. The replacement A006 packet is
`ready_for_review`, with production and test permission explicitly `none` until
independent packet review. A007 and A008 remain non-executable outlines.

The user delegated later acceptance decisions to the orchestrator, but this
record does not claim that the user reviewed this unseen amendment. A future
acceptance requires the named TDD, full validation, sanitized evidence, and all
three review passes with no blocking finding.

## Validation

- YAML parse: passed.
- 007 and 008 delivery artifact validators: passed.
- `git diff --check`: passed.

## Residual Risk

No unresolved contract-level Critical, High, or Medium finding is known before
independent packet review. Implementation remains prohibited until that review
explicitly changes the packet permissions.
