# T202C2 Evidence Summary

## Status

Accepted by the user on 2026-08-30 after T109 review and validation completed.

## Result

The account-create challenge and authority-store transition lifecycle are
implemented, adversarially reviewed, and freshly validated. T109 found three
contract defects in the interrupted implementation. Each defect received a
discriminating RED, a scoped fix, and fresh GREEN evidence. No unresolved
Critical or High finding remains. The reviewed production commit is
`94f3495604e4705894f80ebca084854c32f31a57`.

Acceptance was explicitly granted by the user on 2026-08-30. The governance
and review evidence was committed as `c8208f6`.

## Changed Files

- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/tests/authority_registry.rs`
- `crates/kirje-store/tests/fixtures/authority/registry/account_create/vectors.txt`

The Authority SQLite schema, `crates/kirje-store/src/lib.rs`, dependency graph,
runtime, CLI, MCP, protocol, keyring, and network behavior remain unchanged.

## Review Findings

- **P1, resolved:** restart validation accepted a tampered current store config
  pair after all account transitions were terminal. The store event stream now
  derives the legal state, generation, digest, and update time from enrollment
  through every transition and compares that result with `registered_stores`.
- **P1, resolved:** an unsafe physical config pair could remain merely prepared
  or config-committed when the invoked method carried a stale source state.
  Unsafe before/third classification now takes precedence over method-state
  selection, and terminal recovery retries converge from every observation
  method.
- **P2, resolved:** account-create challenge issuance did not require the
  canonical `credential_reentry_required` state reason. Intrinsic validation
  now rejects a missing or different reason before entropy or mutation.

## Verified Behavior

- Registry-backed account-create challenge issuance and reuse.
- Prepare, config-committed, finalize, abort, and recovery-required transitions.
- Exact retries, restart recovery, concurrency, expiry, fault boundaries, and
  immutable event/registry relationships.
- Store projection reconstruction across sequential terminal transitions.
- Bounded indexed restart validation and privacy/capability exclusions.
- Unchanged Authority SQLite v1 schema and accepted predecessor fixtures.

## Final Content Hashes

```text
1653194713b541836c0966df0c01e34ae7ff0b91ff5cabd5407f244c54b460f9  crates/kirje-store/src/authority.rs
5ee3b0ffb9007b4aeb8b95f8be1b15692d2f8797b49c5c76f34c221c271fd9f0  crates/kirje-store/tests/authority_registry.rs
c5af4427045606c90b8d4f5fcd634290b383a83f45a61248227143582b86b0e5  crates/kirje-store/tests/fixtures/authority/registry/account_create/vectors.txt
5d01739b89246a5f495a965e57e416eee9fd0b5016995add41c6edee7f3e970d  crates/kirje-store/src/authority/schema_v1.sql
80673cbb8a2975c5ee0729a365cb8f49483d3db135879bafc9d792036bd6c3a2  crates/kirje-store/src/lib.rs
596ddb0071ecb38b0b9429c5d91cdbb83abe6a25bc760cf9588b2764274ff850  Cargo.lock
```

## Known Finding

`cargo deny check` fails only on unchanged yanked transitive dependency
`chacha20 0.10.1` through `io-imap`. Bans, licenses, and sources pass. T111 owns
dependency remediation before Security Alpha acceptance.

## Evidence

- Interrupted attempt:
  `.ai-platform/evidence/T202C2/attempts/T202C2-A001.md`
- Fresh and review-fix validation:
  `.ai-platform/evidence/T202C2/test-results.md`
- Reviewed production diff: commit
  `94f3495604e4705894f80ebca084854c32f31a57`.

## Residual Risk

Local macOS validation is complete. Cross-platform CI and distribution evidence
remain later checkpoint work. The known yanked dependency is unchanged and
blocks T112 acceptance until T111 resolves it.
