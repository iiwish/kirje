# T202C3-A006-F001 Fix Packet Review

## Status

`FAILED_NEEDS_CONTRACT_CLARIFICATION`

- Reviewed governance HEAD: `c5732acb78409e20ba8f74a8a0c1f31dcbd19f69`
- Packet: `.ai-platform/specs/007-stable-v1-program/packets/T110-A006.yaml`
- Returned production basis: `2241a946c399ba9c61e67e808a85f777c0d2b402`
- Review date: 2026-08-31
- Execution authorization: none
- Review token: none

The user resumed A006 repair and fixed the serial path as A006 repair and re-
review, A007 claim, A008 delete, then T202C3/T110 closure. The user did not
decide the unresolved public-projection algorithm or parser-test design.

## Independent Passes

| Pass | Result | Critical | High | Medium | Low |
| --- | --- | ---: | ---: | ---: | ---: |
| Engineering/security | PASS | 0 | 0 | 0 | 0 |
| QA/evidence | PASS | 0 | 0 | 0 | 0 |
| Spec compliance | FAIL | 0 | 1 | 2 | 0 |

Because spec compliance failed, the packet did not satisfy its zero-finding
gate. No production, test, or fixture edit started.

## High Finding

F001 treats the cleanup manifest's common store/account subject as signed at
challenge creation. `ActionManifest` is caller-supplied and unproved at this
stage, so those IDs are bounded typed request data rather than signed authority.
The packet does not define safe exact behavior for absent projections,
store/account pair mismatch, or unrelated blocked/recovery rows. Using those
rows to classify before private target validation can therefore create a new
oracle or apply another subject's lifecycle state.

A future contract must specify this ordering without assuming a user decision:

1. Validate complete global schema, anchor, history, transcript, and event
   integrity first; persisted corruption remains precedence step 2.
2. Treat common store/account IDs as untrusted typed request values.
3. Classify only a documented closed public projection without consulting the
   cleanup row, origin transition, locator, tombstone, or another private target
   signal.
4. Define exact closed behavior for absent projections, pair mismatch, and
   unrelated blocked/recovery rows, then perform private step-7 validation.
5. Cross known, absent, pair-mismatched, and unrelated public rows with invalid
   private targets and prove no target distinction, mutation, or entropy.

## Medium Findings

1. A same-context expired cleanup challenge cannot later acquire an invalid
   manifest target because context identity binds that manifest; mutating the
   durable target is persisted corruption at precedence step 2. The successor
   packet must separate: same-context expiry followed by later blocked/recovery
   eligibility; different-context invalid target with zero predecessor
   interaction; and persisted corruption handled at step 2.
2. The closed `active_v2` and `legacy_v1` locator shapes make generic raw-length
   boundaries non-discriminating at the integration surface. A future contract
   must authorize either a safe isolated parser-classification test seam or a
   source plus negative-control proof. Neither option may expose locator bytes
   outside `authority_registry.rs`. This review does not choose an option.

## Scope And Gate

The proposed future worker scope remains limited to:

- `crates/kirje-store/src/authority.rs`
- `crates/kirje-store/tests/authority_registry.rs`
- `crates/kirje-store/tests/fixtures/authority/registry/account_credential_cleanup/**`

That scope is not authorized. The signature fixture remains conditional on
truly changed deterministic public signatures and may never contain a locator
transcript. A007 and A008 remain non-executable; T202C3 and T110 remain
unaccepted. The heartbeat is paused under the user's High-stop condition.

## Subsequent F002 Decision

The user explicitly approved the separate F002 contract revision on 2026-08-31.
That decision does not convert this failed F001 review into a pass. F002 has its
own packet and three-review gate.

## Governance Integration Validation

- YAML parse: passed for all 32 `.ai-platform/**/*.yaml` files.
- 007 artifact validator: passed with zero error or warning.
- 008 artifact validator: passed with zero error or warning.
- `git diff --check`: passed.
- Scope inspection: governance, packet, and evidence files only; no production,
  test, fixture, Cargo, lockfile, or schema file changed.
