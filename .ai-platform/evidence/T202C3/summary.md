# T202C3 Evidence Summary

## Status

`T202C3-A006` is Returned/Needs Fix at candidate commit
`2241a946c399ba9c61e67e808a85f777c0d2b402`. Engineering passed, but spec review
failed with 1 High/1 Medium and QA failed with 4 Medium findings. Autonomous
execution stopped and the heartbeat was paused under the user's High-stop
condition. The user explicitly resumed A006 repair on 2026-08-31. Fix candidate
packet `T202C3-A006-F001` then failed spec review C0/H1/M2/L0 while engineering
and QA passed C0/H0/M0/L0. No implementation started. The user explicitly
approved the F002 contract revision
on 2026-08-31. F002 is ready for three independent packet reviews with all
permissions closed. A006, T202C3, and T110 remain unaccepted. `T202C3-A001` challenge issuance is reviewed
at production commit
`daf22a0`. `T202C3-A002` account-update transition execution is accepted at
production commit `2c00f32` by explicit user decision on 2026-08-30.
`T202C3-A003` account-remove transition execution is accepted at production
commit `703b5a1` by explicit user decision on 2026-08-30.
`T202C3-A004` credential-set transition execution is accepted at production
commit `1c6d7cb` by explicit user decision on 2026-08-30.
`T202C3-A005` credential-delete transition execution is accepted at production
commit `316dae0` by explicit user decision on 2026-08-30.

## Delivered

- Exact effect-free challenge issuance for account update/remove and credential
  set/delete.
- Exact pending reuse after restart without new entropy.
- Active store/config and account/credential/binding snapshot checks.
- Provisional cleanup identity and locator uniqueness checks for update/remove.
- Stable stale-account and busy-store failures before entropy or persistence.
- Restart acceptance for the four new pending challenge actions.
- Exact account-update prepare, config commit, finalize, abort, unsafe recovery,
  retry, expiry, and restart behavior.
- Immutable generation-two account/store versions and permanent replacement
  credential reservation.
- Private cleanup reservation with exact signed-digest binding and
  provisional-to-ready finalize behavior.
- Exact cleanup-ready event and fail-closed material/digest/event validation.
- Exact account-remove prepare, config commit, finalize, abort, unsafe recovery,
  retry, expiry, and restart behavior.
- Store-only after versioning with no replacement credential or account version.
- Finalize-only removed projection and active display-slot release while every
  historical account and credential identity remains reserved.
- Valid create-update-remove history with generation and predecessor receipt
  preservation.
- Exact credential-set prepare, config commit, finalize, abort, unsafe recovery,
  retry, expiry, and restart behavior.
- Credential-targeted grant binding with the existing credential identity and
  immutable generation-two account/store versions.
- No credential identity, cleanup row, credential bytes, locator material, or
  keyring/config/runtime capability added by credential set.
- Exact credential-delete prepare, config commit, finalize, abort, unsafe
  recovery, retry, expiry, and restart behavior.
- Signed authorized/bound-to-missing account transition with permanent
  credential-history retention and immutable generation-three account/store
  versions.
- No credential row deletion, cleanup row, credential bytes, locator material,
  or keyring/config/runtime capability added by credential delete.
- The returned A006 candidate adds canonical cleanup locator/reservation checks
  and cleanup challenge issuance, and passes its focused and full validation.
  These changes are not accepted because required precedence and coverage remain
  incomplete.

No cleanup claim/delete, remote effect, runtime, config, keyring, protocol, CLI,
MCP, network, schema, dependency, or core transcript behavior is included.

## Review Result

The accepted A005 production review has no unresolved Critical, High, or Medium
finding. A005 review covers the exact
create-set-delete chain, terminal replay, target mismatch, injected
prepare/commit/finalize faults, expiry, restart, and transition-kind corruption.
The implementation remains within the packet-authorized authority source,
registry test, and synthetic public-signature fixture.

The A006 packet's independent spec, engineering, and QA passes at governance
HEAD `3533054` each returned zero Critical, High, Medium, or Low finding and
explicitly authorized its exact production/test scopes. This packet pass is not
implementation evidence or acceptance.

Production review of candidate commit `2241a946` did not pass. Engineering was
PASS C0/H0/M0/L0 with a legacy full-flow residual gap. Spec was FAIL
C0/H1/M1/L0. QA was FAIL C0/H0/M4/L0. The blocking High is the cleanup error-
precedence privacy leak; five Medium coverage/proof findings also remain open.

## Returned Candidate Content Hashes

```text
59d13b294ce2a0446ce9579391e49e05f96e62a9f079f5d10f39e5dc425ecc5d  crates/kirje-store/src/authority.rs
ad413f31952e1093e0174809bf4f37a23fffe97817fe65f1229fd3c281b62df2  crates/kirje-store/tests/authority_registry.rs
e5613c2fef5f0181dfe06ededec939b4e132fc4bbf1cd656dbdfbfe26f076608  crates/kirje-store/tests/fixtures/authority/registry/account_credential_cleanup/signatures.txt
5d01739b89246a5f495a965e57e416eee9fd0b5016995add41c6edee7f3e970d  crates/kirje-store/src/authority/schema_v1.sql
596ddb0071ecb38b0b9429c5d91cdbb83abe6a25bc760cf9588b2764274ff850  Cargo.lock
```

## Evidence

- Attempt: `.ai-platform/evidence/T202C3/attempts/T202C3-A001.md`
- Attempt: `.ai-platform/evidence/T202C3/attempts/T202C3-A002.md`
- Attempt: `.ai-platform/evidence/T202C3/attempts/T202C3-A003.md`
- Attempt: `.ai-platform/evidence/T202C3/attempts/T202C3-A004.md`
- Attempt: `.ai-platform/evidence/T202C3/attempts/T202C3-A005.md`
- Returned attempt: `.ai-platform/evidence/T202C3/attempts/T202C3-A006.md`
- Failed fix-packet review: `.ai-platform/evidence/T202C3/attempts/T202C3-A006-F001-packet-review.md`
- Pending F002 packet review: `.ai-platform/evidence/T202C3/attempts/T202C3-A006-F002-packet-review.md`
- Contract amendment: `.ai-platform/evidence/T202C3/attempts/T202C3-A006-contract.md`
- Contract fix: `.ai-platform/evidence/T202C3/attempts/T202C3-A006-contract-A002.md`
- Contract fix: `.ai-platform/evidence/T202C3/attempts/T202C3-A006-contract-A003.md`
- Contract fix: `.ai-platform/evidence/T202C3/attempts/T202C3-A006-contract-A004.md`
- Packet review: `.ai-platform/evidence/T202C3/attempts/T202C3-A006-packet-review.md`
- Test results: `.ai-platform/evidence/T202C3/test-results.md`
- Accepted production commits: `daf22a0`, `2c00f32`, `703b5a1`, `1c6d7cb`, `316dae0`
- Returned candidate commit: `2241a946c399ba9c61e67e808a85f777c0d2b402`

## Residual Scope

Cleanup claim and delete remain fail-closed unimplemented. Cleanup challenge is
implemented only in the returned, unaccepted A006 candidate. The
revised contract defines the canonical locator and tombstone transcripts,
historical origin and transition-bound legacy ownership, exact claim/permit and
delete crash behavior, events 16/17, restart/privacy invariants, and closed
error precedence. It also defines clock-only exact recovery, reservation-time
canonicality, expired replacement/concurrency rollback, synthetic-vector
privacy, and an unpublished credential crate directly depended on only by
store, with the combined store apply method as the sole low-level production
call site. A008 must prove this with an exhaustive AST allowlist across every
production store Rust file, plus Cargo direct-dependency, no-re-export, and
runtime compile-fail controls; no AST test exists yet. Returned candidate
`T202C3-A006` retains one High and five Medium findings. The user resumed repair,
and F001 failed because it treated caller-supplied common IDs as signed and left
absent/pair-mismatch/unrelated-row public classification undefined. The user
approved F002's exact public-pair algorithm, reachable replacement split, and
private numeric-only length-classifier proof. F002 awaits three packet PASS
reviews and no implementation started. A007 claim and A008 delete completion remain non-
executable just-in-time outlines. T202C3 and T110 are not Accepted; the authority
umbrella remains Draft.
