# Analysis: Stable 1.0 Program

## Metadata

- Feature ID: `007-stable-v1-program`
- Status: Completed
- Inputs: constitution, spec, plan, work graph, requirements checklist,
  `008-security-baseline` contracts/tasks, current Git state, and interrupted
  T202C2 execution evidence
- Updated: 2026-08-30

## Executive Result

The direct-to-1.0 checkpoint model is internally consistent and preserves the
confirmed Kirje product and security boundaries. It removes duplicate
per-version governance stacks while retaining executor-sized tasks, TDD,
content-addressed evidence, adversarial review, complete checkpoint gates, and
human acceptance.

The confirmed checkpoint plan remains internally consistent, but eight High
cleanup-contract findings block T202C3. Three define the minimum A006 challenge
contract; three belong to a later A007 claim contract; two belong to a later
A008 delete-completion contract. A007 and A008 are reserved labels only, not
Ready packets or implementation permission. One separate Medium
implementation finding is assigned: the unchanged branch dependency graph contains yanked
`chacha20 0.10.1`, which makes `cargo deny check advisories` fail. T111
owns remediation and Security Alpha cannot be Accepted until the complete
dependency gate passes.

## Requirement Coverage

- SFR-001-SFR-003 map to T109-T112.
- SFR-004-SFR-007 map to T111-T112.
- FR-001-FR-003 map to T113.
- FR-004-FR-005 map to T114.
- FR-006-FR-010 map to T115.
- FR-011 maps to T116.
- FR-012-FR-017 map to T117.
- FR-018-FR-021 map to T118.
- FR-022-FR-025 map to T119.
- FR-026-FR-029 map to T120.
- FR-030-FR-032 map to T121.
- NFR-001-NFR-008 are present in every task whose behavior touches the
  corresponding risk boundary.

Coverage gaps: none.

## Unmapped Task Check

Every task maps to at least one user story and one functional/security or
non-functional requirement. T109 is additionally justified by D-005 current
branch recovery. No process-only task can become Accepted without a concrete
commit, tag, release artifact, or accepted evidence output.

Unmapped tasks: none.

## Constitution Alignment

- Local-first/no GUI: pass.
- Provider-neutral core and shared CLI/MCP application services: pass.
- Untrusted mailbox content: pass.
- Secret-free command, output, fixture, log, and evidence boundary: pass.
- Verified TLS and no guessed provider semantics: pass.
- Plan/authorize/apply and independent owner authorization: pass.
- No automatic uncertain remote-effect replay: pass.
- Protocol/auth/sync/write TDD and reproducible evidence: pass.

Constitution conflicts: none.

## Dependency And Ordering Check

The checkpoint chain is acyclic:

```text
T109 -> T110 -> T111 -> T112
  -> T113 -> T114
  -> T115 -> T116
  -> T117
  -> T118 -> T119
  -> T120
  -> T121
```

This ordering preserves the key safety constraints:

- security alpha precedes mailbox production changes;
- mailbox convergence precedes delivery state expansion;
- delivery behavior precedes policy freeze;
- product behavior precedes compatibility freeze;
- compatibility freeze precedes distribution;
- distribution precedes hardening and stable publication.

No task is marked parallel. CI jobs and read-only review may run concurrently
without changing production ownership.

## Scope And Conflict Check

T109 has exact allowed files matching the preserved interrupted diff and its
evidence/status integration. The task forbids schema, dependency, runtime, CLI,
MCP, keyring, protocol, and network scope growth.

Future Draft tasks use crate/directory scopes because exact files depend on
accepted predecessor APIs. Their packets must narrow those scopes before they
can become Ready. This is deliberate just-in-time packetization, not permission
for broad edits.

Cross-task write conflicts are represented by serial dependencies.

## Packet Completeness

T109 packet:

- governance inputs: present;
- exact work unit and dependencies: present;
- preserved hashes and current branch context: present;
- allowed and forbidden files: present;
- evidence-reuse rule: present;
- focused validation loop: present;
- review and stop conditions: present;
- handoff: present;
- execution status: approved for T109 review on 2026-08-30.

Future packets are intentionally absent because their tasks are Draft and their
exact context depends on predecessor output. They must be created and analyzed
before those tasks become Ready.

Blocking packet gaps for the first checkpoint: none after user approval.

## T110 Just-In-Time Split

T110 crosses four security-baseline state machines (`T202C3` through `T202E`)
and cannot safely be executed as one long attempt. Following the user's
step-by-step instruction, T110 is a serial controller task with one reviewed
commit per bounded attempt. The first attempt is `T202C3-A001`: exact,
effect-free challenge issuance for account update/remove and credential
set/delete. It changes no transition, cleanup, effect, schema, core transcript,
runtime, CLI, MCP, keyring, protocol, or network behavior.

The implementation packet is `.ai-platform/specs/007-stable-v1-program/packets/T110.yaml`.
Its first attempt has no blocking packet finding. T202C3 remains Running after
the attempt because transition execution and cleanup are explicitly excluded.

T202C3-A001 completed test-first implementation and three-pass review at
production commit `daf22a0`. The discriminating RED was the exact current
`authorization_context_stale` rejection of the first valid `account_update`
manifest. GREEN covers all four actions, pending reuse, intrinsic-shape
negatives, stale account state, busy store state, zero effects, restart, and
unchanged schema/dependency bytes. No Critical or High finding remains.

`T202C3-A002` completed test-first implementation and three-pass review at
production commit `2c00f32`. Account update supports exact prepare, config
commit, finalize, abort, unsafe recovery, retry, expiry, restart, immutable
versions, replacement credential reservation, and private provisional-to-ready
cleanup. Review reproduced and fixed an expired-update restart defect. No
unresolved Critical, High, or Medium finding remains. The user explicitly
accepted A002 on 2026-08-30. Account remove is the active bounded attempt.

`T202C3-A003` completed test-first implementation and three-pass review at
production commit `703b5a1`. Removal preserves the exact before account tuple,
creates no replacement credential and no after account version, and retains
every identity. Prepare blocks the account/store and records private
provisional cleanup; config commit adds only the after store version; finalize
removes the current account projection and readies cleanup. Abort restores the
predecessor receipt, while unsafe observation remains fail-closed recovery.
Review covers direct removal, create-update-remove history, display reuse only
with fresh account and credential identities, fault rollback, expiry, restart,
and tamper recovery. No unresolved Critical, High, or Medium finding remains.
The user explicitly accepted A003 on 2026-08-30. Credential set is accepted at
production commit `1c6d7cb`; credential delete, cleanup claim/delete, config,
keyring, runtime, protocol, CLI, MCP, and network behavior remain excluded.

`T202C3-A004` completed test-first implementation and three-pass review at
production commit `1c6d7cb`. The credential-targeted grant binds the complete
signed before/after account mutation and `active_locator_sha256`, while
authority stores no credential bytes or locator material. Prepare advances only
the account generation/receipt projection and blocks account/store without
inserting a credential or cleanup row. Config commit creates the next store and
account versions with the existing credential identity; finalize activates the
authorized/bound after projection. Abort restores the predecessor receipt and
tuple, while unsafe observation remains fail-closed recovery. Fault rollback,
expiry, replay, restart, target mismatch, and kind corruption are covered. No
unresolved Critical, High, or Medium finding remains. The user explicitly
accepted A004 on 2026-08-30.

`T202C3-A005` completed test-first implementation and three-pass review at
production commit `316dae0`. The credential-targeted grant binds the signed
authorized/bound before projection, authorized/missing after projection, store
CAS, and active-locator digest. Prepare and commit retain the original
credential identity, create no cleanup row, and add only the immutable after
account/store versions. Finalize activates the signed missing projection; abort
restores the bound predecessor tuple and receipt; unsafe observation remains
fail-closed recovery. Fault rollback, expiry, replay, create-set-delete restart,
target mismatch, and kind corruption are covered. No unresolved Critical, High,
or Medium finding remains. The user explicitly accepted A005 on 2026-08-30;
cleanup remains excluded from that production commit.

### T202C3-A006 Cleanup Packet Gate

`T202C3-A006` is the next consistent attempt ID and its blocked packet is
`.ai-platform/specs/007-stable-v1-program/packets/T110-A006.yaml`. The user also
authorized an unattended cadence in which future internal attempts may continue
after TDD, full validation, and three-pass review while remaining only
`review_complete`; this does not waive confirmed security semantics or the major
human acceptance gates.

The cleanup challenge packet cannot be made Ready from the current SSOT. Its
minimum unresolved subset is: the domain/transcript/derivation of signed
`tombstone_sha256`; whether challenge ownership binds a historical-before or
current account/binding and how removed accounts plus blocked/recovery stores
behave; and ownership of legacy tombstones whose manifest has
`transition_id=None`. No selection among those alternatives is implied.

Later claim and delete-completion decisions are intentionally not folded into
A006. A007 must separately define claim identity, exact/changed retry, expiry,
response loss, concurrency, opaque `DeleteOnlyLocator` ownership and recovery,
and exact `cleanup_claimed` event 16 semantics. A008 must separately define the
delete-completion capability and crash protocol, missing-key outcome, terminal
retry/recovery, and exact `cleanup_deleted` event 17 semantics including its
order after event 16. A007 and A008 are unpacketized and have no execution
permission.

Result: `T202C3_A006_PACKET_BLOCKED`. A006 remains Blocked until all three
minimum challenge decisions are explicitly confirmed in the security contract
and a replacement packet passes independent review. This does not resolve or
authorize A007 or A008.

## Current Implementation Evidence Check

T109 recovered and reviewed the interrupted T202C2 attempt:

- Turn status: interrupted; workspace diff preserved.
- RED included unresolved account-transition imports/methods and an exact
  `UnsupportedCapability` failure for account-create preparation.
- Original focused registry GREEN: 32 passed.
- Authorization/schema/no-default command: passed.
- Package all-features: passed.
- Rust 1.88 package test: passed.
- Workspace all-features test: passed.
- Workspace Clippy and build: passed.
- Formatting, diff, schema hash, query-bound, privacy, secret, and no-external
  scans: passed.
- `cargo deny` licenses/bans/sources: passed.
- `cargo deny` advisories: failed only on the unchanged yanked
  `chacha20 0.10.1` transitive dependency.

- Review found and fixed two P1 defects and one P2 defect with discriminating
  RED/GREEN tests.
- Fresh focused registry GREEN: 35 passed.
- Fresh no-default, Rust 1.88, workspace tests, workspace Clippy, and workspace
  build: passed.
- Reviewed production commit: `94f3495`.

The final evidence records exact content hashes. Any later change invalidates
the affected result and requires the corresponding gate to run again.

## Findings

### Critical

None.

### High

None.

### Medium

M-001: The dependency policy gate fails on yanked `chacha20 0.10.1` through
`io-imap`. `Cargo.lock` is unchanged by T202C2, so this is not introduced by
the preserved diff. T111 owns removal before Security Alpha acceptance.

### Low

None.

## Residual Risks

- T109 and the account-create checkpoint were explicitly accepted by the user
  on 2026-08-30; T110 may start after its just-in-time packet review.
- Cross-platform support claims remain Draft until T119 produces platform
  evidence.
- Real-provider checks depend on dedicated credentials and may produce honest
  sanitized blockers.
- Future task file scopes require narrowing during just-in-time packetization.

## Gate Result

`T109_ACCEPTED_T110_PACKETIZATION_ALLOWED`

The user approved `plan.md` and `tasks.md` on 2026-08-30. T109 review and fresh
validation are complete at `94f3495`; the user explicitly accepted the
checkpoint on 2026-08-30.
