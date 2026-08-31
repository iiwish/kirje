# Analysis: Stable 1.0 Program

## Metadata

- Feature ID: `007-stable-v1-program`
- Status: Completed
- Inputs: constitution, spec, plan, work graph, requirements checklist,
  `008-security-baseline` contracts/tasks, current Git state, and interrupted
  T202C2 execution evidence
- Updated: 2026-08-31

## Executive Result

The direct-to-1.0 checkpoint model is internally consistent and preserves the
confirmed Kirje product and security boundaries. It removes duplicate
per-version governance stacks while retaining executor-sized tasks, TDD,
content-addressed evidence, adversarial review, complete checkpoint gates, and
human acceptance.

The confirmed checkpoint plan remains internally consistent. The first A006
review failed on three High contradictions/implementability gaps. Repeat review
accepted the historical-binding and clock-only repairs but found one remaining
High in the shared public deletion surface. The focused amendment specifies an
unpublished low-level credential crate directly depended on only by store, a
single combined store adapter-call boundary, reservation/prepare canonicality,
and complete issuance race/replacement matrices. Final QA accepted the High
repair and found one Medium in the literal sole-call proof; A008 now requires an
exhaustive production-store AST allowlist. The A006 challenge candidate
`2241a946` remains Returned/Needs Fix: engineering passed, spec failed
C0/H1/M1/L0, and QA failed C0/H0/M4/L0. The user explicitly resumed A006 repair
on 2026-08-31. Fix packet `T202C3-A006-F001` failed spec review C0/H1/M2/L0;
engineering and QA each passed C0/H0/M0/L0. The user explicitly approved the
F002 contract revision on 2026-08-31. Its packet review returned QA PASS
C0/H0/M0/L0, spec FAIL C0/H0/M1/L0, and engineering FAIL C0/H1/M2/L0 at
`38ca4273`. The user then authorized orchestrator approval of existing-boundary
clarifications. F006 preserved the substantive cleanup contract but failed
review on authority-source, strict-parsing, phase-lifecycle, and negative-control
defects. F007 and F008 reviews then failed/refused. F008's exact counts are spec
C0/H2/M2/L0, engineering/security C0/H4/M1/L0, and QA C0/H4/M2/L0. F009 review
failed with spec C0/H1/M0/L0, engineering/security C0/H1/M2/L0, and QA
C0/H1/M1/L0. F010 review returned spec PASS C0/H0/M0/L0,
engineering/security BLOCK C0/H3/M3/L0, and QA BLOCK C0/H1/M2/L0. Under
delegated authority, the orchestrator approved F011's trusted-local procedural
clarification. F011 review returned spec PASS C0/H0/M0/L0,
engineering/security BLOCK C0/H1/M1/L0, and QA PASS C0/H0/M0/L0. The
orchestrator approved F012's exact phase-scope clarification. This is delegated
contract approval, not user review of the unseen F012 packet. No implementation
started; F012 awaits three independent
reviews with all permissions closed. A007 claim and
A008 delete completion remain non-executable just-in-time outlines. One separate dependency Medium
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

### T202C3 Cleanup Contract And A006 Packet Gate

`T202C3-A006` is the next consistent attempt ID and its review packet is
`.ai-platform/specs/007-stable-v1-program/packets/T110-A006.yaml`. The user also
authorized unattended delegation: the orchestrator may accept future artifacts
only after their required TDD, full validation, evidence, and three-pass review
succeed. A delegated record never claims the user personally reviewed unseen
work and never waives a failed gate. The user's 2026-08-31 clarification
authority separately permits the orchestrator to approve existing-boundary
contract clarifications and review follow-ups; material boundary changes still
stop.

The revised cleanup contract defines the exact canonical private locator
transcript and digest, the 14-field tombstone transcript, finalized transition's
historical-before origin, active/removed account eligibility, blocked/recovery
failure behavior, and transition-bound legacy locators. Canonical v1 rejects
transition-less requests through one pure `authority.rs` manifest preflight
before apply lock/file/database/entropy, returning `authorization_malformed`
with zero I/O/mutation/entropy. A persisted NULL origin remains corruption. This
does not change schema, core types, or core transcript bytes.

The contract explicitly overrides the generic current-binding rule only for
cleanup; removal and credential deletion retain current-before binding. Exact
pending reuse and exact claimed recovery may advance only the paired authority
clock. A006 also validates the canonical transcript at reservation and
rederives it from realm plus signed origin-before context before row insertion.

The same contract reserves serial ownership for later attempts. A007 owns the
new unpublished `kirje-credential` workspace crate, its opaque locator,
root/store-only dependency entries, the store-private fake deletion hook,
store-owned lock permit and combined-method foundation, atomic grant-use/ready-
to-claimed transaction, exact/changed retry, expiry, response loss,
concurrency, and event 16 adjacent after event 7. A008 owns the concrete
low-level keyring delete, sole production call site in the combined store
method, deleted/no-entry `Ok(())` indistinguishability, claimed recovery across
backend and crash windows, dependency/no-re-export/compile-fail enforcement,
terminal retry, and exactly one later event 17. T204 migrates/removes legacy
runtime `SecretStore` paths, wires runtime/CLI only to the high-level store API,
and proves end-to-end integration without low-level access.

Restart validation rederives origin, locator, tombstone, grant count, event
cardinality/order/source/context/receipt/time, and privacy invariants. The
closed error precedence puts malformed input first, corruption second, exact or
changed grant recovery third, signed-context/clock/expiry next, then current
eligibility and target lifecycle, while existing store/backend codes remain
stable.

Result: `T202C3_A006_F012_READY_FOR_PACKET_REVIEW_NO_EXECUTION_PERMISSION`. The historical
packet gate authorized only returned production candidate `2241a946`, whose one
High and five Medium findings remain open. F001 failed spec review C0/H1/M2/L0;
the user approved F002's contract resolution, but its packet review failed with
engineering C0/H1/M2/L0 and spec C0/H0/M1/L0 while QA passed C0/H0/M0/L0. The
F008 review failed/refused with spec C0/H2/M2/L0, engineering/security
C0/H4/M1/L0, and QA C0/H4/M2/L0. The orchestrator approved the existing-boundary
F009 clarification under explicit delegated authority, recorded its failed
review, then recorded the F010/F011 mixed PASS/BLOCK reviews and approved F012's
exact phase-scope correction. No implementation
attempt started. Production, test, and fixture permissions are none; three
independent F012 packet reviews under the packet's substantive severity rule
must pass before standalone A12 can dispatch the exact scope. A007 and A008 remain
unpacketized, non-executable outlines and are not Ready.

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

The A006 candidate passed focused and full store validation at commit
`2241a946`, but passing tests do not override its failed reviews. Its exact
scope, hashes, RED/GREEN, review counts, and blockers are recorded in
`.ai-platform/evidence/T202C3/attempts/T202C3-A006.md`.

## Findings

### Critical

None.

### High

The first A006 review returned three High findings:

- H-A006-R1-001: current-binding text contradicted historical cleanup origin;
  revised authorization/FR-013 text makes cleanup the sole exception.
- H-A006-R1-002: exact pending and claimed recovery lacked a closed mutation
  set; the revision permits paired-clock-only advancement and requires tests.
- H-A006-R1-003: the deletion capability crossed store/runtime crates without an
  implementable owner.

Repeat review accepted the binding and clock repairs but returned one remaining
High, H-A006-R2-001: the public constructor plus pluggable public deletion
method still let runtime bypass authority. The proposed focused repair makes
the low-level crate unpublished and directly depended on only by store, removes
the trait/plugin surface, fixes `Result<(), MailError>` success semantics, and
makes the combined store apply method the sole call site. Final QA accepted this
High repair and returned the Medium below. The final three-pass review at
`3533054` accepted its AST-proof repair with zero finding.

H-A006-EXEC-001: cleanup checks origin/locator/tombstone before blocked/recovery
eligibility. Mixed invalid target plus blocked/recovery state therefore returns
`credential_cleanup_invalid` before `account_update_conflict` or
`owner_recovery_required`, leaking target validity. This production-review High
is open in the returned candidate. F006 preserves complete request-independent
global step-2 validation, which may already stream all private graphs. After
that pass, source and call-order proof must show that no request-directed pending/private
lookup or request-dependent private branch occurs before the closed public pair
classification. A matched
recovery store returns
`owner_recovery_required`; matched blocked store/account or an unrelated matched
proposed pair returns `account_update_conflict`. Same-origin proposed is step-2
corruption.
Only active store plus active/removed account proceeds to private step 7. The
matrix crosses absent store, absent account, pair mismatch, matched recovery,
matched blocked store/account, unrelated matched proposed, unrelated matched
blocked/recovery, active/active, and active/removed independently with wrong
origin, locator kind, locator digest, tombstone, lifecycle, and descriptor.
Challenge issuance orders pure preflight, lock/transaction, complete global
validation, checked effective time/time shape without pending access, public
classification, private validation, pending lookup, reuse/replacement, and
successor commit. It records no pending expiry before eligibility. Ordinary
claim/delete proof-expiry ordering remains separate and unchanged.

### Medium

M-001: The dependency policy gate fails on yanked `chacha20 0.10.1` through
`io-imap`. `Cargo.lock` is unchanged by T202C2, so this is not introduced by
the preserved diff. T111 owns removal before Security Alpha acceptance.

M-A006-R3-001: A literal sole-call scan can miss aliases, wildcards, re-exports,
macro/function-pointer indirection, and indirect bindings. A008 now requires a
dedicated parser-backed AST allowlist over every production store Rust file.
Only private module `credential_cleanup_delete_adapter` and method
`AuthorityStore::apply_credential_cleanup_delete` may contain fully qualified
low-level references; only that method may mention `DeleteOnlyLocator` and call
`kirje_credential::delete_only` exactly once. The proof composes with Cargo
direct-dependency, no-re-export, and runtime compile-fail checks. This contract
fix is closed by `T202C3_A006_PACKET_REVIEW_PASS`; the AST test remains future
A008 work and is not implemented by the A006 packet.

Five A006 execution-review Medium findings remain open in `2241a946`. F001 maps
them to correct-kind legacy full-flow and complete locator bounds/mutations;
invalid and valid expired-replacement rollback/freshness; complete immutable
projection, paired-clock, entropy, concurrency, restart, and cleanup response-
loss assertions; later update/remove/recreation non-rebinding and durable
restart corruption; and zero rows across grant uses plus every effect table,
including `effect_observations`, with source-level no-external-capability and
privacy proof.

F001 spec review added two packet Mediums. F006 requires same-context expired
pending plus later blocked to return `account_update_conflict` and later recovery
store to return `owner_recovery_required`, each without pending-
row lookup-dependent interaction: predecessor state/event and both clocks remain
unchanged, with zero entropy/successor/grant/nonce/cleanup. Active eligible pair
plus valid target uses `OldChallengeExpiredState` and
`OldChallengeExpiredEvent` to prove full transaction rollback. Different-context
invalid target has zero predecessor interaction; persisted corruption is step-2
`owner_recovery_required`. Generic
service/username/total lengths use one private numeric classifier with
numeric-only `#[cfg(test)]` unit tests, no public/test-support API, and no new
locator byte vectors in `authority.rs`; closed-form bytes stay only in
`authority_registry.rs`.

F006 closes the F005 review findings canonically. `data-model.md` and all
duplicates define phase-specific cleanup-challenge precedence, enforce the pre-
classification pending/private lookup and no-durable-expiry prohibition, and
give unrelated existing matched blocked and recovery-store pairs independent
rows returning `account_update_conflict` and `owner_recovery_required`,
respectively. Those rows and every other exact public row are independently
crossed with wrong origin, locator kind, locator digest, tombstone, lifecycle,
and descriptor. F006 removes same-origin proposed from reachable projection,
retains active-pair rollback and requires per-path six-table deltas plus complete
workspace handoff gates. Within the
exact A006 scope, one pure `authority.rs` manifest preflight rejects
`transition_id=None` as `authorization_malformed` before apply lock, file,
database, or entropy work, with zero I/O/mutation/entropy and no core change.
F012 leaves that substantive contract unchanged and defines exact
P12/A12/C12/I12 ancestry, path, status, and mode closure inside the trusted-local
trace, not as a product-security credential or malicious-local-admin defense.

### Low

None.

## Residual Risks

- T109 and the account-create checkpoint were explicitly accepted by the user
  on 2026-08-30. F012 clarification is approved under delegated authority but
  remains packet-review-only with no production, test, or fixture permission.
- Cross-platform support claims remain Draft until T119 produces platform
  evidence.
- Real-provider checks depend on dedicated credentials and may produce honest
  sanitized blockers.
- Future task file scopes require narrowing during just-in-time packetization.

## Gate Result

`T109_ACCEPTED_T202C3_A006_F012_READY_FOR_PACKET_REVIEW_NO_EXECUTION_PERMISSION`

The user approved `plan.md` and `tasks.md` on 2026-08-30. T109 review and fresh
validation are complete at `94f3495`; the user explicitly accepted the
checkpoint on 2026-08-30.
