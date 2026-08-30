# Contract: Pinned Authority Store V1

## Metadata

- Feature ID: `008-security-baseline`
- Status: Confirmed
- Contract name: `kirje.authority-store.v1`
- Updated: 2026-08-28
- Normative schema: `../data-model.md#authority-sqlite-v1`

## Scope And Ownership

The pinned authority store is the sole durable authority for owner trust,
bootstrap state, trust history, challenges, receipts, nonce consumption, store
and account registration, single-use grants, remote-effect claims, adapter-entry
invocations, first observations, and private authority events. A caller-selected
operation ledger is a projection and cannot create or restore authority.

`kirje-store` owns the SQLite schema and transactions. It consumes typed core
authorization values and typed, already-read local trust inputs. It does not
read or write the anchor, parse a second copy of the authorization transcript,
open a keyring, invoke an adapter, or accept a caller-selected production path.
Safe anchor I/O belongs to T203/T207; runtime orchestration belongs to T206.

## Stable Identities And Entropy

All authority UUID identities use UUIDv4 network-order BLOB16 in SQLite and
canonical lowercase hyphenated UUIDs at text boundaries. This includes
`JournalId`, `StoreId`, `AccountId`, `CredentialId`, `GrantId`, `ReceiptId`,
`EffectId`, `EffectClaimId`, `InvocationId`, `AuthoritySessionId`,
`TransitionId`, `CleanupId`, and `OperationId`. `ChallengeId` and `KeyId` are
SHA-256/BLOB32. `ObservationId` is SHA-256/BLOB32 of the exact observation
transcript.

T202A adds one minimal public-key prerequisite in `kirje-core`:

```rust
#[derive(Clone, Eq, PartialEq)]
pub struct OwnerPublicKey([u8; 32]);
```

`OwnerPublicKey` is constructed only through a fallible exact-32-byte boundary.
Construction calls `ed25519_dalek::VerifyingKey::from_bytes`, rejects every
parse failure, and rejects a parsed key when `VerifyingKey::is_weak()` reports
true. It exposes only a borrowed 32-byte public representation. It has no
`Default`, serde, private-key, key-generation, signature, or signing API, and no
unchecked constructor. Invalid or weak construction and equal bootstrap role
keys return stable non-retryable `authorization_malformed`. `BootstrapInput` and
`AnchorSnapshot` use this type and reject equal owner and recovery values before
entropy, file creation, or SQLite mutation. Its named fields assign the roles;
the database role trigger prevents an epoch from cross-referencing those stored
roles. No core Cargo change is required because `kirje-core` already owns the
pinned verification dependency.

Kirje-generated security randomness comes from the operating-system CSPRNG.
Production constructors contain the CSPRNG and expose no entropy argument. The
explicit non-default `test-support` feature exposes a deterministic entropy port
only to isolated tests. An ID or random value is a candidate until its owning
transaction commits; exact retries return the committed value and never generate
a replacement.

The authority database uses:

```text
application_id = 0x4B49524A = 1263096394  # ASCII KIRJ
user_version = 1
busy_timeout = 5000 milliseconds
```

An existing database is accepted only when `application_id` is `KIRJ`,
`user_version` is exactly 1, and the complete object inventory and canonical SQL
match Authority SQLite v1. A nonzero foreign application ID, a zero application
ID on a database containing any user object or row, a `KIRJ` database with a
zero/unsupported schema version or noncanonical inventory, and any version newer
than 1 fail closed. A zero-ID pristine database with no user objects is the only
existing file that may enter v1 initialization.

The T202A-only development fence at commit `f292132` is not a supported database
version. At the 2026-08-30 A003 governance freeze it had never entered `main`, a
remote branch, or a release tag, and no runtime, CLI, MCP, or protocol authority
entry point referenced it. The durable product rule is that this old fence was
never released or integrated. It can contain only bootstrap trust rows, not
registered accounts, credentials, remote effects, or mail operations. A
manually created developer database with that inventory fails closed and must
be removed together with its paired developer anchor before re-bootstrap.
Production code never auto-migrates, silently repairs, or deletes such a
database. Authority SQLite v1 begins at the canonical T202B fence.

## Authority Home

`AuthorityHome::production()` derives all three locations from the exact
`ProjectDirs::from("", "", "kirje")` namespace and has no arguments:

```text
anchor:     config_dir/owner-trust.toml
database:   data_local_dir/authority.sqlite3
apply_lock: data_local_dir/authority.apply.lock
```

`AuthorityStore::open_production` derives this home internally. It accepts an
`AuthorityOpenContext` containing only `AnchorPresence` and an already-derived
`JournalLocationDigest`; it accepts no path, environment variable, CLI/MCP
override, or generic home object. Under `test-support`, `open_isolated` requires
one complete `IsolatedAuthorityHome` with three distinct absolute paths under a
single test-owned root plus the deterministic entropy port. Partial home or
individual path injection is invalid.

The journal-location digest is SHA-256 of a canonical
`KIRJE-AUTHORITY-JOURNAL-LOCATION-V1\0` transcript over the safely opened parent
identity and final native component. Its tags and platform encodings are the
same as `PlatformLocationMaterial`: platform kind at `0x0001`; Unix device,
inode, and final-component bytes at `0x0010`-`0x0012`; Windows volume serial,
parent file index, and final-component UTF-16LE bytes at `0x0020`-`0x0022`.
T202 treats this value as a typed input and never derives it from display path
text.

## Anchor And Trust Bundle

The owner anchor is a strict, duplicate-free TOML document of at most 16 KiB.
It uses `deny_unknown_fields`, lowercase hexadecimal for every 32-byte value,
canonical lowercase UUID text for `journal_id`, decimal positive u64 for
`minimum_epoch`, and this closed state:

```text
normal
```

The anchor never stores `recovery_required`; that status is derived fail closed.
Its exact typed representation and fields are:

```rust
struct AnchorSnapshot {
    version: AuthorityAnchorVersion, // exactly 1
    realm_id: OwnerRealmId,
    journal_id: JournalId,
    journal_location_sha256: JournalLocationDigest,
    minimum_epoch: NonZeroU64,
    owner_key_id: KeyId,
    owner_public_key: OwnerPublicKey,
    recovery_key_id: KeyId,
    recovery_public_key: OwnerPublicKey,
    trust_bundle_sha256: Sha256Digest,
    state: AuthorityAnchorState, // exactly normal
}
```

`KIRJE-TRUST-BUNDLE-V1\0` uses the common transcript container and exactly these
strictly ascending tags:

| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | realm | BLOB32 |
| `0x0002` | journal | UUID16 |
| `0x0003` | epoch | positive u64be |
| `0x0004` | owner key ID | BLOB32 |
| `0x0005` | owner public key | BLOB32 |
| `0x0006` | recovery key ID | BLOB32 |
| `0x0007` | recovery public key | BLOB32 |

The bundle digest is SHA-256 of the exact transcript. Key IDs retain the
role-separated `KIRJE-OWNER-KEY-V1` hash from the authorization contract. The
journal-location digest is deliberately outside the trust bundle and is pinned
separately in both anchor and `authority_meta`.

`minimum_epoch` is an anti-rollback floor. An anchor refuses an active or staged
authority epoch below that value. A normal ready anchor equals the active epoch;
a rotation/recovery anchor equals exactly one signed staged successor.

## Bootstrap Protocol

Bootstrap runs under the fixed apply lock and uses a database-first two-phase
protocol:

```rust
struct BootstrapInput {
    journal_location_sha256: JournalLocationDigest,
    owner_public_key: OwnerPublicKey,
    recovery_public_key: OwnerPublicKey,
    observed_at_unix_ms: i64,
}

struct BootstrapSnapshot {
    realm_id: OwnerRealmId,
    journal_id: JournalId,
    minimum_epoch: NonZeroU64,
    owner_key_id: KeyId,
    owner_public_key: OwnerPublicKey,
    recovery_key_id: KeyId,
    recovery_public_key: OwnerPublicKey,
    trust_bundle_sha256: Sha256Digest,
    journal_location_sha256: JournalLocationDigest,
    anchor: AnchorSnapshot,
}
```

After the pristine-database and application-ID preflight,
`prepare_bootstrap(input)` owns exactly one transaction. It acquires the fixed
apply lock, executes one `BEGIN IMMEDIATE`, executes `schema_v1.sql` as a pure
schema body with no `BEGIN`, `COMMIT`, or `PRAGMA`, generates realm/journal
identities, inserts the two distinct active keys, exact initial active epoch,
singleton pending meta row, and bounded bootstrap event, sets
`application_id = 1263096394` and `user_version = 1`, and then executes one
`COMMIT`. Any SQL error, injected crash, or explicit rollback before that commit
leaves zero user-created tables, indexes, triggers, views, authority rows,
application ID, and user version. There is no inner transaction that can commit
schema objects early.

Exact retry returns the committed `BootstrapSnapshot` after matching both typed
public keys and the location digest; changed input fails with
`owner_recovery_required`. Equal owner/recovery keys fail with
`authorization_malformed` before the transaction.

The caller then writes `snapshot.anchor` through create-only safe anchor I/O.
`confirm_anchor(anchor, observed_at)` performs an exact typed match and changes
only `pending_anchor -> ready` in one transaction. It never creates, replaces,
or repairs the anchor file. A crash before anchor creation is resumable from the
committed public database values. A create-only collision is parsed and compared;
it is never overwritten.

The complete open/bootstrap matrix is:

| Database state | Anchor input | Result |
|---|---|---|
| absent/pristine | missing | `unconfigured`; `prepare_bootstrap` is allowed |
| absent/pristine | present | `recovery_required`; no regeneration |
| security rows without singleton meta | any | `recovery_required` |
| `pending_anchor` | missing | `bootstrap_pending`; return committed snapshot |
| `pending_anchor` | exact initial anchor | `confirmation_required`; `confirm_anchor` is allowed |
| `pending_anchor` | any mismatch | `recovery_required` |
| `ready`, no staged row | exact active anchor and location | `ready` |
| any singleton state | any staged epoch row or any anchor naming a staged successor | `recovery_required` in T202A |
| `ready` | missing, malformed, lower epoch, unknown key, wrong location, or other mismatch | `recovery_required` |

Malformed/unreadable anchor input is mapped to `recovery_required` by the safe
I/O owner before normal store use. Anchor-present/database-missing and every
third-state mismatch are never repaired by silent bootstrap. T202A cannot prove
that a staged row is linked to a valid owner/recovery receipt and required POP,
so it exposes neither `staged_finalize_required` nor any staged mutation path.

T202E extends the classifier only after T202B's read-only core authorization
snapshot exists. It must reconstruct and strictly verify the exact transition
receipt plus every role-required `KIRJE-TRUST-KEY-POP-V1` signature and then
compare the signed successor to the anchor. Only that fully verified state may
return `staged_finalize_required`; every unverified, unsigned, incomplete, or
mismatched staged state remains `recovery_required`.

## Clock Contract

Every authority transaction receiving `observed_at_unix_ms` reads
`authority_meta.last_observed_at` under `BEGIN IMMEDIATE`. A value more than
30,000 milliseconds below the high-water mark fails with
`clock_rollback_detected`. An accepted transaction, including pending challenge
reuse and exact proof replay, writes
`last_observed_at = max(last_observed_at, observed_at)` and synchronizes
`authority_meta.updated_at` to that same effective high-water; subtraction and
expiry math are checked for overflow. These two meta columns are one clock pair.
Idempotent recovery may therefore advance only that pair while leaving the
recovered challenge/receipt timestamps and event history unchanged.

After the rollback check, every authority freshness decision computes
`effective_time = max(last_observed_at, observed_at)`. Expiry is inclusive only
when `effective_time <= expires_at`. At most 30,000 milliseconds of raw negative
skew against `issued_at` is accepted, but the effective time controls issuance,
expiry, verified/occurred timestamps, receipt state, and persisted high-water.
This tolerance never increases `expires_at`, `invoke_before`, or any TTL and
never revives authority after high-water crossed expiry.

## Canonical Durable Transcripts

Every transcript uses the authorization contract container: domain bytes ending
in NUL, field count u16be, then strictly ascending `tag:u16be`, `length:u32be`,
and exact value bytes. Fixed-width integers are big-endian. No JSON/TOML
serialization participates in a digest.

### Challenge Context

`context_sha256` is SHA-256 of `KIRJE-AUTHORIZATION-CONTEXT-V1\0` with action,
target kind, target bytes, optional store/account UUIDs, manifest digest,
optional binding/policy digests, key ID, trust epoch, and bundle digest at tags
`0x0001` through `0x000b`. It deliberately omits grant, nonce, issuance, and
expiry. The pending partial unique index permits one pending challenge for this
exact current context.

### Proof

`KIRJE-AUTHORIZATION-PROOF-V1\0`:

| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | challenge | BLOB32 |
| `0x0002` | key | BLOB32 |
| `0x0003` | signing-payload SHA-256 | BLOB32 |
| `0x0004` | signature | BLOB64 |

`proof_sha256` is SHA-256 of this exact transcript reconstructed from the strict
bounded proof object, not a hash of JSON bytes.

### Authorization Receipt

`KIRJE-AUTHORIZATION-RECEIPT-V1\0` uses tags `0x0001` through `0x000b` in this
order: receipt UUID16, challenge BLOB32, grant UUID16, proof SHA-256, key BLOB32,
manifest SHA-256, signing-payload SHA-256, trust epoch u64be, bundle BLOB32,
verified-at i64be, expires-at i64be. `receipt_sha256` hashes the exact transcript.

### Grant Use

`KIRJE-GRANT-USE-V1\0` uses tags `0x0001` through `0x0007`: grant UUID16,
receipt UUID16, action u16be, target-kind u16be, canonical target bytes,
manifest SHA-256, and use-time i64be. `use_sha256` hashes the exact transcript.

### Effect Claim

`KIRJE-EFFECT-CLAIM-V1\0` uses tags `0x0001` through `0x0010`: claim UUID16,
effect UUID16, grant UUID16, operation UUID16, store UUID16, account UUID16,
config generation u64be, account generation u64be, manifest SHA-256, binding
SHA-256, policy SHA-256, trust epoch u64be, bundle BLOB32, key BLOB32,
claimed-at i64be, and invoke-before i64be. `claim_sha256` hashes the exact
transcript.

### Invocation Start

`KIRJE-INVOCATION-START-V1\0` uses tags `0x0001` through `0x0005`: invocation
UUID16, effect UUID16, claim UUID16, authority session UUID16, and started-at
i64be. `start_sha256` hashes the exact transcript.

### Effect Observation

`KIRJE-EFFECT-OBSERVATION-V1\0` uses tags `0x0001` through `0x0007`: effect
UUID16, claim UUID16, invocation UUID16, certainty u8, result SHA-256, source u8,
and observed-at i64be. `ObservationId` and the observation digest are SHA-256 of
the exact transcript. Result bytes are stored separately, are 1..16 MiB, and
must hash-match before insert and after read.

Closed observation codes are:

```text
certainty:u8  succeeded=0x01 known_no_effect=0x02 ambiguous=0x03
source:u8     adapter_result=0x01 pre_network_failure=0x02 invocation_recovery=0x03
```

`pre_network_failure` is valid only with `known_no_effect`;
`invocation_recovery` is valid only with `ambiguous`.

### Account Transition And Trust POP

`KIRJE-ACCOUNT-TRANSITION-V1\0` uses transition, grant, store, account, kind,
before-config digest, after-config digest, expected generation, next generation,
and prepared-at at tags `0x0001` through `0x000a`. Its digest is the exact-retry
identity.

`KIRJE-TRUST-KEY-POP-V1\0` uses realm, journal, old epoch, next epoch, role u8,
permission mask u32be, proposed key ID, proposed public key, next bundle digest,
and transition receipt UUID16 at tags `0x0001` through `0x000a`. A proposed key
proves possession with `verify_strict` over this transcript. Owner role requires
mask `0x00000007`; recovery role requires `0x00000008`.

### Authority Event Detail

Authority event detail uses `KIRJE-AUTHORITY-EVENT-DETAIL-V1\0` and tags
`0x0001` through `0x000b` in this exact order: event code u16, entity-kind u16,
entity ID bytes, source u8, related-kind u16 or zero, related-ID bytes or zero,
prior-state u16 or zero, next-state u16 or zero, context digest BLOB32 or zero,
receipt UUID16 or zero, occurred-at i64.
The transcript is 1..64 KiB, its digest is checked on every read, and it contains
no proof, signature, nonce, signing payload, manifest, public key, location
material, credential, mailbox content, endpoint, or provider response.

Entity, event, source, transition-kind, and state codes are closed by the schema
and typed Rust codecs. Unrecognized values fail the entire row read. Supported paths
append events and never update or delete them.

Authority event state codes are never inferred from enum order:

```text
0x0000 none
0x0101 bootstrap_pending_anchor  0x0102 bootstrap_ready
0x0201 key_staged                0x0202 key_active
0x0203 key_retired               0x0204 key_revoked
0x0301 epoch_staged              0x0302 epoch_active
0x0303 epoch_retired
0x0401 store_active              0x0402 store_blocked
0x0403 store_removed             0x0404 store_recovery_required
0x0501 account_proposed          0x0502 account_active
0x0503 account_blocked           0x0504 account_removed
0x0601 transition_prepared       0x0602 transition_config_committed
0x0603 transition_finalized      0x0604 transition_aborted
0x0605 transition_recovery_required
0x0701 cleanup_provisional       0x0702 cleanup_ready
0x0703 cleanup_claimed           0x0704 cleanup_deleted
0x0801 challenge_pending         0x0802 challenge_authorized
0x0803 challenge_expired         0x0804 challenge_invalidated
0x0901 grant_unclaimed           0x0902 grant_used
0x0a01 effect_registered         0x0a02 effect_claimed
0x0a03 effect_invoked            0x0a04 effect_observed
```

## Core Projection Prerequisite

T202B adds a read-only core projection rather than a store-local parser:

```rust
struct AuthorizationPayloadSnapshot<'a> {
    owner_realm: OwnerRealmId,
    action: SensitiveAction,
    target_kind: TargetKind,
    target_bytes: &'a [u8],
    target_display: &'a TargetDisplay,
    store_id: Option<StoreId>,
    account_id: Option<AccountId>,
    manifest_sha256: Sha256Digest,
    binding_sha256: Option<Sha256Digest>,
    policy_sha256: Option<Sha256Digest>,
    bundle_sha256: Sha256Digest,
    key_id: KeyId,
    trust_epoch: NonZeroU64,
    grant_id: GrantId,
    nonce: &'a [u8; 32],
    issued_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    effect: Option<AuthorizationEffectSnapshot>,
    canonical_bytes: &'a [u8],
}
```

All snapshot fields are private and available only through borrowed/copying
accessors. `AuthorizationEffectSnapshot` exposes only effect ID, ordinal, and
closed effect kind. `TargetDisplay` has no public constructor and exposes only
its closed display string: canonical lowercase UUID, unsigned trust epoch with
no leading zero, or the literals `policy`/`assurance`. `AuthorizationPayload`
stores canonical target bytes/display once and exposes
`snapshot() -> AuthorizationPayloadSnapshot<'_>`; canonical payload and nonce
are borrowed, not cloned.

`AuthorizationContext` names the selected field `signer_key_id`; the action
policy, not the request, selects owner versus recovery. `TargetKind` and
`EffectKind` expose stable numeric code accessors for store-owned durable
transcripts. `ActionManifest` exposes a borrowed sealed payload accessor so the
store validates the exact same action-specific object that produced its digest.
Core also owns the validated proof constructor/accessors and canonical
proof-transcript/digest codec. The store never duplicates
`AuthorizationPayload::parse`, proof tags, action policy, manifest payload
interpretation, or target formatting.

## SQLite Relationship Enforcement

SQLite, not application comparison alone, binds every duplicated durable
context. Parent rows declare exact composite `UNIQUE` keys and children use
composite foreign keys for challenge/receipt, challenge/nonce/receipt,
grant/receipt/action/target/manifest, challenge-effect/remote-effect, the full
remote-effect/effect-claim context, effect/claim/invocation, and
effect/claim/invocation/observation. Store location/config and
account/store/generation/credential/binding copies are likewise one composite
relationship. A child assembled from individually valid columns belonging to
different parents is rejected by SQLite. All of these foreign keys retain
`ON DELETE RESTRICT`; supported code cannot delete history to repair a mismatch.

## Transaction APIs

Every mutation API acquires the fixed apply lock, opens the existing database
without CREATE, performs nonmutating identity/version preflight, enables and
verifies WAL/FULL only for KIRJ v1, then starts a fresh `BEGIN IMMEDIATE` and
repeats classification plus all SQL/Rust row validation. It performs every
current-context comparison, appends the exact event when the contract defines a
state transition, and commits before returning a durable projection. Clock-pair-
only idempotent recovery is the explicit no-event case. Caller booleans such as
`is_current` or `is_authorized` are not accepted.

### Challenges, Proofs, And Receipts

`CreateChallengeRequest` carries exactly one sealed `ActionManifest`, observed
time, and requested expiry. It contains no caller-duplicated store/account,
policy, role, key, epoch, bundle, target, or effect override. The store reads the
manifest's borrowed typed payload and current authority rows, generates only the
grant UUID and nonce, builds the core `AuthorizationPayload`, persists its
snapshot plus exact manifest/signing bytes, and returns the bounded challenge
projection.

T202B challenge creation supports only `store_enroll`, `owner_rotate`,
`recovery_rotate`, and `owner_recover`. Store enrollment requires the exact
manifest's `unregistered` expectation and absence of that store ID. Trust
challenges require exact current journal/epoch/bundle and affected old key data,
checked successor arithmetic, distinct validated proposed keys, and the signer
role selected from action policy; they do not stage a rotation. Constructible
registry-backed account, credential, cleanup, send, and mailbox actions fail
`authorization_context_stale` with zero entropy, rows, events, or clock change
until T202C expands challenge issuance and inserts the covered challenge-effect
row for remote actions. `ambiguous_close` fails the same way until T202D can
validate the exact effect/observation history. Policy and assurance are rejected
by the core manifest boundary as `unsupported_capability`; no such sealed
manifest can reach the store. T202B persists no challenge-effect row, while its
core projection still exposes the optional effect for T202C.

Challenge creation uses effective authority time and first marks the matching
pending row expired when `effective_time > expires_at`. When the same
`context_sha256` remains pending, it returns that committed
challenge unchanged; it does not replace grant, nonce, issuance, expiry, or
effect identity, consumes no entropy, and may advance only the authority meta
clock pair. Once the old row is authorized or expired, a fresh request may
commit a new challenge with a new 16-byte UUIDv4 grant plus 32-byte nonce. T202E
adds invalidated-state replacement. The planner, not this transaction, owns
remote effect-ID generation.

Every committed challenge stores the exact sequence of its `challenge_created`
event in `created_event_sequence`. The value is linked inside the same
transaction after the event append and before commit; `NULL` is only an
uncommitted intermediate state. Restart validation streams the
`authorization_challenges_context_created_sequence` index and requires each
same-context predecessor to have an exact `challenge_authorized` or
`challenge_expired` terminal event whose sequence is lower than the successor's
created-event sequence. This makes same-context lifecycle intervals
non-overlapping even when multiple events share one effective timestamp.

`VerifyProofRequest` carries a bounded `AuthorizationProof` and observed time.
The transaction compares exact persisted bytes, active role/mask/key/epoch/bundle,
anchor state, nonce, challenge state, and time before `verify_strict`, receipt,
nonce-use, and challenge-state writes.

Proof replay is exact:

| Existing durable state | Submitted proof | Result |
|---|---|---|
| no receipt, pending/current/unexpired | valid first proof | insert one immutable receipt and nonce use |
| no receipt, pending but expired | any proof | mark expired; `authorization_expired` |
| no receipt, already expired | any bounded proof naming that challenge | same `authorization_expired`; clock-pair-only recovery |
| no receipt, invalidated | any proof | T202E: `authorization_invalidated` |
| receipt exists | exact canonical proof | return the same receipt ID/digest with freshly derived state; no new authority |
| receipt exists | changed canonical proof | `authorization_replayed` |
| nonce/authorized marker exists without matching receipt | any | corruption -> `owner_recovery_required` |

The proof transaction checks for an existing receipt before current
key/epoch/bundle and expiry. Exact historical replay returns the same immutable
receipt after expiry and consumes no entropy; it cannot create a grant, refresh
receipt timestamps, append an event, or authorize a new boundary. It may advance
only the authority meta clock pair so receipt state cannot regress. A changed
canonical proof returns `authorization_replayed`. T202E adds and tests replay
after finalized rotation/invalidation and activates the invalidated-without-
receipt branch.

First valid proof consumes exactly 16 entropy bytes for one UUIDv4 receipt after
all deterministic checks and signature verification. It inserts the immutable
receipt and nonce use, changes pending to authorized, updates clock, appends the
authorization event, and commits atomically. Expired pending proof commits the
expired state, clock, and event, then returns `authorization_expired` after
commit. A restart, concurrent loser, or response-loss retry that finds the same
challenge already expired returns the same error after the rollback check,
consumes no entropy, appends no event, changes no challenge row, and may advance
only the authority meta clock pair. Invalid proof, changed replay, and every
failed deterministic check consume no entropy and write nothing. T202B treats
any persisted invalidated
challenge as corruption and returns `owner_recovery_required`; T202E owns the
first valid invalidation writer and the `authorization_invalidated` path.

T202B validation keeps the exact two-key/one-epoch ready trust root; admits only
`pending`, `authorized`, and `expired` challenge states; and keeps
`registered_stores`, `registered_accounts`, `challenge_effects`, `grant_uses`,
`account_transitions`, `credential_cleanup`, `remote_effects`, `effect_claims`,
`effect_invocations`, and `effect_observations` empty. It replaces T202A's
blanket later-row/event count with bounded length/type preflight, core
reparse/recompute of every manifest and payload, per-challenge context/state/
effect validation, exact receipt/nonce causal graphs, and streaming event
validation. There is no historical-row cardinality cap: validation runs in one
consistent read transaction, streams rows in deterministic order, never
collects history into a proportional `Vec`/map, and uses O(1) additional memory
beyond one schema-bounded row/transcript. Bootstrap events remain exact sequence
1 and 2.
Challenge events use the numeric map and detail shapes in `data-model.md`;
sequences are contiguous, `sqlite_sequence = COUNT(*) = MAX(sequence)`, every
created/authorized/expired state has its exact event pair, and pending reuse or
exact replay and already-expired recovery have no event even when their
transaction advances the authority meta clock pair.

### Registry And Account Transitions

T202C expands `create_challenge` for registry-backed account, credential,
cleanup, send, and mailbox manifests. It validates the exact registered store,
account, binding, config and policy context and persists one `challenge_effects`
row for every remote action before implementing the registry/apply transactions
below. T202D expands issuance only for `ambiguous_close`, after effect and
observation history exists to validate its sealed payload.

`EnrollStoreRequest` contains one exact `GrantUseRequest`, store UUID, bounded
private location material and digest, config generation/digest, and observed
time. It inserts/rechecks the grant use and store registration atomically. Exact
retry returns the same registration; either-direction store/location mismatch,
changed config context, or changed receipt fails.

`PrepareAccountTransitionRequest` contains an exact grant-use request,
transition UUID, store/account identities, closed transition kind, complete
before/after config digests, expected/next generations, proposed registry values,
and observed time. `next_generation = expected_generation + 1`. Exact retry
compares every request column and transcript digest. Prepare blocks the affected
account before config/keyring access.

`mark_config_committed`, `finalize_account_transition`, `abort_transition`, and
`mark_transition_recovery_required` accept the transition ID, exact expected
state, actual config digest/generation, and observed time. Before digest permits
retry/authorized abort, after digest permits finalize, and every third digest
enters `recovery_required`. Finalization clears the active transition; remove
retains historical account and credential identities.

### Grant Use, Claim, Invocation, And Observation

```rust
struct GrantUseRequest { grant_id, receipt_id, action, target_kind,
    target_bytes, manifest_sha256, used_at_unix_ms }

struct EffectClaimRequest { grant_use, effect_id, operation_id, store_id,
    store_location_sha256, account_id, config_generation, config_sha256,
    account_generation, credential_id, manifest_sha256, binding_sha256, policy_sha256,
    trust_epoch, bundle_sha256, key_id, claimed_at_unix_ms }

struct BeginInvocationRequest { effect_id, claim_id, authority_session_id,
    started_at_unix_ms }

struct RecordObservationRequest { effect_id, claim_id, invocation_id,
    certainty, result_bytes, source, observed_at_unix_ms }
```

First grant use requires a current, unexpired receipt and exact challenge target,
action, manifest, anchor/meta/key/epoch/bundle, and action-specific registry
context. Exact committed recovery returns the same use even when that context is
later expired or invalidated; changed retry returns `grant_already_used`.
When a first-use request arrives after expiry, the same transaction marks an
otherwise pending/authorized-unclaimed challenge expired and returns
`authorization_expired`; clock tolerance never extends the deadline.

First effect claim performs all comparisons in the same transaction: receipt and
grant, expiry, anchor/meta readiness, active role/key/epoch/bundle, registered
store state/location/config generation/config digest, account state/generation/
credential/binding, policy, manifest, effect, ordinal, and operation UUID. It
sets `invoke_before` exactly to the receipt expiry. Exact committed claim recovery
returns the same claim after later context change; a changed retry returns
`effect_already_claimed`.

First invocation requires a current claim context and
`started_at <= invoke_before`. It generates invocation/session-bound start bytes
and returns `InvocationPermit` only to the process that inserted the row.
`InvocationPermit` is non-`Clone`, non-`Serialize`, has no byte export, and is
consumed by one adapter-entry call. Exact recovery of an existing invocation
returns its projection and no permit, regardless of later expiry; changed retry
returns `effect_already_invoked`.

An observation requires the matching in-memory permit or the fixed-lock crash
recovery path. It does not grant a new remote boundary, so an invoked adapter
result remains recordable after receipt expiry. Exact transcript/result replay
returns the same observation; changed result, certainty, source, or time fails
with `authority_projection_conflict`. After a crashed invocation releases the
fixed apply lock, recovery inserts one `ambiguous/invocation_recovery`
observation and never invokes again.

## Rotation And Recovery

Epoch rows have these exact shapes:

| Shape | Required fields | Forbidden fields |
|---|---|---|
| initial active | epoch 1, both active keys, activated time | predecessor, transition receipt, kind, POPs, retired time |
| staged owner rotation | predecessor=active, owner POP, owner receipt, next epoch | recovery POP, activated/retired time |
| staged recovery-key rotation | predecessor=active, recovery POP, owner receipt, next epoch | owner POP, activated/retired time |
| staged owner recovery | predecessor=active, both POPs, recovery-key receipt, next epoch | activated/retired time |
| active successor | retained transition fields and POPs, activated time | retired time |
| retired epoch | retained historical fields, activated and retired times | none of the required historical fields may be cleared |

There is exactly one active epoch, at most one staged epoch, and a staged epoch
is the unique successor of the active epoch with `next = active + 1`. Proposed
key IDs, roles, permission masks, public keys, and POP signatures are rechecked
before stage and finalize. SQLite additionally requires distinct public keys,
distinct owner/recovery key IDs, the initial epoch to be exact active epoch 1
with activation time and no predecessor/transition/POP, every successor to name
the exact checked predecessor plus one, and each referenced key to have its
owner/recovery role and exact permission mask. Malformed or weak public keys are
unrepresentable through the core `OwnerPublicKey` boundary.

`stage_rotation`, `stage_recovery`, and `finalize_staged` are distinct APIs.
Normal owner/recovery-key rotation uses a current owner receipt plus the proposed
role-key POP. Owner recovery uses a current pinned recovery-key receipt plus POPs
from both replacement keys. The independent OS-administrator boundary restores
or retires the complete anchor/journal pair out of band; it is not a signature
bypass API in `kirje-store`.

The caller writes a create-only/replacement anchor for the signed staged
successor through safe local I/O. T202E, not T202A, may classify an exact anchor
match as `staged_finalize_required`, and only after reconstructing T202B's core
snapshot and strictly verifying the transition receipt and every required POP.
Any other active/staged/anchor combination is `recovery_required`. Finalization
atomically activates the successor, retires
the previous epoch and replaced key(s), updates meta, invalidates pending and
authorized-but-unclaimed old-epoch challenges, and appends events. Historical
keys, receipts, uses, claims, invocations, and observations remain immutable.

Owner recovery additionally moves every nonremoved store to
`recovery_required`, blocks every nonremoved account, clears no history, and
requires signed store re-enrollment, account-binding authorization, and
credential re-entry before authentication or remote work.

## Public Projection And Audit

Target display is closed and derived only by core: UUID targets use canonical
lowercase UUID text, trust epochs use unsigned decimal with no leading zero, and
zero-length policy/assurance targets display the exact literals `policy` and
`assurance`.

Receipt state derives with priority:

```text
Used > Claimed > Invalidated > Expired > Unclaimed
```

`Used` means a grant use exists with no remote claim, or a remote effect has an
immutable observation. `Claimed` means a remote effect claim/invocation exists
without an observation. `Invalidated` means rotation/recovery invalidated an
otherwise unconsumed receipt. `Expired` means no higher-priority durable use
exists and `now > expires_at`. These predicates make claim-without-observation
distinct while observed claim state resolves to `Used`. An exact committed
use/claim remains historical under this projection and is never fresh authority.

Normal receipt projections include only IDs/displays, key fingerprint, epoch,
manifest and receipt digests, timestamps, and derived state. They omit realm,
public keys, signatures, proof, nonce, manifest/signing bytes, private location,
credential and event detail.

Audit is private operator-only keyset pagination over
`authority_events.sequence`: `after_sequence` is optional, `limit` is 1..100,
results are strictly ascending, and `next_after_sequence` is the last returned
sequence. Normal audit projection returns event/entity/source names, bounded
public entity display, timestamps, and detail digest only. Private event detail
is available solely to local re-verification and is never returned by MCP.

## Exact Failure And Corruption Rules

Constraint, digest, foreign-key, transcript, enum, row-shape, active-index, or
cross-row mismatch on read fails the whole authority operation. Supported code
never repairs, deletes, or rewrites a conflicting row. Database/anchor mismatch
uses `owner_recovery_required`; exact-retry mismatches use the stable replay/
already-used/already-claimed/already-invoked codes from the authorization
contract; unsupported newer schema uses `unsupported_capability` with no private
path or row bytes in output.
