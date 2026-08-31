# Contract: Pinned Authority Store V1

## Metadata

- Feature ID: `008-security-baseline`
- Status: Confirmed
- Contract name: `kirje.authority-store.v1`
- Updated: 2026-08-31
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

Authority SQLite v1 is only the complete canonical object inventory in the
normative schema. No earlier developer-only inventory is a supported database
version. A database carrying the `KIRJ` application ID and version 1 but missing
the immutable registry-version parents or any other canonical object fails
closed and must be removed with its paired developer anchor before re-bootstrap.
No such shape entered `main`, a remote branch, or a release, and no runtime,
CLI, MCP, or protocol authority entry point used it. Production code never
auto-migrates, silently repairs, or deletes a noncanonical authority database.

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

T202C1 fixes this boundary more narrowly. `GrantUseRequest` carries the six
immutable identity fields through manifest SHA-256 and contains no caller time.
`EnrollStoreRequest` adds the store UUID, exact bounded canonical
`PlatformLocationMaterial` transcript, location digest, config generation and
digest, plus a raw observed time used only by the authority clock. Location
SHA-256 must equal both the canonical material and the sealed store-enroll
manifest's `ConfigCas.location_sha256`; store ID, generation, and config digest
must equal that manifest. Request and projection implement neither `Debug`,
`Display`, serialization, nor schema generation. Normal projection contains
only store ID, closed store state, config generation, and created/updated
timestamps; it omits location material/digest, config digest, grant/receipt IDs,
manifest, proof, nonce, key, realm, and event detail.

The store derives durable `used_at` from checked effective authority time on the
first successful use. Raw observed time is never persisted in a grant, store,
or event and is not idempotency identity. The exact enrollment-intent digest is
SHA-256 of `KIRJE-STORE-ENROLLMENT-INTENT-V1\0` with tags `0x0001` through
`0x000a`: grant UUID16, receipt UUID16, action u16be, target-kind u16be,
canonical target bytes, manifest SHA-256, store UUID16, location SHA-256,
config generation u64be, and config SHA-256. Canonical material bytes are
represented by their checked location digest. This intent can be reconstructed
from the bounded request plus immutable challenge/receipt/manifest without a
grant or store row; observed time is deliberately absent.

The first no-existing-use attempt checks immutable receipt/challenge and exact
enrollment-intent identity before current authority context. If effective time
is past immutable receipt expiry, it changes the authorized, unclaimed
challenge to expired, advances the paired clock, appends one
`challenge_expired` event, commits, and returns `authorization_expired`; it
inserts no grant or store row. That event is entity kind 8/code 5/source 1,
relates to kind 9 and the receipt UUID, transitions `0x0802 -> 0x0803`, uses the
enrollment-intent digest as context, contains the same receipt UUID, and occurs
at effective authority time. Exact no-use response-loss retry recomputes that
intent, returns the same error with no second event, and may advance only the
paired clock. Changed intent writes nothing. Exact proof replay still returns
the immutable receipt projection in `Expired` state.

Successful store enrollment uses the same effective time for `grant_uses.used_at`,
store `created_at`/`updated_at`, and both contiguous causal events.
`grant_used` is entity kind 10/code 7/source 1, relates to kind 9 and the receipt
UUID, transitions `0x0901 -> 0x0902`, uses `use_sha256` as context, and contains
the receipt UUID. `store_enrolled` is entity kind 4/code 8/source 4, relates to
kind 10 and the grant UUID, transitions `0x0000 -> 0x0401`, uses the same
`use_sha256`, and contains the same receipt UUID. Exact committed retry appends
neither event, retains the original derived use/store time, and may change only
the paired clock high-water for a later raw observation.

Grant-row replay is checked before fresh expiry/current-context authority. An
exact durable row recovers the same enrollment after later expiry; changed
six-field identity returns `grant_already_used`. T202E must preserve this order
after valid invalidation exists. Without a durable grant, store/location aliases
return `config_store_identity_conflict`; request fields disagreeing with sealed
manifest or typed material return `authorization_context_stale`. Enrollment
uses no entropy.

Historical challenge validation is purely intrinsic. No pending, authorized,
expired, used, same-context sibling, or different-context sibling is rejected
because the current registry contains its store or location. Store/location
absence belongs only to fresh store-enroll challenge issuance and a current
no-grant first use; issuance checks both target store ID and sealed location
digest. A successful grant links through its exact receipt to one enrolled store
row. In the T202C1 stage, where transition tables are empty, current store config
must still equal the initial enrollment manifest; T202C2 replaces only that
stage-specific current-config check with the exact transition chain and never
rewrites enrollment history.

Receipt projection applies fixed priority: a receipt with a durable grant use is
`Used` before expiry. Exact proof replay after enrollment returns the same
receipt as `Used` even later than expiry, grants no new authority, and changes
only the permitted paired clock high-water.

Same-context lifecycle validation has two distinct sequences. The replacement
terminal that closes a pending interval is the authorization event when a
receipt exists, otherwise the pending-to-expired event. Every successor's
created event must follow that replacement terminal. A later
authorized-to-expired event proves final state only; it must follow
authorization but may follow a successor already validly created. Thus
`authorize A -> create B -> expire A` is legal, including equal effective
timestamps, while missing, duplicate, swapped, or pre-authorization final-expiry
events are corruption.

Error precedence is closed. Pure request bounds/type/material validation runs
first. Transactional schema/anchor/history corruption is
`owner_recovery_required`. A present grant row is compared next: changed bounded
identity is `grant_already_used`; exact grant with missing/mismatched atomic
store/event graph is corruption; exact graph then passes the checked clock and
recovers. With no grant, exact receipt/challenge/enrollment intent is checked;
mismatch is `authorization_context_stale`. Checked effective time and expiry
follow. Expiry commits before fresh current-authority and occupancy checks, so
expired authority cannot probe aliases. Current mismatch is
`authorization_context_stale`; only a current first use reaches
`config_store_identity_conflict`. Two valid distinct receipts racing the same
store/location are not exact retries: the loser returns that identity conflict,
inserts no grant/event, and never rewrites `enrolled_receipt_id`.

Restart validation admits only these T202C1 grant/store rows and events beyond
T202B and rejects every account, transition, cleanup, effect, invocation,
observation, rotation, or recovery row. It streams bounded rows with O(1)
additional history memory and indexed primary/unique/event lookups.

### Immutable Registry Version Parents

`registered_stores` and `registered_accounts` are current mutable projections.
They are not foreign-key parents for historical remote-effect snapshots.
Authority SQLite v1 has three application-immutable registries:

```text
registered_credentials
  credential_id -> exact account/store + creating transition

registered_store_versions
  store/location + config generation/digest
  -> exactly one enrollment receipt or committed account transition

registered_account_versions
  account/store + account generation/credential/binding
  -> exact credential identity + committed account transition
```

Store enrollment atomically inserts the initial `registered_store_versions` row
with the same receipt, config pair, and effective timestamp as the current store
row. Exact enrollment recovery validates and returns that immutable initial
version even after the current store projection advances; T202C1S proves the
initial state and T202C2 first proves legal-successor recovery. Each later
config-committed transition inserts one new store version. A transition with an
after account snapshot also inserts one account version. Create uses account
generation one; account update, credential set, and credential delete advance
it exactly once. Account removal does not invent an after account version. A new
credential identity is reserved in `registered_credentials` during prepare and
remains reserved after abort.

Transition origin is an exact composite relationship, not a UUID-only link.
Credentials and account versions reference
`(transition_id, account_id, store_id)`; transition-origin store versions
reference `(transition_id, store_id)`. Receipt-origin store versions reference
the enrolled `(store_id, location_sha256, receipt_id)` tuple. Cross-account,
cross-store, or cross-receipt origin substitution therefore fails SQLite
foreign-key enforcement before restart validation.

`remote_effects` has exact composite foreign keys to the store-version and
account-version tables. Current store or account updates therefore neither
rewrite historical effect context nor encounter an `ON UPDATE RESTRICT` child
from an old effect. Fresh challenge issuance still validates the active current
rows and requires their immutable version parents. It never treats any
historical parent as current authority.

The current account row has a composite foreign key to its credential identity.
Account-create prepare uses transaction-local deferred foreign keys because the
new account, credential, and transition rows form one intentional closed cycle.
Deferral ends at commit and an explicit `foreign_key_check` must be empty.

The store-version primary key `(store_id, config_generation)` defines exact
per-store generation order. Restart streams that index directly, validates each
origin and generation successor, and uses keyed transition/event loads; the
query plan must contain no temporary B-tree. Version and credential rows are
never updated or deleted by production APIs. Restart validation recomputes their
origins and treats mutation, cross-linkage, missing parents, duplicate identity,
or an effect referencing a non-version row as `owner_recovery_required`.

### Account-Create Challenge Context

T202C2 adds only `account_create` to challenge issuance. Account update/remove,
credential, cleanup, remote-effect, policy, assurance, rotation-finalization,
and recovery-finalization operations remain unsupported at this stage. An
account-create challenge has no `challenge_effects` row. Its target is the
proposed `AccountId`, and its context contains the enrolled `StoreId`, the same
account identity, the proposed binding digest, no policy digest, and the exact
sealed `AccountCreate` manifest.

The sealed create manifest has exactly this lifecycle shape in addition to the
core manifest checks:

- `before` is absent; `after` is present with account generation 1, binding
  `proposed`, credential `reentry_required`, reason
  `credential_reentry_required`, and no cleanup IDs.
- The mutation cleanup list is empty. The after config digest differs from the
  before config digest, and config generation increments exactly once.
- The config CAS store/location/generation/digest equals the active registered
  store. The after account ID equals the target/context account ID, and the
  context binding equals the after binding.

`display_id_sha256` never means a normalized or case-folded alias. It is
SHA-256 of `KIRJE-ACCOUNT-DISPLAY-ID-V1\0` encoded by the authority transcript
primitive with one tag, `0x0001`, containing the exact validated display-ID
UTF-8 bytes. The authority database stores only this digest outside the sealed
private manifest.

Pending-context recovery runs before fresh registry checks. An exact unexpired
pending challenge is returned unchanged even if a later transaction has made
its proposed context stale. Fresh issuance requires an active store with the
exact config CAS, no active store transition, globally absent account,
credential, and transition-ID identities, and no active proposed/active/blocked
display digest for that store. Historical validation is intrinsic and never
reapplies those fresh absence checks. A stable-ID collision is
`account_identity_conflict`; an active display collision is
`account_already_exists`; a busy store is `account_update_conflict`; an exact
store ID at another sealed location is `config_store_identity_conflict`; and
a store already in recovery is `owner_recovery_required`. Other stale
store/config/binding context is `authorization_context_stale`. All are
non-retryable and consume no entropy or row.

### Account-Create Transition API

```rust
enum AccountTransitionKind {
    AccountCreate,
    AccountUpdate,
    AccountRemove,
    CredentialSet,
    CredentialDelete,
}

enum AccountTransitionState {
    Prepared,
    ConfigCommitted,
    Finalized,
    Aborted,
    RecoveryRequired,
}

struct PrepareAccountTransitionRequest {
    grant_use: GrantUseRequest,
    transition_id: TransitionId,
    store_id: StoreId,
    account_id: AccountId,
    kind: AccountTransitionKind,
    before_config_sha256: Sha256Digest,
    after_config_sha256: Sha256Digest,
    expected_generation: NonZeroU64,
    next_generation: NonZeroU64,
    display_id_sha256: Sha256Digest,
    account_generation: NonZeroU64,
    credential_id: CredentialId,
    binding_sha256: Sha256Digest,
    observed_at_unix_ms: i64,
}

struct AccountTransitionObservationRequest {
    transition_id: TransitionId,
    expected_state: AccountTransitionState,
    actual_config_generation: NonZeroU64,
    actual_config_sha256: Sha256Digest,
    observed_at_unix_ms: i64,
}
```

T202C2 accepts only kind `AccountCreate`, account generation 1, and the exact
create manifest values above. Request construction checks closed values,
nonnegative representable UTC milliseconds, SQLite-representable generations,
`next_generation = expected_generation + 1`, distinct before/after digests,
and target shape before database access. The transaction reparses the immutable
manifest and compares every request value. It does not trust a caller-supplied
state boolean, config-current assertion, display string, event source, or
receipt state.

The bounded transition projection contains only transition ID, account ID,
closed transition/account/store states, config generation, account generation,
and prepared timestamp. It omits store and credential IDs, display and binding
digests, config digests, grant/receipt identities, manifest, proof, signature,
nonce, key, endpoint, and event detail. Request and projection types implement
neither `Debug`, `Display`, serde, `JsonSchema`, nor logging helpers.

Prepared, config-committed, finalized, and aborted projections are scoped to the
selected transition's immutable history, not to the mutable current store row.
They return proposed/blocked with the before generation, proposed/blocked with
the after generation, active/active with the after generation, and removed/
active with the before generation respectively.

Recovery-required is the sole terminal-current-row exception because canonical
v1 stores the raw unsafe pair only in `registered_stores`. The projection may
read that pair only after proving the store is `recovery_required`, the account
is blocked with `active_transition_id` equal to the selected recovery-required
transition, both recovery events recompute from that exact pair and prior state,
and no successor transition or event exists. Any mismatch is corruption. All
create projections retain account generation one and their original prepared
timestamp. A later independent transition may exist only after the selected
transition reached `finalized` or `aborted`, and cannot change that older
transition's projection. Every supported canonical-v1 path through T202E leaves
an account-transition recovery store pair/state unchanged and admits no
successor. T202E trust
recovery may block additional stores but cannot clear, update, delete, or reuse
this terminal row. Recovery clearing requires a separately versioned future
schema/product contract and is outside Kirje v1.

`prepare_account_transition` consumes the grant only inside this transition
transaction. Grant use is not separately callable. The four observation
methods are `mark_config_committed`, `finalize_account_transition`,
`abort_transition`, and `mark_transition_recovery_required`. They use the fixed
apply lock, a fresh `BEGIN IMMEDIATE`, complete ready/history validation, and
store-derived effective authority time. They never open config, keyring,
runtime, protocol, or network resources. Runtime T206 supplies a typed snapshot
read under the config capability/lock; it cannot select an authority path or
event source.

T202C2 also evolves T202C1 store-enrollment recovery without changing its
operation identity. A registered store row carries the current config pair,
state, and update time derived from its transition chain. Exact `enroll_store`
retry validates the original grant/receipt/enrollment manifest, location
material, store identity, enrollment event, and complete legal transition chain,
then returns the original immutable enrollment projection: initial config
generation from the sealed enrollment manifest, state `active`, and both
projection timestamps equal to the store's enrollment `created_at`. It never
requires mutable current pair/state/update time to equal the initial pair. A
changed enrollment request retains the accepted T202C1 precedence. This is
operation-receipt recovery, not current store status.

### Account Transition Transcripts

Transition kind codes are fixed: `1 account_create`, `2 account_update`,
`3 account_remove`, `4 credential_set`, and `5 credential_delete`.
`KIRJE-ACCOUNT-TRANSITION-V1\0` has exactly:

```text
0x0001 transition UUID16          0x0002 grant UUID16
0x0003 store UUID16               0x0004 account UUID16
0x0005 transition-kind u8         0x0006 before-config SHA-256
0x0007 after-config SHA-256       0x0008 expected generation u64be
0x0009 next generation u64be      0x000a prepared-at i64be
```

The exact bytes are retained only in memory; `transition_sha256` stores their
SHA-256. The immutable grant/manifest graph and registry row bind the proposed
account fields omitted from this compact transition transcript.

The no-grant expiry/recovery identity is
`KIRJE-ACCOUNT-TRANSITION-INTENT-V1\0` with these exact tags:

```text
0x0001 grant UUID16               0x0002 receipt UUID16
0x0003 action u16be               0x0004 target-kind u16be
0x0005 canonical target bytes     0x0006 manifest SHA-256
0x0007 transition UUID16          0x0008 store UUID16
0x0009 account UUID16             0x000a transition-kind u8
0x000b before-config SHA-256      0x000c after-config SHA-256
0x000d expected generation u64be  0x000e next generation u64be
0x000f display-ID SHA-256         0x0010 account generation u64be
0x0011 credential UUID16          0x0012 binding SHA-256
```

Raw observed time is absent. Immutable challenge/receipt/manifest rows plus a
bounded request recompute the exact intent after an expiry response loss.

Unsafe config observation is durably bound by
`KIRJE-ACCOUNT-TRANSITION-RECOVERY-V1\0`:

```text
0x0001 transition SHA-256
0x0002 prior transition state u16be
0x0003 actual config generation u64be
0x0004 actual config SHA-256
```

The event context is SHA-256 of these exact bytes. The raw pair remains in the
private registered-store row while the event exposes only the domain-separated
recovery digest. Restart validation recomputes it; changing one unsafe pair to
another therefore cannot remain a valid recovery graph.

### Prepare Transaction

One store has at most one transition in `prepared` or `config_committed`, and a
store in `recovery_required` admits none. This store-wide rule is stricter than
the schema's per-account `active_transition_id`: every mutation replaces the
same config document and therefore shares one generation chain.

First prepare requires the store to be `active` at the exact before config
pair, no active store transition, and all proposed global identities plus the
effective-time transition digest to be absent. The same transaction performs
these operations in order:

1. insert the canonical grant use and `grant_used` event;
2. update the store `active -> blocked` without changing its config pair;
3. enable transaction-local `PRAGMA defer_foreign_keys=ON`, verify it is active,
   insert the proposed account with its transition ID, insert the prepared
   transition referring back to that account, and reserve the credential
   identity against both;
4. run `PRAGMA foreign_key_check` after the cyclic account/transition/credential
   graph exists and require an empty result;
5. append `store_state_changed` and `account_transition_prepared`, update the
   paired authority clock, and commit.

Transaction-local deferral is required only for the schema's intentional new
account/transition/credential cycle. It is never a connection default or a
substitute for final FK checking.
A fault before commit rolls back the grant, store block, account reservation,
transition, events, and clock. A post-commit response loss exactly recovers all
of them.

The prepared account row is `proposed`, has `active_transition_id` set, retains
the exact receipt, account generation 1, credential identity, display digest,
and binding digest, and is not usable for authentication or operations. The
store is `blocked`, so unrelated account work cannot cross the config/authority
gap. This reservation occurs before config or keyring access.
The credential reservation `created_at`, transition `prepared_at`, proposed
account `created_at`/initial `updated_at`, and both prepare state events use the
same effective prepare time. A deterministic pre-commit fault immediately after
credential insertion proves the complete cyclic reservation rolls back.

Error precedence is closed. Pure request validation runs first. Transactional
schema/anchor/history/event corruption is `owner_recovery_required`. A present
grant row is compared next: changed bounded prepare identity is
`grant_already_used`; an exact grant with a missing or mismatched immutable
prepare graph or an illegal later lifecycle is corruption. An exact grant whose
transition legally advanced returns that transition's scoped latest durable
projection instead of a stale prepared snapshot. A later independent transition
may coexist only when the selected transition reached `finalized` or `aborted`;
`recovery_required` instead requires the unchanged terminal store pair/state and
no successor. Checked clock may advance, but no
lifecycle row, timestamp, or event changes. With no grant, exact receipt/challenge/transition
intent is checked; mismatch is `authorization_context_stale`. Expiry commits
before current store and occupancy checks. Current store/config mismatch is
`authorization_context_stale`, store/location conflict is
`config_store_identity_conflict`, a store transition conflict is
`account_update_conflict`, a store already in recovery is
`owner_recovery_required`, global account/credential/transition identity
collision is `account_identity_conflict`, and active display collision is
`account_already_exists`. A racing loser inserts no grant, reservation,
transition, event, or clock update.

An authorized unclaimed receipt that expires at prepare changes only its
challenge state, paired clock, and one authorized-to-expired event whose context
is the transition-intent digest. Exact response-loss/restart/concurrent retry
returns `authorization_expired` with no second event; changed intent is
`authorization_context_stale`. No registry occupancy check occurs before this
durable expiry.

### Config Observation And Terminal Transitions

For one transition, the observed config pair is classified exactly:

```text
before = (expected_generation, before_config_sha256)
after  = (next_generation, after_config_sha256)
third  = every other generation/digest pair
```

After complete history validation and terminal exact-retry lookup, unsafe
physical state takes precedence over the requested safe transition: prepared
plus third, or config-committed plus before/third, enters the common recovery
transaction from any observation method. This prevents a stale method choice
from leaving a newly observed unsafe pair represented as merely prepared or
config-committed. Safe pairs then apply the method-specific rules below.

The remaining matrix is closed. Prepared+before is a no-op for
`mark_config_committed`, aborts for `abort_transition`, and is
`account_update_conflict` for finalize or explicit recovery. Prepared+after
commits only through `mark_config_committed`; every other method returns that
conflict. Config-committed+after is an exact mark recovery, finalizes through
`finalize_account_transition`, and conflicts for abort or explicit recovery.
Finalized+after recovers only finalize; aborted+before recovers only abort.
Recovery-required plus the exact stored actual pair and recomputed recovery
event identity returns the recovery projection from every observation method;
a changed terminal pair conflicts. Every other terminal/method/pair combination
is `account_update_conflict` with no write.

Exact phase recovery is monotonic and transition-scoped. Each method first
proves whether its exact phase event committed, validates every legal successor
inside that transition, and returns that transition's latest durable projection
without replay. If the selected transition reached `finalized` or `aborted`, a
later independent transition may change the mutable store state or generation;
the older result still comes from its own transition, version rows, and events.
`recovery_required` has no later-transition case: exact retry requires the
unchanged terminal current store pair/state, exact recovery graph, and no
successor transition. Only the paired authority clock may advance.

`mark_config_committed` requires request expected state `prepared`. Observing
before is an exact no-op and returns the prepared projection. Observing after
atomically inserts the immutable after store version, inserts the immutable
account-generation-one account version, changes the transition to
`config_committed` with `config_committed_at`, advances the blocked registered
store current pair to after, appends `account_config_committed`, and updates the
clock, in that exact order. Both version `created_at` values,
`config_committed_at`, the store `updated_at`, the event `occurred_at`, and the
paired clock use the same store-derived effective time.
Distinct deterministic faults immediately after the store-version insert and
after the account-version insert prove neither immutable row can survive without
the complete config-committed graph.
An exact retry in `config_committed` returns unchanged. A third pair enters
recovery.

`finalize_account_transition` requires request expected state
`config_committed` and the after pair. It changes the account
`proposed -> active`, clears `active_transition_id`, changes the transition to
`finalized`, then changes the store `blocked -> active`. The store retains the
after config pair. It appends transition-finalized before the store-unblocked
event. Exact finalized retry returns unchanged. Before after config-committed,
or any third pair, enters recovery rather than reopening or replaying config.

`abort_transition` requires request expected state `prepared` and the before
pair. It changes the proposed account to `removed`, sets `removed_at`, clears
`active_transition_id`, changes the transition to `aborted` with `resolved_at`,
then changes the unchanged-before store `blocked -> active`. It appends the
transition-aborted event before the store-unblocked event. The historical
account, credential, grant, receipt, and transition identities remain reserved;
the partial display index permits a later new account identity to reuse that
display ID. An after pair is not abortable and returns
`account_update_conflict`; a third pair enters recovery. Exact aborted retry
returns unchanged.

`mark_transition_recovery_required` accepts expected state `prepared` or
`config_committed`. It accepts only a pair inconsistent with safe continuation:
third from prepared; before or third from config-committed. The same recovery
path is mandatory when another observation method sees such a pair. It stores
the actual observed config pair on the registered store, changes that store
`blocked -> recovery_required`, changes the account to `blocked` while retaining
`active_transition_id`, and changes the transition to `recovery_required` with
`resolved_at`. It appends store-state-changed before
account-transition-recovery-required. No later C2 method can finalize, abort,
or clear this state. T202E owns owner reconciliation.

For finalized and aborted lifecycle methods, terminal exact retry compares the
event-defined terminal operation, declared source state, transition identity,
canonical actual config pair, and immutable graph. Recovery-required derives
its prior source state from the event and all observation methods converge on
the one recovery identity above. Observed time is only a clock sample. A changed
terminal retry returns
`account_update_conflict` and changes nothing. Exact recovery appends no event,
does not change registry or lifecycle timestamps, and may advance only the
paired authority clock.

### Account-Create Event Graph

All event detail uses the existing canonical event transcript. Context is the
transition digest and receipt is the consumed create receipt unless the recovery
shape below requires the recovery-observation digest. The exact new event shapes
and order are:

```text
prepare:
  grant_used (existing shape)
  store_state_changed: entity store, source runtime, related transition,
    store_active -> store_blocked
  account_transition_prepared: entity transition, source runtime,
    related account, none -> transition_prepared

config committed:
  account_config_committed: entity transition, source runtime,
    related account, transition_prepared -> transition_config_committed

finalize:
  account_transition_finalized: entity transition, source runtime,
    related account, transition_config_committed -> transition_finalized
  store_state_changed: entity store, source runtime, related transition,
    store_blocked -> store_active

abort:
  account_transition_aborted: entity transition, source owner_reconciliation,
    related account, transition_prepared -> transition_aborted
  store_state_changed: entity store, source owner_reconciliation,
    related transition, store_blocked -> store_active

recovery required:
  store_state_changed: entity store, source crash_recovery,
    related transition, store_blocked -> store_recovery_required,
    context recovery-observation digest
  account_transition_recovery_required: entity transition,
    source crash_recovery, related account, exact prior transition state ->
    transition_recovery_required, context recovery-observation digest
```

Events in one step share the store-derived effective timestamp and are adjacent.
No account event code is invented; the account row shape is proven by the
transition event and atomic graph. Event detail contains no display/binding/
config digest, credential identity, manifest, location, endpoint, or secret.

### T202C2 Restart Validation

Restart validation admits only account-create challenges, create transitions,
their account rows, and the lifecycle/event shapes above in addition to the
accepted T202C1 history. Every other account-transition kind and every cleanup,
effect, invocation, observation, rotation, or recovery row remains rejected.

The T202C1 store row is current mutable registry state after C2. Its immutable
enrollment identity and exact-retry projection are rederived from the original
store-enroll challenge, receipt, grant, and event. Validation replaces the
T202C1 stage fence that equates current store config with initial enrollment
config; it never rewrites enrollment history.

The validator streams bounded rows and retains at most one store, version,
transition, account, manifest, transcript, and event at a time in Rust. For each
store it streams `registered_store_versions` by the composite primary key's
config-generation order and validates the initial enrollment origin followed by
exact successor generations whose transition origins reached config committed.
It separately streams that store's entity-kind-4 authority events through
`authority_events_entity_sequence`; each state-change detail yields one keyed
transition load and establishes prepare/terminal order without parsing a
caller-supplied order or sorting transitions. Aborted transitions leave the
current pair unchanged; finalized and config-committed transitions advance it;
prepared leaves it before; recovery ends the chain at the stored actual pair.
Only the last transition may be prepared, config-committed, or
recovery-required. The derived final pair/state must equal the registered store
row.

Every account row has exactly one create transition and one exact create receipt.
Its state/timestamps/active-transition shape must be exactly active/finalized,
removed/aborted, proposed/prepared-or-config-committed, or
blocked/recovery-required. Account/credential IDs remain globally unique;
display uniqueness applies only to proposed/active/blocked rows. Transition,
grant, account, store, receipt, manifest, transcript, timestamp, FK, and event
graphs are rederived rather than trusted.

The complete history validator has affine query-count growth, O(1) additional
Rust history memory, no per-history collection, and no unindexed repeated full
scan. `EXPLAIN QUERY PLAN` must show the store-version primary-key lookup and
`authority_events_entity_sequence` with no `USE TEMP B-TREE`; tests also require
the keyed account-version/credential/transition plans plus at least 128 complete
sequential create histories. Corruption, read faults,
unknown enum/state codes, duplicate/missing/swapped events, broken transition
chains, dangling cyclic references, impossible current config, and timestamp
drift all fail the entire open as `owner_recovery_required`.

### Credential Cleanup Authority Contract

Credential cleanup is a transition-bound historical operation. Canonical v1
admits a cleanup only when its origin is a finalized `account_update` or
`account_remove` transition whose signed manifest contains the cleanup
descriptor exactly once in provisional state. The cleanup's account authority
is the origin manifest's `before` snapshot and its immutable account-version
row: store ID, account ID, historical account generation, historical credential
ID, historical binding digest, and historical display ID are never rebound to a
later current snapshot. A later update, removal, or same-display recreation
therefore cannot redirect the tombstone.

The invariant begins before reservation. `CredentialCleanupReservation::new`
parses one complete locator transcript, enforces its tag/UTF-8/NUL/length and
closed kind/service/username shape, requires the caller's locator kind to equal
the transcript kind, and computes `locator_sha256` from the complete canonical
bytes. Malformed construction is `invalid_input`. Before transition prepare
inserts a cleanup row or mutates grant/store/account/transition/event/clock
state, the store loads realm plus the signed historical-before origin candidate,
rederives the exact active-v2 or legacy-v1 service and username, and compares
kind, canonical transcript, and digest with the sealed reservation and signed
descriptor. A canonical but wrong-origin reservation is
`authorization_context_stale` with zero durable mutation. This is transition
input hardening only; A006 does not change prepare, commit, finalize, abort, or
recovery state-machine behavior.

The private locator row contains exactly the canonical
`KIRJE-DELETE-ONLY-LOCATOR-V1\0` transcript from the account-config contract.
`active_v2` rederives the exact V2 service and lowercase username from the
realm/store/account/historical-credential/historical-binding tuple.
`legacy_v1` rederives the exact legacy service and origin-before display ID.
The row's `locator_sha256` hashes that complete transcript. It never hashes raw
concatenation, only a username, or a mutable current account.

Generic service, username, and total-length gates are classified by one private
numeric length helper in `authority.rs`. Its `#[cfg(test)]` unit tests pass only
numeric byte/character/total lengths and expected classifications, including
service 0/1/128/129, username 0/1/1024/1025, total 0/1/4096/4097, and the
greatest constructible canonical total. They expose no public or test-support
API and add no locator transcript or locator-field test bytes to `authority.rs`.
Closed-form canonical and mutation byte vectors remain only in
`authority_registry.rs`. This test seam changes no public type, schema,
transcript, locator projection, or runtime capability.

The signed tombstone digest is:

```text
SHA256(KIRJE-CREDENTIAL-CLEANUP-TOMBSTONE-V1\0
  0x0001 realm_id:BLOB32
  0x0002 cleanup_id:UUID16
  0x0003 transition_id:UUID16
  0x0004 transition_sha256:BLOB32
  0x0005 origin_manifest_sha256:BLOB32
  0x0006 store_id:UUID16
  0x0007 account_id:UUID16
  0x0008 historical_account_generation:u64be
  0x0009 historical_credential_id:UUID16
  0x000a historical_binding_sha256:BLOB32
  0x000b locator_kind:u8
  0x000c locator_sha256:BLOB32
  0x000d created_at:i64be
  0x000e origin_expected_state:u8)
```

The transcript uses the canonical TLV container, exactly 14 strictly ascending
tags, and `origin_expected_state=0x01` (`provisional`). Raw locator material and
mutable cleanup `state`, `claim_grant_id`, and `deleted_at` are excluded.
`created_at` equals the origin transition's `prepared_at`. The authority store
rederives every field from the realm meta row, cleanup row, finalized origin
transition and transition digest, origin grant/challenge manifest, descriptor,
and origin-before account/version graph. No caller supplies a trusted field.

The schema's nullable `credential_cleanup.transition_id` does not create a v1
legacy branch. Before the apply lock, file access, database access, or entropy,
one pure cleanup-manifest preflight in `authority.rs` rejects
`transition_id=None` as `authorization_malformed` with zero I/O, mutation, or
entropy. A persisted NULL transition is `owner_recovery_required`. `legacy_v1`
is valid only when the exact legacy locator is owned by the same transition-
bound origin graph. This rule changes no schema, core type, or core transcript
bytes.

#### Effect-Free Challenge

Credential-cleanup challenge creation treats the manifest's common store and
account IDs as bounded untrusted typed request values. Complete schema, anchor,
history, transcript, and event integrity validation is request-independent and
may already have streamed every private cleanup, origin, locator, and tombstone
graph. After the request-independent global validation pass, no request-directed
pending/private lookup or request-dependent private branch may occur before the
closed public pair classification. An absent store, absent account, or account
whose persisted `store_id` differs from the requested store ID returns
`credential_cleanup_invalid` without request-directed pending/private lookup.

The challenge-issuance phases are exact and cannot be reordered: (1) pure
request/manifest preflight, including rejection of `transition_id=None`; (2)
acquire the authority apply lock and begin the transaction; (3) complete the
request-independent global step-2 integrity pass; (4) validate checked effective
time and canonical time shape without pending-row access; (5) classify the
closed public store/account pair; (6) validate the private cleanup, origin,
locator, and tombstone target; (7) perform the first request-directed pending-
challenge lookup; (8) return exact reuse or perform expired replacement; and
(9) create and commit a successor when required. No request-directed pending or
private lookup/branch occurs before phase 5, and no pending expiry is durably
recorded before public eligibility succeeds.

For an existing matched public store/account pair, a `recovery_required` store
returns `owner_recovery_required`; a blocked store or a blocked account
returns `account_update_conflict`. These public results occur before any private
target-validity result. An unrelated but existing matched blocked/recovery pair
deliberately returns that pair's public projection result and never reveals
whether the requested cleanup target is valid. Only an active store plus an
active or removed account proceeds to private validation of the exact cleanup
manifest with expected state `ready`, rederived locator/tombstone digests, one
finalized origin transition, and the historical-before binding. A removed
account is eligible and a new account with the same display ID is irrelevant.
Provisional, claimed, deleted, wrong-kind, wrong-origin, duplicated-descriptor,
or mismatched locator/tombstone state is `credential_cleanup_invalid`.

The public-pair cross-product is complete rather than sampled. Absent store,
absent account, and pair mismatch each return `credential_cleanup_invalid`.
Matched recovery store returns `owner_recovery_required`. Matched blocked store
or blocked account returns `account_update_conflict`. A finalized-origin account
persisted as `proposed` is global step-2 corruption. An unrelated but matched
proposed pair is reachable and returns `account_update_conflict`; an unrelated
matched blocked/recovery pair returns its same public result.
Every one of those public-ineligible cells is crossed independently with wrong
origin, wrong locator kind, wrong locator digest, wrong tombstone, wrong
lifecycle, and wrong descriptor target cells; none performs request-directed
pending/private lookup or distinguishes target validity. Active store with
active account and active store with removed account each proceed, and each of
the six private-invalid cells then returns `credential_cleanup_invalid` from the
private validation stage.

Issuance is effect-free: it consumes no grant, changes no cleanup row, and
creates no effect, invocation, or external-call capability. Exact pending reuse
returns the same bounded challenge without entropy after the same history and
eligibility checks. It may advance only the paired authority clock high-water;
it never changes challenge, cleanup, lifecycle, or event timestamps and never
appends an event. No public projection, event, log, fixture, or error contains
the private locator transcript, service, username, or one of its raw fields.

An expired matching pending cleanup challenge is replaced under the same global
challenge transaction rule. One valid replacement atomically changes a still-
pending predecessor to expired, appends its one event 5, creates one successor
with a fresh grant UUID and nonce, and appends one event 3 after the predecessor
terminal event. Both events use the transaction's effective time; no cleanup,
grant-use, effect, or external row is written.

Replacement proof separates public classification from pending-row work. A test
may arrange a same-context expired pending row and then make its matched store
recovery-required, its matched store blocked, or its matched account blocked.
The same finalized-origin account may otherwise remain active or become removed;
persisting it as proposed is corruption. Each blocked/recovery call returns the closed public recovery/conflict error with zero
request-directed pending-row lookup-dependent interaction: predecessor state,
events, and both authority clock fields are unchanged; entropy, successor,
grant, nonce, and cleanup deltas are zero.

Tentative-expiry rollback is proved only after an active-store plus active-or-
removed-account public classification and valid private target validation. The
existing deterministic fault hooks `OldChallengeExpiredState` and
`OldChallengeExpiredEvent` independently fail after predecessor state mutation
and after predecessor event insertion. Each fault rolls the entire transaction
back to the exact prestate with no committed predecessor/event/clock change and
zero entropy, successor, grant, nonce, or cleanup delta. A different-context
invalid target has zero predecessor interaction. Persisted target/history
corruption is global step 2 and returns `owner_recovery_required`.

Concurrent exact issuance has one creator. The winner commits one challenge,
one grant identity, one nonce, and one event 3. Every loser reopens the winning
pending row, returns its exact immutable projection, consumes no entropy,
appends no event, and may advance only the paired clock high-water. Restart
performs the same intrinsic validation and exact reuse without creating a
second lifecycle interval.

For first issuance, exact reuse, response-loss replay, valid expired replacement,
each `OldChallengeExpiredState`/`OldChallengeExpiredEvent` failure, restart reuse,
the concurrent winner, and every concurrent loser, the transaction has zero row
delta in `challenge_effects`, `remote_effects`, `effect_claims`,
`effect_invocations`, `effect_observations`, and `grant_uses`, zero external-call
cardinality, and unchanged cleanup. `grant_uses` is measured as a prestate-to-
poststate delta because immutable origin-transition uses may already exist.

#### Claim And Permit

The cleanup claim transaction owns both grant consumption and `ready ->
claimed`. First claim validates the exact receipt/challenge/manifest, the
historical origin and tombstone graph, current active store plus active-or-
removed account eligibility, expiry, and cleanup readiness. It inserts exactly
one canonical grant-use row, sets `claim_grant_id` to that same grant, and
updates the cleanup in one transaction at one store-derived effective time.
There is no second cleanup-claim identity or transcript: the immutable
`KIRJE-GRANT-USE-V1\0` transcript, its `use_sha256`, and the exact cleanup target
and manifest are the claim identity.

The transaction appends exactly two adjacent events in this order:

```text
grant_used: existing canonical event 7
cleanup_claimed: entity cleanup, event 16, source runtime (4),
  related grant, cleanup_ready -> cleanup_claimed,
  context use_sha256, same receipt, same effective time
```

Only the transaction winner receives an opaque `CleanupDeletePermit`. The
permit owns the fixed cleanup apply lock and validated private locator source;
it is
non-`Clone`, non-`Debug`, non-serializable, and exposes no raw bytes, service,
username, digest, conversion, read, probe, copy, export, set, or rebind
capability. A concurrent different grant loses with
`credential_cleanup_invalid` and writes nothing.

A post-commit response loss is recoverable only by the exact same grant-use and
cleanup identity. Exact claimed recovery validates the complete durable graph,
reacquires the same apply lock, and only then may issue a fresh opaque permit.
It may advance only the paired authority clock high-water, appends no event,
and changes no cleanup, grant, challenge, lifecycle, or event timestamp. Changed
reuse of the same grant is `grant_already_used`. Exact recovery after deletion returns
the immutable terminal projection with no permit. First use after expiry
durably applies the ordinary authorized-unclaimed expiry transaction and
returns `authorization_expired`; exact committed claim or deletion remains
historical and is checked before expiry.

#### Consuming Delete Boundary

The only deletion API is one combined public `AuthorityStore`/cleanup service
operation that consumes `CleanupDeletePermit`. Under its apply lock, store
constructs the opaque `DeleteOnlyLocator`, invokes
`kirje_credential::delete_only` exactly once, and, after `Ok(())`, commits
`claimed -> deleted`. There is no caller-accessible `mark_deleted` method.
Deleted and `NoEntry` both map to `Ok(())`; there is no outcome enum or presence
signal. Authority open, read, challenge, claim validation, and recovery-
validation paths never call the keyring. This explicit consuming apply method
is the sole adapter-call boundary, and store does not re-export any low-level
credential crate item.

`kirje-credential` is unpublished and only `kirje-store` may list it as a
direct Cargo dependency. The Rust-visible constructor and function exist only
for that sole consumer; the enforceable workspace boundary is the dependency
allowlist because Rust provides no friend-crate visibility. A007 creates the
low-level crate, opaque locator, store dependency, and store-private fake
deletion hook. A008 adds the real low-level keyring delete implementation and
the sole production call in
`AuthorityStore::apply_credential_cleanup_delete` inside the exact private
module `credential_cleanup_delete_adapter`. A dedicated A008 AST test parses
every production Rust file in `kirje-store` and closes alias, wildcard,
re-export, macro, function-pointer, indirect-binding, type/constructor/API, and
call bypasses. Only that exact method may mention `DeleteOnlyLocator` or call
`kirje_credential::delete_only`, and the call count is exactly one. The AST
allowlist composes with the Cargo direct-dependency allowlist, store no-re-export
rule, and runtime compile-fail no-dependency fixture. T204 calls only the
high-level store API while migrating/removing legacy runtime `SecretStore`
paths; runtime never imports, names, receives, or re-exports the low-level crate
or locator.

Backend failure returns its existing stable backend error, retains `claimed`,
sets no `deleted_at`, and appends no event. Success sets `deleted_at` to the
store-derived effective time and appends exactly one event:

```text
cleanup_deleted: entity cleanup, event 17, source runtime (4),
  related same grant, cleanup_claimed -> cleanup_deleted,
  context same use_sha256, same receipt, occurred_at=deleted_at
```

Event 17 follows the one event 16 for that cleanup and never precedes or
duplicates it. A crash before low-level delete invocation leaves claimed state.
A crash during or after low-level delete success but before the terminal
transaction also leaves
claimed state, so exact recovery reacquires the lock and repeats the idempotent
delete. A crash after the terminal commit returns the deleted projection on
exact retry without calling the low-level backend. A changed same-grant retry is
`grant_already_used`; a different-grant retry against an occupied target is
`credential_cleanup_invalid`.

#### Restart, Cardinality, And Failure Order

Restart validation streams every cleanup with its origin transition,
historical account version, credential, grant, challenge/manifest, private
locator, and entity events. It rederives both canonical transcripts and digests.
The lifecycle graph is exact:

| Cleanup state | Claim grant uses | Events | Terminal fields |
| --- | --- | --- | --- |
| `provisional` | 0 | no cleanup event before origin finalize | no claim or deletion |
| `ready` | 0 | exactly one event 15 | no claim or deletion |
| `claimed` | exactly 1 | one event 15, adjacent event 7 then one event 16 | claim present, no deletion |
| `deleted` | exactly 1 | claimed graph plus one later event 17 | same claim, one `deleted_at` |

Unknown kind/state, NULL transition, non-finalized or wrong-kind origin,
duplicate/missing descriptor, wrong historical tuple, malformed locator,
digest mismatch, timestamp drift, grant-count mismatch, duplicate/missing/
swapped event, incorrect source/related/context/receipt, or an impossible
state-field combination fails the entire authority open as
`owner_recovery_required`. Validation and public/error projection retain O(1)
additional Rust history memory and never expose locator material.

Credential cleanup uses phase-specific closed precedence. Cleanup challenge
issuance uses exactly: (1) pure request/manifest bounds, encoding, and
`transition_id=None` preflight; (2) lock/transaction acquisition; (3)
request-independent schema/anchor/history/transcript/event/row validation, with
corruption returning `owner_recovery_required`; (4) checked effective time and
canonical time-shape validation without pending access; (5) closed public pair
classification; (6) private cleanup/origin/locator/tombstone validation; (7)
pending lookup; (8) exact reuse or expired replacement; and (9) successor
creation/commit. At phase 5, absent store/account or pair mismatch is
`credential_cleanup_invalid`, matched recovery store is
`owner_recovery_required`, matched blocked store/account is
`account_update_conflict`, and an unrelated matched proposed pair is
`account_update_conflict`. A finalized-origin account persisted as proposed is
phase-3 corruption. Only active store plus active/removed origin account reaches
phase 6. No pending or private request-directed lookup/branch precedes phase 5,
and pending expiry is never durable before public eligibility.

Cleanup claim and delete retain the ordinary grant/proof precedence after global
integrity validation: existing-grant exact recovery versus changed same-grant;
receipt/challenge/manifest/intent match; clock rollback; proof authorization
expiry and its ordinary durable expiry behavior; current eligibility; private
target lifecycle/locator/tombstone/origin validation; then store/backend error.
The cleanup-challenge issuance exception does not reorder claim/delete proof
verification or weaken any corruption check.

No failure contains a private locator value, account address, endpoint,
credential presence distinction, digest, backend diagnostic, or other private
row material.

### Grant Use, Claim, Invocation, And Observation

```rust
struct GrantUseRequest { grant_id, receipt_id, action, target_kind,
    target_bytes, manifest_sha256 }

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
`authorization_expired`; clock tolerance never extends the deadline. Durable
use time is always store-derived effective authority time, not a caller field.

First effect claim performs all comparisons in the same transaction: receipt and
grant, expiry, anchor/meta readiness, active role/key/epoch/bundle, registered
store state/location/config generation/config digest, account state/generation/
credential/binding, policy, manifest, effect, ordinal, and operation UUID. It
sets `invoke_before` exactly to the receipt expiry. Exact committed claim recovery
returns the same claim after later context change; a changed retry returns
`effect_already_claimed`.

T202D reuses T202C1's exact grant-use helper inside the first remote effect-claim
transaction; it does not introduce a second transcript, replay order, expiry
path, or independently callable grant-use mutation.

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
