# Contract: Account Config V2 And Credential Binding

## Metadata

- Feature ID: `008-security-baseline`
- Status: Confirmed
- Contract name: `kirje.account-config.v2`
- Updated: 2026-08-31

## Purpose

This contract separates four concepts that v0.3 represented with one display
ID:

- human-facing account alias
- durable account identity
- credential-store identity
- exact authenticated endpoint binding

A caller-selected config file cannot redirect a credential by copying or
reusing any one of those values. The pinned owner realm registry is
authoritative for the relationship between config location, store, account,
credential, and binding.

## Stored Types

```rust
struct AccountConfigDocumentV2 {
    version: u16,
    store_id: StoreId,
    generation: NonZeroU64,
    accounts: Vec<StoredAccountV2>,
}

struct StoredAccountV2 {
    display_id: AccountDisplayId,
    account_id: AccountId,
    generation: NonZeroU64,
    email: BoundedEmail,
    username: BoundedUsername,
    incoming: Endpoint,
    outgoing: Option<Endpoint>,
    credential_kind: CredentialKind,
    credential_id: CredentialId,
    binding_version: u16,
    binding_sha256: BindingDigest,
    binding_state: BindingState,
    credential_state: StoredCredentialState,
    state_reason: Option<AccountStateReason>,
    pending_cleanup_ids: Vec<CleanupId>,
}
```

All serialized structs deny unknown fields. Version, IDs, generation, state,
and digest fields have no serde defaults.

`MailAccountConfig` remains the provider-neutral adapter snapshot. Runtime
constructs it only from one validated `StoredAccountV2`; it does not use the
display ID as the adapter's durable identity.

## Validation

### Document

- Maximum bytes: 1 MiB plus one-byte overflow detection.
- Maximum accounts: 100.
- `version` must equal 2; newer versions return a stable unsupported-version
  error without attempting migration.
- `store_id`, account IDs, and credential IDs must be canonical UUIDv4.
- Document and account generations must be positive.
- Display IDs, account IDs, and credential IDs must each be unique.
- Cleanup IDs must be unique and bounded.
- Account list is serialized in deterministic display-ID then account-ID order.
- Every stored digest must recompute exactly from its current fields.

### Account

- Display ID remains 1-64 ASCII letters, numbers, `-`, or `_` and is immutable.
- Email and username retain current bounded validation and exact bytes.
- Incoming is verified-TLS IMAP; optional outgoing is verified-TLS SMTP.
- OAuth2 and other unsupported credential kinds cannot be active.
- Host normalization affects only binding encoding, not an unchecked stored
  value.
- State combinations follow the matrix below.

### State Matrix

| Binding | Credential | Authentication |
|---|---|---|
| `quarantined` | `legacy_quarantined` | denied |
| `proposed` | `reentry_required` or `missing` | denied |
| `authorized` | `reentry_required` | denied |
| `authorized` | `missing` | denied |
| `authorized` | `bound` | eligible after realm checks |
| `invalidated` | any non-bound state | denied |
| `mismatch` | any | denied and recovery/status only |

`bound` with a non-authorized binding, a stale digest, an unregistered store,
an authority mismatch, or a different credential ID is invalid.

## Repository Contract

The account repository is explicit rather than upsert-based:

```rust
trait AccountRepository {
    fn initialize_if_absent(&self) -> Result<AccountConfigSnapshot, MailError>;
    fn snapshot(&self) -> Result<AccountConfigSnapshot, MailError>;
    fn get_by_account_id(&self, id: AccountId) -> Result<Option<StoredAccountV2>, MailError>;
    fn get_by_display_id(&self, id: &AccountDisplayId) -> Result<Option<StoredAccountV2>, MailError>;
    fn create(&self, expected: ConfigCas, account: ProposedAccount) -> Result<ConfigCommit, MailError>;
    fn update(&self, expected: AccountCas, account: ProposedAccountUpdate) -> Result<ConfigCommit, MailError>;
    fn remove(&self, expected: AccountCas) -> Result<ConfigCommit, MailError>;
    fn set_credential_state(&self, expected: AccountCas, state: CredentialStateChange) -> Result<ConfigCommit, MailError>;
}
```

No production `upsert` method exists. Create with an existing display ID or
account ID is a non-retryable conflict and changes no state. Update requires the
exact account ID, expected account generation, expected document generation,
and loaded config digest. Display ID cannot change.

## Config Snapshot And CAS

```rust
struct AccountConfigSnapshot {
    store_id: StoreId,
    generation: NonZeroU64,
    config_sha256: Sha256Digest,
    location: ConfigLocationIdentity,
    accounts: Arc<[StoredAccountV2]>,
}

struct ConfigCas {
    store_id: StoreId,
    generation: NonZeroU64,
    config_sha256: Sha256Digest,
    location_sha256: Sha256Digest,
}
```

Fresh initialization is a separate create-only transition. Under the config
lock, `initialize_if_absent` requires a genuinely missing final component,
generates one StoreId, and commits `version=2`, `generation=1`, and an empty
account list. A concurrent loser reads and returns the winner's complete
document. Initialization does not migrate, access authority/keyring/network, or
regenerate an ID after a committed file exists.

Canonical nested domains used by control manifests are:

```text
KIRJE-ENDPOINT-V1\0
0x0001 protocol:u8
0x0002 exact_host:UTF-8
0x0003 host_kind:u8
0x0004 canonical_host:ASCII
0x0005 port:u16
0x0006 security:u8

KIRJE-ACCOUNT-SNAPSHOT-V1\0
0x0001 display_id:UTF-8             0x0002 account_id:UUID16
0x0003 generation:u64               0x0004 email:UTF-8
0x0005 username:UTF-8               0x0006 credential_kind:u8
0x0007 credential_id:UUID16         0x0008 binding_version:u16
0x0009 binding_sha256:BLOB32        0x000a binding_state:u8
0x000b credential_state:u8          0x000c state_reason:zero-or-u8
0x000d incoming:ENDPOINT            0x000e outgoing:zero-or-ENDPOINT
0x000f cleanup_ids:list<UUID16>

KIRJE-CONFIG-CAS-V1\0
0x0001 store_id:UUID16              0x0002 generation:u64
0x0003 exact_content_sha256:BLOB32  0x0004 location_sha256:BLOB32

KIRJE-ACCOUNT-CAS-V1\0
0x0001 config_cas:CONFIG-CAS        0x0002 account_id:UUID16
0x0003 account_generation:u64       0x0004 account_snapshot_sha256:BLOB32

KIRJE-CLEANUP-DESCRIPTOR-V1\0
0x0001 cleanup_id:UUID16            0x0002 locator_kind:u8
0x0003 locator_sha256:BLOB32        0x0004 expected_state:u8
```

These use the authorization contract's TLV/list/optional primitives. Fixed
codes are: binding state `1 quarantined`, `2 proposed`, `3 authorized`,
`4 invalidated`, `5 mismatch`; credential state `1 legacy_quarantined`,
`2 reentry_required`, `3 missing`, `4 bound`, `5 invalidated`; cleanup locator
kind `1 active_v2`, `2 legacy_v1`. Every mutation with an after account snapshot
advances account generation exactly once: create starts at one; account update,
credential set, and credential delete increment it. Account ID and display ID
remain unchanged after create. Remove has no after snapshot or account-version
row. Every config mutation exactly increments document generation.

`AccountStateReason:u8` is closed: `1 legacy_unbound`,
`2 credential_reentry_required`, `3 binding_changed`, `4 owner_recovery`,
`5 authority_mismatch`, `6 config_migration`. Stored snapshots contain only
this optional code; public status renders the corresponding snake-case name.
No free-form reason text is stored or signed.

Every authenticated operation carries one `AuthorizedAccountSnapshot` derived
from this object. It does not reload account endpoints after retrieving the
credential.

## Config Location Identity

The location digest uses the already-open parent directory metadata and final
component:

```text
KIRJE-CONFIG-LOCATION-V1\0
0x0001 platform:u8 (0x01 Unix, 0x02 Windows)

Unix-only:
0x0010 parent_device:u64be
0x0011 parent_inode:u64be
0x0012 final_component:exact native OsStr bytes

Windows-only:
0x0020 volume_serial:u64be (native value zero-extended)
0x0021 parent_file_index:u64be
0x0022 final_component:exact native UTF-16LE units
```

Each platform transcript has exactly four fields. Windows path preflight
rejects unsafe namespaces/device aliases before opening the parent. Exact case
and UTF-16 units are retained. On a case-insensitive directory, an alternate
spelling therefore causes the registry's store-to-location uniqueness check to
fail closed; on a case-sensitive directory, distinct files remain distinct.

If parent identity cannot be obtained, the operation returns
`secure_file_semantics_unsupported`; it does not substitute a lexical path.
Parent links may resolve before opening and are not a containment guarantee.

The authority registry enforces both directions:

```text
one store ID -> one location digest
one location digest -> one store ID
```

## Bounded Open And Write

For every load, migration, or mutation:

1. Resolve the caller's selected path into parent plus final component.
2. Open the parent as one capability directory.
3. Open/create the permanent sibling lock final component with no-follow;
   validate it as regular and acquire exclusive `fs4` lock.
4. Open the config final component once with no-follow and nonblocking options.
5. Treat only a genuine final-component `NotFound` as absent. Directory,
   permission, link/reparse, malformed, and all other errors remain errors.
6. Validate the opened handle as regular.
7. Read at most 1 MiB plus one byte from that handle and require EOF.
8. Parse and validate one strict version.

Write:

1. Recheck location, store ID, generation, and exact loaded content digest under
   the same lock.
2. Serialize deterministically and reject output above 1 MiB.
3. Create an unpredictable private sibling temp file through the same open
   parent; creation is exclusive and final-component no-follow.
4. Apply private platform permissions/ACL, write all bytes, and `sync_all`.
5. Recheck CAS immediately before replacement.
6. Persist a bounded same-parent replacement journal at the fixed derived name
   `.kirje-<name-digest>.replace`. It contains transaction ID; before kind
   (`absent`, `v1`, or `v2`); optional before generation; optional before digest;
   required after generation/digest; and unpredictable temp/backup component
   names. Absent has neither before value, v1 has a digest without a generation,
   and v2 has both. Create the journal exclusively, `sync_all` it, and sync the
   parent or required platform durability equivalent before changing any name.
7. On Unix, rename temp over final through the same open parent and sync the
   parent. On Windows, rename final to the unique backup and temp to final under
   the same lock; no delete-then-rename fallback is permitted.
8. Reopen the final component through the same parent, verify the after digest,
   then remove backup and journal. Return the new generation and digest.

Every load first acquires the same lock and resolves a replacement journal.
The only recoverable Windows shapes are:

```text
final=after                                      -> clean up
final=before, temp=after                         -> continue forward
final=absent, backup=before, temp=after           -> install temp
final=absent, backup=before, temp=absent          -> restore before
final=absent, backup=absent, temp=after           -> install fresh/migrated temp
```

Any other digest/object combination enters `recovery_required`. The two-rename
gap is invisible to Kirje readers because recovery precedes every read under
the lock. Kirje claims filesystem-atomic overwrite only where the platform
primitive provides it; Windows guarantees locked, journaled crash recovery
instead.

`name-digest` is lowercase hex SHA-256 of
`KIRJE-LOCAL-NAME-V1\0 || exact-final-component-native-bytes`. The sibling lock
is `.kirje-<name-digest>.lock`; generated temp and backup names use the safe
fixed prefix `.kirje-<name-digest>-` plus a CSPRNG hex suffix. Recovery opens
every sibling relative to the already-open parent with no-follow and validates
regular-file identity. A platform that cannot establish journal-entry and
rename durability returns `secure_file_semantics_unsupported` rather than
silently weakening the protocol.

Locking coordinates Kirje processes. Generation/content CAS is the correctness
check. Neither is represented as protection against an out-of-bound writer with
the same unrestricted OS access.

## V1 Migration

### Input

The strict legacy parser accepts only:

```toml
version = 1
[[accounts]]
id = "..."
...
```

It applies current account validation and rejects duplicate display IDs. It
never calls keyring, authority, network, protocol adapters, or owner proof APIs.

### Transform

Under one config lock:

1. Parse and validate the complete bounded v1 document.
2. Generate one store ID and independent account/credential IDs.
3. Compute each candidate account binding.
4. Set every account to binding `quarantined`, credential
   `legacy_quarantined`, reason `legacy_unbound`, generation 1.
5. Set document generation 1.
6. Serialize, write, sync, and replace once.

Generated IDs exist only in the candidate until rename commits. A crash before
rename leaves v1; a crash after rename leaves complete v2. The next load reads
committed IDs and never regenerates them.

### Post-Migration

- Read-only bounded inspection is available.
- Authentication, credential presence checks, account writes, and remote
  effects are denied before owner trust and store enrollment.
- Owner-authorized store enrollment records the location/store mapping.
- Each legacy account receives an owner-authorized binding transition and a
  legacy delete-only cleanup tombstone.
- The credential must be re-entered for the v2 locator before readiness.
- No workflow reads/tests/copies a legacy credential.

## Authority Registration

The config projection is not authoritative by itself. Before active credential
or governed work, the fixed authority store must match:

```text
realm ID
store ID and location digest
config generation and digest
account ID and generation
credential ID
account binding digest
account state
```

A copied config with the same store ID at another location, a different store
ID at an enrolled location, or a config digest that does not match an in-flight
transition returns a stable conflict before any keyring call.

## Credential Ports

Active and cleanup capabilities are separate. `ActiveSecretStore` remains a
runtime-facing port. The lower-level workspace crate `crates/kirje-credential`
has `publish = false`, is a direct dependency of `kirje-store` only, and owns
the cleanup locator and concrete delete-only keyring backend. `kirje-runtime`,
`kirje-core`, `kirje-cli`, `kirje-mcp`, `kirje-protocol`, and every other
workspace crate neither depends directly on nor receives or re-exports this
crate.

```rust
trait ActiveSecretStore {
    fn set(&self, locator: &ActiveCredentialLocator, secret: &SecretString) -> Result<(), MailError>;
    fn get(&self, locator: &ActiveCredentialLocator) -> Result<SecretString, MailError>;
    fn contains(&self, locator: &ActiveCredentialLocator) -> Result<bool, MailError>;
    fn delete_active(&self, locator: &ActiveCredentialLocator) -> Result<(), MailError>;
}

pub struct DeleteOnlyLocator { /* private canonical fields */ }

pub fn delete_only(locator: DeleteOnlyLocator) -> Result<(), MailError>;
```

`DeleteOnlyLocator` is opaque, non-`Clone`, non-`Debug`, non-serializable, and
has no raw field/byte export or conversion to `ActiveCredentialLocator`.
`kirje-credential` exposes the checked locator constructor and `delete_only`
only as the Rust-visible surface required by its sole direct Cargo consumer;
the crate remains unpublished and these items are not product/workspace APIs.
Rust has no friend-crate visibility, so the enforceable boundary is the exact
workspace Cargo direct-dependency allowlist, not a claim of Rust privacy. The
constructor accepts the complete canonical locator transcript plus expected
kind/digest and retains only the private parsed service/username needed by the
backend. There is no public or sealed janitor trait and no pluggable deletion
surface. Both deletion and an already-absent keyring entry return `Ok(())`;
there is no presence bit or outcome enum.

`kirje-store` owns opaque `CleanupDeletePermit`, including the fixed apply-lock
guard and the validated private locator source. The sole public cleanup deletion
API is one combined `AuthorityStore`/cleanup service method. Under the permit's
apply lock it constructs `DeleteOnlyLocator`, calls
`kirje_credential::delete_only` exactly once, and records terminal authority
state after success. Authority open, read, challenge, claim validation, and
recovery-validation paths never call the keyring; this explicit consuming apply
method is the only adapter-call boundary. Runtime calls only that high-level
store API and cannot construct, inspect, export, or receive a locator, call the
low-level function, or mark cleanup deleted independently. `kirje-store` does
not re-export the locator, constructor, function, module, or crate.

A007 creates the unpublished low-level crate and opaque locator, adds the root
workspace and store-only dependency entries, and adds a store-private fake
deletion hook for authority state-machine tests. A008 adds the real low-level
keyring delete implementation and the sole production call site in the store's
combined method. T204 wires runtime and CLI application services only to the
high-level store cleanup API and migrates/removes legacy runtime `SecretStore`
paths; runtime never sees the locator or low-level backend.

## Credential Locator Transcripts

Every `credential_cleanup.locator_material` value is exactly one canonical
transcript using the authorization contract's TLV primitive:

```text
KIRJE-DELETE-ONLY-LOCATOR-V1\0
0x0001 locator_kind:u8
0x0002 service:UTF-8
0x0003 username:UTF-8
```

The three tags occur once in ascending order. Service and username reject NUL,
malformed or noncanonical UTF-8, unknown/duplicate/out-of-order tags, and
trailing bytes. Service is 1..128 bytes and characters, username is 1..1024
bytes and characters, and the complete transcript is 1..4096 bytes.
`locator_sha256` is SHA-256 of the complete domain-prefixed transcript, never a
hash of an implementation struct, concatenated strings, or only the username.

Canonical byte goldens may commit deterministic, clearly synthetic, non-real
locator transcript bytes only inside Rust test source. Signature fixtures never
contain locator transcripts. Evidence, output, events, errors, and logs record
only synthetic vector IDs, expected digests, cardinalities, and pass/fail
results. Real or private locator bytes are prohibited from every committed
source, fixture, evidence, or generated artifact.

The closed locator forms are:

| Kind | Service | Username |
| --- | --- | --- |
| `active_v2` (`0x01`) | exact `dev.kirje.mail.credentials.v2` | exact `v2:` plus 64 lowercase hexadecimal characters for the V2 locator digest derived from realm, store, account, historical credential, and historical binding |
| `legacy_v1` (`0x02`) | exact `dev.kirje.mail` | exact validated historical display-ID bytes from the origin transition's before snapshot |

An `active_v2` cleanup rederives the documented V2 digest from the immutable
historical-before tuple. A `legacy_v1` cleanup never substitutes a current or
recreated account's display ID. Any other service, username shape, uppercase
hexadecimal character, locator kind, or digest relationship is
`credential_cleanup_invalid` before low-level backend access.

## Locator V2

```text
service = dev.kirje.mail.credentials.v2
username = v2:<lowercase SHA-256 hex>
```

Digest input:

```text
KIRJE-CREDENTIAL-LOCATOR-V2\0
owner realm
store ID
account ID
credential ID
binding digest
```

The old `dev.kirje.mail/<display-id>` form is never used by active set/get/
contains/delete, migration, status, or doctor. It can appear only as private
delete-only tombstone material after owner authorization, encoded as the exact
`legacy_v1` transcript above.

## Account Lifecycle

### Create

1. Build/validate a proposed complete account and random account/credential IDs.
2. Build a control manifest with expected config generation/digest.
3. Obtain owner receipt and claim the grant.
4. Prepare the authority transition, which reserves all identities and blocks
   the store before config access.
5. Create only if display ID and IDs remain absent under config lock/CAS.
6. Report the exact committed after generation/digest to authority and mark the
   transition config-committed.
7. Finalize the registry account as active while its config binding remains
   `proposed/reentry_required`, then unblock the store.
8. Credential set is a separate owner-authorized action.

The authority admits one config transition per store. Before the config replace,
an abort marks the proposed registry account `removed` and preserves that row
plus every account, credential, receipt, grant, and transition identity
permanently; supported paths never physically delete it. After the replace,
recovery marks config committed and finalizes
without repeating config work. Any pair other than the exact before/after pair
leaves the store recovery-required and the reserved account blocked; it never
probes a credential or connects. Canonical v1 has no recovery-clearing or
successor mutation for that store row through T202E: the exact unsafe pair and
recovery-required state remain available for deterministic restart projection.
Clearing that terminal state requires a separately reviewed post-v1 schema and
product contract.

Prepare also reserves the credential ID in the immutable credential registry.
Its `created_at` equals the transition prepare time and prepare state-event time.
Marking the after config committed inserts the immutable store version, then the
immutable account version, updates the transition to config-committed, advances
the blocked current store projection, appends the event, and updates the paired
clock in that exact order. Both version `created_at` values, transition
`config_committed_at`, current-store `updated_at`, event time, and paired clock
are the same effective observation time. Dedicated faults after credential,
store-version, and account-version insertion prove rollback at each boundary.
Historical remote effects refer to those version rows rather than mutable
current registry tuples, so later account or config updates cannot invalidate
old audit relationships or be blocked by them.

### Update

Binding-preserving metadata is not introduced in v0.3.1. Every supported
account update is explicit and compares the complete old/new snapshots.

If email, username, credential kind, endpoint, port, protocol, transport, or
SMTP presence changes:

- account ID and display ID remain
- account generation increments
- a new credential ID is generated
- old credential becomes unreachable
- a provisional delete-only tombstone is committed with the transition
- binding becomes authorized only under the new owner receipt
- credential becomes `reentry_required`

Canonical-equivalent DNS/IP host text may preserve the binding, but the update
still requires the explicit owner-authorized CAS path. Email/username case
changes alter the binding.

### Remove And Recreate

Remove blocks the account, commits cleanup tombstones, removes it from active
config, and preserves authority history. Reusing the display ID later creates a
new account and credential ID. Old operation references cannot resolve to the
new account.

Account removal is not exposed until every index/ledger lookup uses stable
account ID or has an explicit migration mapping.

## Credential Mutation Crash Order

### Set

```text
grant use + transition prepare
-> hidden prompt
-> keyring set new locator
-> config commit bound
-> authority finalize
```

Crash after keyring set but before config commit leaves an unreachable orphan.
Recovery never probes it as active; an owner-authorized cleanup may delete it.

### Delete

```text
grant use + transition prepare
-> idempotent keyring delete active locator
-> config commit missing
-> authority finalize
```

Crash after delete leaves config temporarily claiming `bound`, but authority
transition blocks authentication. Recovery repeats only idempotent delete and
commits missing.

### Binding Change

```text
grant use + transition prepare with provisional old-locator tombstone
-> config commit new credential ID/reentry_required + cleanup ID
-> authority finalize cleanup ready
```

Cleanup never reads or tests the old credential.

### Retired Cleanup

Cleanup challenge and claim bind the immutable origin transition's historical
before account generation, credential identity, binding digest, and, for a
legacy locator, display ID. A later account update, removal, recreation, or
credential change does not rebind this origin. The authority store admits only
a finalized, transition-bound cleanup created in provisional state and later
made ready; canonical v1 treats a persisted cleanup without `transition_id` as
corruption. The schema remains unchanged and the core optional transcript field
remains parseable, but no supported v1 operation accepts the absent form.

Claim yields an opaque `CleanupDeletePermit` that owns the fixed cleanup apply
lock and the validated private locator source. The permit is non-`Clone`,
non-`Debug`, non-serializable, and has no byte, service, username, or locator
export. Only the combined consuming cleanup apply service may accept it. Under
that lock the service constructs the opaque locator, invokes the low-level
delete function exactly once, and records terminal authority state after an
indistinguishable delete/already-absent `Ok(())`; there is no public or
caller-owned `mark_deleted` operation. A backend failure leaves authority state
claimed. An exact retry may obtain another permit only after reacquiring the
same apply lock; a deleted retry returns only the terminal projection and never
calls the low-level backend again.

## Readiness Snapshot

Runtime authenticates only from:

```rust
struct AuthorizedAccountSnapshot {
    realm_id: OwnerRealmId,
    store_id: StoreId,
    config_generation: NonZeroU64,
    config_sha256: Sha256Digest,
    account_id: AccountId,
    account_generation: NonZeroU64,
    credential_id: CredentialId,
    binding_sha256: BindingDigest,
    account: MailAccountConfig,
    locator: ActiveCredentialLocator,
}
```

Construction rechecks the pinned registry. Adapter invocation consumes this
snapshot and the retrieved secret together. No account or endpoint reload is
allowed between lookup and TLS authentication.

## Public Status

```json
{
  "display_id": "example",
  "account_id": "<stable uuid>",
  "store_state": "registered",
  "owner_state": "ready",
  "binding_state": "authorized",
  "credential_state": "ready",
  "ready_for_authentication": true,
  "reason_code": null
}
```

Status does not probe legacy entries and omits store/credential IDs, binding and
location digests, locator material, trust bytes, and cross-account keyring
presence. When the active keyring backend is unavailable, state is
public `credential_state=store_unavailable`; stored credential state is not
changed and backend diagnostic text is not emitted.

Stored and public credential states are deliberately distinct:

| Stored | Public |
|---|---|
| `legacy_quarantined` | `legacy_quarantined` |
| `reentry_required` | `reentry_required` |
| `missing` | `missing` |
| `bound` plus matching authority/keyring context | `ready` |
| `invalidated` | `invalidated` |

Core uses separate non-convertible enums `StoredCredentialState` and
`PublicCredentialState`; `store_unavailable` exists only in the public enum and
can never enter `AccountSnapshot` or config serialization.

Config parse/migration failure uses stable error `config_migration_failed` and
public reason code `config_migration`; neither includes parser or path content.

## CLI Boundary

Account and secret writes are planned control actions:

```text
store init
store status
store enroll-plan
store apply <operation-id>
account create-plan
account update-plan
account remove-plan
account apply <operation-id>
secret set-plan
secret delete-plan
secret cleanup-plan
secret apply <operation-id>
```

`store init` only creates an empty unregistered config. `store enroll-plan`
freezes the exact `ConfigCas` and store-enroll manifest. `store apply` recovers
any replacement journal, rechecks the CAS under the config lock, consumes the
grant, and inserts the unique store/location mapping in one authority
transaction. It does not modify config or access keyring/network. An exact
retry returns the existing receipt; either uniqueness-direction conflict
returns `config_store_identity_conflict`.

Apply accepts an operation ID only. Proof submission occurs through the
authorization command; no account/secret command accepts inline signature,
proof, key, nonce, trust, policy override, or secret argument. Credential bytes
use a hidden TTY prompt only after authorization recheck and grant claim.

MCP exposes bounded discovery/status, including read-only store status, and
existing shared non-control services. It has no account, secret, cleanup, or
store-enrollment mutation.

## Stable Failure Codes

```text
account_already_exists
account_identity_conflict
account_update_conflict
config_store_identity_conflict
config_migration_failed
config_version_unsupported
config_concurrent_update
credential_legacy_quarantined
credential_reentry_required
credential_binding_invalid
credential_cleanup_invalid
secure_file_semantics_unsupported
owner_authorization_required
```

Errors do not include address, username, endpoint, path, IDs other than the
explicit caller target, digests, locator, keyring backend detail, or credential
presence in another account/store.

## Required Tests

- account binding golden bytes/digest and one-field mutation cases
- DNS case/IP canonical equivalence and email/username exact-case differences
- create-only duplicate display ID under sequential and concurrent writers
- v1 migration, duplicate rejection, restart at every write boundary, and
  newer-version rejection
- config exact limit, plus one, link/reparse, directory, FIFO/device, path
  replacement, permissions, and malformed state
- generation/content CAS and two-process lost-update prevention
- copied config/store/location conflicts with zero keyring calls
- no legacy get/contains calls in migration, status, doctor, or authentication
- credential set/delete/update crash windows and unreachable orphan behavior
- canonical active-v2/legacy-v1 reservation constructor and origin-rederived
  prepare rejection before row insertion
- lower credential crate `publish = false` and direct-dependency allowlist:
  Cargo metadata/tree proves only `kirje-store` directly depends on it
- exactly one production `kirje_credential::delete_only(` call site, located in
  the store's combined apply method, and no store re-export of low-level APIs
- compile-fail fixture proves runtime cannot import or name
  `kirje_credential` because it is not a dependency
- opaque locator negative tests, store-private fake deletion-hook tests, and
  runtime no-constructor/no-raw-locator source scan
- delete-only combined permit method and idempotent absence behavior
- remove/recreate same display ID with no old operation/index inheritance
- account status golden output and secret/locator/digest scan
- MCP exact allowlist and no account/secret mutation schema
