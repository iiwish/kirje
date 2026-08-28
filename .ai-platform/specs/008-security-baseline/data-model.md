# Data Model: Security Baseline

## Metadata

- Feature ID: `008-security-baseline`
- Status: Confirmed
- Schema targets: account config v2, authority SQLite v1, operation ledger v3
- Updated: 2026-08-27

## Identity Types

| Type | Wire/storage form | Invariant |
|---|---|---|
| `OwnerRealmId` | 32 random bytes | Create-once; not a UUID or secret |
| `JournalId` | UUIDv4 / BLOB16 | Matches anchor and authority meta |
| `StoreId` | UUIDv4 / BLOB16 | One registered location per realm |
| `AccountId` | UUIDv4 / BLOB16 | Durable account reference |
| `CredentialId` | UUIDv4 / BLOB16 | Changes on binding change |
| `GrantId` | UUIDv4 / BLOB16 | One authorization grant |
| `ReceiptId` | UUIDv4 / BLOB16 | Immutable proof-verification result |
| `EffectId` | UUIDv4 / BLOB16 | One exact remote effect |
| `ClaimId` | UUIDv4 / BLOB16 | One authority effect claim |
| `InvocationId` | UUIDv4 / BLOB16 | One adapter-entry attempt |
| `ChallengeId` | SHA-256 / BLOB32 | Digest of exact signing payload |
| `KeyId` | SHA-256 / BLOB32 | Digest of role-tagged Ed25519 public key |
| `BindingDigest` | SHA-256 / BLOB32 | Exact account-binding transcript digest |
| `PolicyDigest` | SHA-256 / BLOB32 | Canonical policy digest when applicable |
| `ManifestDigest` | SHA-256 / BLOB32 | Exact action-manifest digest |

UUIDs must be canonical lowercase hyphenated version-4 UUIDs at text
boundaries. No deserialization default generates an identity. All random values
use the operating-system source and become stable only inside a committed state
transition.

## Account Config V2

### Document

```toml
version = 2
store_id = "7a40f5c0-4c4c-4be0-a62c-b1d3c5e425a7"
generation = 1

[[accounts]]
display_id = "example"
account_id = "af5fd4af-909f-4a28-895e-bc2e40de2a83"
generation = 1
email = "agent@example.test"
username = "agent@example.test"
credential_kind = "app_password"
credential_id = "0134fa7d-1d3f-4335-b7cb-287cc6d9f9e8"
binding_version = 1
binding_sha256 = "<64-lowercase-hex>"
binding_state = "quarantined"
credential_state = "legacy_quarantined"
state_reason = "legacy_unbound"
pending_cleanup_ids = []

[accounts.incoming]
protocol = "imap"
host = "imap.example.test"
port = 993
security = "implicit_tls"
```

The optional `[accounts.outgoing]` table has the same endpoint fields and must
use SMTP. All structs use `deny_unknown_fields`.

### Document Invariants

- `version == 2` and `generation > 0`.
- Exactly one valid `store_id` exists.
- At most 100 accounts exist.
- `display_id`, `account_id`, and `credential_id` are each unique within the
  document.
- Every account generation is positive.
- Stored binding digest equals a fresh digest of the validated fields.
- `display_id` is immutable for one `account_id`.
- `legacy_quarantined` is valid only with a quarantined binding and never with
  ready authentication.
- `bound` requires an authorized binding and a matching active authority
  registration.
- `removed` accounts do not remain in the active account list; their identity
  and cleanup references remain in authority history.
- `pending_cleanup_ids` contains unique authority cleanup IDs only and exposes
  no locator material.
- Maximum encoded config length is 1 MiB. Malformed, over-limit, duplicate, or
  invalid documents are not partially loaded.

### Account States

`binding_state`:

```text
quarantined | proposed | authorized | invalidated | mismatch
```

`credential_state`:

```text
legacy_quarantined | reentry_required | missing | bound | invalidated
```

Readiness derives from config plus authority and keyring results; it is not
stored as an independently mutable boolean.

## Account Binding V1

Domain: `KIRJE-ACCOUNT-BINDING-V1\0`.

Fields in strict tag order:

| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | exact email | validated UTF-8 bytes |
| `0x0002` | exact authentication username | validated UTF-8 bytes |
| `0x0003` | credential kind | fixed u8 code |
| `0x0010` | IMAP protocol | fixed u8 code |
| `0x0011` | IMAP host | normalized tagged DNS/IP bytes |
| `0x0012` | IMAP port | u16 big-endian |
| `0x0013` | IMAP security | fixed u8 code |
| `0x0020` | SMTP presence | zero/one byte |
| `0x0021` | SMTP protocol | fixed u8 code or zero length |
| `0x0022` | SMTP host | normalized tagged DNS/IP bytes or zero length |
| `0x0023` | SMTP port | u16 big-endian or zero length |
| `0x0024` | SMTP security | fixed u8 code or zero length |

DNS host bytes are lowercase ASCII. IP values are parsed and emitted as
canonical `IpAddr::to_string()` ASCII with an explicit IP-family tag. Email and
username bytes are not case-folded or Unicode-normalized.

Fixed codes are independent of Rust enum order:

```text
CredentialKind:u8       password=0x01 app_password=0x02 oauth2=0x03
Protocol:u8             imap=0x01 smtp=0x02 jmap=0x03
TransportSecurity:u8    implicit_tls=0x01 starttls=0x02 https=0x03
HostKind:u8             dns_ascii=0x01 ipv4=0x02 ipv6=0x03
```

OAuth2 and JMAP values are parseable for forward-compatible inspection but
cannot enter the v0.3.1 active/bound state. Host value is
`HostKind || canonical_host_ascii`. The transcript always contains all twelve
tags. `0x0020` is exactly `0x00` or `0x01`; when zero, tags `0x0021`-`0x0024`
all have zero length, and when one all four are nonempty with their fixed
lengths. Any other shape is invalid.

## Owner Anchor V1

Path: platform `config_dir/owner-trust.toml`. Maximum size: 16 KiB.

Fields:

```text
version
realm_id
journal_id
journal_location_sha256
minimum_epoch
owner_key_id
owner_public_key
recovery_key_id
recovery_public_key
trust_bundle_sha256
state
```

The anchor is created once by bootstrap and updated only by owner/recovery
rotation protocol. Public keys are 32 bytes. The file contains no mailbox
credential, private signing key, challenge, proof, or operation content.

The journal must match every pinned field. A missing journal, path mismatch,
journal ID mismatch, lower active epoch, unknown active key, or bundle mismatch
sets `recovery_required` before credential or network access.

## Authority SQLite V1

### Database Pragmas

```text
application_id = KIRJE_AUTHORITY_APPLICATION_ID
user_version = 1
foreign_keys = ON
trusted_schema = OFF
journal_mode = WAL
synchronous = FULL
busy_timeout = bounded project constant
```

The database opens only at the fixed platform path. Test path injection is
available only through a non-production constructor that requires a complete
isolated authority-home object.

In the schema listings, `BLOB16`, `BLOB32`, and `BLOB64` are normative
shorthand for `BLOB NOT NULL CHECK(typeof(column) = 'blob' AND
length(column)=16|32|64)`. `BLOB16?`, `BLOB32?`, and `BLOB64?` are the nullable
forms and mean `BLOB CHECK(column IS NULL OR (typeof(column) = 'blob' AND
length(column)=N))`. A repeated `NOT NULL` beside a non-null shorthand is
declarative redundancy, not a different type. Rust validates the same type and
length constraints before writes and after reads; SQLite type affinity alone
is never the boundary.

### `authority_meta`

Singleton row:

```text
singleton INTEGER PRIMARY KEY CHECK(singleton = 1)
journal_id BLOB16 UNIQUE NOT NULL
realm_id BLOB32 UNIQUE NOT NULL
active_epoch INTEGER NOT NULL CHECK(active_epoch > 0)
trust_bundle_sha256 BLOB32 NOT NULL
last_observed_at INTEGER NOT NULL
created_at INTEGER NOT NULL
updated_at INTEGER NOT NULL
```

### `authority_keys`

```text
key_id BLOB32 PRIMARY KEY
role TEXT CHECK(role IN ('owner','recovery'))
public_key BLOB32 NOT NULL
state TEXT CHECK(state IN ('active','retired','revoked'))
valid_from_epoch INTEGER NOT NULL
valid_to_epoch INTEGER
installed_at INTEGER NOT NULL
retired_at INTEGER
```

Partial unique indexes permit one active key per role. Historical keys are
retained for receipt re-verification.

### `trust_epochs`

```text
epoch INTEGER PRIMARY KEY CHECK(epoch > 0)
owner_key_id BLOB32 REFERENCES authority_keys
recovery_key_id BLOB32 REFERENCES authority_keys
bundle_sha256 BLOB32 UNIQUE NOT NULL
state TEXT CHECK(state IN ('staged','active','retired'))
predecessor_epoch INTEGER
transition_receipt_id BLOB16?
new_key_proof BLOB64?
staged_at INTEGER NOT NULL
activated_at INTEGER
```

One partial unique index permits one active epoch. Rotation stages journal
state, atomically replaces the anchor, then finalizes the matching staged epoch.
Open-time recovery may finalize only a fully signed staged transition matching
the anchor; every other mismatch enters recovery.

### `registered_stores`

```text
store_id BLOB16 PRIMARY KEY
location_material BLOB NOT NULL CHECK(length(location_material) BETWEEN 1 AND 4096)
location_sha256 BLOB32 UNIQUE NOT NULL
config_generation INTEGER NOT NULL
config_sha256 BLOB32 NOT NULL
state TEXT CHECK(state IN ('active','blocked','removed','recovery_required'))
enrolled_receipt_id BLOB16 NOT NULL
active_transition_id BLOB16?
updated_at INTEGER NOT NULL
```

Both `store_id -> location_sha256` and `location_sha256 -> store_id` are unique.
`location_material` is private, bounded, platform-tagged parent identity plus
final component data. Normal status returns only state and a digest prefix.

### `registered_accounts`

```text
account_id BLOB16 PRIMARY KEY
store_id BLOB16 REFERENCES registered_stores
display_id_sha256 BLOB32 NOT NULL
account_generation INTEGER NOT NULL
credential_id BLOB16 UNIQUE NOT NULL
binding_sha256 BLOB32 NOT NULL
state TEXT CHECK(state IN ('proposed','active','blocked','removed'))
authorized_receipt_id BLOB16 NOT NULL
updated_at INTEGER NOT NULL
```

The authority store does not need the clear email, username, endpoint, or
display ID to enforce identity. The complete old/new snapshots live in the
bounded private control manifest and config projection.

`CREATE UNIQUE INDEX registered_accounts_active_display_id ON
registered_accounts(store_id, display_id_sha256)
WHERE state IN ('proposed','active','blocked')`
prevents two current identities from using one display ID while retaining
immutable removed history. Recreating a removed display ID always allocates a
new account and credential ID; it never updates or deletes the historical row.

### `account_transitions`

```text
transition_id BLOB16 PRIMARY KEY
grant_id BLOB16 UNIQUE NOT NULL
store_id BLOB16 NOT NULL
account_id BLOB16?
kind TEXT NOT NULL
before_config_sha256 BLOB32?
after_config_sha256 BLOB32 NOT NULL
expected_generation INTEGER NOT NULL
next_generation INTEGER NOT NULL
state TEXT CHECK(state IN ('prepared','config_committed','finalized','aborted','recovery_required'))
prepared_at INTEGER NOT NULL
finalized_at INTEGER
```

Recovery compares the actual config digest with `before_config_sha256` and
`after_config_sha256`. Before may retry/abort; after may finalize; any third
value enters recovery and blocks credentials/network.

### `credential_cleanup`

```text
cleanup_id BLOB16 PRIMARY KEY
transition_id BLOB16? REFERENCES account_transitions
locator_kind TEXT CHECK(locator_kind IN ('active_v2','legacy_v1'))
locator_material BLOB NOT NULL CHECK(length(locator_material) BETWEEN 1 AND 4096)
locator_sha256 BLOB32 UNIQUE NOT NULL
state TEXT CHECK(state IN ('provisional','ready','claimed','deleted'))
claim_id BLOB16? UNIQUE
created_at INTEGER NOT NULL
deleted_at INTEGER
```

The Rust API exposes `DeleteOnlyLocator`, which has no conversion to an active
locator and supports only idempotent delete. No cleanup path may call get,
contains, list, copy, export, test, or set.

### `authorization_challenges`

```text
challenge_id BLOB32 PRIMARY KEY
grant_id BLOB16 UNIQUE NOT NULL
action TEXT NOT NULL
target_kind TEXT NOT NULL
target_id BLOB NOT NULL CHECK(length(target_id) BETWEEN 1 AND 256)
store_id BLOB16?
account_id BLOB16?
manifest BLOB NOT NULL CHECK(length(manifest) BETWEEN 1 AND 4194304)
manifest_sha256 BLOB32 NOT NULL
signing_payload BLOB NOT NULL CHECK(length(signing_payload) BETWEEN 1 AND 4194304)
signing_sha256 BLOB32 NOT NULL
key_id BLOB32 NOT NULL
trust_epoch INTEGER NOT NULL
bundle_sha256 BLOB32 NOT NULL
binding_sha256 BLOB32?
policy_sha256 BLOB32?
nonce BLOB32 UNIQUE NOT NULL
issued_at INTEGER NOT NULL
expires_at INTEGER NOT NULL
state TEXT CHECK(state IN ('pending','authorized','expired','invalidated'))
CHECK(expires_at > issued_at AND expires_at - issued_at <= 900000)
```

Manifest and signing payload have 4 MiB limits enforced in Rust and SQL. A
partial unique index prevents multiple pending challenges for the same exact
action/target/manifest context.

### `challenge_effects`

```text
challenge_id BLOB32 REFERENCES authorization_challenges
ordinal INTEGER NOT NULL
effect_id BLOB16 UNIQUE NOT NULL
effect_kind TEXT NOT NULL
PRIMARY KEY(challenge_id, ordinal)
```

Effect count is bounded by the closed action matrix.

### `authorization_receipts`

```text
receipt_id BLOB16 PRIMARY KEY
challenge_id BLOB32 UNIQUE NOT NULL
grant_id BLOB16 UNIQUE NOT NULL
proof_sha256 BLOB32 UNIQUE NOT NULL
key_id BLOB32 NOT NULL
signature BLOB64 NOT NULL
canonical_proof BLOB NOT NULL CHECK(length(canonical_proof) BETWEEN 1 AND 4096)
receipt BLOB NOT NULL CHECK(length(receipt) BETWEEN 1 AND 16384)
receipt_sha256 BLOB32 NOT NULL
verified_at INTEGER NOT NULL
expires_at INTEGER NOT NULL
```

Exact proof replay looks up `proof_sha256`, compares canonical bytes in constant
logical behavior, and returns the existing receipt. Any changed proof for a
consumed challenge/nonce fails.

### `nonce_uses`

```text
nonce BLOB32 PRIMARY KEY
challenge_id BLOB32 UNIQUE NOT NULL
receipt_id BLOB16 UNIQUE NOT NULL
consumed_at INTEGER NOT NULL
```

Receipt insertion, nonce insertion, and challenge consumption share one
`BEGIN IMMEDIATE` transaction.

### `grant_uses`

```text
grant_id BLOB16 PRIMARY KEY
receipt_id BLOB16 UNIQUE NOT NULL
action TEXT NOT NULL
target_kind TEXT NOT NULL
target_id BLOB NOT NULL CHECK(length(target_id) BETWEEN 1 AND 256)
use_sha256 BLOB32 NOT NULL
used_at INTEGER NOT NULL
```

Every sensitive action inserts or recovers exactly one grant use before local
or remote mutation. The row makes control-plane receipts single-use even when
no remote effect exists. Exact idempotent recovery returns the same use; changed
action or target context fails.

### `remote_effects`

```text
effect_id BLOB16 PRIMARY KEY
operation_id TEXT NOT NULL
ordinal INTEGER NOT NULL
effect_kind TEXT NOT NULL
store_id BLOB16 NOT NULL
account_id BLOB16 NOT NULL
manifest_sha256 BLOB32 NOT NULL
binding_sha256 BLOB32 NOT NULL
policy_sha256 BLOB32 NOT NULL
created_at INTEGER NOT NULL
UNIQUE(operation_id, ordinal)
```

### `effect_claims`

```text
claim_id BLOB16 PRIMARY KEY
effect_id BLOB16 UNIQUE REFERENCES remote_effects
grant_id BLOB16 REFERENCES grant_uses
operation_id TEXT NOT NULL
claim_receipt BLOB NOT NULL CHECK(length(claim_receipt) BETWEEN 1 AND 65536)
claim_sha256 BLOB32 NOT NULL
claimed_at INTEGER NOT NULL
invoke_before INTEGER NOT NULL
```

Claim insertion rechecks the full current context. `effect_id UNIQUE` is the
global claim boundary.

### `effect_invocations`

```text
invocation_id BLOB16 PRIMARY KEY
effect_id BLOB16 UNIQUE REFERENCES remote_effects
claim_id BLOB16 UNIQUE REFERENCES effect_claims
session_id BLOB16 NOT NULL
start_receipt BLOB NOT NULL CHECK(length(start_receipt) BETWEEN 1 AND 65536)
start_sha256 BLOB32 NOT NULL
started_at INTEGER NOT NULL
```

Only the process that inserts this row receives an in-memory
`InvocationPermit`. The type is non-serializable and required by the adapter
entry method. A pre-existing row never creates another permit.

### `effect_observations`

```text
observation_id BLOB32 PRIMARY KEY
effect_id BLOB16 REFERENCES remote_effects
certainty TEXT CHECK(certainty IN ('succeeded','known_no_effect','ambiguous'))
result BLOB NOT NULL CHECK(length(result) BETWEEN 1 AND 16777216)
result_sha256 BLOB32 NOT NULL
source TEXT NOT NULL
observed_at INTEGER NOT NULL
UNIQUE(effect_id)
```

Authority persists the observation before the caller-selected ledger. A missing
observation after a process died while holding the apply lock becomes one
`ambiguous` observation and is never retried automatically.

### `authority_events`

```text
sequence INTEGER PRIMARY KEY AUTOINCREMENT
entity_kind TEXT NOT NULL
entity_id BLOB NOT NULL CHECK(length(entity_id) BETWEEN 1 AND 256)
event TEXT NOT NULL
occurred_at INTEGER NOT NULL
detail BLOB NOT NULL CHECK(length(detail) BETWEEN 1 AND 65536)
detail_sha256 BLOB32 NOT NULL
```

Details are typed, bounded, and private. Supported application paths append but
never update or delete event rows. This is not a tamper-proof transparency log.

## Credential Locator V2

```text
service  = "dev.kirje.mail.credentials.v2"
username = "v2:" || lowercase_hex(SHA256(
  "KIRJE-CREDENTIAL-LOCATOR-V2\0" ||
  realm_id || store_id || account_id || credential_id || binding_sha256
))
```

The locator is non-secret but private. Active lookup receives only a fully
validated `ActiveCredentialLocator`; legacy and retired cleanup receives only a
`DeleteOnlyLocator`.

The legacy service/username pair remains identifiable for owner-authorized
delete-only cleanup, but migration, status, doctor, active deletion, and normal
authentication never probe it.

## Operation Ledger V3

### Added Operation Fields

```text
store_id BLOB16?
account_id_v2 BLOB16?
identity_scope TEXT NOT NULL CHECK(identity_scope IN ('stable_account','stable_store','stable_realm','legacy_terminal','replan_required'))
manifest_version INTEGER
manifest BLOB
manifest_sha256 BLOB32?
authorization_state TEXT
authorization_receipt_id BLOB16?
authorization_receipt_sha256 BLOB32?
remote_effect_id BLOB16?
effect_phase TEXT
apply_claim_id BLOB16?
apply_claim_sha256 BLOB32?
invocation_id BLOB16?
observation_sha256 BLOB32?
legacy_approved_at INTEGER
legacy_origin TEXT
CHECK(
  (identity_scope = 'stable_account' AND store_id IS NOT NULL AND account_id_v2 IS NOT NULL)
  OR (identity_scope = 'stable_store' AND store_id IS NOT NULL AND account_id_v2 IS NULL)
  OR (identity_scope = 'stable_realm' AND store_id IS NULL AND account_id_v2 IS NULL)
  OR (identity_scope IN ('legacy_terminal','replan_required'))
)
CHECK(
  identity_scope != 'legacy_terminal'
  OR status IN ('sent','succeeded','failed','ambiguous','expired')
)
CHECK(
  identity_scope != 'replan_required'
  OR (authorization_state = 'replan_required'
      AND authorization_receipt_id IS NULL
      AND apply_claim_id IS NULL
      AND invocation_id IS NULL)
)
```

Payload JSON remains for public compatibility but is no longer the authority
for signing or identity. New records require an exact canonical manifest.
Every new v3 record has the scope required by its closed action policy and a
canonical manifest. Account-scoped operations require both IDs; store
enrollment requires only store ID; realm trust operations require neither.
Only migrated terminal history may use `legacy_terminal`; any nonterminal row
without one unique mapping becomes `replan_required` and cannot authorize or
apply. Rust row validation mirrors every SQL scope/status/nullability check.

Migration receives an immutable, bounded context rather than opening config:

```rust
struct LegacyAccountMap {
    legacy_display_id_sha256: Sha256Digest,
    store_id: StoreId,
    account_id: AccountId,
    account_generation: NonZeroU64,
    account_binding_sha256: BindingDigest,
}

struct LedgerV3MigrationContext {
    config_generation: NonZeroU64,
    config_sha256: Sha256Digest,
    accounts: Arc<[LegacyAccountMap]>,
}
```

Duplicate legacy digests or mappings fail migration. T204 constructs this
context from one validated config snapshot; T205 consumes only the immutable
value; T206 wires the startup transaction and never lets the store reload
config independently.

`authorization_state`:

```text
not_required | required | authorized | expired | invalidated | replan_required
```

`effect_phase`:

```text
none | registered | claimed | invoked | observed
```

### Migration Matrix

| V2 record | V3 result |
|---|---|
| draft | `not_required`, local state preserved |
| planned remote operation | `required` |
| approved remote operation | `required`, `legacy_tty_unverified` provenance |
| applying remote operation | terminal `ambiguous`, legacy provenance |
| expired | terminal preserved |
| failed | terminal preserved |
| ambiguous | terminal preserved |
| succeeded/sent | terminal preserved |

Compatible non-terminal payloads receive a stable manifest only after their
display account maps uniquely to config v2. Any missing or ambiguous mapping is
`replan_required`. Migration follows v1 to v2 to v3 inside one SQLite
transaction and is idempotent after restart.

## Account Mutation Protocol

Every account or credential mutation follows:

```text
verified owner grant
-> authority account_transition PREPARE (account blocked)
-> acquire config lock and verify generation/content CAS
-> keyring mutation in the action-specific crash-safe order
-> atomic config replacement
-> authority transition FINALIZE
```

Recovery:

- config has `before_config_sha256`: retry or owner-authorized abort
- config has `after_config_sha256`: finalize without replaying completed keyring
  work
- config has neither: set store/account `recovery_required`; do not probe a
  credential or connect

Credential set writes the new active locator before config commit. Credential
delete removes the active locator before config commit and treats absence as
idempotent. Binding change creates a new credential ID and provisional
delete-only cleanup before config commit.

## Apply Protocol

```text
1. Acquire fixed authority apply lock.
2. Load one config/account snapshot and authority context.
3. BEGIN IMMEDIATE: revalidate grant and insert/recover effect claim.
4. Project claim receipt to operation ledger.
5. BEGIN IMMEDIATE: insert effect invocation and obtain InvocationPermit.
6. Resolve active locator and load credential from the same validated snapshot.
7. Invoke exactly one adapter method with the permit.
8. Persist authority observation.
9. Project bounded observation to operation ledger.
10. Release apply lock.
```

A crash before step 5 never reaches an adapter. A crash after step 5 but before
step 8 leaves an invocation without observation; the next lock holder records
`ambiguous` and does not invoke again. A ledger copy or rollback cannot alter
steps 3 or 5.

## Public Status Projection

Account status returns bounded state, never complete private records:

```text
display_id
account_id
store_state
owner_state
binding_state
credential_state
ready_for_authentication
reason_code
```

It omits store ID, credential ID, binding digest, location digest/material,
keyring locator, full endpoint snapshot, cross-account presence, proof,
signature, and private authority history. CLI operator-only account inspection
may expose the configured non-secret endpoint fields already required for
review, but MCP and evidence remain at the bounded status projection.
