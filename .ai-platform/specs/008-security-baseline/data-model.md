# Data Model: Security Baseline

## Metadata

- Feature ID: `008-security-baseline`
- Status: Confirmed
- Schema targets: account config v2, authority SQLite v1, operation ledger v3
- Updated: 2026-08-28

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
| `EffectClaimId` | UUIDv4 / BLOB16 | One authority effect claim |
| `InvocationId` | UUIDv4 / BLOB16 | One adapter-entry attempt |
| `AuthoritySessionId` | UUIDv4 / BLOB16 | One process-local apply session, durable only with an invocation |
| `OperationId` | UUIDv4 / BLOB16 | One operation in authority and ledger projections |
| `ChallengeId` | SHA-256 / BLOB32 | Digest of exact signing payload |
| `KeyId` | SHA-256 / BLOB32 | Digest of role-tagged Ed25519 public key |
| `ObservationId` | SHA-256 / BLOB32 | Digest of exact effect-observation transcript |
| `BindingDigest` | SHA-256 / BLOB32 | Exact account-binding transcript digest |
| `PolicyDigest` | SHA-256 / BLOB32 | Canonical policy digest when applicable |
| `ManifestDigest` | SHA-256 / BLOB32 | Exact action-manifest digest |

UUIDs use BLOB16 in every authority table and canonical lowercase hyphenated
version-4 UUIDs at text boundaries. No deserialization default generates an
identity. All Kirje-generated security random values use the operating-system
CSPRNG and become stable only inside a committed state transition. The explicit
non-default `test-support` feature is the only deterministic entropy injection
boundary; production constructors expose no entropy port.

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
state = normal
```

The document is strict duplicate-free TOML with `version = 1`, lowercase hex for
32-byte values, lowercase UUID text, decimal positive `minimum_epoch`, and the
single closed anchor state `normal`. Recovery status is derived and is never
written into the anchor. `minimum_epoch` rejects active or staged journal state
below its value.

The anchor is created once by bootstrap and updated only by the signed rotation
or recovery protocol. Public keys are 32 bytes. The file contains no mailbox
credential, private signing key, challenge, proof, or operation content. The
exact trust-bundle transcript, bootstrap protocol, home constructors, and match
matrix are normative in `contracts/authority-store.md`.

## Authority SQLite V1

### Database Pragmas

```sql
PRAGMA application_id = 1263096394; -- 0x4B49524A, ASCII KIRJ
PRAGMA user_version = 1;
PRAGMA foreign_keys = ON;
PRAGMA trusted_schema = OFF;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;
```

Production opening derives the fixed home and accepts only typed anchor/location
inputs. Isolated path and deterministic entropy injection exist only under the
non-default `test-support` feature. Exact open, bootstrap, mismatch, clock,
replay, transaction, and public-projection behavior is defined in
`contracts/authority-store.md`.

All u64 protocol values persisted as SQLite INTEGER are restricted to
`1..=i64::MAX`; wider values fail before a write. All timestamps are Unix
milliseconds in `0..=i64::MAX`. Rust validates every SQL invariant before writes
and after reads.

### Executable DDL Body

The following is the complete v1 schema body after the application-ID and
pristine-database preflight. It deliberately contains no transaction-control or
PRAGMA statement. `prepare_bootstrap` owns one `BEGIN IMMEDIATE`, executes this
body, inserts the initial keys, epoch, meta row, and bootstrap event, sets
`application_id` and `user_version`, and issues one `COMMIT`. Any failure or
injected crash before that commit rolls back every user object, row, and version
marker. Every foreign key uses `ON DELETE RESTRICT` because supported authority
paths delete no history.

```sql
CREATE TABLE authority_keys (
    key_id BLOB PRIMARY KEY
        CHECK(typeof(key_id) = 'blob' AND length(key_id) = 32),
    role TEXT NOT NULL
        CHECK(typeof(role) = 'text' AND role IN ('owner','recovery')),
    permission_mask INTEGER NOT NULL
        CHECK(typeof(permission_mask) = 'integer'
          AND permission_mask IN (7,8)
          AND ((role = 'owner' AND permission_mask = 7)
            OR (role = 'recovery' AND permission_mask = 8))),
    public_key BLOB NOT NULL UNIQUE
        CHECK(typeof(public_key) = 'blob' AND length(public_key) = 32),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text'
          AND state IN ('staged','active','retired','revoked')),
    valid_from_epoch INTEGER NOT NULL
        CHECK(typeof(valid_from_epoch) = 'integer' AND valid_from_epoch > 0),
    valid_to_epoch INTEGER
        CHECK(valid_to_epoch IS NULL OR
          (typeof(valid_to_epoch) = 'integer' AND valid_to_epoch >= valid_from_epoch)),
    installed_at INTEGER NOT NULL
        CHECK(typeof(installed_at) = 'integer' AND installed_at >= 0),
    retired_at INTEGER
        CHECK(retired_at IS NULL OR (typeof(retired_at) = 'integer' AND retired_at >= installed_at)),
    CHECK((state IN ('staged','active') AND valid_to_epoch IS NULL AND retired_at IS NULL)
       OR (state IN ('retired','revoked') AND valid_to_epoch IS NOT NULL AND retired_at IS NOT NULL)),
    UNIQUE(key_id, role, permission_mask)
) STRICT;

CREATE UNIQUE INDEX authority_keys_one_active_role
ON authority_keys(role) WHERE state = 'active';
CREATE UNIQUE INDEX authority_keys_one_staged_role
ON authority_keys(role) WHERE state = 'staged';

CREATE TRIGGER authority_keys_identity_immutable
BEFORE UPDATE OF key_id, role, permission_mask, public_key, valid_from_epoch
ON authority_keys
WHEN NEW.key_id <> OLD.key_id
  OR NEW.role <> OLD.role
  OR NEW.permission_mask <> OLD.permission_mask
  OR NEW.public_key <> OLD.public_key
  OR NEW.valid_from_epoch <> OLD.valid_from_epoch
BEGIN
    SELECT RAISE(ABORT, 'authority key identity is immutable');
END;

CREATE TABLE trust_epochs (
    epoch INTEGER PRIMARY KEY
        CHECK(typeof(epoch) = 'integer' AND epoch > 0),
    owner_key_id BLOB NOT NULL
        CHECK(typeof(owner_key_id) = 'blob' AND length(owner_key_id) = 32),
    recovery_key_id BLOB NOT NULL
        CHECK(typeof(recovery_key_id) = 'blob' AND length(recovery_key_id) = 32),
    bundle_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(bundle_sha256) = 'blob' AND length(bundle_sha256) = 32),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text' AND state IN ('staged','active','retired')),
    predecessor_epoch INTEGER
        CHECK(predecessor_epoch IS NULL OR
          (typeof(predecessor_epoch) = 'integer' AND predecessor_epoch > 0
           AND predecessor_epoch < 9223372036854775807
           AND epoch = predecessor_epoch + 1)),
    rotation_kind TEXT
        CHECK(rotation_kind IS NULL OR
          (typeof(rotation_kind) = 'text'
           AND rotation_kind IN ('owner_rotate','recovery_rotate','owner_recover'))),
    transition_receipt_id BLOB
        CHECK(transition_receipt_id IS NULL OR
          (typeof(transition_receipt_id) = 'blob' AND length(transition_receipt_id) = 16)),
    new_owner_key_proof BLOB
        CHECK(new_owner_key_proof IS NULL OR
          (typeof(new_owner_key_proof) = 'blob' AND length(new_owner_key_proof) = 64)),
    new_recovery_key_proof BLOB
        CHECK(new_recovery_key_proof IS NULL OR
          (typeof(new_recovery_key_proof) = 'blob' AND length(new_recovery_key_proof) = 64)),
    staged_at INTEGER NOT NULL
        CHECK(typeof(staged_at) = 'integer' AND staged_at >= 0),
    activated_at INTEGER
        CHECK(activated_at IS NULL OR
          (typeof(activated_at) = 'integer' AND activated_at >= staged_at)),
    retired_at INTEGER
        CHECK(retired_at IS NULL OR
          (typeof(retired_at) = 'integer' AND activated_at IS NOT NULL
           AND retired_at >= activated_at)),
    CHECK(owner_key_id <> recovery_key_id),
    CHECK((predecessor_epoch IS NULL AND epoch = 1 AND state = 'active'
           AND rotation_kind IS NULL AND transition_receipt_id IS NULL
           AND new_owner_key_proof IS NULL AND new_recovery_key_proof IS NULL
           AND activated_at IS NOT NULL AND retired_at IS NULL)
       OR (predecessor_epoch IS NOT NULL AND epoch > 1 AND rotation_kind IS NOT NULL
           AND transition_receipt_id IS NOT NULL
           AND ((rotation_kind = 'owner_rotate' AND new_owner_key_proof IS NOT NULL
                 AND new_recovery_key_proof IS NULL)
             OR (rotation_kind = 'recovery_rotate' AND new_owner_key_proof IS NULL
                 AND new_recovery_key_proof IS NOT NULL)
             OR (rotation_kind = 'owner_recover' AND new_owner_key_proof IS NOT NULL
                 AND new_recovery_key_proof IS NOT NULL)))),
    CHECK((state = 'staged' AND activated_at IS NULL AND retired_at IS NULL)
       OR (state = 'active' AND activated_at IS NOT NULL AND retired_at IS NULL)
       OR (state = 'retired' AND activated_at IS NOT NULL AND retired_at IS NOT NULL)),
    FOREIGN KEY(owner_key_id) REFERENCES authority_keys(key_id) ON DELETE RESTRICT,
    FOREIGN KEY(recovery_key_id) REFERENCES authority_keys(key_id) ON DELETE RESTRICT,
    FOREIGN KEY(predecessor_epoch) REFERENCES trust_epochs(epoch) ON DELETE RESTRICT,
    FOREIGN KEY(transition_receipt_id) REFERENCES authorization_receipts(receipt_id) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX trust_epochs_one_active
ON trust_epochs(state) WHERE state = 'active';
CREATE UNIQUE INDEX trust_epochs_one_staged
ON trust_epochs(state) WHERE state = 'staged';
CREATE UNIQUE INDEX trust_epochs_one_staged_successor
ON trust_epochs(predecessor_epoch) WHERE state = 'staged';

CREATE TRIGGER trust_epochs_key_roles_insert
BEFORE INSERT ON trust_epochs
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM authority_keys
        WHERE key_id = NEW.owner_key_id AND role = 'owner' AND permission_mask = 7
          AND valid_from_epoch <= NEW.epoch
          AND (NEW.epoch <> 1 OR (state = 'active' AND valid_from_epoch = 1))
    ) THEN RAISE(ABORT, 'trust epoch owner key role mismatch') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM authority_keys
        WHERE key_id = NEW.recovery_key_id AND role = 'recovery' AND permission_mask = 8
          AND valid_from_epoch <= NEW.epoch
          AND (NEW.epoch <> 1 OR (state = 'active' AND valid_from_epoch = 1))
    ) THEN RAISE(ABORT, 'trust epoch recovery key role mismatch') END;
END;

CREATE TRIGGER trust_epochs_key_roles_update
BEFORE UPDATE OF owner_key_id, recovery_key_id ON trust_epochs
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM authority_keys
        WHERE key_id = NEW.owner_key_id AND role = 'owner' AND permission_mask = 7
          AND valid_from_epoch <= NEW.epoch
          AND (NEW.epoch <> 1 OR (state = 'active' AND valid_from_epoch = 1))
    ) THEN RAISE(ABORT, 'trust epoch owner key role mismatch') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM authority_keys
        WHERE key_id = NEW.recovery_key_id AND role = 'recovery' AND permission_mask = 8
          AND valid_from_epoch <= NEW.epoch
          AND (NEW.epoch <> 1 OR (state = 'active' AND valid_from_epoch = 1))
    ) THEN RAISE(ABORT, 'trust epoch recovery key role mismatch') END;
END;

CREATE TABLE authority_meta (
    singleton INTEGER PRIMARY KEY
        CHECK(typeof(singleton) = 'integer' AND singleton = 1),
    bootstrap_state TEXT NOT NULL
        CHECK(typeof(bootstrap_state) = 'text'
          AND bootstrap_state IN ('pending_anchor','ready')),
    journal_id BLOB NOT NULL UNIQUE
        CHECK(typeof(journal_id) = 'blob' AND length(journal_id) = 16),
    realm_id BLOB NOT NULL UNIQUE
        CHECK(typeof(realm_id) = 'blob' AND length(realm_id) = 32),
    journal_location_sha256 BLOB NOT NULL
        CHECK(typeof(journal_location_sha256) = 'blob'
          AND length(journal_location_sha256) = 32),
    active_epoch INTEGER NOT NULL
        CHECK(typeof(active_epoch) = 'integer' AND active_epoch > 0),
    trust_bundle_sha256 BLOB NOT NULL
        CHECK(typeof(trust_bundle_sha256) = 'blob' AND length(trust_bundle_sha256) = 32),
    last_observed_at INTEGER NOT NULL
        CHECK(typeof(last_observed_at) = 'integer' AND last_observed_at >= 0),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    updated_at INTEGER NOT NULL
        CHECK(typeof(updated_at) = 'integer' AND updated_at >= created_at),
    anchor_confirmed_at INTEGER
        CHECK(anchor_confirmed_at IS NULL OR
          (typeof(anchor_confirmed_at) = 'integer' AND anchor_confirmed_at >= created_at)),
    CHECK((bootstrap_state = 'pending_anchor' AND anchor_confirmed_at IS NULL)
       OR (bootstrap_state = 'ready' AND anchor_confirmed_at IS NOT NULL)),
    FOREIGN KEY(active_epoch) REFERENCES trust_epochs(epoch) ON DELETE RESTRICT
) STRICT;

CREATE TABLE registered_stores (
    store_id BLOB PRIMARY KEY
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    location_material BLOB NOT NULL
        CHECK(typeof(location_material) = 'blob'
          AND length(location_material) BETWEEN 1 AND 4096),
    location_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(location_sha256) = 'blob' AND length(location_sha256) = 32),
    config_generation INTEGER NOT NULL
        CHECK(typeof(config_generation) = 'integer' AND config_generation > 0),
    config_sha256 BLOB NOT NULL
        CHECK(typeof(config_sha256) = 'blob' AND length(config_sha256) = 32),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text'
          AND state IN ('active','blocked','removed','recovery_required')),
    enrolled_receipt_id BLOB NOT NULL UNIQUE
        CHECK(typeof(enrolled_receipt_id) = 'blob' AND length(enrolled_receipt_id) = 16),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    updated_at INTEGER NOT NULL
        CHECK(typeof(updated_at) = 'integer' AND updated_at >= created_at),
    removed_at INTEGER
        CHECK(removed_at IS NULL OR
          (typeof(removed_at) = 'integer' AND removed_at >= created_at)),
    CHECK((state = 'removed' AND removed_at IS NOT NULL)
       OR (state != 'removed' AND removed_at IS NULL)),
    UNIQUE(store_id, location_sha256, config_generation, config_sha256),
    FOREIGN KEY(enrolled_receipt_id) REFERENCES authorization_receipts(receipt_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE registered_accounts (
    account_id BLOB PRIMARY KEY
        CHECK(typeof(account_id) = 'blob' AND length(account_id) = 16),
    store_id BLOB NOT NULL
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    display_id_sha256 BLOB NOT NULL
        CHECK(typeof(display_id_sha256) = 'blob' AND length(display_id_sha256) = 32),
    account_generation INTEGER NOT NULL
        CHECK(typeof(account_generation) = 'integer' AND account_generation > 0),
    credential_id BLOB NOT NULL UNIQUE
        CHECK(typeof(credential_id) = 'blob' AND length(credential_id) = 16),
    binding_sha256 BLOB NOT NULL
        CHECK(typeof(binding_sha256) = 'blob' AND length(binding_sha256) = 32),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text' AND state IN ('proposed','active','blocked','removed')),
    authorized_receipt_id BLOB NOT NULL UNIQUE
        CHECK(typeof(authorized_receipt_id) = 'blob' AND length(authorized_receipt_id) = 16),
    active_transition_id BLOB UNIQUE
        CHECK(active_transition_id IS NULL OR
          (typeof(active_transition_id) = 'blob' AND length(active_transition_id) = 16)),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    updated_at INTEGER NOT NULL
        CHECK(typeof(updated_at) = 'integer' AND updated_at >= created_at),
    removed_at INTEGER
        CHECK(removed_at IS NULL OR
          (typeof(removed_at) = 'integer' AND removed_at >= created_at)),
    CHECK((state = 'removed' AND removed_at IS NOT NULL AND active_transition_id IS NULL)
       OR (state != 'removed' AND removed_at IS NULL)),
    CHECK(active_transition_id IS NULL OR state IN ('proposed','blocked')),
    UNIQUE(account_id, store_id),
    UNIQUE(account_id, store_id, account_generation, credential_id, binding_sha256),
    FOREIGN KEY(store_id) REFERENCES registered_stores(store_id) ON DELETE RESTRICT,
    FOREIGN KEY(authorized_receipt_id) REFERENCES authorization_receipts(receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY(active_transition_id) REFERENCES account_transitions(transition_id) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX registered_accounts_active_display_id
ON registered_accounts(store_id, display_id_sha256)
WHERE state IN ('proposed','active','blocked');
CREATE INDEX registered_accounts_store_state
ON registered_accounts(store_id, state);

CREATE TABLE authorization_challenges (
    challenge_id BLOB PRIMARY KEY
        CHECK(typeof(challenge_id) = 'blob' AND length(challenge_id) = 32),
    grant_id BLOB NOT NULL UNIQUE
        CHECK(typeof(grant_id) = 'blob' AND length(grant_id) = 16),
    action INTEGER NOT NULL
        CHECK(typeof(action) = 'integer'
          AND action IN (1,16,17,18,19,20,256,272,273,274,288,289,290,
                         512,513,528,529,530,544)),
    target_kind INTEGER NOT NULL
        CHECK(typeof(target_kind) = 'integer' AND target_kind IN (1,2,3,4,5,6,7,8,9)),
    target_id BLOB NOT NULL
        CHECK(typeof(target_id) = 'blob' AND length(target_id) BETWEEN 0 AND 256),
    store_id BLOB
        CHECK(store_id IS NULL OR (typeof(store_id) = 'blob' AND length(store_id) = 16)),
    account_id BLOB
        CHECK(account_id IS NULL OR (typeof(account_id) = 'blob' AND length(account_id) = 16)),
    context_sha256 BLOB NOT NULL
        CHECK(typeof(context_sha256) = 'blob' AND length(context_sha256) = 32),
    manifest BLOB NOT NULL
        CHECK(typeof(manifest) = 'blob' AND length(manifest) BETWEEN 1 AND 4194304),
    manifest_sha256 BLOB NOT NULL
        CHECK(typeof(manifest_sha256) = 'blob' AND length(manifest_sha256) = 32),
    signing_payload BLOB NOT NULL
        CHECK(typeof(signing_payload) = 'blob'
          AND length(signing_payload) BETWEEN 1 AND 4194304),
    signing_sha256 BLOB NOT NULL
        CHECK(typeof(signing_sha256) = 'blob' AND length(signing_sha256) = 32),
    key_id BLOB NOT NULL
        CHECK(typeof(key_id) = 'blob' AND length(key_id) = 32),
    trust_epoch INTEGER NOT NULL
        CHECK(typeof(trust_epoch) = 'integer' AND trust_epoch > 0),
    bundle_sha256 BLOB NOT NULL
        CHECK(typeof(bundle_sha256) = 'blob' AND length(bundle_sha256) = 32),
    binding_sha256 BLOB
        CHECK(binding_sha256 IS NULL OR
          (typeof(binding_sha256) = 'blob' AND length(binding_sha256) = 32)),
    policy_sha256 BLOB
        CHECK(policy_sha256 IS NULL OR
          (typeof(policy_sha256) = 'blob' AND length(policy_sha256) = 32)),
    nonce BLOB NOT NULL UNIQUE
        CHECK(typeof(nonce) = 'blob' AND length(nonce) = 32),
    issued_at INTEGER NOT NULL
        CHECK(typeof(issued_at) = 'integer' AND issued_at >= 0),
    expires_at INTEGER NOT NULL
        CHECK(typeof(expires_at) = 'integer' AND expires_at > issued_at
          AND expires_at - issued_at <= 900000),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text'
          AND state IN ('pending','authorized','expired','invalidated')),
    invalidated_at INTEGER
        CHECK(invalidated_at IS NULL OR
          (typeof(invalidated_at) = 'integer' AND invalidated_at >= issued_at)),
    CHECK(challenge_id = signing_sha256),
    CHECK((target_kind IN (1,2,3,4,5,9) AND length(target_id) = 16)
       OR (target_kind = 8 AND length(target_id) = 8)
       OR (target_kind IN (6,7) AND length(target_id) = 0)),
    CHECK((action IN (1,16,17,18,19,20) AND target_kind = 1)
       OR (action = 256 AND target_kind = 2)
       OR (action IN (272,273,274) AND target_kind = 3)
       OR (action IN (288,289) AND target_kind = 4)
       OR (action = 290 AND target_kind = 5)
       OR (action = 512 AND target_kind = 6)
       OR (action = 513 AND target_kind = 7)
       OR (action IN (528,529,530) AND target_kind = 8)
       OR (action = 544 AND target_kind = 9)),
    CHECK((action IN (1,16,17,18,19,20,544)
           AND store_id IS NOT NULL AND account_id IS NOT NULL
           AND binding_sha256 IS NOT NULL AND policy_sha256 IS NOT NULL)
       OR (action = 256 AND store_id IS NOT NULL AND account_id IS NULL
           AND binding_sha256 IS NULL AND policy_sha256 IS NULL)
       OR (action IN (272,273,274,288,289,290)
           AND store_id IS NOT NULL AND account_id IS NOT NULL
           AND binding_sha256 IS NOT NULL AND policy_sha256 IS NULL)
       OR (action IN (512,513,528,529,530)
           AND store_id IS NULL AND account_id IS NULL
           AND binding_sha256 IS NULL AND policy_sha256 IS NULL)),
    CHECK((state = 'invalidated' AND invalidated_at IS NOT NULL)
       OR (state != 'invalidated' AND invalidated_at IS NULL)),
    UNIQUE(challenge_id, grant_id),
    UNIQUE(challenge_id, nonce),
    UNIQUE(nonce, challenge_id),
    UNIQUE(grant_id, action, target_kind, target_id, manifest_sha256),
    UNIQUE(challenge_id, grant_id, key_id, trust_epoch, bundle_sha256,
           manifest_sha256, signing_sha256, expires_at),
    UNIQUE(challenge_id, grant_id, store_id, account_id, manifest_sha256,
           binding_sha256, policy_sha256, trust_epoch, bundle_sha256, key_id),
    FOREIGN KEY(key_id) REFERENCES authority_keys(key_id) ON DELETE RESTRICT,
    FOREIGN KEY(trust_epoch) REFERENCES trust_epochs(epoch) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX authorization_challenges_one_pending_context
ON authorization_challenges(context_sha256) WHERE state = 'pending';
CREATE INDEX authorization_challenges_state_epoch_expiry
ON authorization_challenges(state, trust_epoch, expires_at);

CREATE TABLE challenge_effects (
    challenge_id BLOB NOT NULL
        CHECK(typeof(challenge_id) = 'blob' AND length(challenge_id) = 32),
    ordinal INTEGER NOT NULL
        CHECK(typeof(ordinal) = 'integer' AND ordinal BETWEEN 0 AND 7),
    effect_id BLOB NOT NULL UNIQUE
        CHECK(typeof(effect_id) = 'blob' AND length(effect_id) = 16),
    effect_kind INTEGER NOT NULL
        CHECK(typeof(effect_kind) = 'integer' AND effect_kind IN (1,2,3,4,5,6)),
    PRIMARY KEY(challenge_id, ordinal),
    UNIQUE(challenge_id, ordinal, effect_id, effect_kind),
    FOREIGN KEY(challenge_id) REFERENCES authorization_challenges(challenge_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE authorization_receipts (
    receipt_id BLOB PRIMARY KEY
        CHECK(typeof(receipt_id) = 'blob' AND length(receipt_id) = 16),
    challenge_id BLOB NOT NULL UNIQUE
        CHECK(typeof(challenge_id) = 'blob' AND length(challenge_id) = 32),
    grant_id BLOB NOT NULL UNIQUE
        CHECK(typeof(grant_id) = 'blob' AND length(grant_id) = 16),
    proof_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(proof_sha256) = 'blob' AND length(proof_sha256) = 32),
    key_id BLOB NOT NULL
        CHECK(typeof(key_id) = 'blob' AND length(key_id) = 32),
    signature BLOB NOT NULL
        CHECK(typeof(signature) = 'blob' AND length(signature) = 64),
    canonical_proof BLOB NOT NULL
        CHECK(typeof(canonical_proof) = 'blob'
          AND length(canonical_proof) BETWEEN 1 AND 4096),
    manifest_sha256 BLOB NOT NULL
        CHECK(typeof(manifest_sha256) = 'blob' AND length(manifest_sha256) = 32),
    signing_sha256 BLOB NOT NULL
        CHECK(typeof(signing_sha256) = 'blob' AND length(signing_sha256) = 32),
    trust_epoch INTEGER NOT NULL
        CHECK(typeof(trust_epoch) = 'integer' AND trust_epoch > 0),
    bundle_sha256 BLOB NOT NULL
        CHECK(typeof(bundle_sha256) = 'blob' AND length(bundle_sha256) = 32),
    receipt BLOB NOT NULL
        CHECK(typeof(receipt) = 'blob' AND length(receipt) BETWEEN 1 AND 16384),
    receipt_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(receipt_sha256) = 'blob' AND length(receipt_sha256) = 32),
    verified_at INTEGER NOT NULL
        CHECK(typeof(verified_at) = 'integer' AND verified_at >= 0),
    expires_at INTEGER NOT NULL
        CHECK(typeof(expires_at) = 'integer' AND expires_at >= verified_at),
    UNIQUE(receipt_id, challenge_id),
    UNIQUE(receipt_id, grant_id),
    UNIQUE(grant_id, receipt_id),
    FOREIGN KEY(challenge_id, grant_id, key_id, trust_epoch, bundle_sha256,
                manifest_sha256, signing_sha256, expires_at)
        REFERENCES authorization_challenges(
            challenge_id, grant_id, key_id, trust_epoch, bundle_sha256,
            manifest_sha256, signing_sha256, expires_at
        ) ON DELETE RESTRICT,
    FOREIGN KEY(key_id) REFERENCES authority_keys(key_id) ON DELETE RESTRICT,
    FOREIGN KEY(trust_epoch) REFERENCES trust_epochs(epoch) ON DELETE RESTRICT
) STRICT;

CREATE INDEX authorization_receipts_epoch_expiry
ON authorization_receipts(trust_epoch, expires_at);

CREATE TABLE nonce_uses (
    nonce BLOB PRIMARY KEY
        CHECK(typeof(nonce) = 'blob' AND length(nonce) = 32),
    challenge_id BLOB NOT NULL UNIQUE
        CHECK(typeof(challenge_id) = 'blob' AND length(challenge_id) = 32),
    receipt_id BLOB NOT NULL UNIQUE
        CHECK(typeof(receipt_id) = 'blob' AND length(receipt_id) = 16),
    consumed_at INTEGER NOT NULL
        CHECK(typeof(consumed_at) = 'integer' AND consumed_at >= 0),
    FOREIGN KEY(nonce, challenge_id)
        REFERENCES authorization_challenges(nonce, challenge_id) ON DELETE RESTRICT,
    FOREIGN KEY(receipt_id, challenge_id)
        REFERENCES authorization_receipts(receipt_id, challenge_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE grant_uses (
    grant_id BLOB PRIMARY KEY
        CHECK(typeof(grant_id) = 'blob' AND length(grant_id) = 16),
    receipt_id BLOB NOT NULL UNIQUE
        CHECK(typeof(receipt_id) = 'blob' AND length(receipt_id) = 16),
    action INTEGER NOT NULL
        CHECK(typeof(action) = 'integer'
          AND action IN (1,16,17,18,19,20,256,272,273,274,288,289,290,
                         512,513,528,529,530,544)),
    target_kind INTEGER NOT NULL
        CHECK(typeof(target_kind) = 'integer' AND target_kind IN (1,2,3,4,5,6,7,8,9)),
    target_id BLOB NOT NULL
        CHECK(typeof(target_id) = 'blob' AND length(target_id) BETWEEN 0 AND 256),
    manifest_sha256 BLOB NOT NULL
        CHECK(typeof(manifest_sha256) = 'blob' AND length(manifest_sha256) = 32),
    use_receipt BLOB NOT NULL
        CHECK(typeof(use_receipt) = 'blob' AND length(use_receipt) BETWEEN 1 AND 16384),
    use_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(use_sha256) = 'blob' AND length(use_sha256) = 32),
    used_at INTEGER NOT NULL
        CHECK(typeof(used_at) = 'integer' AND used_at >= 0),
    CHECK((target_kind IN (1,2,3,4,5,9) AND length(target_id) = 16)
       OR (target_kind = 8 AND length(target_id) = 8)
       OR (target_kind IN (6,7) AND length(target_id) = 0)),
    FOREIGN KEY(grant_id, receipt_id)
        REFERENCES authorization_receipts(grant_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY(grant_id, action, target_kind, target_id, manifest_sha256)
        REFERENCES authorization_challenges(
            grant_id, action, target_kind, target_id, manifest_sha256
        ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE account_transitions (
    transition_id BLOB PRIMARY KEY
        CHECK(typeof(transition_id) = 'blob' AND length(transition_id) = 16),
    grant_id BLOB NOT NULL UNIQUE
        CHECK(typeof(grant_id) = 'blob' AND length(grant_id) = 16),
    store_id BLOB NOT NULL
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    account_id BLOB NOT NULL
        CHECK(typeof(account_id) = 'blob' AND length(account_id) = 16),
    kind TEXT NOT NULL
        CHECK(typeof(kind) = 'text'
          AND kind IN ('account_create','account_update','account_remove',
                       'credential_set','credential_delete')),
    before_config_sha256 BLOB NOT NULL
        CHECK(typeof(before_config_sha256) = 'blob' AND length(before_config_sha256) = 32),
    after_config_sha256 BLOB NOT NULL
        CHECK(typeof(after_config_sha256) = 'blob' AND length(after_config_sha256) = 32),
    expected_generation INTEGER NOT NULL
        CHECK(typeof(expected_generation) = 'integer'
          AND expected_generation > 0 AND expected_generation < 9223372036854775807),
    next_generation INTEGER NOT NULL
        CHECK(typeof(next_generation) = 'integer'
          AND next_generation = expected_generation + 1),
    transition_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(transition_sha256) = 'blob' AND length(transition_sha256) = 32),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text'
          AND state IN ('prepared','config_committed','finalized','aborted','recovery_required')),
    prepared_at INTEGER NOT NULL
        CHECK(typeof(prepared_at) = 'integer' AND prepared_at >= 0),
    config_committed_at INTEGER
        CHECK(config_committed_at IS NULL OR
          (typeof(config_committed_at) = 'integer' AND config_committed_at >= prepared_at)),
    finalized_at INTEGER
        CHECK(finalized_at IS NULL OR
          (typeof(finalized_at) = 'integer' AND config_committed_at IS NOT NULL
           AND finalized_at >= config_committed_at)),
    resolved_at INTEGER
        CHECK(resolved_at IS NULL OR
          (typeof(resolved_at) = 'integer' AND resolved_at >= prepared_at)),
    CHECK((state = 'prepared' AND config_committed_at IS NULL
           AND finalized_at IS NULL AND resolved_at IS NULL)
       OR (state = 'config_committed' AND config_committed_at IS NOT NULL
           AND finalized_at IS NULL AND resolved_at IS NULL)
       OR (state = 'finalized' AND config_committed_at IS NOT NULL
           AND finalized_at IS NOT NULL AND resolved_at IS NULL)
       OR (state = 'aborted' AND config_committed_at IS NULL
           AND finalized_at IS NULL AND resolved_at IS NOT NULL)
       OR (state = 'recovery_required' AND finalized_at IS NULL
           AND resolved_at IS NOT NULL)),
    FOREIGN KEY(grant_id) REFERENCES grant_uses(grant_id) ON DELETE RESTRICT,
    FOREIGN KEY(store_id) REFERENCES registered_stores(store_id) ON DELETE RESTRICT,
    FOREIGN KEY(account_id, store_id)
        REFERENCES registered_accounts(account_id, store_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX account_transitions_store_state
ON account_transitions(store_id, state);
CREATE INDEX account_transitions_account_state
ON account_transitions(account_id, state);

CREATE TABLE credential_cleanup (
    cleanup_id BLOB PRIMARY KEY
        CHECK(typeof(cleanup_id) = 'blob' AND length(cleanup_id) = 16),
    transition_id BLOB
        CHECK(transition_id IS NULL OR
          (typeof(transition_id) = 'blob' AND length(transition_id) = 16)),
    locator_kind TEXT NOT NULL
        CHECK(typeof(locator_kind) = 'text' AND locator_kind IN ('active_v2','legacy_v1')),
    locator_material BLOB NOT NULL
        CHECK(typeof(locator_material) = 'blob'
          AND length(locator_material) BETWEEN 1 AND 4096),
    locator_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(locator_sha256) = 'blob' AND length(locator_sha256) = 32),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text'
          AND state IN ('provisional','ready','claimed','deleted')),
    claim_grant_id BLOB UNIQUE
        CHECK(claim_grant_id IS NULL OR
          (typeof(claim_grant_id) = 'blob' AND length(claim_grant_id) = 16)),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    deleted_at INTEGER
        CHECK(deleted_at IS NULL OR
          (typeof(deleted_at) = 'integer' AND deleted_at >= created_at)),
    CHECK((state IN ('provisional','ready') AND claim_grant_id IS NULL AND deleted_at IS NULL)
       OR (state = 'claimed' AND claim_grant_id IS NOT NULL AND deleted_at IS NULL)
       OR (state = 'deleted' AND claim_grant_id IS NOT NULL AND deleted_at IS NOT NULL)),
    FOREIGN KEY(transition_id) REFERENCES account_transitions(transition_id) ON DELETE RESTRICT,
    FOREIGN KEY(claim_grant_id) REFERENCES grant_uses(grant_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE remote_effects (
    effect_id BLOB PRIMARY KEY
        CHECK(typeof(effect_id) = 'blob' AND length(effect_id) = 16),
    challenge_id BLOB NOT NULL
        CHECK(typeof(challenge_id) = 'blob' AND length(challenge_id) = 32),
    grant_id BLOB NOT NULL UNIQUE
        CHECK(typeof(grant_id) = 'blob' AND length(grant_id) = 16),
    operation_id BLOB NOT NULL
        CHECK(typeof(operation_id) = 'blob' AND length(operation_id) = 16),
    ordinal INTEGER NOT NULL
        CHECK(typeof(ordinal) = 'integer' AND ordinal BETWEEN 0 AND 7),
    effect_kind INTEGER NOT NULL
        CHECK(typeof(effect_kind) = 'integer' AND effect_kind IN (1,2,3,4,5,6)),
    store_id BLOB NOT NULL
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    store_location_sha256 BLOB NOT NULL
        CHECK(typeof(store_location_sha256) = 'blob'
          AND length(store_location_sha256) = 32),
    account_id BLOB NOT NULL
        CHECK(typeof(account_id) = 'blob' AND length(account_id) = 16),
    config_generation INTEGER NOT NULL
        CHECK(typeof(config_generation) = 'integer' AND config_generation > 0),
    config_sha256 BLOB NOT NULL
        CHECK(typeof(config_sha256) = 'blob' AND length(config_sha256) = 32),
    account_generation INTEGER NOT NULL
        CHECK(typeof(account_generation) = 'integer' AND account_generation > 0),
    credential_id BLOB NOT NULL
        CHECK(typeof(credential_id) = 'blob' AND length(credential_id) = 16),
    manifest_sha256 BLOB NOT NULL
        CHECK(typeof(manifest_sha256) = 'blob' AND length(manifest_sha256) = 32),
    binding_sha256 BLOB NOT NULL
        CHECK(typeof(binding_sha256) = 'blob' AND length(binding_sha256) = 32),
    policy_sha256 BLOB NOT NULL
        CHECK(typeof(policy_sha256) = 'blob' AND length(policy_sha256) = 32),
    trust_epoch INTEGER NOT NULL
        CHECK(typeof(trust_epoch) = 'integer' AND trust_epoch > 0),
    bundle_sha256 BLOB NOT NULL
        CHECK(typeof(bundle_sha256) = 'blob' AND length(bundle_sha256) = 32),
    key_id BLOB NOT NULL
        CHECK(typeof(key_id) = 'blob' AND length(key_id) = 32),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    UNIQUE(operation_id, ordinal),
    UNIQUE(challenge_id, ordinal),
    UNIQUE(effect_id, grant_id, operation_id, store_id, store_location_sha256,
           account_id, config_generation, config_sha256, account_generation,
           credential_id, manifest_sha256, binding_sha256, policy_sha256,
           trust_epoch, bundle_sha256, key_id),
    FOREIGN KEY(challenge_id, ordinal, effect_id, effect_kind)
        REFERENCES challenge_effects(challenge_id, ordinal, effect_id, effect_kind)
        ON DELETE RESTRICT,
    FOREIGN KEY(challenge_id, grant_id, store_id, account_id, manifest_sha256,
                binding_sha256, policy_sha256, trust_epoch, bundle_sha256, key_id)
        REFERENCES authorization_challenges(
            challenge_id, grant_id, store_id, account_id, manifest_sha256,
            binding_sha256, policy_sha256, trust_epoch, bundle_sha256, key_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(grant_id) REFERENCES grant_uses(grant_id) ON DELETE RESTRICT,
    FOREIGN KEY(store_id, store_location_sha256, config_generation, config_sha256)
        REFERENCES registered_stores(
            store_id, location_sha256, config_generation, config_sha256
        ) ON DELETE RESTRICT,
    FOREIGN KEY(account_id, store_id, account_generation, credential_id, binding_sha256)
        REFERENCES registered_accounts(
            account_id, store_id, account_generation, credential_id, binding_sha256
        ) ON DELETE RESTRICT,
    FOREIGN KEY(trust_epoch) REFERENCES trust_epochs(epoch) ON DELETE RESTRICT,
    FOREIGN KEY(key_id) REFERENCES authority_keys(key_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE effect_claims (
    claim_id BLOB PRIMARY KEY
        CHECK(typeof(claim_id) = 'blob' AND length(claim_id) = 16),
    effect_id BLOB NOT NULL UNIQUE
        CHECK(typeof(effect_id) = 'blob' AND length(effect_id) = 16),
    grant_id BLOB NOT NULL UNIQUE
        CHECK(typeof(grant_id) = 'blob' AND length(grant_id) = 16),
    operation_id BLOB NOT NULL
        CHECK(typeof(operation_id) = 'blob' AND length(operation_id) = 16),
    store_id BLOB NOT NULL
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    store_location_sha256 BLOB NOT NULL
        CHECK(typeof(store_location_sha256) = 'blob'
          AND length(store_location_sha256) = 32),
    account_id BLOB NOT NULL
        CHECK(typeof(account_id) = 'blob' AND length(account_id) = 16),
    config_generation INTEGER NOT NULL
        CHECK(typeof(config_generation) = 'integer' AND config_generation > 0),
    config_sha256 BLOB NOT NULL
        CHECK(typeof(config_sha256) = 'blob' AND length(config_sha256) = 32),
    account_generation INTEGER NOT NULL
        CHECK(typeof(account_generation) = 'integer' AND account_generation > 0),
    credential_id BLOB NOT NULL
        CHECK(typeof(credential_id) = 'blob' AND length(credential_id) = 16),
    manifest_sha256 BLOB NOT NULL
        CHECK(typeof(manifest_sha256) = 'blob' AND length(manifest_sha256) = 32),
    binding_sha256 BLOB NOT NULL
        CHECK(typeof(binding_sha256) = 'blob' AND length(binding_sha256) = 32),
    policy_sha256 BLOB NOT NULL
        CHECK(typeof(policy_sha256) = 'blob' AND length(policy_sha256) = 32),
    trust_epoch INTEGER NOT NULL
        CHECK(typeof(trust_epoch) = 'integer' AND trust_epoch > 0),
    bundle_sha256 BLOB NOT NULL
        CHECK(typeof(bundle_sha256) = 'blob' AND length(bundle_sha256) = 32),
    key_id BLOB NOT NULL
        CHECK(typeof(key_id) = 'blob' AND length(key_id) = 32),
    claim_receipt BLOB NOT NULL
        CHECK(typeof(claim_receipt) = 'blob'
          AND length(claim_receipt) BETWEEN 1 AND 65536),
    claim_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(claim_sha256) = 'blob' AND length(claim_sha256) = 32),
    claimed_at INTEGER NOT NULL
        CHECK(typeof(claimed_at) = 'integer' AND claimed_at >= 0),
    invoke_before INTEGER NOT NULL
        CHECK(typeof(invoke_before) = 'integer' AND invoke_before >= claimed_at),
    UNIQUE(effect_id, claim_id),
    FOREIGN KEY(effect_id, grant_id, operation_id, store_id,
                store_location_sha256, account_id, config_generation,
                config_sha256, account_generation, credential_id,
                manifest_sha256, binding_sha256, policy_sha256, trust_epoch,
                bundle_sha256, key_id)
        REFERENCES remote_effects(
            effect_id, grant_id, operation_id, store_id,
            store_location_sha256, account_id, config_generation,
            config_sha256, account_generation, credential_id,
            manifest_sha256, binding_sha256, policy_sha256, trust_epoch,
            bundle_sha256, key_id
        ) ON DELETE RESTRICT
) STRICT;

CREATE INDEX effect_claims_invoke_before
ON effect_claims(invoke_before);

CREATE TABLE effect_invocations (
    invocation_id BLOB PRIMARY KEY
        CHECK(typeof(invocation_id) = 'blob' AND length(invocation_id) = 16),
    effect_id BLOB NOT NULL UNIQUE
        CHECK(typeof(effect_id) = 'blob' AND length(effect_id) = 16),
    claim_id BLOB NOT NULL UNIQUE
        CHECK(typeof(claim_id) = 'blob' AND length(claim_id) = 16),
    session_id BLOB NOT NULL
        CHECK(typeof(session_id) = 'blob' AND length(session_id) = 16),
    start_receipt BLOB NOT NULL
        CHECK(typeof(start_receipt) = 'blob'
          AND length(start_receipt) BETWEEN 1 AND 65536),
    start_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(start_sha256) = 'blob' AND length(start_sha256) = 32),
    started_at INTEGER NOT NULL
        CHECK(typeof(started_at) = 'integer' AND started_at >= 0),
    UNIQUE(effect_id, claim_id, invocation_id),
    FOREIGN KEY(effect_id, claim_id)
        REFERENCES effect_claims(effect_id, claim_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE effect_observations (
    observation_id BLOB PRIMARY KEY
        CHECK(typeof(observation_id) = 'blob' AND length(observation_id) = 32),
    effect_id BLOB NOT NULL UNIQUE
        CHECK(typeof(effect_id) = 'blob' AND length(effect_id) = 16),
    claim_id BLOB NOT NULL UNIQUE
        CHECK(typeof(claim_id) = 'blob' AND length(claim_id) = 16),
    invocation_id BLOB NOT NULL UNIQUE
        CHECK(typeof(invocation_id) = 'blob' AND length(invocation_id) = 16),
    certainty INTEGER NOT NULL
        CHECK(typeof(certainty) = 'integer' AND certainty IN (1,2,3)),
    result BLOB NOT NULL
        CHECK(typeof(result) = 'blob' AND length(result) BETWEEN 1 AND 16777216),
    result_sha256 BLOB NOT NULL
        CHECK(typeof(result_sha256) = 'blob' AND length(result_sha256) = 32),
    source INTEGER NOT NULL
        CHECK(typeof(source) = 'integer' AND source IN (1,2,3)),
    observation BLOB NOT NULL
        CHECK(typeof(observation) = 'blob' AND length(observation) BETWEEN 1 AND 4096),
    observed_at INTEGER NOT NULL
        CHECK(typeof(observed_at) = 'integer' AND observed_at >= 0),
    CHECK((source = 2 AND certainty = 2)
       OR (source = 3 AND certainty = 3)
       OR source = 1),
    FOREIGN KEY(effect_id, claim_id, invocation_id)
        REFERENCES effect_invocations(effect_id, claim_id, invocation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE authority_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT
        CHECK(typeof(sequence) = 'integer' AND sequence > 0),
    entity_kind INTEGER NOT NULL
        CHECK(typeof(entity_kind) = 'integer' AND entity_kind BETWEEN 1 AND 13),
    entity_id BLOB NOT NULL
        CHECK(typeof(entity_id) = 'blob' AND length(entity_id) BETWEEN 1 AND 32),
    event_code INTEGER NOT NULL
        CHECK(typeof(event_code) = 'integer' AND event_code BETWEEN 1 AND 26),
    source INTEGER NOT NULL
        CHECK(typeof(source) = 'integer' AND source BETWEEN 1 AND 6),
    occurred_at INTEGER NOT NULL
        CHECK(typeof(occurred_at) = 'integer' AND occurred_at >= 0),
    detail BLOB NOT NULL
        CHECK(typeof(detail) = 'blob' AND length(detail) BETWEEN 1 AND 65536),
    detail_sha256 BLOB NOT NULL
        CHECK(typeof(detail_sha256) = 'blob' AND length(detail_sha256) = 32)
) STRICT;

CREATE INDEX authority_events_entity_sequence
ON authority_events(entity_kind, entity_id, sequence);

```

The `BEGIN`/`END` tokens inside trigger definitions are trigger-program
syntax, not transaction control. `schema_v1.sql` is this fence byte-for-byte and
contains no top-level `BEGIN`, `COMMIT`, or `PRAGMA`.

Composite parent keys and child foreign keys bind duplicated context as one
relationship: authorization receipt to challenge; nonce use to
nonce/challenge/receipt; grant use to grant/receipt/action/target/manifest;
remote effect to challenge effect, challenge context, store context, and account
context; effect claim to the complete remote-effect context; invocation to its
effect/claim; and observation to its effect/claim/invocation. SQLite must reject
cross-linked rows even when every individual identifier exists. The schema test
executes valid minimal chains, the receipt/nonce/grant cross-link reproductions,
the later effect-chain cross-links, `PRAGMA foreign_key_check`,
`PRAGMA integrity_check`, and the declared index inventory.

`authority_keys.public_key` is globally unique. SQL enforces distinct key IDs,
role/mask relationships, exact initial active epoch 1 shape, and checked
successor `predecessor + 1`; the core `OwnerPublicKey` prerequisite rejects
malformed or weak Ed25519 encodings before persistence.

The closed authority-event entities are realm, key, trust epoch, store, account,
transition, cleanup, challenge, receipt, grant, effect, invocation, and
observation. Event codes are bootstrap prepared/confirmed, challenge created/
authorized/expired/invalidated, grant used, store enrolled/state changed,
account transition prepared/config committed/finalized/aborted/recovery
required, cleanup ready/claimed/deleted, effect claimed, invocation started,
effect observed, rotation staged/finalized, recovery staged/finalized, key
retired, and epoch retired, in that exact order as codes 1..26. Sources 1..6
are authority store, bootstrap, proof verifier, runtime, crash recovery, and
owner reconciliation.

Polymorphic event entity IDs intentionally have no foreign key; their exact
kind/length pair and typed detail must match a durable row or retained realm
identity inside the inserting transaction. Challenge `store_id`/`account_id`
also intentionally omit foreign keys because enrollment/create challenges can
name proposed identities. All other durable relationships use explicit foreign
keys and are rechecked transactionally.

Challenge-effect ordinals are contiguous from zero and match the parsed core
snapshot. V1's closed action matrix permits zero effects for control actions and
exactly one ordinal-zero effect for supported remote actions; SQL enforces the
absolute 0..7 bound and the transaction enforces contiguity/action shape.

The schema is created completely by T202A. T202B-T202E add operations against
this fixed v1 schema and do not invent migrations or columns.

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
