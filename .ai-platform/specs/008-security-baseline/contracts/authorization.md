# Contract: Owner Authorization V1

## Metadata

- Feature ID: `008-security-baseline`
- Status: Confirmed
- Contract name: `kirje.authorization.v1`
- Updated: 2026-08-31

## Security Property

Within the documented OS trust boundary, Kirje invokes a remote effect or
sensitive control-plane mutation only when all of the following are true:

1. The fixed owner anchor and authority journal agree.
2. The exact typed action manifest has one current, unexpired Ed25519 owner
   authorization receipt.
3. Current store, account, binding, policy, key, epoch, and trust-bundle context
   still matches the receipt.
4. The grant/effect has not already been used.
5. The fixed authority store durably records the use, effect claim, and adapter
   invocation before the relevant next boundary.

Terminal presence, TTY allocation, knowledge of an ID, an agent prompt, a
caller-selected outbox, and an MCP request are not owner identity proof.

## Cryptography

- Algorithm: Ed25519
- Verification: `ed25519_dalek::VerifyingKey::verify_strict`
- Public key: 32 bytes
- Detached signature: 64 bytes
- Challenge and display digests: SHA-256
- Key ID: SHA-256 of `KIRJE-OWNER-KEY-V1\0 || role-tag || public-key`
- Encoding for JSON byte fields: Base64url without padding
- Private keys: never accepted, generated, stored, serialized, logged, or used
  by Kirje

Kirje signs no authorization payload. Test-only signers use deterministic
fixtures outside production APIs.

### Owner Public-Key Boundary

T202A introduces the minimal public `kirje_core::OwnerPublicKey` needed
by bootstrap and typed anchor snapshots. It is constructible only from exactly
32 bytes that `ed25519_dalek::VerifyingKey::from_bytes` accepts and
`VerifyingKey::is_weak()` reports as non-weak. It exposes only borrowed public
bytes and equality; it has no unchecked, `Default`, serde, private-key,
key-generation, signature, or signing API. Bootstrap rejects malformed, weak,
or equal owner/recovery keys with stable non-retryable
`authorization_malformed` before entropy, file, or database work. The named
`BootstrapInput` fields assign owner and recovery roles; there is no external
role metadata to infer or second-guess. The swapped-role negative means an epoch
cannot reference a stored recovery-role row as its owner key, or an owner-role
row as its recovery key.

## Canonical Transcript

### Container

```text
domain: fixed ASCII bytes ending in NUL
field_count: u16 big-endian
for each field:
  tag: u16 big-endian
  length: u32 big-endian
  value: exact bytes
```

Rules:

- Tags are strictly increasing.
- Every defined tag appears exactly once unless an action-specific manifest
  explicitly defines a repeated ordinal sub-record.
- Optional values use the exact field-specific fixed/nested/text primitive;
  absence never omits a tag.
- Integers use one specified fixed width; booleans use one byte `0` or `1`.
- UUIDs use 16 network-order bytes, digests/realm/nonce use 32 bytes.
- Text is validated UTF-8 and retains exact bytes unless its field contract
  defines normalization.
- Unknown, duplicate, missing, out-of-order, wrong-length, trailing, over-limit,
  or non-minimal data is invalid before cryptographic verification.
- No JSON, TOML, locale, terminal formatting, or map iteration participates in
  the signed representation.

Nested primitives are also fixed:

```text
optional fixed/nested T = zero bytes when absent, exact T bytes when present
optional text T         = 0x00, or 0x01 || exact UTF-8 bytes
list<T>                 = count:u16be || repeated(
                            ordinal:u16be || length:u32be || item)
```

List ordinals are exactly `0..count-1`. Every nested record is a complete
domain-prefixed transcript. Unknown enum codes, unknown tags, non-contiguous
ordinals, malformed presence bytes, and representations not selected by this
contract fail before digest or signature verification.

### Closed Codes

Codes are independent of source enum order and are never reassigned:

```text
SensitiveAction:u16be
0x0001 send_submit
0x0010 mail_seen             0x0011 mail_starred
0x0012 mail_move             0x0013 mail_archive
0x0014 mail_safe_delete
0x0100 store_enroll
0x0110 account_create        0x0111 account_update
0x0112 account_remove
0x0120 credential_set        0x0121 credential_delete
0x0122 credential_cleanup
0x0200 policy_update         0x0201 assurance_update
0x0210 owner_rotate          0x0211 recovery_rotate
0x0212 owner_recover         0x0220 ambiguous_close

TargetKind:u16be
0x0001 operation             0x0002 store
0x0003 account               0x0004 credential
0x0005 cleanup               0x0006 policy
0x0007 assurance             0x0008 trust_epoch
0x0009 remote_effect

EffectKind:u16be
0x0000 none                  0x0001 smtp_submit
0x0002 imap_seen             0x0003 imap_starred
0x0004 imap_move             0x0005 imap_archive
0x0006 imap_safe_delete

OwnerKeyRole:u8
0x01 owner                   0x02 recovery

MIMEBuilderVersion:u16
0x0001 kirje_mime_v1

CleanupState:u8
0x01 provisional             0x02 ready
0x03 claimed                 0x04 deleted

LocatorKind:u8
0x01 active_v2               0x02 legacy_v1

AmbiguousAssertion:u8
0x01 occurred                0x02 no_effect
0x03 unknown

AmbiguousTerminal:u8
0x01 succeeded               0x02 failed_known_no_effect
0x03 ambiguous_closed

ObservationCertainty:u8
0x01 succeeded               0x02 known_no_effect
0x03 ambiguous

ObservationSource:u8
0x01 adapter_result          0x02 pre_network_failure
0x03 invocation_recovery

TrustPermissionMask:u32be
0x00000001 authorize_action
0x00000002 rotate_owner
0x00000004 rotate_recovery
0x00000008 recover_owner
```

Operation/store/account/credential/cleanup/remote-effect target IDs are UUID16;
trust-epoch target ID is u64 big-endian; policy and assurance target IDs are
zero length. JSON uses the listed snake-case names. Unknown serialized names or
codes fail closed.

Owner keys use the exact permission mask `0x00000007`; recovery keys use the
exact mask `0x00000008`. Unknown bits or any other role/mask combination fail.
Store enrollment state `0x00` means unregistered, rotation/recovery invalidation
scope `0x01` means all pending/unclaimed state, and no other v1 codes exist.

## Authorization Transcript

Domain: `KIRJE-AUTHORIZATION-V1\0`.

| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | owner realm | BLOB32 |
| `0x0002` | action | closed u16 code |
| `0x0003` | target kind | closed u16 code |
| `0x0004` | immutable target ID | exact kind encoding, 0-256 bytes |
| `0x0005` | store ID | zero or BLOB16 |
| `0x0006` | account ID | zero or BLOB16 |
| `0x0007` | manifest SHA-256 | BLOB32 |
| `0x0008` | account binding SHA-256 | zero or BLOB32 |
| `0x0009` | policy SHA-256 | zero or BLOB32 |
| `0x000a` | trust-bundle SHA-256 | BLOB32 |
| `0x000b` | signer key ID | BLOB32 |
| `0x000c` | trust epoch | u64, positive |
| `0x000d` | grant ID | BLOB16 UUIDv4 |
| `0x000e` | nonce | BLOB32 CSPRNG |
| `0x000f` | issued at | i64 Unix milliseconds |
| `0x0010` | expires at | i64 Unix milliseconds |
| `0x0011` | effect list | bounded sub-record |

`expires_at` is greater than `issued_at` and no more than 900,000 milliseconds
later. The effect list uses the canonical list container with maximum count
eight. Each item is domain `KIRJE-EFFECT-V1\0`, tag `0x0001` effect UUID16 and
tag `0x0002` effect-kind u16. The list ordinal is the effect ordinal. Control
actions without a remote effect use count zero.

`challenge_id = SHA256(exact_authorization_transcript)`.

## Action Manifest

Domain: `KIRJE-MANIFEST-V1\0`. The first fields are common:

| Tag | Field | Encoding |
|---|---|---|
| `0x0001` | action code | u16 |
| `0x0002` | target kind | u16 |
| `0x0003` | target ID | exact kind bytes |
| `0x0004` | store ID | zero or UUID16 |
| `0x0005` | account ID | zero or UUID16 |
| `0x0006` | account binding digest | zero or BLOB32 |
| `0x0007` | policy digest | zero or BLOB32 |
| `0x0008` | effect kind | u16, `none` for control actions |
| `0x0009` | effect ID | zero or UUID16 |

All nine common tags appear exactly once. Remote actions require a non-`none`
effect kind and effect ID that match the authorization effect list; control
actions require `none` and a zero-length effect ID. Action-specific fields start
at `0x0100`. The closed `SensitiveAction` enum and sealed typed manifest
payloads are exhaustive; callers cannot construct arbitrary tag/value pairs.
An unknown action or missing typed encoder fails closed.

### Nested Mail Records

```text
KIRJE-ADDRESS-V1\0
0x0001 display_name : optional text
0x0002 email        : exact validated UTF-8

KIRJE-ATTACHMENT-SUMMARY-V1\0
0x0001 disposition  : u8 (0x01 complete, 0x02 truncated, 0x03 omitted)
0x0002 text         : optional text
0x0003 original_bytes : zero or u64
0x0004 untrusted    : bool, always true

KIRJE-ATTACHMENT-V1\0
0x0001 filename     : exact validated UTF-8
0x0002 mime_type    : exact validated ASCII
0x0003 decoded_size : u64
0x0004 content_sha256 : BLOB32
0x0005 summary      : zero or complete ATTACHMENT-SUMMARY transcript
```

### Exact Action Fields

`send_submit` uses:

| Tag | Field | Encoding |
|---|---|---|
| `0x0100` | account generation | u64, positive |
| `0x0101` | From | ADDRESS transcript |
| `0x0102` | To | list of ADDRESS |
| `0x0103` | Cc | list of ADDRESS |
| `0x0104` | Bcc | list of ADDRESS |
| `0x0105` | subject | exact UTF-8 |
| `0x0106` | text body | optional text |
| `0x0107` | HTML body | optional text |
| `0x0108` | attachments | list of ATTACHMENT |
| `0x0109` | Message-ID | exact validated ASCII |
| `0x010a` | Date | i64 Unix milliseconds |
| `0x010b` | MIME builder version | u16 |
| `0x010c` | MIME boundary | exact validated ASCII |
| `0x010d` | In-Reply-To | optional text |
| `0x010e` | References | list of exact message-ID bytes |
| `0x010f` | canonical RFC822 digest | zero or BLOB32 |

The exact From, Message-ID, Date, builder version, boundary, reply fields, and
policy digest are fixed before challenge creation. A prebuilt artifact digest
is optional only when the versioned builder inputs above are complete.

All mailbox actions use:

| Tag | Field | Encoding |
|---|---|---|
| `0x0100` | account generation | u64, positive |
| `0x0101` | source mailbox | exact UTF-8 bytes |
| `0x0102` | UIDVALIDITY | u32 |
| `0x0103` | UID | u32, positive |
| `0x0104` | requested value | zero or one bool byte |
| `0x0105` | requested destination | optional text |
| `0x0106` | special-use input | u8 (`0` none, `1` archive, `2` trash) |
| `0x0107` | resolved destination | optional text |
| `0x0108` | strategy | u8 (`1` STORE, `2` UID_MOVE, `3` COPY_THEN_MARK_DELETED) |
| `0x0109` | complete capability digest | BLOB32 |
| `0x010a` | capability completeness | bool, must be true |

The action code itself fixes seen/starred/move/archive/safe-delete. Seen and
starred require requested value; destination actions require the applicable
destination fields. No strategy performs EXPUNGE.

The only valid per-action shapes are:

| Action | Value | Requested destination | Special use | Resolved destination | Strategy |
|---|---|---|---|---|---|
| `mail_seen` | present | absent | `0` | absent | `STORE` |
| `mail_starred` | present | absent | `0` | absent | `STORE` |
| `mail_move` | absent | present | `0` | present | `UID_MOVE` or `COPY_THEN_MARK_DELETED` |
| `mail_archive` | absent | absent | `1` | present | `UID_MOVE` or `COPY_THEN_MARK_DELETED` |
| `mail_safe_delete` | absent | absent | `2` | present | `UID_MOVE` or `COPY_THEN_MARK_DELETED` |

UIDVALIDITY and UID are positive. `UID_MOVE` requires a complete capability set
that supports MOVE; the fallback requires a complete set and performs no
EXPUNGE. Any other optional-field, special-use, or strategy combination fails.

Control-plane actions use the nested `ConfigCas`, `AccountSnapshot`, and
`CleanupDescriptor` transcripts defined by the account-config contract:

The control table uses only the following exact encodings. Every multibyte
integer (`u16`, `u32`, `u64`, or `i64`) is fixed-width big-endian. A
`transition_id`, `cleanup_id`, `operation_id`, `invocation_id`, or `journal_id`
is UUID16. `old_key_id`, `new_key_id`, `new_owner_id`, and `new_recovery_id`
are BLOB32 key IDs. `old_public_key`, `new_public_key`, `new_owner_key`, and
`new_recovery_key` are BLOB32 Ed25519 public keys. `old_bundle`, `new_bundle`,
`after_config_sha256`, `active_locator_sha256`, `locator_sha256`,
`tombstone_sha256`, `original_manifest_sha256`, `claim_sha256`, and a present
`observation_sha256` are BLOB32 SHA-256 digests. `config_cas`, every present
account snapshot, and every cleanup item are complete domain-prefixed nested
transcripts; their optional and list containers use the canonical primitives
above. No implementation-defined UUID, integer, digest, public-key, bundle, or
nested-record encoding is permitted.

| Action | Action-specific fields |
|---|---|
| `store_enroll` | `0100 transition_id:UUID16`, `0101 config_cas:ConfigCas`, `0102 expected_store_state:u8` where `0` means unregistered |
| account create/update/remove | `0100 transition_id:UUID16`, `0101 config_cas:ConfigCas`, `0102 before:optional AccountSnapshot`, `0103 after:optional AccountSnapshot`, `0104 next_config_generation:u64be`, `0105 after_config_sha256:BLOB32`, `0106 cleanup:list<CleanupDescriptor>` |
| credential set/delete | account fields plus `0107 active_locator_sha256:BLOB32`; credential bytes never appear |
| credential cleanup | `0100 cleanup_id:UUID16`, `0101 locator_kind:u8`, `0102 locator_sha256:BLOB32`, `0103 tombstone_sha256:BLOB32`, `0104 transition_id:UUID16`, `0105 expected_state:u8` (`0x02 ready`) |
| owner/recovery rotate | `0100 transition_id:UUID16`, `0101 role:OwnerKeyRole:u8`, `0102 old_key_id:BLOB32`, `0103 old_public_key:BLOB32`, `0104 new_key_id:BLOB32`, `0105 new_public_key:BLOB32`, `0106 old_epoch:u64be`, `0107 new_epoch:u64be`, `0108 old_bundle:BLOB32`, `0109 new_bundle:BLOB32`, `010a permissions:u32be` |
| owner recover | `0100 transition_id:UUID16`, `0101 journal_id:UUID16`, `0102 old_epoch:u64be`, `0103 new_epoch:u64be`, `0104 old_bundle:BLOB32`, `0105 new_owner_id:BLOB32`, `0106 new_owner_key:BLOB32`, `0107 new_recovery_id:BLOB32`, `0108 new_recovery_key:BLOB32`, `0109 new_bundle:BLOB32`, `010a invalidation_scope:u8` where `1` means all |
| ambiguous close | `0100 operation_id:UUID16`, `0101 invocation_id:UUID16`, `0102 original_manifest_sha256:BLOB32`, `0103 claim_sha256:BLOB32`, `0104 observation_sha256:zero-or-BLOB32`, `0105 assertion:AmbiguousAssertion:u8`, `0106 assertion_text:UTF-8`, `0107 terminal:AmbiguousTerminal:u8` |

Rotation proof of possession is a second detached signature over the same exact
manifest and is not a manifest field. `policy_update` and `assurance_update`
remain closed sensitive codes with owner-only/MCP-prohibited policy, but
challenge creation returns `unsupported_capability` until their independent
canonical snapshot contracts are introduced. They never accept opaque bytes.

`assertion_text` is validated UTF-8 of at most 1,024 bytes and 1,024
characters. Cross-field identity is exact: store target equals `ConfigCas`
store/common store; account target/common account equals every present account
snapshot; credential target equals the new credential for set and current
credential for delete; cleanup target equals `cleanup_id`; trust target is the
old epoch and equals `old_epoch`; ambiguous target equals the original remote
effect. Repeated IDs/digests in common context, nested records, and action
fields must match byte-for-byte.

Canonical v1 accepts `credential_cleanup` only when `transition_id` is present.
The existing core optional field and zero-length parser form remain unchanged
for transcript compatibility, but an absent value is never an authorized v1
semantic. For the A006 exact scope, `authority.rs` runs one pure cleanup-manifest
preflight before acquiring the apply lock or performing file, database, or
entropy work. `transition_id=None` returns `authorization_malformed` with zero
I/O, mutation, or entropy. This requires no core type or transcript change. A
persisted cleanup with no transition is authority corruption. The common store,
account, and binding fields bind the finalized origin transition's historical
before account snapshot, not the current mutable account generation. The
manifest locator kind and digest match the private canonical locator transcript,
and `tombstone_sha256` is the digest of the exact tombstone transcript defined
by the authority-store contract. No raw locator field enters this manifest.

At cleanup challenge creation, `ActionManifest` is caller-supplied and has not
yet been signed or proved. Its common store/account IDs are therefore bounded
untrusted typed request values, even though a later persisted challenge binds
them into the signing payload. Complete schema, anchor, history, transcript, and
event validation is a request-independent global pass and may already have
streamed every private cleanup, origin, locator, and tombstone graph. After the
request-independent global validation pass, no request-directed private lookup
or request-dependent private branch may occur before the closed public pair
classification. An absent store, absent account, or persisted account/store pair
mismatch is `credential_cleanup_invalid`. For an existing matched public pair,
recovery-required store is `owner_recovery_required`; blocked store or blocked/
proposed account is `account_update_conflict`. This deliberately applies to an
unrelated matched blocked/recovery pair and reveals no cleanup validity. Active
store plus active or removed account alone proceeds to request-directed private
cleanup validation. These rules do not make caller-supplied IDs signed authority
before proof verification.

### Send Manifest

The manifest covers:

- operation ID and effect ID
- account ID, account generation, and binding digest
- ordered to, cc, and bcc lists with exact name-presence/name/email bytes
- exact subject, text-presence/text bytes, and HTML-presence/HTML bytes
- ordered attachment filename, MIME type, decoded size, content SHA-256, and
  bounded untrusted text-summary bytes or explicit summary absence/truncation
- generated Message-ID, Date policy, From identity, MIME boundary policy,
  In-Reply-To, and References
- canonical RFC822 artifact SHA-256 when the action creates it before challenge
- evaluated delivery-policy digest and effect ID

No attachment path appears. Attachment bytes remain in the private immutable
operation snapshot; their digest and bounded review summary are signed.

### Mailbox Operation Manifest

The manifest covers:

- operation ID and effect ID
- account ID, generation, and binding digest
- closed operation kind
- source mailbox exact bytes
- UIDVALIDITY and UID
- requested boolean/value where applicable
- explicit destination or exact special-use resolution input
- protocol strategy inputs that can change the effect, including required
  complete capability digest

The operation kinds are seen, starred, move, archive, and safe-delete. Permanent
delete/EXPUNGE has no v1 action code.

### Account And Credential Manifest

The manifest covers:

- action kind
- transition ID and expected config/store/account generations
- complete canonical old snapshot or explicit absence
- complete canonical proposed snapshot or explicit removal
- old and new binding digests
- old and new credential IDs where applicable
- location digest for store enrollment
- cleanup tombstone IDs and delete-only locator digests where applicable

Credential bytes never appear. A credential-set manifest authorizes entering a
credential for one new bound locator; the bytes arrive only through a hidden
local prompt after the grant-use claim.

### Trust, Policy, And Reconciliation Manifest

- Trust rotation covers role, old/new key IDs and public keys, old/new epoch,
  old/new trust-bundle digests, permissions, and proposed-key proof of
  possession.
- Policy/assurance mutation is fail-closed unsupported in v0.3.1 until the exact
  old/proposed snapshot contracts and digests are introduced.
- Ambiguous closure covers the original operation/effect/invocation/observation
  digests, assertion category, bounded operator assertion, and resulting
  terminal projection. It performs no network operation.

## Sensitive Action Matrix

| Action | Target | Effect | Authorization | MCP mutation |
|---|---|---|---|---|
| `send_submit` | operation | `smtp_submit` | owner | apply only, shared verifier |
| `mail_seen` | operation | `imap_seen` | owner | apply only, shared verifier |
| `mail_starred` | operation | `imap_starred` | owner | apply only, shared verifier |
| `mail_move` | operation | `imap_move` | owner | apply only, shared verifier |
| `mail_archive` | operation | `imap_archive` | owner | apply only, shared verifier |
| `mail_safe_delete` | operation | `imap_safe_delete` | owner | apply only, shared verifier |
| `store_enroll` | store | none | owner | prohibited |
| `account_create` | account | none | owner | prohibited |
| `account_update` | account | none | owner | prohibited |
| `account_remove` | account | none | owner | prohibited |
| `credential_set` | credential | none | owner | prohibited |
| `credential_delete` | credential | none | owner | prohibited |
| `credential_cleanup` | cleanup | none | owner | prohibited |
| `policy_update` | policy | none | owner, challenge unsupported v0.3.1 | prohibited |
| `assurance_update` | assurance | none | owner, challenge unsupported v0.3.1 | prohibited |
| `owner_rotate` | trust_epoch | none | owner + new-key proof | prohibited |
| `recovery_rotate` | trust_epoch | none | owner + new-key proof | prohibited |
| `owner_recover` | trust_epoch | none | recovery | prohibited |
| `ambiguous_close` | remote_effect | none | owner | prohibited |

Common-context presence is also closed:

| Action class | Store | Account | Binding | Policy | Authorization effects |
|---|---|---|---|---|---|
| send/mailbox | required | required | required | required | exactly one matching common effect |
| store enrollment | required | zero | zero | zero | empty |
| account/credential/cleanup | required | required | required | zero | empty |
| trust rotation/recovery | zero | zero | zero | zero | empty |
| ambiguous closure | required | required | required | required | empty |
| unsupported policy/assurance | required | zero or account-scoped as future schema defines | zero | required | empty |

Remote actions use the digest of the complete evaluated policy. In v0.3.1 the
canonical no-additional-restrictions policy is the digest of the exact bytes
`KIRJE-POLICY-DEFAULT-V1\0`; no absent/implicit default is permitted. Account
create/update and credential set use the proposed binding. Account
remove and credential delete use the current signed before binding. Credential
cleanup is the sole historical-origin exception: its common binding is the
finalized origin transition's immutable before binding even when the account
has since advanced or been removed. Any other binding selection, presence, or
effect count fails before challenge persistence.

Core exposes a closed `ManifestSupport` value in each action policy. The six
remote actions and supported control actions name one sealed payload variant.
`policy_update` and `assurance_update` return
`ManifestSupport::UnsupportedCapability`; they have no payload variant, builder,
or parser branch. Challenge creation returns stable non-retryable
`unsupported_capability`. A future release must add a reviewed snapshot domain,
payload variant, golden bytes, and policy-table change together.

Bootstrap is create-once under the documented OS owner/administrator boundary,
not an authorization action before a trust root exists. Any future action not
in this matrix is denied.

## Challenge

Challenge creation:

1. Loads the immutable target and one account/config/policy snapshot.
2. Builds and validates the complete manifest.
3. Registers the effect ID already covered by a sealed remote-action manifest;
   the planner owns effect-ID generation before manifest construction.
4. Loads current anchor/journal/key/epoch context.
5. Generates a random grant ID and 32-byte nonce.
6. Persists manifest and signing payload before returning review output.

The explicit owner-facing challenge export is:

```json
{
  "contract_version": "kirje.authorization.v1",
  "challenge_id": "<64 lowercase hex>",
  "action": "send_submit",
  "target_kind": "operation",
  "target_id": "<bounded id>",
  "key_id": "<64 lowercase hex>",
  "trust_epoch": 1,
  "issued_at": "<RFC3339 UTC>",
  "expires_at": "<RFC3339 UTC>",
  "manifest_sha256": "<64 lowercase hex>",
  "signing_payload_sha256": "<64 lowercase hex>",
  "signing_payload_base64url": "<bounded exact transcript>",
  "manifest_base64url": "<bounded exact manifest>",
  "review": { "bounded": true, "authoritative": false }
}
```

The external signer must parse `manifest_base64url`, validate its action-specific
matrix, recompute both digests and challenge ID, and display every covered
effect field independently. It must not sign only the `review` object.
This export is an intentional authorization artifact: the encoded signing
payload necessarily covers realm, grant, and nonce, and the exact manifest is
present for independent review. Ordinary receipt/status/error/log output never
re-emits those private bytes.

## Proof

Proof JSON uses `deny_unknown_fields` and has a 4 KiB input limit:

```json
{
  "contract_version": "kirje.authorization-proof.v1",
  "challenge_id": "<64 lowercase hex>",
  "key_id": "<64 lowercase hex>",
  "signing_payload_sha256": "<64 lowercase hex>",
  "signature_base64url": "<64-byte detached signature>"
}
```

No proof field can override action, target, realm, epoch, nonce, expiry,
manifest, binding, policy, effect, or trust context.

Core seals proof fields behind validated construction and read-only accessors,
does not expose signature-bearing `Debug`, and owns the one
serializer-independent durable representation:
`KIRJE-AUTHORIZATION-PROOF-V1\0` with challenge, key,
signing-payload SHA-256, and signature at tags `0x0001`-`0x0004`.
`proof_sha256` hashes that transcript, never the JSON document.

The authority store uses the same container for these durable transcripts:

| Domain | Strict tag-order fields |
|---|---|
| `KIRJE-AUTHORIZATION-RECEIPT-V1` | receipt, challenge, grant, proof digest, key, manifest digest, signing digest, trust epoch, bundle, verified-at, expires-at |
| `KIRJE-GRANT-USE-V1` | grant, receipt, action, target kind, canonical target bytes, manifest digest, use-time |
| `KIRJE-EFFECT-CLAIM-V1` | claim, effect, grant, operation, store, account, config generation, account generation, manifest, binding, policy, trust epoch, bundle, key, claimed-at, invoke-before |
| `KIRJE-INVOCATION-START-V1` | invocation, effect, claim, authority session, started-at |
| `KIRJE-EFFECT-OBSERVATION-V1` | effect, claim, invocation, certainty, result digest, source, observed-at |

Tags start at `0x0001` and increase by one in the listed order. UUIDs are BLOB16,
digests are BLOB32, signature is BLOB64, action/target are u16be, certainty/source
are u8, generations/epoch are u64be, and times are i64be. Exact receipt, claim,
start, and observation transcript/digest rules are normative in
`contracts/authority-store.md`.

## Verification Transaction

One `BEGIN IMMEDIATE` transaction:

1. Parses the proof under size/field/depth bounds.
2. Loads the challenge and persisted bytes. An existing receipt branches to
   exact historical replay before any current-key/epoch/bundle requirement.
3. Rejects a wall clock more than 30 seconds behind the journal's last observed
   time; updates the monotonic high-water wall clock.
4. Computes `effective_time = max(last_observed_at, observed_at)` and requires
   `effective_time <= expires_at` exactly. Clock tolerance never extends expiry
   or permits authority to become live again after high-water passed expiry.
5. Allows at most 30 seconds of negative skew against `issued_at`; larger skew
   returns `clock_rollback_detected`.
6. Compares challenge/key/payload digests and exact encoded lengths.
7. Calls `verify_strict` on the exact persisted signing payload.
8. Inserts immutable receipt and nonce use, then consumes the challenge.

The transaction updates `last_observed_at = effective_time` after allowing at
most 30 seconds of negative skew. Raw observed time is used only for rollback
and issued-at skew rejection; issuance, expiry, verified time, receipt state,
and event time use `effective_time`. An expired pending proof commits the expired
state, event, and clock before the API returns `authorization_expired` outside
the transaction.

The signer role comes only from `SensitiveAction::policy().required_role`.
Owner and recovery rotation are signed by the active owner key; owner recovery
is signed by the active recovery key. A request, manifest field, or proposed-key
role cannot override the signer selected from the closed action policy.

Proof replay follows this exact table. T202B admits only pending, authorized,
and expired challenge rows; T202E activates the invalidated row below:

| Durable state | Proof | Result |
|---|---|---|
| pending, current, unexpired, no receipt | valid first proof | one receipt and nonce use |
| pending, expired, no receipt | any | mark expired and return `authorization_expired` |
| already expired, no receipt | any bounded proof naming that challenge | same `authorization_expired`; no new event/state |
| invalidated, no receipt | any | T202E: `authorization_invalidated` |
| receipt exists, including after expiry/rotation | exact canonical proof | same immutable receipt projection with freshly derived state; no authority refresh |
| receipt exists | changed canonical proof | `authorization_replayed` |
| nonce/authorized state exists without its receipt | any | fail closed with `owner_recovery_required` |

Historical exact replay never changes receipt ID, digest, verified time, expiry,
grant identity, or trust context. It does not make a later use/claim boundary
current. Its transaction may advance only the paired
`authority_meta.last_observed_at`/`updated_at` high-water; this does not refresh
the receipt or append an event, and ensures a receipt projected as expired can
never regress to unclaimed under tolerated clock rollback.

An already-expired no-receipt retry follows the same rollback gate and may
advance only that meta clock pair. It returns the same
`authorization_expired`, consumes no entropy, appends no event, and leaves the
challenge row unchanged. This is the exact recovery path for restart,
concurrent losers, and commit-before-error-response loss.

T202B proves exact replay after restart and expiry while the initial trust root
is active. T202E owns the finalized-rotation/invalidation integration fixture
and proves that the same replay branch remains historical after trust changes,
then activates invalidated-without-receipt handling. T202B treats an invalidated
challenge row as corruption and does not implement or accept rotated trust
history.

## Grant Use And Effect Apply

All actions insert or recover one `grant_use` before mutation. For remote
actions, the same authority transaction also inserts/rechecks the effect claim.
The store accepts typed `GrantUseRequest`, `EffectClaimRequest`,
`BeginInvocationRequest`, and `RecordObservationRequest`; it accepts no caller
boolean asserting current authorization.

Apply rechecks:

- receipt and grant identity
- unexpired `expires_at`
- anchor/journal match
- active owner key, trust epoch, and trust bundle
- registered store/location/config generation and digest
- registered account/generation/credential/binding state
- current policy digest
- exact target and manifest digest
- grant-use state
- effect ID and claim/invocation state

No credential lookup, keyring presence probe, config mutation, or network access
occurs before this transaction commits.

Effect claim additionally compares operation UUID, config digest, config/account
generations, credential ID, location digest, and exact registered row states in
the same transaction. `invoke_before` equals the immutable receipt expiry.

Exact committed grant-use and claim recovery returns the original record even
after later expiry or invalidation, but grants no new authority. A first use,
first claim, or first invocation is a new authority boundary and requires
current context. An exact existing invocation returns its original projection
without a permit. Observation is evidence for an already-entered adapter
boundary and may be recorded after expiry; exact observation replay returns the
same record, while any changed result/certainty/source/time is a projection
conflict.

For remote actions, `begin_invocation` uniquely inserts the invocation row and
returns a non-`Clone`, non-serializable, byte-inaccessible `InvocationPermit`
only to the inserting process. Adapter methods that can mutate remote state
consume that permit. An existing invocation returns no permit. After a crashed
invocation releases the fixed apply lock, recovery writes one
`ambiguous/invocation_recovery` observation and never invokes again.

## Receipt Projection

Normal output includes only:

```text
receipt_id
challenge_id
action
target kind/id
key fingerprint
trust epoch
manifest digest
receipt digest
verified/expires timestamps
state
```

It omits signature bytes, canonical proof, signing payload, full manifest,
public-key bytes, realm bytes, nonce, locator material, mailbox credential, and
private event details. Operator audit can re-verify the private stored evidence
without returning it through normal JSON or MCP.

Target display is closed: UUID targets use canonical lowercase UUID text, trust
epochs use decimal without leading zero, and zero-length policy/assurance
targets display `policy`/`assurance`. Receipt state derives in this priority:

```text
Used > Claimed > Invalidated > Expired > Unclaimed
```

`Used` is a grant use without a remote claim, or a remotely observed effect.
`Claimed` is a remote claim/invocation without an observation. These predicates
make claim-without-observation distinct while an observed claim resolves to
`Used`. Historical committed use or claim remains visible but never acts as
fresh authority. Audit uses ascending event-sequence keyset pagination with
limit 1..100 and returns no private bytes through its normal projection.

## Rotation And Recovery

Normal rotation requires:

- current owner receipt over the complete transition manifest
- detached proof of possession by the proposed new role key over the same
  transition
- proposed key differs from all active keys
- next epoch equals current epoch plus one

The proposed role key signs the exact `KIRJE-TRUST-KEY-POP-V1` transcript from
the authority-store contract. Owner role/mask is exactly `owner/0x00000007` and
recovery role/mask is exactly `recovery/0x00000008`. Recovery replaces both keys
and therefore requires both replacement-key POPs plus a current pinned recovery
receipt.

One active epoch and at most one staged successor exist. Stage requires exact
`active + 1`; staged, active, and retired row shapes retain predecessor,
transition receipt, rotation kind, POPs, and activation/retirement times as
specified by `contracts/authority-store.md`.

Rotation stages journal rows, updates the anchor through safe local I/O, and
finalizes only when the anchor exactly matches that signed staged successor.
T202A has no receipt/POP verifier and therefore classifies every staged row or
staged anchor as `recovery_required`; it never returns
`staged_finalize_required`. T202E introduces that classification only after
using T202B's core authorization snapshot to reconstruct and strictly verify the
exact transition receipt and every role-required POP. A crash before anchor
replacement leaves the active epoch valid and the staged epoch non-authoritative.
A fully verified matching staged anchor may finalize after restart. Missing
anchor, lower epoch, an unsigned/second staged row, unknown key, wrong
bundle/location, or every other mismatch is `recovery_required`.

Finalization retires the previous epoch and replaced key(s), then invalidates
pending and authorized-but-unclaimed old-epoch challenges. Historical receipts,
keys, uses, claims, invocations, and observations remain. Recovery additionally
moves nonremoved stores to `recovery_required`, blocks nonremoved accounts,
invalidates active bindings, and requires signed re-enrollment plus credential
re-entry. The independent OS-administrator recovery boundary restores or retires
the complete anchor/journal pair out of band; it is not a store signature bypass.

## CLI Surface

Owner/operator commands:

```text
kirje owner bootstrap
kirje owner status
kirje owner rotate
kirje owner recover
kirje authorization create <target>
kirje authorization show <challenge-id>
kirje authorization export <challenge-id>
kirje authorization submit --input <file|->
kirje authorization status <target>
kirje authorization audit <receipt-id>
```

Bootstrap/rotation key documents and proof files use the shared bounded no-link
reader. Production authority paths have no override flags. Existing
`send approve` and `operation approve` are non-mutating compatibility errors
with `owner_authorization_required` and migration guidance.

## MCP Surface

MCP may inspect bounded authorization state through existing operation status
and may call shared apply services. It has no tool for challenge creation or
export, proof submission, owner/key mutation, account mutation, credential
mutation, policy mutation, cleanup, or ambiguous closure.

The tool list is an exact golden allowlist. Every request schema is recursively
checked against prohibited names and aliases, including signature, proof, nonce,
key, public key, trust, authority override, authorization override, policy
override, and receipt injection. Tool-name substring checks are insufficient.

## Stable Failure Codes

```text
owner_trust_not_configured
owner_recovery_required
owner_key_inactive
trust_epoch_stale
trust_bundle_mismatch
clock_rollback_detected
authorization_required
authorization_expired
authorization_invalidated
authorization_malformed
authorization_signature_invalid
authorization_replayed
authorization_context_stale
grant_already_used
effect_already_claimed
effect_already_invoked
authority_projection_conflict
unsupported_capability
```

Failures are non-retryable unless a fresh challenge or explicit recovery is the
documented next action. They include no rejected proof bytes, signature,
manifest, nonce, credential, provider content, or private path.
