#![cfg(feature = "test-support")]

use std::{
    num::NonZeroU64,
    str::FromStr,
    sync::{Arc, Barrier},
    thread,
};

use kirje_core::{
    AccountId, ActionManifest, AmbiguousAssertion, AmbiguousCloseManifest, AmbiguousTerminal,
    AuthorizationProof, AuthorizationReceiptState, ConfigCas, InvalidationScope, InvocationId,
    MailErrorCode, ManifestContext, ManifestPayload, ManifestTarget, OperationId, OwnerKeyRole,
    OwnerPublicKey, OwnerRecoverManifest, RemoteEffectId, SensitiveAction, Sha256Digest,
    StoreEnrollManifest, StoreEnrollmentState, StoreId, TransitionId, TrustPermissionMask,
    TrustRotationManifest, owner_key_id,
};
use kirje_store::{
    AnchorPresence, AuthorityFaultPoint, AuthorityOpenContext, AuthorityOpenState, AuthorityStore,
    AuthorizationChallengeExport, BootstrapInput, BootstrapSnapshot, CreateChallengeRequest,
    DeterministicEntropy, IsolatedAuthorityHome, JournalLocationDigest, VerifyProofRequest,
};
use rusqlite::{Connection, params};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const OWNER_PUBLIC_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RECOVERY_PUBLIC_KEY: &str =
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const PROPOSED_OWNER_PUBLIC_KEY: &str =
    "4bf48fa32e86a0ef4082fc223fc872118b434cab5dc2c96dc4c7ec7952839cfe";
const PROPOSED_RECOVERY_PUBLIC_KEY: &str =
    "c9854b3828a79659fa754e69b9a26e7cf72f9701b319d199f9c0819cc7d05079";
const COLLISION_OWNER_PUBLIC_KEY: &str =
    "5bb02fff306f67ea6d86790ac9b582a7f9262c5b3453e8f6f3b0d2a36a462c7e";
const COLLISION_SIGNATURE_ONE: &str = "e074f8eb2029391cda815ac5655c7287db7260e60beda6b8ba09fa9570037258fc2e2424f7af69f812665b98bad8e114125670a0a6f5a539cb2bb5c9e5710007";
const COLLISION_SIGNATURE_TWO: &str = "d9c73eb3828e0db21608198e7a5846ffb1a4982660957cfd8cd41e5c8b0d16c05783f8da03668f5bece6ce12f78912327535021c78fbc58c4b9476b7d57d2003";

// Synthetic detached signatures over deterministic store-enrollment fixtures below.
// They contain no user material and their private signing seeds are intentionally absent.
const STORE_ENROLL_SIGNATURE: &str = "9120c14deba557dbf3bcaf7f6ca8f6d484fb783c894e29f83977d7f3f050ed1fa614c446805532438e21d1351fb987b9f0a409087f261a8a3f3526165a4dd208";

fn hex32(value: &str) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

fn synthetic_signature() -> [u8; 64] {
    hex64(STORE_ENROLL_SIGNATURE)
}

fn hex64(value: &str) -> [u8; 64] {
    let mut output = [0_u8; 64];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn owner_key() -> OwnerPublicKey {
    OwnerPublicKey::try_from(hex32(OWNER_PUBLIC_KEY)).unwrap()
}

fn recovery_key() -> OwnerPublicKey {
    OwnerPublicKey::try_from(hex32(RECOVERY_PUBLIC_KEY)).unwrap()
}

fn collision_owner_key() -> OwnerPublicKey {
    OwnerPublicKey::try_from(hex32(COLLISION_OWNER_PUBLIC_KEY)).unwrap()
}

fn proposed_owner_key() -> [u8; 32] {
    hex32(PROPOSED_OWNER_PUBLIC_KEY)
}

fn proposed_recovery_key() -> [u8; 32] {
    hex32(PROPOSED_RECOVERY_PUBLIC_KEY)
}

fn location() -> JournalLocationDigest {
    JournalLocationDigest::from_bytes([0x91; 32])
}

fn context(anchor: AnchorPresence) -> AuthorityOpenContext {
    AuthorityOpenContext {
        anchor,
        journal_location_sha256: location(),
    }
}

fn deterministic(bytes: Vec<u8>) -> DeterministicEntropy {
    DeterministicEntropy::new(bytes).unwrap()
}

fn bootstrap_entropy() -> DeterministicEntropy {
    deterministic((0_u8..48).collect())
}

fn ready_home(observed_at: i64) -> (TempDir, IsolatedAuthorityHome, BootstrapSnapshot) {
    ready_home_with_owner(observed_at, owner_key())
}

fn ready_home_with_owner(
    observed_at: i64,
    owner_public_key: OwnerPublicKey,
) -> (TempDir, IsolatedAuthorityHome, BootstrapSnapshot) {
    let temp = TempDir::new().unwrap();
    let home = IsolatedAuthorityHome::new(temp.path().to_path_buf()).unwrap();
    let pending = AuthorityStore::open_isolated(
        context(AnchorPresence::Missing),
        home.clone(),
        bootstrap_entropy(),
    )
    .unwrap()
    .prepare_bootstrap(BootstrapInput {
        journal_location_sha256: location(),
        owner_public_key,
        recovery_public_key: recovery_key(),
        observed_at_unix_ms: observed_at,
    })
    .unwrap();
    AuthorityStore::open_isolated(
        context(AnchorPresence::Present(pending.anchor.clone())),
        home.clone(),
        deterministic(Vec::new()),
    )
    .unwrap()
    .confirm_anchor(&pending.anchor, observed_at)
    .unwrap();
    (temp, home, pending)
}

fn open_ready(
    home: IsolatedAuthorityHome,
    snapshot: &BootstrapSnapshot,
    entropy: DeterministicEntropy,
) -> AuthorityStore {
    let store = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(snapshot.anchor.clone())),
        home,
        entropy,
    )
    .unwrap();
    assert!(matches!(store.state(), AuthorityOpenState::Ready(_)));
    store
}

fn signed_challenge_fixture(
    home: IsolatedAuthorityHome,
    snapshot: &BootstrapSnapshot,
) -> AuthorizationChallengeExport {
    open_ready(home, snapshot, deterministic((0x40_u8..0x70).collect()))
        .create_challenge(challenge_request(
            store_enroll_manifest(id("41414141-4141-4141-8141-414141414141")),
            400_000,
            400_500,
        ))
        .unwrap()
}

fn authorize_signed_challenge(
    home: IsolatedAuthorityHome,
    snapshot: &BootstrapSnapshot,
) -> (
    AuthorizationChallengeExport,
    kirje_core::AuthorizationReceiptProjection,
) {
    let challenge = signed_challenge_fixture(home.clone(), snapshot);
    let receipt = open_ready(home, snapshot, deterministic(vec![0xd0; 16]))
        .verify_proof(VerifyProofRequest {
            proof: AuthorizationProof::new(
                challenge.challenge_id,
                challenge.key_id,
                challenge.signing_payload_sha256,
                synthetic_signature(),
            ),
            observed_at_unix_ms: 400_100,
        })
        .unwrap();
    (challenge, receipt)
}

fn store_enroll_manifest(store_id: StoreId) -> ActionManifest {
    let config_cas = ConfigCas {
        store_id,
        generation: NonZeroU64::new(1).unwrap(),
        exact_content_sha256: Sha256Digest::from_bytes([0x31; 32]),
        location_sha256: Sha256Digest::from_bytes([0x32; 32]),
    };
    ActionManifest::new(
        ManifestContext {
            target: ManifestTarget::Store(store_id),
            store_id: Some(store_id),
            account_id: None,
            account_binding_sha256: None,
            policy_sha256: None,
            effect_id: None,
        },
        ManifestPayload::StoreEnroll(StoreEnrollManifest {
            transition_id: id("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            config_cas,
            expected_store_state: StoreEnrollmentState::Unregistered,
        }),
    )
    .unwrap()
}

fn challenge_request(
    manifest: ActionManifest,
    observed_at_unix_ms: i64,
    expires_at_unix_ms: i64,
) -> CreateChallengeRequest {
    CreateChallengeRequest {
        manifest,
        observed_at_unix_ms,
        expires_at_unix_ms,
    }
}

fn trust_bundle(
    snapshot: &BootstrapSnapshot,
    epoch: u64,
    owner_public: &[u8; 32],
    recovery_public: &[u8; 32],
) -> Sha256Digest {
    let owner_id = owner_key_id(OwnerKeyRole::Owner, owner_public);
    let recovery_id = owner_key_id(OwnerKeyRole::Recovery, recovery_public);
    let epoch = epoch.to_be_bytes();
    Sha256Digest::digest(&encode(
        b"KIRJE-TRUST-BUNDLE-V1\0",
        &[
            snapshot.realm_id.as_bytes(),
            snapshot.journal_id.as_bytes(),
            &epoch,
            owner_id.as_bytes(),
            owner_public,
            recovery_id.as_bytes(),
            recovery_public,
        ],
    ))
}

fn rotation_manifest(snapshot: &BootstrapSnapshot, role: OwnerKeyRole) -> ActionManifest {
    let (action, target, old_id, old_key, new_key, permissions) = match role {
        OwnerKeyRole::Owner => (
            SensitiveAction::OwnerRotate,
            ManifestPayload::OwnerRotate as fn(TrustRotationManifest) -> ManifestPayload,
            snapshot.owner_key_id,
            *snapshot.owner_public_key.as_bytes(),
            proposed_owner_key(),
            TrustPermissionMask::Owner,
        ),
        OwnerKeyRole::Recovery => (
            SensitiveAction::RecoveryRotate,
            ManifestPayload::RecoveryRotate as fn(TrustRotationManifest) -> ManifestPayload,
            snapshot.recovery_key_id,
            *snapshot.recovery_public_key.as_bytes(),
            proposed_recovery_key(),
            TrustPermissionMask::Recovery,
        ),
    };
    let proposed_owner = if role == OwnerKeyRole::Owner {
        new_key
    } else {
        *snapshot.owner_public_key.as_bytes()
    };
    let proposed_recovery = if role == OwnerKeyRole::Recovery {
        new_key
    } else {
        *snapshot.recovery_public_key.as_bytes()
    };
    let new_bundle = trust_bundle(snapshot, 2, &proposed_owner, &proposed_recovery);
    let manifest = TrustRotationManifest {
        transition_id: if role == OwnerKeyRole::Owner {
            id("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        } else {
            id("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        },
        role,
        old_key_id: old_id,
        old_public_key: old_key,
        new_key_id: owner_key_id(role, &new_key),
        new_public_key: new_key,
        old_epoch: NonZeroU64::new(1).unwrap(),
        new_epoch: NonZeroU64::new(2).unwrap(),
        old_bundle: snapshot.trust_bundle_sha256,
        new_bundle,
        permissions,
    };
    ActionManifest::new(
        ManifestContext {
            target: ManifestTarget::TrustEpoch(NonZeroU64::new(1).unwrap()),
            store_id: None,
            account_id: None,
            account_binding_sha256: None,
            policy_sha256: None,
            effect_id: None,
        },
        target(manifest),
    )
    .unwrap_or_else(|error| panic!("{action:?} manifest failed: {error}"))
}

fn recovery_manifest(snapshot: &BootstrapSnapshot) -> ActionManifest {
    let owner = proposed_owner_key();
    let recovery = proposed_recovery_key();
    ActionManifest::new(
        ManifestContext {
            target: ManifestTarget::TrustEpoch(NonZeroU64::new(1).unwrap()),
            store_id: None,
            account_id: None,
            account_binding_sha256: None,
            policy_sha256: None,
            effect_id: None,
        },
        ManifestPayload::OwnerRecover(OwnerRecoverManifest {
            transition_id: id("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
            journal_id: snapshot.journal_id,
            old_epoch: NonZeroU64::new(1).unwrap(),
            new_epoch: NonZeroU64::new(2).unwrap(),
            old_bundle: snapshot.trust_bundle_sha256,
            new_owner_id: owner_key_id(OwnerKeyRole::Owner, &owner),
            new_owner_key: owner,
            new_recovery_id: owner_key_id(OwnerKeyRole::Recovery, &recovery),
            new_recovery_key: recovery,
            new_bundle: trust_bundle(snapshot, 2, &owner, &recovery),
            invalidation_scope: InvalidationScope::All,
        }),
    )
    .unwrap()
}

fn stale_rotation_manifest(snapshot: &BootstrapSnapshot, role: OwnerKeyRole) -> ActionManifest {
    let current = rotation_manifest(snapshot, role);
    let payload = match current.payload() {
        ManifestPayload::OwnerRotate(value) => {
            let mut stale = value.clone();
            stale.old_bundle = Sha256Digest::from_bytes([0xa1; 32]);
            ManifestPayload::OwnerRotate(stale)
        }
        ManifestPayload::RecoveryRotate(value) => {
            let mut stale = value.clone();
            stale.old_bundle = Sha256Digest::from_bytes([0xa2; 32]);
            ManifestPayload::RecoveryRotate(stale)
        }
        _ => unreachable!(),
    };
    ActionManifest::new(current.context().clone(), payload).unwrap()
}

fn stale_recovery_manifest(snapshot: &BootstrapSnapshot) -> ActionManifest {
    let current = recovery_manifest(snapshot);
    let ManifestPayload::OwnerRecover(value) = current.payload() else {
        unreachable!();
    };
    let mut stale = value.clone();
    stale.old_bundle = Sha256Digest::from_bytes([0xa3; 32]);
    ActionManifest::new(
        current.context().clone(),
        ManifestPayload::OwnerRecover(stale),
    )
    .unwrap()
}

fn deferred_ambiguous_manifest() -> ActionManifest {
    ActionManifest::new(
        ManifestContext {
            target: ManifestTarget::RemoteEffect(id::<RemoteEffectId>(
                "44444444-4444-4444-8444-444444444444",
            )),
            store_id: Some(id::<StoreId>("11111111-1111-4111-8111-111111111111")),
            account_id: Some(id::<AccountId>("22222222-2222-4222-8222-222222222222")),
            account_binding_sha256: Some(Sha256Digest::from_bytes([0x31; 32])),
            policy_sha256: Some(Sha256Digest::from_bytes([0x32; 32])),
            effect_id: None,
        },
        ManifestPayload::AmbiguousClose(AmbiguousCloseManifest {
            operation_id: id::<OperationId>("33333333-3333-4333-8333-333333333333"),
            invocation_id: id::<InvocationId>("55555555-5555-4555-8555-555555555555"),
            original_manifest_sha256: Sha256Digest::from_bytes([0x33; 32]),
            claim_sha256: Sha256Digest::from_bytes([0x34; 32]),
            observation_sha256: Some(Sha256Digest::from_bytes([0x35; 32])),
            assertion: AmbiguousAssertion::Occurred,
            assertion_text: "synthetic controlled observation".to_owned(),
            terminal: AmbiguousTerminal::Succeeded,
        }),
    )
    .unwrap()
}

fn encode(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(domain);
    output.extend_from_slice(&u16::try_from(fields.len()).unwrap().to_be_bytes());
    for (index, field) in fields.iter().enumerate() {
        output.extend_from_slice(&u16::try_from(index + 1).unwrap().to_be_bytes());
        output.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        output.extend_from_slice(field);
    }
    output
}

fn scalar(connection: &Connection, sql: &str) -> i64 {
    connection.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn query_plan(connection: &Connection, sql: &str) -> Vec<String> {
    connection
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap()
        .query_map([], |row| row.get(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn assert_recovery_required(home: IsolatedAuthorityHome, snapshot: &BootstrapSnapshot) {
    let reopened = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(snapshot.anchor.clone())),
        home,
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(matches!(
        reopened.state(),
        AuthorityOpenState::RecoveryRequired
    ));
}

fn swap_event_sequences(connection: &Connection, left: i64, right: i64) {
    connection
        .execute(
            "UPDATE authority_events SET sequence=100 WHERE sequence=?1",
            [left],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE authority_events SET sequence=?1 WHERE sequence=?2",
            params![left, right],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE authority_events SET sequence=?1 WHERE sequence=100",
            [right],
        )
        .unwrap();
}

fn clock_pair(connection: &Connection) -> (i64, i64) {
    connection
        .query_row(
            "SELECT last_observed_at,updated_at FROM authority_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn authorization_fingerprint(connection: &Connection) -> (i64, i64, i64, i64, (i64, i64)) {
    (
        scalar(connection, "SELECT COUNT(*) FROM authorization_challenges"),
        scalar(connection, "SELECT COUNT(*) FROM authorization_receipts"),
        scalar(connection, "SELECT COUNT(*) FROM nonce_uses"),
        scalar(connection, "SELECT COUNT(*) FROM authority_events"),
        clock_pair(connection),
    )
}

fn insert_isolated_forbidden_row(connection: &Connection, table: &str) {
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    let sql = match table {
        "registered_stores" => {
            "INSERT INTO registered_stores VALUES
             (zeroblob(16),x'01',zeroblob(32),1,zeroblob(32),'active',
              zeroblob(16),1,1,NULL)"
        }
        "registered_accounts" => {
            "INSERT INTO registered_accounts VALUES
             (zeroblob(16),zeroblob(16),zeroblob(32),1,zeroblob(16),zeroblob(32),
              'active',zeroblob(16),NULL,1,1,NULL)"
        }
        "challenge_effects" => {
            "INSERT INTO challenge_effects VALUES(zeroblob(32),0,zeroblob(16),1)"
        }
        "grant_uses" => {
            "INSERT INTO grant_uses VALUES
             (zeroblob(16),zeroblob(16),256,2,zeroblob(16),zeroblob(32),
              x'01',zeroblob(32),1)"
        }
        "account_transitions" => {
            "INSERT INTO account_transitions VALUES
             (zeroblob(16),zeroblob(16),zeroblob(16),zeroblob(16),'account_create',
              zeroblob(32),zeroblob(32),1,2,zeroblob(32),'prepared',1,NULL,NULL,NULL)"
        }
        "credential_cleanup" => {
            "INSERT INTO credential_cleanup VALUES
             (zeroblob(16),NULL,'active_v2',x'01',zeroblob(32),'provisional',NULL,1,NULL)"
        }
        "remote_effects" => {
            "INSERT INTO remote_effects VALUES
             (zeroblob(16),zeroblob(32),zeroblob(16),zeroblob(16),0,1,
              zeroblob(16),zeroblob(32),zeroblob(16),1,zeroblob(32),1,
              zeroblob(16),zeroblob(32),zeroblob(32),zeroblob(32),1,
              zeroblob(32),zeroblob(32),1)"
        }
        "effect_claims" => {
            "INSERT INTO effect_claims VALUES
             (zeroblob(16),zeroblob(16),zeroblob(16),zeroblob(16),zeroblob(16),
              zeroblob(32),zeroblob(16),1,zeroblob(32),1,zeroblob(16),
              zeroblob(32),zeroblob(32),zeroblob(32),1,zeroblob(32),zeroblob(32),
              x'01',zeroblob(32),1,2)"
        }
        "effect_invocations" => {
            "INSERT INTO effect_invocations VALUES
             (zeroblob(16),zeroblob(16),zeroblob(16),zeroblob(16),x'01',zeroblob(32),1)"
        }
        "effect_observations" => {
            "INSERT INTO effect_observations VALUES
             (zeroblob(32),zeroblob(16),zeroblob(16),zeroblob(16),1,x'01',
              zeroblob(32),1,x'01',1)"
        }
        _ => panic!("unknown forbidden table {table}"),
    };
    connection.execute(sql, []).unwrap();
}

fn install_wrong_storage_class(
    home: &IsolatedAuthorityHome,
    table: &str,
    mutation_sql: &str,
    typeof_sql: &str,
) {
    let connection = Connection::open(home.database_path()).unwrap();
    let original: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )
        .unwrap();
    let weakened = original.replace(") STRICT", ")");
    assert_ne!(weakened, original);
    connection
        .execute_batch("PRAGMA writable_schema=ON;")
        .unwrap();
    connection
        .execute(
            "UPDATE sqlite_schema SET sql=?1 WHERE type='table' AND name=?2",
            params![weakened, table],
        )
        .unwrap();
    let schema_version: i64 = connection
        .query_row("PRAGMA schema_version", [], |row| row.get(0))
        .unwrap();
    connection
        .pragma_update(None, "schema_version", schema_version + 1)
        .unwrap();
    drop(connection);

    let connection = Connection::open(home.database_path()).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
        .unwrap();
    connection.execute(mutation_sql, []).unwrap();
    assert_eq!(
        connection
            .query_row(typeof_sql, [], |row| row.get::<_, String>(0))
            .unwrap(),
        "text"
    );
    connection
        .execute_batch("PRAGMA writable_schema=ON;")
        .unwrap();
    connection
        .execute(
            "UPDATE sqlite_schema SET sql=?1 WHERE type='table' AND name=?2",
            params![original, table],
        )
        .unwrap();
    let schema_version: i64 = connection
        .query_row("PRAGMA schema_version", [], |row| row.get(0))
        .unwrap();
    connection
        .pragma_update(None, "schema_version", schema_version + 1)
        .unwrap();
    drop(connection);

    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        original
    );
    assert_eq!(
        connection
            .query_row(typeof_sql, [], |row| row.get::<_, String>(0))
            .unwrap(),
        "text"
    );
}

fn install_ignored_constraint_mutation(home: &IsolatedAuthorityHome, mutation_sql: &str) {
    let connection = Connection::open(home.database_path()).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
        .unwrap();
    connection.execute(mutation_sql, []).unwrap();
}

#[allow(clippy::too_many_arguments)]
fn event_detail(
    event_code: u16,
    entity_id: &[u8],
    source: u8,
    related_kind: u16,
    related_id: &[u8],
    prior_state: u16,
    next_state: u16,
    context: Sha256Digest,
    receipt: &[u8],
    occurred_at: i64,
) -> Vec<u8> {
    let event_code = event_code.to_be_bytes();
    let entity_kind = 8_u16.to_be_bytes();
    let source = [source];
    let related_kind = related_kind.to_be_bytes();
    let prior_state = prior_state.to_be_bytes();
    let next_state = next_state.to_be_bytes();
    let occurred_at = occurred_at.to_be_bytes();
    encode(
        b"KIRJE-AUTHORITY-EVENT-DETAIL-V1\0",
        &[
            &event_code,
            &entity_kind,
            entity_id,
            &source,
            &related_kind,
            related_id,
            &prior_state,
            &next_state,
            context.as_bytes(),
            receipt,
            &occurred_at,
        ],
    )
}

#[test]
fn challenge_support_context_entropy_reuse_expiry_and_events_are_exact() {
    let (_temp, home, snapshot) = ready_home(100_000);
    let source = deterministic((0x40_u8..0xa0).collect());
    let store = open_ready(home.clone(), &snapshot, source.clone());
    let store_id = id("11111111-1111-4111-8111-111111111111");
    let manifest = store_enroll_manifest(store_id);
    let first = store
        .create_challenge(challenge_request(manifest.clone(), 100_000, 100_100))
        .unwrap();
    assert_eq!(source.consumed_bytes(), 48);
    assert_eq!(first.action, SensitiveAction::StoreEnroll);
    assert_eq!(first.target_id, store_id.to_string());
    assert_eq!(first.key_id, snapshot.owner_key_id);
    assert_eq!(first.trust_epoch, NonZeroU64::new(1).unwrap());
    assert_eq!(first.manifest_sha256, manifest.sha256());
    assert_eq!(first.challenge_id, first.signing_payload_sha256);
    assert!(first.review.bounded && !first.review.authoritative);

    let reused = store
        .create_challenge(challenge_request(manifest.clone(), 100_050, 100_150))
        .unwrap();
    assert_eq!(source.consumed_bytes(), 48);
    assert_eq!(reused.challenge_id, first.challenge_id);
    assert_eq!(reused.expires_at, first.expires_at);

    let replaced = store
        .create_challenge(challenge_request(manifest, 100_101, 100_201))
        .unwrap();
    assert_eq!(source.consumed_bytes(), 96);
    assert_ne!(replaced.challenge_id, first.challenge_id);

    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authorization_challenges"),
        2
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authorization_challenges WHERE state='expired'"
        ),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM challenge_effects"),
        0
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        5
    );
    assert_eq!(clock_pair(&connection), (100_101, 100_101));
    let events = connection
        .prepare("SELECT event_code,source,entity_kind FROM authority_events ORDER BY sequence")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<Vec<(i64, i64, i64)>, _>>()
        .unwrap();
    assert_eq!(
        events,
        vec![(1, 2, 1), (2, 2, 1), (3, 1, 8), (5, 1, 8), (3, 1, 8)]
    );

    let context_fields = [
        SensitiveAction::StoreEnroll.code().to_be_bytes().to_vec(),
        2_u16.to_be_bytes().to_vec(),
        store_id.as_bytes().to_vec(),
        store_id.as_bytes().to_vec(),
        Vec::new(),
        store_enroll_manifest(store_id).sha256().as_bytes().to_vec(),
        Vec::new(),
        Vec::new(),
        snapshot.owner_key_id.as_bytes().to_vec(),
        1_u64.to_be_bytes().to_vec(),
        snapshot.trust_bundle_sha256.as_bytes().to_vec(),
    ];
    let refs = context_fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let expected = Sha256::digest(encode(b"KIRJE-AUTHORIZATION-CONTEXT-V1\0", &refs));
    let stored: Vec<u8> = connection
        .query_row(
            "SELECT context_sha256 FROM authorization_challenges WHERE challenge_id=?1",
            [replaced.challenge_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, expected.as_slice());
}

#[test]
fn challenge_created_event_sequence_links_the_exact_created_event() {
    let (_temp, home, snapshot) = ready_home(130_000);
    let challenge = open_ready(home.clone(), &snapshot, deterministic(vec![0x45; 48]))
        .create_challenge(challenge_request(
            store_enroll_manifest(id("13131313-1313-4313-8313-131313131313")),
            130_000,
            130_500,
        ))
        .unwrap();
    let connection = Connection::open(home.database_path()).unwrap();
    let (linked_sequence, event_sequence, event_code, entity_kind, entity_id): (
        i64,
        i64,
        i64,
        i64,
        Vec<u8>,
    ) = connection
        .query_row(
            "SELECT c.created_event_sequence,e.sequence,e.event_code,e.entity_kind,e.entity_id
             FROM authorization_challenges c
             JOIN authority_events e ON e.sequence=c.created_event_sequence
             WHERE c.challenge_id=?1",
            [challenge.challenge_id.as_bytes()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(linked_sequence, event_sequence);
    assert_eq!(event_code, 3);
    assert_eq!(entity_kind, 8);
    assert_eq!(entity_id, challenge.challenge_id.as_bytes());
}

#[test]
fn restart_rejects_null_wrong_type_and_mismatched_created_event_links() {
    for mutation in ["null", "wrong_type", "mismatch"] {
        let (_temp, home, snapshot) = ready_home(140_000);
        let challenge = open_ready(home.clone(), &snapshot, deterministic(vec![0x46; 48]))
            .create_challenge(challenge_request(
                store_enroll_manifest(id("14141414-1414-4414-8414-141414141414")),
                140_000,
                140_500,
            ))
            .unwrap();
        match mutation {
            "null" => {
                Connection::open(home.database_path())
                    .unwrap()
                    .execute(
                        "UPDATE authorization_challenges SET created_event_sequence=NULL
                         WHERE challenge_id=?1",
                        [challenge.challenge_id.as_bytes()],
                    )
                    .unwrap();
            }
            "wrong_type" => install_wrong_storage_class(
                &home,
                "authorization_challenges",
                "UPDATE authorization_challenges SET created_event_sequence='wrong-storage-class'",
                "SELECT typeof(created_event_sequence) FROM authorization_challenges",
            ),
            "mismatch" => {
                Connection::open(home.database_path())
                    .unwrap()
                    .execute(
                        "UPDATE authorization_challenges SET created_event_sequence=1
                         WHERE challenge_id=?1",
                        [challenge.challenge_id.as_bytes()],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert_recovery_required(home, &snapshot);
    }
}

#[test]
fn pending_reuse_is_inclusive_at_exact_expiry_before_new_lifetime_validation() {
    let (_temp, home, snapshot) = ready_home(150_000);
    let source = deterministic(vec![0x4a; 96]);
    let store = open_ready(home.clone(), &snapshot, source.clone());
    let manifest = store_enroll_manifest(id("15151515-1515-4515-8515-151515151515"));
    let first = store
        .create_challenge(challenge_request(manifest.clone(), 150_000, 150_100))
        .unwrap();
    let connection = Connection::open(home.database_path()).unwrap();
    let before_events = scalar(&connection, "SELECT COUNT(*) FROM authority_events");
    let before_rows = scalar(&connection, "SELECT COUNT(*) FROM authorization_challenges");
    drop(connection);

    let reused = store
        .create_challenge(challenge_request(manifest, 150_100, 150_100))
        .unwrap();

    assert_eq!(reused.challenge_id, first.challenge_id);
    assert_eq!(reused.issued_at, first.issued_at);
    assert_eq!(reused.expires_at, first.expires_at);
    assert_eq!(source.consumed_bytes(), 48);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        before_events
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authorization_challenges"),
        before_rows
    );
    assert_eq!(clock_pair(&connection), (150_100, 150_100));
}

#[test]
fn four_supported_actions_select_the_contract_signer_without_staging_trust() {
    let (_temp, home, snapshot) = ready_home(200_000);
    let source = deterministic((0_u8..192).collect());
    let store = open_ready(home.clone(), &snapshot, source.clone());
    let cases = [
        (
            store_enroll_manifest(id("21212121-2121-4121-8121-212121212121")),
            snapshot.owner_key_id,
        ),
        (
            rotation_manifest(&snapshot, OwnerKeyRole::Owner),
            snapshot.owner_key_id,
        ),
        (
            rotation_manifest(&snapshot, OwnerKeyRole::Recovery),
            snapshot.owner_key_id,
        ),
        (recovery_manifest(&snapshot), snapshot.recovery_key_id),
    ];
    for (index, (manifest, expected_key)) in cases.into_iter().enumerate() {
        let index = i64::try_from(index).unwrap();
        let challenge = store
            .create_challenge(challenge_request(
                manifest,
                200_000 + index,
                200_100 + index,
            ))
            .unwrap();
        assert_eq!(challenge.key_id, expected_key);
    }
    assert_eq!(source.consumed_bytes(), 4 * 48);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_keys"),
        2
    );
    assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM trust_epochs"), 1);
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM registered_stores"),
        0
    );
}

#[test]
fn supported_action_stale_mutations_are_deterministic_and_write_nothing() {
    let (_temp, home, snapshot) = ready_home(400_000);
    let challenge = signed_challenge_fixture(home.clone(), &snapshot);
    let receipt = open_ready(home.clone(), &snapshot, deterministic(vec![0x71; 16]))
        .verify_proof(VerifyProofRequest {
            proof: AuthorizationProof::new(
                challenge.challenge_id,
                challenge.key_id,
                challenge.signing_payload_sha256,
                synthetic_signature(),
            ),
            observed_at_unix_ms: 400_100,
        })
        .unwrap();
    let source = deterministic(vec![0x72; 48]);
    let stale_store = open_ready(home.clone(), &snapshot, source.clone());
    let connection = Connection::open(home.database_path()).unwrap();
    connection
        .execute(
            "INSERT INTO registered_stores
             (store_id,location_material,location_sha256,config_generation,config_sha256,
              state,enrolled_receipt_id,created_at,updated_at,removed_at)
             VALUES(?1,?2,?3,1,?4,'active',?5,400100,400100,NULL)",
            params![
                id::<StoreId>("41414141-4141-4141-8141-414141414141").as_bytes(),
                [0x73_u8].as_slice(),
                [0x74_u8; 32].as_slice(),
                [0x75_u8; 32].as_slice(),
                receipt.receipt_id.as_bytes(),
            ],
        )
        .unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
    let before = authorization_fingerprint(&connection);
    drop(connection);
    let result = stale_store.create_challenge(challenge_request(
        store_enroll_manifest(id("41414141-4141-4141-8141-414141414141")),
        400_101,
        400_501,
    ));
    let Err(error) = result else {
        panic!("registered store accepted a stale enrollment challenge");
    };
    assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
    assert_eq!(source.consumed_bytes(), 0);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(authorization_fingerprint(&connection), before);

    for (index, manifest) in [
        stale_rotation_manifest(&snapshot, OwnerKeyRole::Owner),
        stale_rotation_manifest(&snapshot, OwnerKeyRole::Recovery),
        stale_recovery_manifest(&snapshot),
    ]
    .into_iter()
    .enumerate()
    {
        let observed_at = 500_000 + i64::try_from(index).unwrap();
        let (_temp, home, current) = ready_home(observed_at);
        let source = deterministic(vec![0x76; 48]);
        let connection = Connection::open(home.database_path()).unwrap();
        let before = authorization_fingerprint(&connection);
        drop(connection);
        let result = open_ready(home.clone(), &current, source.clone())
            .create_challenge(challenge_request(manifest, observed_at, observed_at + 500));
        let Err(error) = result else {
            panic!("stale trust challenge unexpectedly succeeded");
        };
        assert_eq!(error.code, MailErrorCode::AuthorizationContextStale);
        assert_eq!(source.consumed_bytes(), 0);
        let connection = Connection::open(home.database_path()).unwrap();
        assert_eq!(authorization_fingerprint(&connection), before);
    }
}

#[test]
fn deterministic_rejections_and_clock_boundaries_consume_no_entropy_or_write() {
    let (_temp, home, snapshot) = ready_home(300_000);
    let source = deterministic(vec![0x81; 96]);
    let store = open_ready(home.clone(), &snapshot, source.clone());
    let connection = Connection::open(home.database_path()).unwrap();
    let before = clock_pair(&connection);
    drop(connection);

    let malformed_expiry = store.create_challenge(challenge_request(
        store_enroll_manifest(id("31313131-3131-4131-8131-313131313131")),
        300_000,
        300_000,
    ));
    let Err(malformed_expiry) = malformed_expiry else {
        panic!("invalid expiry was accepted");
    };
    assert_eq!(malformed_expiry.code, MailErrorCode::InvalidInput);

    let stale = store.create_challenge(challenge_request(
        recovery_manifest(&snapshot),
        269_999,
        300_100,
    ));
    let Err(stale) = stale else {
        panic!("clock rollback was accepted");
    };
    assert_eq!(stale.code, MailErrorCode::ClockRollbackDetected);
    assert_eq!(source.consumed_bytes(), 0);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(clock_pair(&connection), before);
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authorization_challenges"),
        0
    );

    let accepted = store
        .create_challenge(challenge_request(
            store_enroll_manifest(id("32323232-3232-4232-8232-323232323232")),
            270_000,
            300_100,
        ))
        .unwrap();
    assert_eq!(accepted.issued_at.timestamp_millis(), 300_000);
}

#[test]
#[allow(clippy::too_many_lines)]
fn entropy_exhaustion_and_challenge_identifier_collisions_are_atomic() {
    for (available, expected_consumed) in [(15_usize, 0_usize), (47, 16)] {
        let (_temp, home, snapshot) = ready_home(310_000);
        let source = deterministic(vec![0x7a; available]);
        let result = open_ready(home.clone(), &snapshot, source.clone()).create_challenge(
            challenge_request(
                store_enroll_manifest(id("33333333-3333-4333-8333-333333333333")),
                310_000,
                310_500,
            ),
        );
        let Err(error) = result else {
            panic!("challenge entropy exhaustion unexpectedly succeeded");
        };
        assert_eq!(error.code, MailErrorCode::Internal);
        assert_eq!(source.consumed_bytes(), expected_consumed);
        let connection = Connection::open(home.database_path()).unwrap();
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM authorization_challenges"),
            0
        );
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
            2
        );
        assert_eq!(clock_pair(&connection), (310_000, 310_000));
    }

    let (_temp, home, snapshot) = ready_home(320_000);
    let grant_collision = deterministic(
        [
            [0x81; 16].as_slice(),
            [0x82; 32].as_slice(),
            [0x81; 16].as_slice(),
            [0x83; 32].as_slice(),
        ]
        .concat(),
    );
    let store = open_ready(home.clone(), &snapshot, grant_collision.clone());
    store
        .create_challenge(challenge_request(
            store_enroll_manifest(id("34343434-3434-4434-8434-343434343434")),
            320_000,
            320_500,
        ))
        .unwrap();
    let result = store.create_challenge(challenge_request(
        store_enroll_manifest(id("35353535-3535-4535-8535-353535353535")),
        320_001,
        320_501,
    ));
    let Err(error) = result else {
        panic!("grant collision unexpectedly succeeded");
    };
    assert_eq!(error.code, MailErrorCode::StoreWrite);
    assert_eq!(grant_collision.consumed_bytes(), 96);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authorization_challenges"),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        3
    );
    assert_eq!(clock_pair(&connection), (320_000, 320_000));

    let (_temp, home, snapshot) = ready_home(330_000);
    let nonce_collision = deterministic(
        [
            [0x84; 16].as_slice(),
            [0x85; 32].as_slice(),
            [0x86; 16].as_slice(),
            [0x85; 32].as_slice(),
        ]
        .concat(),
    );
    let store = open_ready(home.clone(), &snapshot, nonce_collision.clone());
    store
        .create_challenge(challenge_request(
            store_enroll_manifest(id("36363636-3636-4636-8636-363636363636")),
            330_000,
            330_500,
        ))
        .unwrap();
    let result = store.create_challenge(challenge_request(
        store_enroll_manifest(id("38383838-3838-4838-8838-383838383838")),
        330_001,
        330_501,
    ));
    let Err(error) = result else {
        panic!("nonce collision unexpectedly succeeded");
    };
    assert_eq!(error.code, MailErrorCode::StoreWrite);
    assert_eq!(nonce_collision.consumed_bytes(), 96);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authorization_challenges"),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        3
    );
    assert_eq!(clock_pair(&connection), (330_000, 330_000));
}

#[test]
fn receipt_entropy_exhaustion_preserves_pending_state_and_clock() {
    let (_temp, home, snapshot) = ready_home(400_000);
    let challenge = signed_challenge_fixture(home.clone(), &snapshot);
    let source = deterministic(vec![0xd0; 15]);
    let error = open_ready(home.clone(), &snapshot, source.clone())
        .verify_proof(VerifyProofRequest {
            proof: AuthorizationProof::new(
                challenge.challenge_id,
                challenge.key_id,
                challenge.signing_payload_sha256,
                synthetic_signature(),
            ),
            observed_at_unix_ms: 400_100,
        })
        .unwrap_err();
    assert_eq!(error.code, MailErrorCode::Internal);
    assert_eq!(source.consumed_bytes(), 0);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authorization_receipts"),
        0
    );
    assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM nonce_uses"), 0);
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authorization_challenges WHERE state='pending'"
        ),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        3
    );
    assert_eq!(clock_pair(&connection), (400_000, 400_000));
}

#[test]
fn deferred_context_and_invalid_proof_fail_before_entropy_or_mutation() {
    let (_temp, home, snapshot) = ready_home(350_000);
    let source = deterministic(vec![0x35; 96]);
    let store = open_ready(home.clone(), &snapshot, source.clone());
    let before = Connection::open(home.database_path()).unwrap();
    let before_clock = clock_pair(&before);
    drop(before);
    let deferred = store.create_challenge(challenge_request(
        deferred_ambiguous_manifest(),
        350_000,
        350_500,
    ));
    let Err(deferred) = deferred else {
        panic!("deferred action persisted a challenge");
    };
    assert_eq!(deferred.code, MailErrorCode::AuthorizationContextStale);
    assert_eq!(source.consumed_bytes(), 0);

    let challenge = store
        .create_challenge(challenge_request(
            store_enroll_manifest(id("35353535-3535-4535-8535-353535353535")),
            350_000,
            350_500,
        ))
        .unwrap();
    let proof_entropy = deterministic(vec![0x36; 16]);
    let verifier = open_ready(home.clone(), &snapshot, proof_entropy.clone());
    let invalid = verifier.verify_proof(VerifyProofRequest {
        proof: AuthorizationProof::new(
            challenge.challenge_id,
            challenge.key_id,
            challenge.signing_payload_sha256,
            [0x36; 64],
        ),
        observed_at_unix_ms: 350_100,
    });
    assert_eq!(
        invalid.unwrap_err().code,
        MailErrorCode::AuthorizationSignatureInvalid
    );
    assert_eq!(proof_entropy.consumed_bytes(), 0);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authorization_challenges WHERE state='pending'"
        ),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authorization_receipts"),
        0
    );
    assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM nonce_uses"), 0);
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        3
    );
    assert_eq!(before_clock, (350_000, 350_000));
    assert_eq!(clock_pair(&connection), before_clock);
}

#[test]
fn unrepresentable_public_timestamps_fail_before_entropy_or_commit() {
    let (_temp, home, snapshot) = ready_home(360_000);
    let source = deterministic(vec![0x37; 48]);
    let result =
        open_ready(home.clone(), &snapshot, source.clone()).create_challenge(challenge_request(
            store_enroll_manifest(id("37373737-3737-4737-8737-373737373737")),
            i64::MAX - 1_000,
            i64::MAX - 500,
        ));
    let Err(error) = result else {
        panic!("unrepresentable timestamp was accepted");
    };
    assert_eq!(error.code, MailErrorCode::InvalidInput);
    assert_eq!(source.consumed_bytes(), 0);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authorization_challenges"),
        0
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        2
    );
    assert_eq!(clock_pair(&connection), (360_000, 360_000));
}

#[test]
#[allow(clippy::too_many_lines)]
fn valid_proof_commits_one_immutable_receipt_nonce_and_exact_replay() {
    let (_temp, home, snapshot) = ready_home(400_000);
    let challenge_entropy = deterministic((0x40_u8..0x70).collect());
    let store = open_ready(home.clone(), &snapshot, challenge_entropy.clone());
    let challenge = store
        .create_challenge(challenge_request(
            store_enroll_manifest(id("41414141-4141-4141-8141-414141414141")),
            400_000,
            400_500,
        ))
        .unwrap();
    let receipt_entropy = deterministic((0xd0_u8..0xe0).collect());
    let verifier = open_ready(home.clone(), &snapshot, receipt_entropy.clone());
    let proof = AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        synthetic_signature(),
    );
    let receipt = verifier
        .verify_proof(VerifyProofRequest {
            proof: proof.clone(),
            observed_at_unix_ms: 400_100,
        })
        .unwrap();
    assert_eq!(receipt_entropy.consumed_bytes(), 16);
    assert_eq!(receipt.challenge_id, challenge.challenge_id);
    assert_eq!(receipt.state, AuthorizationReceiptState::Unclaimed);

    let replay = open_ready(home.clone(), &snapshot, deterministic(Vec::new()))
        .verify_proof(VerifyProofRequest {
            proof: proof.clone(),
            observed_at_unix_ms: 400_600,
        })
        .unwrap();
    assert_eq!(replay.receipt_id, receipt.receipt_id);
    assert_eq!(replay.receipt_sha256, receipt.receipt_sha256);
    assert_eq!(replay.verified_at, receipt.verified_at);
    assert_eq!(replay.state, AuthorizationReceiptState::Expired);

    let changed = AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        [0x55; 64],
    );
    let error = verifier
        .verify_proof(VerifyProofRequest {
            proof: changed,
            observed_at_unix_ms: 400_600,
        })
        .unwrap_err();
    assert_eq!(error.code, MailErrorCode::AuthorizationReplayed);

    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authorization_receipts"),
        1
    );
    assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM nonce_uses"), 1);
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        4
    );
    assert_eq!(clock_pair(&connection), (400_600, 400_600));
    let (grant_id, bundle, stored_receipt, stored_receipt_sha256): (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = connection
        .query_row(
            "SELECT c.grant_id,c.bundle_sha256,r.receipt,r.receipt_sha256
             FROM authorization_challenges c
             JOIN authorization_receipts r ON r.challenge_id=c.challenge_id
             WHERE c.challenge_id=?1",
            [challenge.challenge_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    let epoch = 1_u64.to_be_bytes();
    let verified_at_bytes = 400_100_i64.to_be_bytes();
    let expires = 400_500_i64.to_be_bytes();
    let expected_receipt = encode(
        b"KIRJE-AUTHORIZATION-RECEIPT-V1\0",
        &[
            receipt.receipt_id.as_bytes(),
            challenge.challenge_id.as_bytes(),
            &grant_id,
            proof.proof_sha256().as_bytes(),
            challenge.key_id.as_bytes(),
            challenge.manifest_sha256.as_bytes(),
            challenge.signing_payload_sha256.as_bytes(),
            &epoch,
            &bundle,
            &verified_at_bytes,
            &expires,
        ],
    );
    assert_eq!(stored_receipt, expected_receipt);
    assert_eq!(
        stored_receipt_sha256,
        Sha256::digest(&expected_receipt).as_slice()
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT event_code,source,entity_kind FROM authority_events WHERE sequence=4",
                [],
                |row| Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?
                )),
            )
            .unwrap(),
        (4, 3, 8)
    );
}

#[test]
fn pending_expiry_is_durable_and_exact_retry_cannot_revive_it() {
    let (_temp, home, snapshot) = ready_home(500_000);
    let store = open_ready(home.clone(), &snapshot, deterministic(vec![0x91; 48]));
    let challenge = store
        .create_challenge(challenge_request(
            store_enroll_manifest(id("51515151-5151-4151-8151-515151515151")),
            500_000,
            500_010,
        ))
        .unwrap();
    let proof = AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        [0x99; 64],
    );
    let verifier_entropy = deterministic(vec![0xa1; 16]);
    let verifier = open_ready(home.clone(), &snapshot, verifier_entropy.clone());
    let error = verifier
        .verify_proof(VerifyProofRequest {
            proof: proof.clone(),
            observed_at_unix_ms: 500_011,
        })
        .unwrap_err();
    assert_eq!(error.code, MailErrorCode::AuthorizationExpired);
    assert_eq!(verifier_entropy.consumed_bytes(), 0);

    let retry = open_ready(home.clone(), &snapshot, deterministic(Vec::new()))
        .verify_proof(VerifyProofRequest {
            proof,
            observed_at_unix_ms: 470_011,
        })
        .unwrap_err();
    assert_eq!(retry.code, MailErrorCode::AuthorizationExpired);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authorization_receipts"),
        0
    );
    assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM nonce_uses"), 0);
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        4
    );
    assert_eq!(clock_pair(&connection), (500_011, 500_011));
}

#[test]
fn invalidated_challenge_is_recovery_required_on_proof_and_restart() {
    let (_temp, home, snapshot) = ready_home(520_000);
    let challenge = open_ready(home.clone(), &snapshot, deterministic(vec![0x96; 48]))
        .create_challenge(challenge_request(
            store_enroll_manifest(id("52525252-5252-4252-8252-525252525252")),
            520_000,
            520_500,
        ))
        .unwrap();
    let source = deterministic(vec![0x97; 16]);
    let stale_verifier = open_ready(home.clone(), &snapshot, source.clone());
    let connection = Connection::open(home.database_path()).unwrap();
    connection
        .execute(
            "UPDATE authorization_challenges
             SET state='invalidated',invalidated_at=520001 WHERE challenge_id=?1",
            [challenge.challenge_id.as_bytes()],
        )
        .unwrap();
    let before = authorization_fingerprint(&connection);
    drop(connection);

    let error = stale_verifier
        .verify_proof(VerifyProofRequest {
            proof: AuthorizationProof::new(
                challenge.challenge_id,
                challenge.key_id,
                challenge.signing_payload_sha256,
                [0x97; 64],
            ),
            observed_at_unix_ms: 520_001,
        })
        .unwrap_err();
    assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
    assert_eq!(source.consumed_bytes(), 0);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(authorization_fingerprint(&connection), before);
    drop(connection);

    let reopened = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(snapshot.anchor.clone())),
        home,
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(matches!(
        reopened.state(),
        AuthorityOpenState::RecoveryRequired
    ));
}

#[test]
fn orphan_challenge_event_is_owner_recovery_on_stale_writes_and_restart() {
    let (_temp, home, snapshot) = ready_home(540_000);
    let source = deterministic(vec![0x9a; 64]);
    let stale = open_ready(home.clone(), &snapshot, source.clone());
    let unknown_challenge = Sha256Digest::from_bytes([0x9b; 32]);
    let detail = event_detail(
        3,
        unknown_challenge.as_bytes(),
        1,
        10,
        &[0x9c; 16],
        0,
        0x0801,
        Sha256Digest::from_bytes([0x9d; 32]),
        &[],
        540_000,
    );
    let detail_sha256 = Sha256::digest(&detail);
    let connection = Connection::open(home.database_path()).unwrap();
    connection
        .execute(
            "INSERT INTO authority_events
             (entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256)
             VALUES(8,?1,3,1,540000,?2,?3)",
            params![
                unknown_challenge.as_bytes(),
                detail,
                detail_sha256.as_slice(),
            ],
        )
        .unwrap();
    assert_eq!(
        scalar(&connection, "SELECT MAX(sequence) FROM authority_events"),
        3
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT seq FROM sqlite_sequence WHERE name='authority_events'"
        ),
        3
    );
    let before = authorization_fingerprint(&connection);
    drop(connection);

    let create_result = stale.create_challenge(challenge_request(
        store_enroll_manifest(id("54545454-5454-4454-8454-545454545454")),
        540_001,
        540_501,
    ));
    let Err(create_error) = create_result else {
        panic!("orphan authority event was accepted by challenge creation");
    };
    assert_eq!(create_error.code, MailErrorCode::OwnerRecoveryRequired);
    assert!(!create_error.retryable);
    assert_eq!(
        create_error.message,
        "authority state requires owner recovery"
    );
    assert_eq!(source.consumed_bytes(), 0);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(authorization_fingerprint(&connection), before);
    drop(connection);

    let verify_result = stale.verify_proof(VerifyProofRequest {
        proof: AuthorizationProof::new(
            unknown_challenge,
            Sha256Digest::from_bytes([0x9e; 32]),
            Sha256Digest::from_bytes([0x9f; 32]),
            [0xa0; 64],
        ),
        observed_at_unix_ms: 540_001,
    });
    let Err(verify_error) = verify_result else {
        panic!("orphan authority event was accepted by proof verification");
    };
    assert_eq!(verify_error.code, MailErrorCode::OwnerRecoveryRequired);
    assert!(!verify_error.retryable);
    assert_eq!(
        verify_error.message,
        "authority state requires owner recovery"
    );
    assert_eq!(source.consumed_bytes(), 0);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(authorization_fingerprint(&connection), before);
    drop(connection);

    assert_recovery_required(home, &snapshot);
}

#[test]
fn concurrent_challenge_and_proof_calls_have_one_durable_winner() {
    let (_temp, home, snapshot) = ready_home(600_000);
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    let sources = [deterministic(vec![0xb1; 48]), deterministic(vec![0xc1; 48])];
    for source in sources.clone() {
        let home = home.clone();
        let snapshot = snapshot.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let store = open_ready(home, &snapshot, source);
            barrier.wait();
            store
                .create_challenge(challenge_request(
                    store_enroll_manifest(id("61616161-6161-4161-8161-616161616161")),
                    600_000,
                    600_500,
                ))
                .unwrap()
        }));
    }
    let left = handles.remove(0).join().unwrap();
    let right = handles.remove(0).join().unwrap();
    assert_eq!(left.challenge_id, right.challenge_id);
    assert_eq!(
        sources
            .iter()
            .map(DeterministicEntropy::consumed_bytes)
            .sum::<usize>(),
        48
    );

    let (_proof_temp, proof_home, proof_snapshot) = ready_home(400_000);
    let signed_challenge = open_ready(
        proof_home.clone(),
        &proof_snapshot,
        deterministic((0x40_u8..0x70).collect()),
    )
    .create_challenge(challenge_request(
        store_enroll_manifest(id("41414141-4141-4141-8141-414141414141")),
        400_000,
        400_500,
    ))
    .unwrap();
    let proof = AuthorizationProof::new(
        signed_challenge.challenge_id,
        signed_challenge.key_id,
        signed_challenge.signing_payload_sha256,
        synthetic_signature(),
    );
    let barrier = Arc::new(Barrier::new(2));
    let sources = [deterministic(vec![0xd1; 16]), deterministic(vec![0xe1; 16])];
    let mut handles = Vec::new();
    for source in sources.clone() {
        let home = proof_home.clone();
        let snapshot = proof_snapshot.clone();
        let proof = proof.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let store = open_ready(home, &snapshot, source);
            barrier.wait();
            store
                .verify_proof(VerifyProofRequest {
                    proof,
                    observed_at_unix_ms: 400_100,
                })
                .unwrap()
        }));
    }
    let left = handles.remove(0).join().unwrap();
    let right = handles.remove(0).join().unwrap();
    assert_eq!(left.receipt_id, right.receipt_id);
    assert_eq!(
        sources
            .iter()
            .map(DeterministicEntropy::consumed_bytes)
            .sum::<usize>(),
        16
    );
}

#[test]
fn precommit_faults_rollback_and_postcommit_loss_recovers_exact_state() {
    let challenge_faults = [
        AuthorityFaultPoint::ChallengeInserted,
        AuthorityFaultPoint::ChallengeClockUpdated,
        AuthorityFaultPoint::ChallengeCreatedEventAppended,
        AuthorityFaultPoint::ChallengeCreatedEvent,
        AuthorityFaultPoint::ChallengeBeforeCommit,
    ];
    for fault in challenge_faults {
        let (_temp, home, snapshot) = ready_home(700_000);
        let source = deterministic(vec![0x72; 48]);
        let faulted_home = home.clone().with_authority_fault(fault);
        let result = open_ready(faulted_home, &snapshot, source.clone()).create_challenge(
            challenge_request(
                store_enroll_manifest(id("71717171-7171-4171-8171-717171717171")),
                700_000,
                700_500,
            ),
        );
        assert!(result.is_err());
        assert_eq!(source.consumed_bytes(), 48);
        let connection = Connection::open(home.database_path()).unwrap();
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM authorization_challenges"),
            0
        );
        assert_eq!(
            scalar(
                &connection,
                "SELECT COUNT(*) FROM authorization_challenges
                 WHERE created_event_sequence IS NOT NULL"
            ),
            0
        );
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
            2
        );
        assert_eq!(clock_pair(&connection), (700_000, 700_000));
    }

    let (_temp, home, snapshot) = ready_home(710_000);
    let source = deterministic(vec![0x73; 48]);
    let lost = open_ready(
        home.clone()
            .with_authority_fault(AuthorityFaultPoint::ChallengeAfterCommit),
        &snapshot,
        source.clone(),
    )
    .create_challenge(challenge_request(
        store_enroll_manifest(id("72727272-7272-4272-8272-727272727272")),
        710_000,
        710_500,
    ));
    assert!(lost.is_err());
    assert_eq!(source.consumed_bytes(), 48);
    let recovered = open_ready(home, &snapshot, deterministic(Vec::new()))
        .create_challenge(challenge_request(
            store_enroll_manifest(id("72727272-7272-4272-8272-727272727272")),
            710_000,
            710_500,
        ))
        .unwrap();
    assert_eq!(recovered.issued_at.timestamp_millis(), 710_000);
}

#[test]
fn proof_faults_are_atomic_and_postcommit_response_loss_replays_exactly() {
    let faults = [
        AuthorityFaultPoint::ReceiptInserted,
        AuthorityFaultPoint::NonceInserted,
        AuthorityFaultPoint::AuthorizedStateUpdated,
        AuthorityFaultPoint::ProofClockUpdated,
        AuthorityFaultPoint::AuthorizationEvent,
        AuthorityFaultPoint::ProofBeforeCommit,
    ];
    for fault in faults {
        let (_temp, home, snapshot) = ready_home(400_000);
        let challenge = signed_challenge_fixture(home.clone(), &snapshot);
        let source = deterministic(vec![0xd0; 16]);
        let proof = AuthorizationProof::new(
            challenge.challenge_id,
            challenge.key_id,
            challenge.signing_payload_sha256,
            synthetic_signature(),
        );
        let result = open_ready(
            home.clone().with_authority_fault(fault),
            &snapshot,
            source.clone(),
        )
        .verify_proof(VerifyProofRequest {
            proof,
            observed_at_unix_ms: 400_100,
        });
        assert!(result.is_err());
        assert_eq!(source.consumed_bytes(), 16);
        let connection = Connection::open(home.database_path()).unwrap();
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM authorization_receipts"),
            0
        );
        assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM nonce_uses"), 0);
        assert_eq!(
            scalar(
                &connection,
                "SELECT COUNT(*) FROM authorization_challenges WHERE state='pending'"
            ),
            1
        );
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
            3
        );
        assert_eq!(clock_pair(&connection), (400_000, 400_000));
    }

    let (_temp, home, snapshot) = ready_home(400_000);
    let challenge = signed_challenge_fixture(home.clone(), &snapshot);
    let proof = AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        synthetic_signature(),
    );
    let source = deterministic(vec![0xd0; 16]);
    let lost = open_ready(
        home.clone()
            .with_authority_fault(AuthorityFaultPoint::ProofAfterCommit),
        &snapshot,
        source.clone(),
    )
    .verify_proof(VerifyProofRequest {
        proof: proof.clone(),
        observed_at_unix_ms: 400_100,
    });
    assert!(lost.is_err());
    assert_eq!(source.consumed_bytes(), 16);
    let replay = open_ready(home, &snapshot, deterministic(Vec::new()))
        .verify_proof(VerifyProofRequest {
            proof,
            observed_at_unix_ms: 400_100,
        })
        .unwrap();
    assert_eq!(replay.verified_at.timestamp_millis(), 400_100);
}

#[test]
#[allow(clippy::too_many_lines)]
fn expiry_and_replacement_faults_preserve_committed_error_semantics() {
    for fault in [
        AuthorityFaultPoint::ExpiredStateUpdated,
        AuthorityFaultPoint::ExpiryClockUpdated,
        AuthorityFaultPoint::ExpiryEvent,
        AuthorityFaultPoint::ExpiryBeforeCommit,
    ] {
        let (_temp, home, snapshot) = ready_home(1_000_000);
        let challenge = open_ready(home.clone(), &snapshot, deterministic(vec![0x51; 48]))
            .create_challenge(challenge_request(
                store_enroll_manifest(id("a1a1a1a1-a1a1-41a1-81a1-a1a1a1a1a1a1")),
                1_000_000,
                1_000_010,
            ))
            .unwrap();
        let proof = AuthorizationProof::new(
            challenge.challenge_id,
            challenge.key_id,
            challenge.signing_payload_sha256,
            [0x51; 64],
        );
        let source = deterministic(Vec::new());
        let result = open_ready(
            home.clone().with_authority_fault(fault),
            &snapshot,
            source.clone(),
        )
        .verify_proof(VerifyProofRequest {
            proof,
            observed_at_unix_ms: 1_000_011,
        });
        assert!(result.is_err());
        assert_eq!(source.consumed_bytes(), 0);
        let connection = Connection::open(home.database_path()).unwrap();
        assert_eq!(
            scalar(
                &connection,
                "SELECT COUNT(*) FROM authorization_challenges WHERE state='pending'"
            ),
            1
        );
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
            3
        );
        assert_eq!(clock_pair(&connection), (1_000_000, 1_000_000));
    }

    let (_temp, home, snapshot) = ready_home(1_010_000);
    let challenge = open_ready(home.clone(), &snapshot, deterministic(vec![0x52; 48]))
        .create_challenge(challenge_request(
            store_enroll_manifest(id("a2a2a2a2-a2a2-42a2-82a2-a2a2a2a2a2a2")),
            1_010_000,
            1_010_010,
        ))
        .unwrap();
    let proof = AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        [0x52; 64],
    );
    let expiry_response_loss_entropy = deterministic(Vec::new());
    let lost = open_ready(
        home.clone()
            .with_authority_fault(AuthorityFaultPoint::ExpiryAfterCommit),
        &snapshot,
        expiry_response_loss_entropy.clone(),
    )
    .verify_proof(VerifyProofRequest {
        proof: proof.clone(),
        observed_at_unix_ms: 1_010_011,
    });
    assert!(lost.is_err());
    assert_eq!(expiry_response_loss_entropy.consumed_bytes(), 0);
    let retry = open_ready(home.clone(), &snapshot, deterministic(Vec::new()))
        .verify_proof(VerifyProofRequest {
            proof,
            observed_at_unix_ms: 1_010_011,
        })
        .unwrap_err();
    assert_eq!(retry.code, MailErrorCode::AuthorizationExpired);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authorization_challenges WHERE state='expired'"
        ),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        4
    );

    for fault in [
        AuthorityFaultPoint::OldChallengeExpiredState,
        AuthorityFaultPoint::OldChallengeExpiredEvent,
    ] {
        let (_temp, home, snapshot) = ready_home(1_020_000);
        let manifest = store_enroll_manifest(id("a3a3a3a3-a3a3-43a3-83a3-a3a3a3a3a3a3"));
        open_ready(home.clone(), &snapshot, deterministic(vec![0x53; 48]))
            .create_challenge(challenge_request(manifest.clone(), 1_020_000, 1_020_010))
            .unwrap();
        let source = deterministic(vec![0x54; 48]);
        let result = open_ready(
            home.clone().with_authority_fault(fault),
            &snapshot,
            source.clone(),
        )
        .create_challenge(challenge_request(manifest, 1_020_011, 1_020_100));
        assert!(result.is_err());
        assert_eq!(source.consumed_bytes(), 0);
        let connection = Connection::open(home.database_path()).unwrap();
        assert_eq!(
            scalar(
                &connection,
                "SELECT COUNT(*) FROM authorization_challenges WHERE state='pending'"
            ),
            1
        );
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
            3
        );
    }
}

#[test]
fn restart_validator_rejects_private_row_event_and_later_table_corruption() {
    let (_temp, home, snapshot) = ready_home(800_000);
    let challenge = open_ready(home.clone(), &snapshot, deterministic(vec![0x82; 48]))
        .create_challenge(challenge_request(
            store_enroll_manifest(id("81818181-8181-4181-8181-818181818181")),
            800_000,
            800_500,
        ))
        .unwrap();
    let reopened = open_ready(home.clone(), &snapshot, deterministic(Vec::new()));
    assert!(matches!(reopened.state(), AuthorityOpenState::Ready(_)));

    let connection = Connection::open(home.database_path()).unwrap();
    let (grant_id, context_sha256): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT grant_id,context_sha256 FROM authorization_challenges WHERE challenge_id=?1",
            [challenge.challenge_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let context_sha256 = Sha256Digest::from_bytes(context_sha256.try_into().unwrap());
    let detail = event_detail(
        3,
        challenge.challenge_id.as_bytes(),
        4,
        10,
        &grant_id,
        0,
        0x0801,
        context_sha256,
        &[],
        800_000,
    );
    let digest = Sha256::digest(&detail);
    connection
        .execute(
            "UPDATE authority_events SET source=4,detail=?1,detail_sha256=?2 WHERE event_code=3",
            params![detail, digest.as_slice()],
        )
        .unwrap();
    drop(connection);
    let corrupted = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(snapshot.anchor.clone())),
        home.clone(),
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(matches!(
        corrupted.state(),
        AuthorityOpenState::RecoveryRequired
    ));

    let (_temp, home, snapshot) = ready_home(810_000);
    let challenge = open_ready(home.clone(), &snapshot, deterministic(vec![0x83; 48]))
        .create_challenge(challenge_request(
            store_enroll_manifest(id("82828282-8282-4282-8282-828282828282")),
            810_000,
            810_500,
        ))
        .unwrap();
    let connection = Connection::open(home.database_path()).unwrap();
    connection
        .execute(
            "INSERT INTO challenge_effects(challenge_id,ordinal,effect_id,effect_kind)
             VALUES(?1,0,?2,1)",
            params![
                challenge.challenge_id.as_bytes(),
                id::<TransitionId>("83838383-8383-4383-8383-838383838383").as_bytes()
            ],
        )
        .unwrap();
    drop(connection);
    let corrupted = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(snapshot.anchor.clone())),
        home,
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(matches!(
        corrupted.state(),
        AuthorityOpenState::RecoveryRequired
    ));
}

#[test]
fn restart_validator_rejects_each_later_stage_table_independently() {
    for table in [
        "registered_stores",
        "registered_accounts",
        "challenge_effects",
        "grant_uses",
        "account_transitions",
        "credential_cleanup",
        "remote_effects",
        "effect_claims",
        "effect_invocations",
        "effect_observations",
    ] {
        let (_temp, home, snapshot) = ready_home(820_000);
        let connection = Connection::open(home.database_path()).unwrap();
        insert_isolated_forbidden_row(&connection, table);
        assert_eq!(
            scalar(&connection, &format!("SELECT COUNT(*) FROM {table}")),
            1,
            "{table} fixture was not installed"
        );
        drop(connection);
        let corrupted = AuthorityStore::open_isolated(
            context(AnchorPresence::Present(snapshot.anchor.clone())),
            home,
            deterministic(Vec::new()),
        )
        .unwrap();
        assert!(
            matches!(corrupted.state(), AuthorityOpenState::RecoveryRequired),
            "{table} row was accepted"
        );
    }
}

#[test]
fn persisted_authorization_rows_reject_wrong_sql_classes_with_canonical_schema() {
    for kind in ["challenge", "receipt", "nonce", "event"] {
        let (_temp, home, snapshot) = ready_home(400_000);
        match kind {
            "challenge" => {
                signed_challenge_fixture(home.clone(), &snapshot);
                install_wrong_storage_class(
                    &home,
                    "authorization_challenges",
                    "UPDATE authorization_challenges SET issued_at='wrong-storage-class'",
                    "SELECT typeof(issued_at) FROM authorization_challenges",
                );
            }
            "receipt" => {
                authorize_signed_challenge(home.clone(), &snapshot);
                install_wrong_storage_class(
                    &home,
                    "authorization_receipts",
                    "UPDATE authorization_receipts SET verified_at='wrong-storage-class'",
                    "SELECT typeof(verified_at) FROM authorization_receipts",
                );
            }
            "nonce" => {
                authorize_signed_challenge(home.clone(), &snapshot);
                install_wrong_storage_class(
                    &home,
                    "nonce_uses",
                    "UPDATE nonce_uses SET consumed_at='wrong-storage-class'",
                    "SELECT typeof(consumed_at) FROM nonce_uses",
                );
            }
            "event" => install_wrong_storage_class(
                &home,
                "authority_events",
                "UPDATE authority_events SET occurred_at='wrong-storage-class' WHERE sequence=1",
                "SELECT typeof(occurred_at) FROM authority_events WHERE sequence=1",
            ),
            _ => unreachable!(),
        }
        let corrupted = AuthorityStore::open_isolated(
            context(AnchorPresence::Present(snapshot.anchor.clone())),
            home,
            deterministic(Vec::new()),
        )
        .unwrap();
        assert!(
            matches!(corrupted.state(), AuthorityOpenState::RecoveryRequired),
            "{kind} wrong SQL class was accepted"
        );
    }
}

#[test]
fn persisted_authorization_rows_reject_oversized_blob_and_text_values() {
    for kind in ["challenge", "challenge_state", "receipt", "nonce", "event"] {
        let (_temp, home, snapshot) = ready_home(400_000);
        let (length_sql, expected_length) = match kind {
            "challenge" => {
                signed_challenge_fixture(home.clone(), &snapshot);
                install_ignored_constraint_mutation(
                    &home,
                    "UPDATE authorization_challenges SET manifest=zeroblob(4194305)",
                );
                (
                    "SELECT length(manifest) FROM authorization_challenges",
                    4_194_305,
                )
            }
            "challenge_state" => {
                signed_challenge_fixture(home.clone(), &snapshot);
                install_ignored_constraint_mutation(
                    &home,
                    "UPDATE authorization_challenges
                     SET state=replace(hex(zeroblob(1024)),'00','x')",
                );
                ("SELECT length(state) FROM authorization_challenges", 1_024)
            }
            "receipt" => {
                authorize_signed_challenge(home.clone(), &snapshot);
                install_ignored_constraint_mutation(
                    &home,
                    "UPDATE authorization_receipts SET canonical_proof=zeroblob(4097)",
                );
                (
                    "SELECT length(canonical_proof) FROM authorization_receipts",
                    4_097,
                )
            }
            "nonce" => {
                authorize_signed_challenge(home.clone(), &snapshot);
                install_ignored_constraint_mutation(
                    &home,
                    "UPDATE nonce_uses SET nonce=zeroblob(33)",
                );
                ("SELECT length(nonce) FROM nonce_uses", 33)
            }
            "event" => {
                install_ignored_constraint_mutation(
                    &home,
                    "UPDATE authority_events SET detail=zeroblob(65537) WHERE sequence=1",
                );
                (
                    "SELECT length(detail) FROM authority_events WHERE sequence=1",
                    65_537,
                )
            }
            _ => unreachable!(),
        };
        let connection = Connection::open(home.database_path()).unwrap();
        assert_eq!(scalar(&connection, length_sql), expected_length);
        drop(connection);
        let corrupted = AuthorityStore::open_isolated(
            context(AnchorPresence::Present(snapshot.anchor.clone())),
            home,
            deterministic(Vec::new()),
        )
        .unwrap();
        assert!(
            matches!(corrupted.state(), AuthorityOpenState::RecoveryRequired),
            "{kind} oversized persisted value was accepted"
        );
    }
}

#[test]
fn restart_validator_streams_history_without_a_cardinality_cap() {
    let (_temp, home, snapshot) = ready_home(850_000);
    let mut bytes = Vec::new();
    for value in 1_u8..=128 {
        bytes.extend_from_slice(&[value; 48]);
    }
    let source = deterministic(bytes);
    let store = open_ready(home.clone(), &snapshot, source.clone());
    for index in 0_u32..128 {
        let store_id = id::<StoreId>(&format!("aaaaaaaa-0000-4000-8000-{index:012x}"));
        store
            .create_challenge(challenge_request(
                store_enroll_manifest(store_id),
                850_000 + i64::from(index),
                850_500 + i64::from(index),
            ))
            .unwrap();
    }
    assert_eq!(source.consumed_bytes(), 128 * 48);
    let reopened = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(snapshot.anchor.clone())),
        home.clone(),
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(matches!(reopened.state(), AuthorityOpenState::Ready(_)));
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authorization_challenges"),
        128
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authorization_challenges
             WHERE created_event_sequence IS NOT NULL"
        ),
        128
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        130
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT
             (SELECT COUNT(*) FROM registered_stores)+
             (SELECT COUNT(*) FROM registered_accounts)+
             (SELECT COUNT(*) FROM challenge_effects)+
             (SELECT COUNT(*) FROM grant_uses)+
             (SELECT COUNT(*) FROM account_transitions)+
             (SELECT COUNT(*) FROM credential_cleanup)+
             (SELECT COUNT(*) FROM remote_effects)+
             (SELECT COUNT(*) FROM effect_claims)+
             (SELECT COUNT(*) FROM effect_invocations)+
             (SELECT COUNT(*) FROM effect_observations)"
        ),
        0
    );
}

#[test]
fn lifecycle_and_terminal_lookup_query_plans_use_declared_indexes() {
    let (_temp, home, snapshot) = ready_home(875_000);
    open_ready(home.clone(), &snapshot, deterministic(vec![0x87; 48]))
        .create_challenge(challenge_request(
            store_enroll_manifest(id("87878787-8787-4787-8787-878787878787")),
            875_000,
            875_500,
        ))
        .unwrap();
    let connection = Connection::open(home.database_path()).unwrap();
    let lifecycle = query_plan(
        &connection,
        "SELECT context_sha256,created_event_sequence,challenge_id,state
         FROM authorization_challenges
              INDEXED BY authorization_challenges_context_created_sequence
         ORDER BY context_sha256,created_event_sequence,challenge_id",
    );
    let lifecycle_plan = lifecycle.join(" | ");
    assert!(
        lifecycle_plan.contains("USING INDEX authorization_challenges_context_created_sequence"),
        "unexpected lifecycle plan: {lifecycle_plan}"
    );
    assert!(!lifecycle_plan.contains("CORRELATED"));
    assert!(!lifecycle_plan.contains("USE TEMP B-TREE"));

    let terminal = query_plan(
        &connection,
        "SELECT sequence,event_code FROM authority_events
              INDEXED BY authority_events_entity_sequence
         WHERE entity_kind=8 AND entity_id=zeroblob(32) AND event_code IN (3,4,5)
         ORDER BY sequence LIMIT 4",
    );
    let terminal_plan = terminal.join(" | ");
    assert!(
        terminal_plan.contains("USING INDEX authority_events_entity_sequence"),
        "unexpected terminal-event plan: {terminal_plan}"
    );
    assert!(!terminal_plan.contains("SCAN authority_events"));
    assert!(!terminal_plan.contains("CORRELATED"));
    assert!(!terminal_plan.contains("USE TEMP B-TREE"));
}

#[test]
fn restart_validator_rejects_a_schema_valid_recomputed_proof_receipt_mutation() {
    let (_temp, home, snapshot) = ready_home(400_000);
    let challenge = signed_challenge_fixture(home.clone(), &snapshot);
    let proof = AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        synthetic_signature(),
    );
    let receipt = open_ready(
        home.clone(),
        &snapshot,
        deterministic((0xd0_u8..0xe0).collect()),
    )
    .verify_proof(VerifyProofRequest {
        proof,
        observed_at_unix_ms: 400_100,
    })
    .unwrap();
    let changed = AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        [0x5a; 64],
    );
    let changed_digest = changed.proof_sha256();
    let connection = Connection::open(home.database_path()).unwrap();
    let (grant_id, bundle): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT grant_id,bundle_sha256 FROM authorization_challenges WHERE challenge_id=?1",
            [challenge.challenge_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let epoch = 1_u64.to_be_bytes();
    let verified = 400_100_i64.to_be_bytes();
    let expires = 400_500_i64.to_be_bytes();
    let changed_receipt = encode(
        b"KIRJE-AUTHORIZATION-RECEIPT-V1\0",
        &[
            receipt.receipt_id.as_bytes(),
            challenge.challenge_id.as_bytes(),
            &grant_id,
            changed_digest.as_bytes(),
            challenge.key_id.as_bytes(),
            challenge.manifest_sha256.as_bytes(),
            challenge.signing_payload_sha256.as_bytes(),
            &epoch,
            &bundle,
            &verified,
            &expires,
        ],
    );
    let receipt_digest = Sha256::digest(&changed_receipt);
    connection
        .execute(
            "UPDATE authorization_receipts SET proof_sha256=?1,signature=?2,
             canonical_proof=?3,receipt=?4,receipt_sha256=?5 WHERE receipt_id=?6",
            params![
                changed_digest.as_bytes(),
                [0x5a_u8; 64].as_slice(),
                changed.canonical_bytes(),
                changed_receipt,
                receipt_digest.as_slice(),
                receipt.receipt_id.as_bytes(),
            ],
        )
        .unwrap();
    drop(connection);
    let corrupted = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(snapshot.anchor.clone())),
        home,
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(matches!(
        corrupted.state(),
        AuthorityOpenState::RecoveryRequired
    ));
}

#[test]
fn restart_validator_rejects_conflicting_exact_terminal_events() {
    let (_temp, home, snapshot) = ready_home(400_000);
    let challenge = signed_challenge_fixture(home.clone(), &snapshot);
    let proof = AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        synthetic_signature(),
    );
    open_ready(
        home.clone(),
        &snapshot,
        deterministic((0xd0_u8..0xe0).collect()),
    )
    .verify_proof(VerifyProofRequest {
        proof: proof.clone(),
        observed_at_unix_ms: 400_100,
    })
    .unwrap();
    open_ready(home.clone(), &snapshot, deterministic(Vec::new()))
        .verify_proof(VerifyProofRequest {
            proof,
            observed_at_unix_ms: 400_600,
        })
        .unwrap();
    let connection = Connection::open(home.database_path()).unwrap();
    let context_bytes: Vec<u8> = connection
        .query_row(
            "SELECT context_sha256 FROM authorization_challenges WHERE challenge_id=?1",
            [challenge.challenge_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let detail = event_detail(
        5,
        challenge.challenge_id.as_bytes(),
        1,
        0,
        &[],
        0x0801,
        0x0803,
        Sha256Digest::from_bytes(context_bytes.try_into().unwrap()),
        &[],
        400_600,
    );
    let detail_sha256 = Sha256::digest(&detail);
    connection
        .execute(
            "INSERT INTO authority_events
             (entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256)
             VALUES(8,?1,5,1,400600,?2,?3)",
            params![
                challenge.challenge_id.as_bytes(),
                detail,
                detail_sha256.as_slice(),
            ],
        )
        .unwrap();
    drop(connection);
    let corrupted = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(snapshot.anchor.clone())),
        home,
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(matches!(
        corrupted.state(),
        AuthorityOpenState::RecoveryRequired
    ));
}

#[test]
fn restart_validator_rejects_replacement_created_before_predecessor_expired() {
    let (_temp, home, snapshot) = ready_home(420_000);
    let manifest = store_enroll_manifest(id("42424242-4242-4242-8242-424242424242"));
    let _first = open_ready(home.clone(), &snapshot, deterministic(vec![0x42; 48]))
        .create_challenge(challenge_request(manifest.clone(), 420_000, 420_010))
        .unwrap();
    let second = open_ready(home.clone(), &snapshot, deterministic(vec![0x43; 48]))
        .create_challenge(challenge_request(manifest, 420_011, 420_100))
        .unwrap();
    let connection = Connection::open(home.database_path()).unwrap();
    swap_event_sequences(&connection, 4, 5);
    connection
        .execute(
            "UPDATE authorization_challenges SET created_event_sequence=4
             WHERE challenge_id=?1",
            [second.challenge_id.as_bytes()],
        )
        .unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        5
    );
    assert_eq!(
        scalar(&connection, "SELECT MAX(sequence) FROM authority_events"),
        5
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT seq FROM sqlite_sequence WHERE name='authority_events'"
        ),
        5
    );
    drop(connection);

    let corrupted = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(snapshot.anchor.clone())),
        home,
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(matches!(
        corrupted.state(),
        AuthorityOpenState::RecoveryRequired
    ));
}

#[test]
fn restart_validator_rejects_authorized_terminal_after_same_time_successor_creation() {
    let (_temp, home, snapshot) = ready_home(400_000);
    let (first, _) = authorize_signed_challenge(home.clone(), &snapshot);
    let second = open_ready(home.clone(), &snapshot, deterministic(vec![0x47; 48]))
        .create_challenge(challenge_request(
            store_enroll_manifest(id("41414141-4141-4141-8141-414141414141")),
            400_100,
            400_600,
        ))
        .unwrap();
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(
            &connection,
            "SELECT occurred_at FROM authority_events
             WHERE entity_id=(SELECT challenge_id FROM authorization_challenges
                              WHERE state='authorized') AND event_code=4"
        ),
        400_100
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT occurred_at FROM authority_events
             WHERE entity_id=(SELECT challenge_id FROM authorization_challenges
                              WHERE state='pending') AND event_code=3"
        ),
        400_100
    );
    swap_event_sequences(&connection, 4, 5);
    connection
        .execute(
            "UPDATE authorization_challenges SET created_event_sequence=4
             WHERE challenge_id=?1",
            [second.challenge_id.as_bytes()],
        )
        .unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT sequence FROM authority_events
                 WHERE entity_id=?1 AND event_code=4",
                [first.challenge_id.as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        5
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT created_event_sequence FROM authorization_challenges
                 WHERE challenge_id=?1",
                [second.challenge_id.as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        4
    );
    drop(connection);
    assert_recovery_required(home, &snapshot);
}

#[test]
fn restart_validator_rejects_pending_predecessor_with_a_valid_expired_successor() {
    let (_temp, home, snapshot) = ready_home(430_000);
    let manifest = store_enroll_manifest(id("43434343-4343-4343-8343-434343434343"));
    let first = open_ready(home.clone(), &snapshot, deterministic(vec![0x48; 48]))
        .create_challenge(challenge_request(manifest.clone(), 430_000, 430_010))
        .unwrap();
    let second = open_ready(home.clone(), &snapshot, deterministic(vec![0x49; 48]))
        .create_challenge(challenge_request(manifest, 430_011, 430_100))
        .unwrap();
    let connection = Connection::open(home.database_path()).unwrap();
    let context_bytes: Vec<u8> = connection
        .query_row(
            "SELECT context_sha256 FROM authorization_challenges WHERE challenge_id=?1",
            [second.challenge_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let occurred_at = 430_101;
    let detail = event_detail(
        5,
        second.challenge_id.as_bytes(),
        1,
        0,
        &[],
        0x0801,
        0x0803,
        Sha256Digest::from_bytes(context_bytes.try_into().unwrap()),
        &[],
        occurred_at,
    );
    let detail_sha256 = Sha256::digest(&detail);
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    swap_event_sequences(&connection, 4, 5);
    connection
        .execute(
            "UPDATE authorization_challenges
             SET state='expired',created_event_sequence=4 WHERE challenge_id=?1",
            [second.challenge_id.as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE authorization_challenges SET state='pending' WHERE challenge_id=?1",
            [first.challenge_id.as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE authority_events
             SET entity_kind=8,entity_id=?1,event_code=5,source=1,occurred_at=?2,
                 detail=?3,detail_sha256=?4
             WHERE sequence=5",
            params![
                second.challenge_id.as_bytes(),
                occurred_at,
                detail,
                detail_sha256.as_slice(),
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE authority_meta SET last_observed_at=?1,updated_at=?1 WHERE singleton=1",
            [occurred_at],
        )
        .unwrap();
    connection.execute_batch("COMMIT").unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM authority_events
                 WHERE entity_id=?1 AND event_code IN (4,5)",
                [first.challenge_id.as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM authority_events
                 WHERE entity_id=?1 AND event_code=5",
                [second.challenge_id.as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    drop(connection);
    assert_recovery_required(home, &snapshot);
}

#[test]
fn restart_validator_accepts_one_legal_trailing_pending_challenge() {
    let (_temp, home, snapshot) = ready_home(440_000);
    let manifest = store_enroll_manifest(id("44444444-4444-4444-8444-444444444444"));
    open_ready(home.clone(), &snapshot, deterministic(vec![0x4a; 48]))
        .create_challenge(challenge_request(manifest.clone(), 440_000, 440_010))
        .unwrap();
    open_ready(home.clone(), &snapshot, deterministic(vec![0x4b; 48]))
        .create_challenge(challenge_request(manifest, 440_011, 440_100))
        .unwrap();
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authorization_challenges WHERE state='pending'"
        ),
        1
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT MIN(created_event_sequence < terminal_sequence)
             FROM (
                 SELECT c.created_event_sequence,
                        (SELECT e.sequence FROM authority_events e
                         WHERE e.entity_id=c.challenge_id AND e.event_code=5) terminal_sequence
                 FROM authorization_challenges c WHERE c.state='expired'
             )"
        ),
        1
    );
    drop(connection);
    let reopened = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(snapshot.anchor.clone())),
        home,
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(matches!(reopened.state(), AuthorityOpenState::Ready(_)));
}

#[test]
fn challenge_export_is_bounded_and_receipt_projection_has_no_private_material() {
    let (_temp, home, snapshot) = ready_home(900_000);
    let challenge = open_ready(home, &snapshot, deterministic(vec![0x92; 48]))
        .create_challenge(challenge_request(
            store_enroll_manifest(id("91919191-9191-4191-8191-919191919191")),
            900_000,
            900_500,
        ))
        .unwrap();
    assert_eq!(challenge.contract_version, "kirje.authorization.v1");
    assert!(!challenge.signing_payload_base64url.contains('='));
    assert!(!challenge.manifest_base64url.contains('='));
    assert!(challenge.signing_payload_base64url.len() < 6_000_000);
    assert!(challenge.manifest_base64url.len() < 6_000_000);
    let owner_artifact = challenge.to_json_value();
    assert_eq!(owner_artifact["contract_version"], "kirje.authorization.v1");
    assert_eq!(
        owner_artifact["challenge_id"],
        challenge.challenge_id.to_string()
    );
    assert_eq!(owner_artifact["review"]["bounded"], true);
    assert_eq!(owner_artifact["review"]["authoritative"], false);
    assert_eq!(
        owner_artifact.as_object().unwrap().len(),
        14,
        "owner artifact field set drifted"
    );

    let public_json = serde_json::to_string(&kirje_core::AuthorizationReceiptProjection {
        contract_version: "kirje.authorization-receipt.v1".to_owned(),
        receipt_id: id("92929292-9292-4292-8292-929292929292"),
        challenge_id: challenge.challenge_id,
        action: challenge.action,
        target_kind: challenge.target_kind,
        target_id: challenge.target_id,
        key_fingerprint: challenge.key_id.fingerprint(),
        trust_epoch: challenge.trust_epoch,
        manifest_sha256: challenge.manifest_sha256,
        receipt_sha256: Sha256Digest::from_bytes([0x93; 32]),
        verified_at: challenge.issued_at,
        expires_at: challenge.expires_at,
        state: AuthorizationReceiptState::Unclaimed,
    })
    .unwrap();
    for forbidden in [
        "signature",
        "proof",
        "nonce",
        "signing_payload",
        "manifest_base64url",
        "public_key",
        "realm",
        "detail",
        "sqlite",
        "path",
    ] {
        assert!(!public_json.contains(forbidden), "leaked {forbidden}");
    }
}

#[test]
fn receipt_identifier_collision_is_atomic_with_exact_entropy() {
    let (_temp, home, snapshot) = ready_home_with_owner(1_200_000, collision_owner_key());
    let first = open_ready(
        home.clone(),
        &snapshot,
        deterministic([[0x61; 16].as_slice(), [0x62; 32].as_slice()].concat()),
    )
    .create_challenge(challenge_request(
        store_enroll_manifest(id("c1c1c1c1-c1c1-41c1-81c1-c1c1c1c1c1c1")),
        1_200_000,
        1_200_500,
    ))
    .unwrap();
    let second = open_ready(
        home.clone(),
        &snapshot,
        deterministic([[0x63; 16].as_slice(), [0x64; 32].as_slice()].concat()),
    )
    .create_challenge(challenge_request(
        store_enroll_manifest(id("c2c2c2c2-c2c2-42c2-82c2-c2c2c2c2c2c2")),
        1_200_001,
        1_200_501,
    ))
    .unwrap();
    let receipt_entropy = deterministic(vec![0x77; 16]);
    open_ready(home.clone(), &snapshot, receipt_entropy.clone())
        .verify_proof(VerifyProofRequest {
            proof: AuthorizationProof::new(
                first.challenge_id,
                first.key_id,
                first.signing_payload_sha256,
                hex64(COLLISION_SIGNATURE_ONE),
            ),
            observed_at_unix_ms: 1_200_100,
        })
        .unwrap();
    assert_eq!(receipt_entropy.consumed_bytes(), 16);

    let collision_entropy = deterministic(vec![0x77; 16]);
    let error = open_ready(home.clone(), &snapshot, collision_entropy.clone())
        .verify_proof(VerifyProofRequest {
            proof: AuthorizationProof::new(
                second.challenge_id,
                second.key_id,
                second.signing_payload_sha256,
                hex64(COLLISION_SIGNATURE_TWO),
            ),
            observed_at_unix_ms: 1_200_101,
        })
        .unwrap_err();
    assert_eq!(error.code, MailErrorCode::StoreWrite);
    assert_eq!(collision_entropy.consumed_bytes(), 16);
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authorization_receipts"),
        1
    );
    assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM nonce_uses"), 1);
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authorization_challenges WHERE state='pending'"
        ),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM authority_events"),
        5
    );
    assert_eq!(clock_pair(&connection), (1_200_100, 1_200_100));
}
