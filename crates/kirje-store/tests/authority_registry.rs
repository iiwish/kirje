#![cfg(feature = "test-support")]

use std::{
    num::NonZeroU64,
    str::FromStr,
    sync::{Arc, Barrier},
    thread,
};

use kirje_core::{
    AccountBinding, AccountId, AccountSnapshot, AccountStateReason, ActionManifest,
    AuthorizationGrantId, AuthorizationProof, AuthorizationReceiptProjection,
    AuthorizationReceiptState, BindingState, ConfigCas, CredentialId, CredentialKind, Endpoint,
    EndpointSnapshot, HostKind, MailAccountConfig, MailError, MailErrorCode, ManifestContext,
    ManifestPayload, ManifestTarget, OwnerPublicKey, PlatformLocationMaterial, Protocol,
    SensitiveAction, Sha256Digest, StoreEnrollManifest, StoreEnrollmentState, StoreId,
    StoredCredentialState, TargetKind, TransitionId, TransportSecurity,
};
use kirje_store::{
    AccountTransitionKind, AccountTransitionObservationRequest, AccountTransitionProjection,
    AccountTransitionState, AnchorPresence, AuthorityFaultPoint, AuthorityOpenContext,
    AuthorityOpenState, AuthorityStore, AuthorityValidationQueryCounts,
    AuthorizationChallengeExport, BootstrapInput, BootstrapSnapshot, CreateChallengeRequest,
    DeterministicEntropy, EnrollStoreRequest, EnrolledStoreProjection, EnrolledStoreState,
    GrantUseRequest, IsolatedAuthorityHome, JournalLocationDigest, PrepareAccountTransitionRequest,
    RegisteredAccountState, RegisteredStoreTransitionState, VerifyProofRequest,
    reset_authority_validation_query_counts, take_authority_validation_query_counts,
};
use rusqlite::{Connection, params};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

const OWNER_PUBLIC_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RECOVERY_PUBLIC_KEY: &str =
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const SIGNATURES: &str =
    include_str!("fixtures/authority/registry/store_enrollment/signatures.txt");
const ACCOUNT_CREATE_VECTORS: &str =
    include_str!("fixtures/authority/registry/account_create/vectors.txt");

struct ReadyFixture {
    _temp: TempDir,
    home: IsolatedAuthorityHome,
    snapshot: BootstrapSnapshot,
}

struct AuthorizedFixture {
    challenge: AuthorizationChallengeExport,
    receipt: AuthorizationReceiptProjection,
    proof: AuthorizationProof,
    manifest: ActionManifest,
    grant_id: AuthorizationGrantId,
}

fn hex<const N: usize>(value: &str) -> [u8; N] {
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

fn key(value: &str) -> OwnerPublicKey {
    OwnerPublicKey::try_from(hex::<32>(value)).unwrap()
}

fn signature(index: usize) -> [u8; 64] {
    let value = SIGNATURES
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .nth(index)
        .unwrap();
    hex(value)
}

fn account_signature(name: &str) -> [u8; 64] {
    hex(account_vector(name))
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

fn ready_fixture() -> ReadyFixture {
    ready_fixture_with_owner(OWNER_PUBLIC_KEY)
}

fn ready_fixture_with_owner(owner_public_key: &str) -> ReadyFixture {
    let temp = TempDir::new().unwrap();
    let home = IsolatedAuthorityHome::new(temp.path().to_path_buf()).unwrap();
    let pending = AuthorityStore::open_isolated(
        context(AnchorPresence::Missing),
        home.clone(),
        deterministic((0_u8..48).collect()),
    )
    .unwrap()
    .prepare_bootstrap(BootstrapInput {
        journal_location_sha256: location(),
        owner_public_key: key(owner_public_key),
        recovery_public_key: key(RECOVERY_PUBLIC_KEY),
        observed_at_unix_ms: 400_000,
    })
    .unwrap();
    AuthorityStore::open_isolated(
        context(AnchorPresence::Present(pending.anchor.clone())),
        home.clone(),
        deterministic(Vec::new()),
    )
    .unwrap()
    .confirm_anchor(&pending.anchor, 400_000)
    .unwrap();
    ReadyFixture {
        _temp: temp,
        home,
        snapshot: pending,
    }
}

fn account_ready_fixture() -> ReadyFixture {
    ready_fixture_with_owner(account_vector("owner_public_key"))
}

fn enroll_account_fixture_store(fixture: &ReadyFixture) -> AuthorizedFixture {
    let challenge = create_challenge(fixture, 0);
    let proof = AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        account_signature("store_signature"),
    );
    let receipt = open_ready(
        fixture,
        deterministic(hex::<16>(account_vector("store_receipt_entropy")).to_vec()),
    )
    .verify_proof(VerifyProofRequest {
        proof: proof.clone(),
        observed_at_unix_ms: issued_at(0) + 100,
    })
    .unwrap();
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    let grant: Vec<u8> = connection
        .query_row(
            "SELECT grant_id FROM authorization_challenges WHERE challenge_id=?1",
            [challenge.challenge_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let authorized = AuthorizedFixture {
        challenge,
        receipt,
        proof,
        manifest: manifest(0),
        grant_id: AuthorizationGrantId::try_from(Uuid::from_slice(&grant).unwrap()).unwrap(),
    };
    open_ready(fixture, deterministic(Vec::new()))
        .enroll_store(enrollment_request(0, &authorized, issued_at(0) + 200))
        .unwrap();
    authorized
}

fn open_ready(fixture: &ReadyFixture, entropy: DeterministicEntropy) -> AuthorityStore {
    let store = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(fixture.snapshot.anchor.clone())),
        fixture.home.clone(),
        entropy,
    )
    .unwrap();
    assert!(matches!(store.state(), AuthorityOpenState::Ready(_)));
    store
}

fn open_ready_with_fault(fixture: &ReadyFixture, fault: AuthorityFaultPoint) -> AuthorityStore {
    let store = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(fixture.snapshot.anchor.clone())),
        fixture.home.clone().with_authority_fault(fault),
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(matches!(store.state(), AuthorityOpenState::Ready(_)));
    store
}

fn synthetic_uuid(index: usize, namespace: u32) -> String {
    format!(
        "{namespace:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        (index >> 12) & 0xffff,
        index & 0xfff,
        index & 0xfff,
        index + 1,
    )
}

fn profile(index: usize) -> (usize, usize, usize, usize) {
    match index {
        128 => (0, 128, 128, 128),
        129 => (129, 0, 129, 129),
        130 | 131 => (130, 130, 130, 130),
        _ => (index, index, index, index),
    }
}

fn store_id(index: usize) -> StoreId {
    StoreId::from_str(&synthetic_uuid(profile(index).0, 0x5100_0000)).unwrap()
}

fn location_material(index: usize) -> PlatformLocationMaterial {
    let location_index = profile(index).1;
    PlatformLocationMaterial::Unix {
        parent_device: 0x1000 + u64::try_from(location_index).unwrap(),
        parent_inode: 0x2000 + u64::try_from(location_index).unwrap(),
        final_component: format!("synthetic-store-{location_index}").into_bytes(),
    }
}

fn location_sha256(index: usize) -> Sha256Digest {
    Sha256Digest::digest(&location_material(index).canonical_bytes().unwrap())
}

fn config_sha256(index: usize) -> Sha256Digest {
    Sha256Digest::digest(format!("synthetic-config-{}", profile(index).2).as_bytes())
}

fn account_vector(name: &str) -> &'static str {
    ACCOUNT_CREATE_VECTORS
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
        .unwrap()
}

fn account_id() -> AccountId {
    AccountId::from_str(account_vector("account_id")).unwrap()
}

fn credential_id() -> CredentialId {
    CredentialId::from_str(account_vector("credential_id")).unwrap()
}

fn account_transition_id() -> TransitionId {
    TransitionId::from_str(account_vector("transition_id")).unwrap()
}

fn account_after_config_sha256() -> Sha256Digest {
    Sha256Digest::from_bytes(hex(account_vector("after_config_sha256")))
}

fn account_third_config_sha256() -> Sha256Digest {
    Sha256Digest::from_bytes(hex(account_vector("third_config_sha256")))
}

fn account_binding() -> AccountBinding {
    AccountBinding::from_config(&MailAccountConfig {
        id: account_vector("display_id").to_owned(),
        email: account_vector("email").to_owned(),
        username: account_vector("username").to_owned(),
        incoming: Endpoint {
            protocol: Protocol::Imap,
            host: account_vector("incoming_host").to_owned(),
            port: 993,
            security: TransportSecurity::ImplicitTls,
        },
        outgoing: Some(Endpoint {
            protocol: Protocol::Smtp,
            host: account_vector("outgoing_host").to_owned(),
            port: 465,
            security: TransportSecurity::ImplicitTls,
        }),
        credential_kind: CredentialKind::AppPassword,
    })
    .unwrap()
}

fn account_manifest() -> ActionManifest {
    account_manifest_with_state_reason(Some(AccountStateReason::CredentialReentryRequired))
}

fn account_manifest_with_state_reason(state_reason: Option<AccountStateReason>) -> ActionManifest {
    let account_id = account_id();
    let binding_sha256 = account_binding().sha256();
    let after = AccountSnapshot {
        display_id: account_vector("display_id").to_owned(),
        account_id,
        generation: NonZeroU64::new(1).unwrap(),
        email: account_vector("email").to_owned(),
        username: account_vector("username").to_owned(),
        credential_kind: CredentialKind::AppPassword,
        credential_id: credential_id(),
        binding_version: 1,
        binding_sha256,
        binding_state: BindingState::Proposed,
        credential_state: StoredCredentialState::ReentryRequired,
        state_reason,
        incoming: EndpointSnapshot {
            protocol: Protocol::Imap,
            exact_host: account_vector("incoming_host").to_owned(),
            host_kind: HostKind::Dns,
            canonical_host: account_vector("incoming_host").to_owned(),
            port: 993,
            security: TransportSecurity::ImplicitTls,
        },
        outgoing: Some(EndpointSnapshot {
            protocol: Protocol::Smtp,
            exact_host: account_vector("outgoing_host").to_owned(),
            host_kind: HostKind::Dns,
            canonical_host: account_vector("outgoing_host").to_owned(),
            port: 465,
            security: TransportSecurity::ImplicitTls,
        }),
        cleanup_ids: Vec::new(),
    };
    ActionManifest::new(
        ManifestContext {
            target: ManifestTarget::Account(account_id),
            store_id: Some(store_id(0)),
            account_id: Some(account_id),
            account_binding_sha256: Some(binding_sha256),
            policy_sha256: None,
            effect_id: None,
        },
        ManifestPayload::AccountCreate(kirje_core::AccountMutationManifest {
            transition_id: account_transition_id(),
            config_cas: ConfigCas {
                store_id: store_id(0),
                generation: NonZeroU64::new(1).unwrap(),
                exact_content_sha256: config_sha256(0),
                location_sha256: location_sha256(0),
            },
            before: None,
            after: Some(after),
            next_config_generation: NonZeroU64::new(2).unwrap(),
            after_config_sha256: account_after_config_sha256(),
            cleanup: Vec::new(),
        }),
    )
    .unwrap()
}

fn second_account_id() -> AccountId {
    AccountId::from_str(account_vector("second_account_id")).unwrap()
}

fn second_credential_id() -> CredentialId {
    CredentialId::from_str(account_vector("second_credential_id")).unwrap()
}

fn second_account_transition_id() -> TransitionId {
    TransitionId::from_str(account_vector("second_transition_id")).unwrap()
}

fn second_account_after_config_sha256() -> Sha256Digest {
    Sha256Digest::from_bytes(hex(account_vector("second_after_config_sha256")))
}

fn second_account_binding() -> AccountBinding {
    AccountBinding::from_config(&MailAccountConfig {
        id: account_vector("second_display_id").to_owned(),
        email: account_vector("second_email").to_owned(),
        username: account_vector("second_username").to_owned(),
        incoming: Endpoint {
            protocol: Protocol::Imap,
            host: account_vector("incoming_host").to_owned(),
            port: 993,
            security: TransportSecurity::ImplicitTls,
        },
        outgoing: Some(Endpoint {
            protocol: Protocol::Smtp,
            host: account_vector("outgoing_host").to_owned(),
            port: 465,
            security: TransportSecurity::ImplicitTls,
        }),
        credential_kind: CredentialKind::AppPassword,
    })
    .unwrap()
}

fn second_account_manifest() -> ActionManifest {
    second_account_manifest_from(
        NonZeroU64::new(2).unwrap(),
        account_after_config_sha256(),
        NonZeroU64::new(3).unwrap(),
        second_account_after_config_sha256(),
    )
}

fn second_account_manifest_after_abort() -> ActionManifest {
    second_account_manifest_from(
        NonZeroU64::new(1).unwrap(),
        config_sha256(0),
        NonZeroU64::new(2).unwrap(),
        second_account_after_config_sha256(),
    )
}

fn second_account_manifest_from(
    generation: NonZeroU64,
    before_config_sha256: Sha256Digest,
    next_generation: NonZeroU64,
    after_config_sha256: Sha256Digest,
) -> ActionManifest {
    let account_id = second_account_id();
    let binding_sha256 = second_account_binding().sha256();
    let after = AccountSnapshot {
        display_id: account_vector("second_display_id").to_owned(),
        account_id,
        generation: NonZeroU64::new(1).unwrap(),
        email: account_vector("second_email").to_owned(),
        username: account_vector("second_username").to_owned(),
        credential_kind: CredentialKind::AppPassword,
        credential_id: second_credential_id(),
        binding_version: 1,
        binding_sha256,
        binding_state: BindingState::Proposed,
        credential_state: StoredCredentialState::ReentryRequired,
        state_reason: Some(AccountStateReason::CredentialReentryRequired),
        incoming: EndpointSnapshot {
            protocol: Protocol::Imap,
            exact_host: account_vector("incoming_host").to_owned(),
            host_kind: HostKind::Dns,
            canonical_host: account_vector("incoming_host").to_owned(),
            port: 993,
            security: TransportSecurity::ImplicitTls,
        },
        outgoing: Some(EndpointSnapshot {
            protocol: Protocol::Smtp,
            exact_host: account_vector("outgoing_host").to_owned(),
            host_kind: HostKind::Dns,
            canonical_host: account_vector("outgoing_host").to_owned(),
            port: 465,
            security: TransportSecurity::ImplicitTls,
        }),
        cleanup_ids: Vec::new(),
    };
    ActionManifest::new(
        ManifestContext {
            target: ManifestTarget::Account(account_id),
            store_id: Some(store_id(0)),
            account_id: Some(account_id),
            account_binding_sha256: Some(binding_sha256),
            policy_sha256: None,
            effect_id: None,
        },
        ManifestPayload::AccountCreate(kirje_core::AccountMutationManifest {
            transition_id: second_account_transition_id(),
            config_cas: ConfigCas {
                store_id: store_id(0),
                generation,
                exact_content_sha256: before_config_sha256,
                location_sha256: location_sha256(0),
            },
            before: None,
            after: Some(after),
            next_config_generation: next_generation,
            after_config_sha256,
            cleanup: Vec::new(),
        }),
    )
    .unwrap()
}

fn manifest(index: usize) -> ActionManifest {
    let store_id = store_id(index);
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
            transition_id: TransitionId::from_str(&synthetic_uuid(profile(index).3, 0x5200_0000))
                .unwrap(),
            config_cas: ConfigCas {
                store_id,
                generation: NonZeroU64::new(1).unwrap(),
                exact_content_sha256: config_sha256(index),
                location_sha256: location_sha256(index),
            },
            expected_store_state: StoreEnrollmentState::Unregistered,
        }),
    )
    .unwrap()
}

fn issued_at(index: usize) -> i64 {
    match index {
        128 => 500_200,
        129 => 500_300,
        130 => 500_400,
        131 => 500_500,
        _ => 500_000 + i64::try_from(index).unwrap() * 1_000,
    }
}

fn create_challenge(fixture: &ReadyFixture, index: usize) -> AuthorizationChallengeExport {
    open_ready(
        fixture,
        deterministic(vec![u8::try_from(index).unwrap(); 48]),
    )
    .create_challenge(CreateChallengeRequest {
        manifest: manifest(index),
        observed_at_unix_ms: issued_at(index),
        expires_at_unix_ms: issued_at(index) + 900,
    })
    .unwrap()
}

fn authorize(fixture: &ReadyFixture, index: usize) -> AuthorizedFixture {
    let challenge = create_challenge(fixture, index);
    let proof = AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        signature(index),
    );
    let receipt = open_ready(
        fixture,
        deterministic(vec![u8::try_from(index).unwrap(); 16]),
    )
    .verify_proof(VerifyProofRequest {
        proof: proof.clone(),
        observed_at_unix_ms: issued_at(index) + 100,
    })
    .unwrap();
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    let grant: Vec<u8> = connection
        .query_row(
            "SELECT grant_id FROM authorization_challenges WHERE challenge_id=?1",
            [challenge.challenge_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let grant_id = AuthorizationGrantId::try_from(Uuid::from_slice(&grant).unwrap()).unwrap();
    AuthorizedFixture {
        challenge,
        receipt,
        proof,
        manifest: manifest(index),
        grant_id,
    }
}

fn store_id_from_manifest(value: &ActionManifest) -> StoreId {
    let ManifestPayload::StoreEnroll(value) = value.payload() else {
        unreachable!();
    };
    value.config_cas.store_id
}

fn grant_request(value: &AuthorizedFixture) -> GrantUseRequest {
    GrantUseRequest::new(
        value.grant_id,
        value.receipt.receipt_id,
        value.challenge.action,
        value.challenge.target_kind,
        store_id_from_manifest(&value.manifest).as_bytes().to_vec(),
        value.manifest.sha256(),
    )
    .unwrap()
}

fn enrollment_request(
    index: usize,
    authorized: &AuthorizedFixture,
    observed_at_unix_ms: i64,
) -> EnrollStoreRequest {
    EnrollStoreRequest::new(
        grant_request(authorized),
        store_id(index),
        location_material(index),
        location_sha256(index),
        NonZeroU64::new(1).unwrap(),
        config_sha256(index),
        observed_at_unix_ms,
    )
    .unwrap()
}

fn authorize_account_create(fixture: &ReadyFixture) -> (AuthorizedFixture, AuthorizedFixture) {
    let enrollment = enroll_account_fixture_store(fixture);
    let manifest = account_manifest();
    let challenge = open_ready(
        fixture,
        deterministic(hex::<48>(account_vector("challenge_entropy")).to_vec()),
    )
    .create_challenge(CreateChallengeRequest {
        manifest: manifest.clone(),
        observed_at_unix_ms: 501_000,
        expires_at_unix_ms: 501_900,
    })
    .unwrap();
    let proof = AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        account_signature("account_signature"),
    );
    let receipt = open_ready(
        fixture,
        deterministic(hex::<16>(account_vector("receipt_entropy")).to_vec()),
    )
    .verify_proof(VerifyProofRequest {
        proof: proof.clone(),
        observed_at_unix_ms: 501_100,
    })
    .unwrap();
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    let grant: Vec<u8> = connection
        .query_row(
            "SELECT grant_id FROM authorization_challenges WHERE challenge_id=?1",
            [challenge.challenge_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let account = AuthorizedFixture {
        challenge,
        receipt,
        proof,
        manifest,
        grant_id: AuthorizationGrantId::try_from(Uuid::from_slice(&grant).unwrap()).unwrap(),
    };
    (account, enrollment)
}

fn authorize_second_account_create(fixture: &ReadyFixture) -> AuthorizedFixture {
    authorize_successor_account_create(
        fixture,
        second_account_manifest(),
        "second_challenge_entropy",
        "second_receipt_entropy",
        "second_account_signature",
        501_500,
    )
}

fn authorize_second_account_create_after_abort(fixture: &ReadyFixture) -> AuthorizedFixture {
    authorize_successor_account_create(
        fixture,
        second_account_manifest_after_abort(),
        "second_after_abort_challenge_entropy",
        "second_after_abort_receipt_entropy",
        "second_after_abort_account_signature",
        501_400,
    )
}

fn authorize_successor_account_create(
    fixture: &ReadyFixture,
    manifest: ActionManifest,
    challenge_entropy: &str,
    receipt_entropy: &str,
    signature: &str,
    issued_at_unix_ms: i64,
) -> AuthorizedFixture {
    let challenge = open_ready(
        fixture,
        deterministic(hex::<48>(account_vector(challenge_entropy)).to_vec()),
    )
    .create_challenge(CreateChallengeRequest {
        manifest: manifest.clone(),
        observed_at_unix_ms: issued_at_unix_ms,
        expires_at_unix_ms: issued_at_unix_ms + 900,
    })
    .unwrap();
    let proof = AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        account_signature(signature),
    );
    let receipt = open_ready(
        fixture,
        deterministic(hex::<16>(account_vector(receipt_entropy)).to_vec()),
    )
    .verify_proof(VerifyProofRequest {
        proof: proof.clone(),
        observed_at_unix_ms: issued_at_unix_ms + 100,
    })
    .unwrap();
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    let grant: Vec<u8> = connection
        .query_row(
            "SELECT grant_id FROM authorization_challenges WHERE challenge_id=?1",
            [challenge.challenge_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    AuthorizedFixture {
        challenge,
        receipt,
        proof,
        manifest,
        grant_id: AuthorizationGrantId::try_from(Uuid::from_slice(&grant).unwrap()).unwrap(),
    }
}

fn account_grant_request(value: &AuthorizedFixture) -> GrantUseRequest {
    GrantUseRequest::new(
        value.grant_id,
        value.receipt.receipt_id,
        SensitiveAction::AccountCreate,
        TargetKind::Account,
        account_id().as_bytes().to_vec(),
        value.manifest.sha256(),
    )
    .unwrap()
}

fn prepare_account_request(
    authorized: &AuthorizedFixture,
    observed_at_unix_ms: i64,
) -> PrepareAccountTransitionRequest {
    PrepareAccountTransitionRequest::new(
        account_grant_request(authorized),
        account_transition_id(),
        store_id(0),
        account_id(),
        AccountTransitionKind::AccountCreate,
        config_sha256(0),
        account_after_config_sha256(),
        NonZeroU64::new(1).unwrap(),
        NonZeroU64::new(2).unwrap(),
        Sha256Digest::digest(&encode(
            b"KIRJE-ACCOUNT-DISPLAY-ID-V1\0",
            &[account_vector("display_id").as_bytes()],
        )),
        NonZeroU64::new(1).unwrap(),
        credential_id(),
        account_binding().sha256(),
        observed_at_unix_ms,
    )
    .unwrap()
}

fn observe_account(
    state: AccountTransitionState,
    generation: u64,
    config_sha256: Sha256Digest,
    observed_at_unix_ms: i64,
) -> AccountTransitionObservationRequest {
    AccountTransitionObservationRequest::new(
        account_transition_id(),
        state,
        NonZeroU64::new(generation).unwrap(),
        config_sha256,
        observed_at_unix_ms,
    )
    .unwrap()
}

fn prepare_second_account_request(
    authorized: &AuthorizedFixture,
    observed_at_unix_ms: i64,
) -> PrepareAccountTransitionRequest {
    prepare_second_account_request_from(
        authorized,
        NonZeroU64::new(2).unwrap(),
        account_after_config_sha256(),
        NonZeroU64::new(3).unwrap(),
        observed_at_unix_ms,
    )
}

fn prepare_second_account_request_after_abort(
    authorized: &AuthorizedFixture,
    observed_at_unix_ms: i64,
) -> PrepareAccountTransitionRequest {
    prepare_second_account_request_from(
        authorized,
        NonZeroU64::new(1).unwrap(),
        config_sha256(0),
        NonZeroU64::new(2).unwrap(),
        observed_at_unix_ms,
    )
}

fn prepare_second_account_request_from(
    authorized: &AuthorizedFixture,
    expected_generation: NonZeroU64,
    before_config_sha256: Sha256Digest,
    next_generation: NonZeroU64,
    observed_at_unix_ms: i64,
) -> PrepareAccountTransitionRequest {
    let grant = GrantUseRequest::new(
        authorized.grant_id,
        authorized.receipt.receipt_id,
        SensitiveAction::AccountCreate,
        TargetKind::Account,
        second_account_id().as_bytes().to_vec(),
        authorized.manifest.sha256(),
    )
    .unwrap();
    PrepareAccountTransitionRequest::new(
        grant,
        second_account_transition_id(),
        store_id(0),
        second_account_id(),
        AccountTransitionKind::AccountCreate,
        before_config_sha256,
        second_account_after_config_sha256(),
        expected_generation,
        next_generation,
        Sha256Digest::digest(&encode(
            b"KIRJE-ACCOUNT-DISPLAY-ID-V1\0",
            &[account_vector("second_display_id").as_bytes()],
        )),
        NonZeroU64::new(1).unwrap(),
        second_credential_id(),
        second_account_binding().sha256(),
        observed_at_unix_ms,
    )
    .unwrap()
}

fn observe_second_account(
    state: AccountTransitionState,
    generation: u64,
    config_sha256: Sha256Digest,
    observed_at_unix_ms: i64,
) -> AccountTransitionObservationRequest {
    AccountTransitionObservationRequest::new(
        second_account_transition_id(),
        state,
        NonZeroU64::new(generation).unwrap(),
        config_sha256,
        observed_at_unix_ms,
    )
    .unwrap()
}

fn scalar(connection: &Connection, sql: &str) -> i64 {
    connection.query_row(sql, [], |row| row.get(0)).unwrap()
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

fn registry_fingerprint(connection: &Connection) -> (i64, i64, i64, i64, (i64, i64)) {
    (
        scalar(connection, "SELECT COUNT(*) FROM grant_uses"),
        scalar(connection, "SELECT COUNT(*) FROM registered_stores"),
        scalar(connection, "SELECT COUNT(*) FROM registered_store_versions"),
        scalar(connection, "SELECT COUNT(*) FROM authority_events"),
        clock_pair(connection),
    )
}

fn issuance_fingerprint(connection: &Connection) -> (i64, i64, i64, i64, i64, (i64, i64)) {
    (
        scalar(connection, "SELECT COUNT(*) FROM authorization_challenges"),
        scalar(
            connection,
            "SELECT COALESCE(SUM(created_event_sequence),0) FROM authorization_challenges",
        ),
        scalar(connection, "SELECT COUNT(*) FROM authority_events"),
        scalar(connection, "SELECT COUNT(*) FROM grant_uses"),
        scalar(connection, "SELECT COUNT(*) FROM registered_stores"),
        clock_pair(connection),
    )
}

#[allow(clippy::type_complexity)]
fn account_registry_fingerprint(
    connection: &Connection,
) -> (i64, i64, i64, i64, i64, i64, i64, i64, (i64, i64)) {
    (
        scalar(connection, "SELECT COUNT(*) FROM grant_uses"),
        scalar(connection, "SELECT COUNT(*) FROM registered_stores"),
        scalar(connection, "SELECT COUNT(*) FROM registered_accounts"),
        scalar(connection, "SELECT COUNT(*) FROM account_transitions"),
        scalar(connection, "SELECT COUNT(*) FROM registered_credentials"),
        scalar(connection, "SELECT COUNT(*) FROM registered_store_versions"),
        scalar(
            connection,
            "SELECT COUNT(*) FROM registered_account_versions",
        ),
        scalar(connection, "SELECT COUNT(*) FROM authority_events"),
        clock_pair(connection),
    )
}

fn assert_same_projection(left: &EnrolledStoreProjection, right: &EnrolledStoreProjection) {
    assert_eq!(left.store_id, right.store_id);
    assert!(left.state == right.state);
    assert_eq!(left.config_generation, right.config_generation);
    assert_eq!(left.created_at, right.created_at);
    assert_eq!(left.updated_at, right.updated_at);
}

fn exact_error<T>(result: Result<T, MailError>) -> MailError {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => error,
    }
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

fn query_plan(connection: &Connection, sql: &str) -> Vec<String> {
    connection
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap()
        .query_map([], |row| row.get(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn assert_recovery_required(fixture: &ReadyFixture) {
    let reopened = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(fixture.snapshot.anchor.clone())),
        fixture.home.clone(),
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
            "UPDATE authority_events SET sequence=1000000 WHERE sequence=?1",
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
            "UPDATE authority_events SET sequence=?1 WHERE sequence=1000000",
            [right],
        )
        .unwrap();
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
}

fn public_declaration<'a>(source: &'a str, name: &str) -> &'a str {
    let declaration = source.find(name).unwrap();
    let start = source[..declaration]
        .rfind("#[derive")
        .unwrap_or(declaration);
    let body = source[declaration..].find('{').unwrap() + declaration;
    let mut depth = 0_i32;
    for (offset, byte) in source[body..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..=body + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated declaration {name}")
}

const PRIVATE_TRAIT_TYPES: [&str; 11] = [
    "GrantUseRequest",
    "EnrollStoreRequest",
    "EnrolledStoreState",
    "EnrolledStoreProjection",
    "AccountTransitionKind",
    "AccountTransitionState",
    "RegisteredAccountState",
    "RegisteredStoreTransitionState",
    "PrepareAccountTransitionRequest",
    "AccountTransitionObservationRequest",
    "AccountTransitionProjection",
];
const FORBIDDEN_PUBLIC_TRAITS: [&str; 4] = ["Debug", "Display", "Serialize", "JsonSchema"];

fn rust_source_tokens(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if bytes[index..].starts_with(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            let mut depth = 1_u32;
            while index < bytes.len() && depth != 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
        } else if bytes[index] == b'"' {
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else if bytes[index] == b'"' {
                    index += 1;
                    break;
                } else {
                    index += 1;
                }
            }
        } else if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            tokens.push(source[start..index].to_owned());
        } else {
            tokens.push(char::from(bytes[index]).to_string());
            index += 1;
        }
    }
    tokens
}

fn forbidden_trait_violations(source: &str) -> Vec<String> {
    let tokens = rust_source_tokens(source);
    let mut violations = Vec::new();
    for index in 0..tokens.len().saturating_sub(2) {
        if tokens[index] == "pub"
            && matches!(tokens[index + 1].as_str(), "struct" | "enum")
            && PRIVATE_TRAIT_TYPES.contains(&tokens[index + 2].as_str())
        {
            let type_name = &tokens[index + 2];
            let attribute_start = tokens[..index]
                .iter()
                .rposition(|token| matches!(token.as_str(), "}" | ";"))
                .map_or(0, |boundary| boundary + 1);
            let attributes = &tokens[attribute_start..index];
            if attributes.iter().any(|token| token == "derive") {
                for trait_name in FORBIDDEN_PUBLIC_TRAITS {
                    if attributes.iter().any(|token| token == trait_name) {
                        violations.push(format!("{type_name}:{trait_name}"));
                    }
                }
            }
        }
    }
    for (index, token) in tokens.iter().enumerate() {
        if token != "impl" {
            continue;
        }
        let body = tokens[index + 1..]
            .iter()
            .position(|token| token == "{")
            .map_or(tokens.len(), |offset| index + 1 + offset);
        let Some(for_token) = tokens[index + 1..body]
            .iter()
            .position(|token| token == "for")
            .map(|offset| index + 1 + offset)
        else {
            continue;
        };
        let trait_tokens = &tokens[index + 1..for_token];
        let target_tokens = &tokens[for_token + 1..body];
        for type_name in PRIVATE_TRAIT_TYPES {
            if !target_tokens.iter().any(|token| token == type_name) {
                continue;
            }
            for trait_name in FORBIDDEN_PUBLIC_TRAITS {
                if trait_tokens.iter().any(|token| token == trait_name) {
                    violations.push(format!("{type_name}:{trait_name}"));
                }
            }
        }
    }
    violations.sort();
    violations.dedup();
    violations
}

#[test]
fn trait_privacy_gate_detects_derived_and_manual_forbidden_impls() {
    let declarations = r"
        pub struct GrantUseRequest {}
        pub struct EnrollStoreRequest {}
        pub enum EnrolledStoreState { Active }
        pub struct EnrolledStoreProjection {}
    ";
    for (impl_source, expected) in [
        (
            "impl core::fmt::Debug for GrantUseRequest {}",
            "GrantUseRequest:Debug",
        ),
        (
            "impl core::fmt::Display for EnrollStoreRequest {}",
            "EnrollStoreRequest:Display",
        ),
        (
            "impl serde::Serialize for EnrolledStoreState {}",
            "EnrolledStoreState:Serialize",
        ),
        (
            "impl schemars::JsonSchema for EnrolledStoreProjection {}",
            "EnrolledStoreProjection:JsonSchema",
        ),
    ] {
        let source = format!("{declarations}\n{impl_source}");
        let violations = forbidden_trait_violations(&source);
        assert!(
            violations.iter().any(|value| value == expected),
            "privacy gate missed {expected}: {violations:?}"
        );
    }

    for trait_name in FORBIDDEN_PUBLIC_TRAITS {
        let source = declarations.replacen(
            "pub struct GrantUseRequest",
            &format!("#[derive({trait_name})]\npub struct GrantUseRequest"),
            1,
        );
        let expected = format!("GrantUseRequest:{trait_name}");
        let violations = forbidden_trait_violations(&source);
        assert!(
            violations.iter().any(|value| value == &expected),
            "privacy gate missed {expected}: {violations:?}"
        );
    }

    let decoys = format!(
        "{declarations}\n// impl Debug for GrantUseRequest {{}}\n\
         const TEXT: &str = \"impl serde::Serialize for EnrollStoreRequest {{}}\";"
    );
    assert!(forbidden_trait_violations(&decoys).is_empty());
}

#[test]
#[allow(clippy::too_many_lines)]
fn request_bounds_privacy_and_grant_transcript_are_exact() {
    let bad = exact_error(GrantUseRequest::new(
        AuthorizationGrantId::from_str("61000000-0000-4000-8000-000000000001").unwrap(),
        kirje_core::AuthorizationReceiptId::from_str("62000000-0000-4000-8000-000000000001")
            .unwrap(),
        SensitiveAction::StoreEnroll,
        TargetKind::Store,
        Vec::new(),
        Sha256Digest::from_bytes([1; 32]),
    ));
    assert_eq!(bad.code, MailErrorCode::InvalidInput);

    let fixture = ready_fixture();
    let authorized = authorize(&fixture, 0);
    let grant = grant_request(&authorized);
    let bad_time = exact_error(EnrollStoreRequest::new(
        grant.clone(),
        store_id(0),
        location_material(0),
        location_sha256(0),
        NonZeroU64::new(1).unwrap(),
        config_sha256(0),
        -1,
    ));
    assert_eq!(bad_time.code, MailErrorCode::InvalidInput);
    let bad_digest = exact_error(EnrollStoreRequest::new(
        grant.clone(),
        store_id(0),
        location_material(0),
        Sha256Digest::from_bytes([0xee; 32]),
        NonZeroU64::new(1).unwrap(),
        config_sha256(0),
        issued_at(0) + 200,
    ));
    assert_eq!(bad_digest.code, MailErrorCode::InvalidInput);
    let too_wide = exact_error(EnrollStoreRequest::new(
        grant,
        store_id(0),
        location_material(0),
        location_sha256(0),
        NonZeroU64::new(u64::try_from(i64::MAX).unwrap() + 1).unwrap(),
        config_sha256(0),
        issued_at(0) + 200,
    ));
    assert_eq!(too_wide.code, MailErrorCode::InvalidInput);

    let projection = open_ready(&fixture, deterministic(Vec::new()))
        .enroll_store(enrollment_request(0, &authorized, issued_at(0) + 200))
        .unwrap();
    assert!(projection.state == EnrolledStoreState::Active);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    let (stored, digest, used_at): (Vec<u8>, Vec<u8>, i64) = connection
        .query_row(
            "SELECT use_receipt,use_sha256,used_at FROM grant_uses",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let action = SensitiveAction::StoreEnroll.code().to_be_bytes();
    let target = TargetKind::Store.code().to_be_bytes();
    let used = used_at.to_be_bytes();
    let expected = encode(
        b"KIRJE-GRANT-USE-V1\0",
        &[
            authorized.grant_id.as_bytes(),
            authorized.receipt.receipt_id.as_bytes(),
            &action,
            &target,
            store_id(0).as_bytes(),
            authorized.manifest.sha256().as_bytes(),
            &used,
        ],
    );
    assert_eq!(stored, expected);
    assert_eq!(digest, Sha256::digest(&expected).as_slice());

    let source = include_str!("../src/authority.rs");
    let violations = forbidden_trait_violations(source);
    assert!(
        violations.is_empty(),
        "private API gained forbidden traits: {violations:?}"
    );
    let projection = public_declaration(source, "pub struct EnrolledStoreProjection");
    for private in [
        "location_material",
        "location_sha256",
        "config_sha256",
        "receipt_id",
        "grant_id",
        "manifest",
    ] {
        assert!(!projection.contains(private));
    }
    let transition_projection =
        public_declaration(source, "pub struct AccountTransitionProjection");
    for private in [
        "store_id",
        "credential_id",
        "display",
        "binding",
        "config_sha256",
        "location",
        "manifest",
        "receipt",
        "grant",
        "proof",
        "signature",
        "nonce",
        "key",
        "path",
    ] {
        assert!(!transition_projection.contains(private));
    }
}

#[test]
fn first_use_exact_recovery_and_receipt_priority_use_effective_time() {
    let fixture = ready_fixture();
    let authorized = authorize(&fixture, 1);
    assert_eq!(
        authorized.receipt.state,
        AuthorizationReceiptState::Unclaimed
    );
    let source = deterministic(Vec::new());
    let store = open_ready(&fixture, source.clone());
    let first = store
        .enroll_store(enrollment_request(1, &authorized, issued_at(1) + 90))
        .unwrap();
    assert_eq!(source.consumed_bytes(), 0);
    assert_eq!(first.store_id, store_id(1));
    assert_eq!(first.config_generation, NonZeroU64::new(1).unwrap());
    assert!(first.state == EnrolledStoreState::Active);
    assert_eq!(first.created_at.timestamp_millis(), issued_at(1) + 100);
    assert_eq!(first.created_at, first.updated_at);

    let connection = Connection::open(fixture.home.database_path()).unwrap();
    let version = connection
        .query_row(
            "SELECT store_id,location_sha256,config_generation,config_sha256,
                        enrolled_receipt_id,committed_transition_id,created_at
                 FROM registered_store_versions",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(version.0, store_id(1).as_bytes());
    assert_eq!(version.1, location_sha256(1).as_bytes());
    assert_eq!(version.2, 1);
    assert_eq!(version.3, config_sha256(1).as_bytes());
    assert_eq!(version.4, authorized.receipt.receipt_id.as_bytes());
    assert!(version.5.is_none());
    assert_eq!(version.6, issued_at(1) + 100);
    let before = registry_fingerprint(&connection);
    let recovered = store
        .enroll_store(enrollment_request(1, &authorized, issued_at(1) + 1_500))
        .unwrap();
    assert_same_projection(&first, &recovered);
    assert_eq!(source.consumed_bytes(), 0);
    let after = registry_fingerprint(&connection);
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1);
    assert_eq!(after.2, before.2);
    assert_eq!(after.3, before.3);
    assert_eq!(after.4, (issued_at(1) + 1_500, issued_at(1) + 1_500));

    let replay = open_ready(&fixture, deterministic(Vec::new()))
        .verify_proof(VerifyProofRequest {
            proof: authorized.proof.clone(),
            observed_at_unix_ms: issued_at(1) + 1_600,
        })
        .unwrap();
    assert_eq!(replay.state, AuthorizationReceiptState::Used);
    assert!(matches!(
        open_ready(&fixture, deterministic(Vec::new())).state(),
        AuthorityOpenState::Ready(_)
    ));
    reset_authority_validation_query_counts();
    assert!(matches!(
        open_ready(&fixture, deterministic(Vec::new())).state(),
        AuthorityOpenState::Ready(_)
    ));
    assert_eq!(
        take_authority_validation_query_counts().registry_parent_preflight,
        1
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn authorized_unclaimed_expiry_is_committed_exactly_once() {
    let fixture = ready_fixture();
    let authorized = authorize(&fixture, 2);
    let entropy = deterministic(Vec::new());
    let store = open_ready(&fixture, entropy.clone());
    let request = enrollment_request(2, &authorized, issued_at(2) + 901);
    let error = exact_error(store.enroll_store(request.clone()));
    assert_eq!(error.code, MailErrorCode::AuthorizationExpired);
    assert!(!error.retryable);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM grant_uses"), 0);
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM registered_stores"),
        0
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authority_events WHERE event_code=5"
        ),
        1
    );
    let fingerprint = registry_fingerprint(&connection);
    let retry =
        exact_error(store.enroll_store(enrollment_request(2, &authorized, issued_at(2) + 950)));
    assert_eq!(retry.code, MailErrorCode::AuthorizationExpired);
    let later = registry_fingerprint(&connection);
    assert_eq!(
        (later.0, later.1, later.2, later.3),
        (fingerprint.0, fingerprint.1, fingerprint.2, fingerprint.3)
    );
    assert_eq!(later.4, (issued_at(2) + 950, issued_at(2) + 950));
    let rollback =
        exact_error(store.enroll_store(enrollment_request(2, &authorized, issued_at(2) + 925)));
    assert_eq!(rollback.code, MailErrorCode::AuthorizationExpired);
    assert_eq!(registry_fingerprint(&connection), later);
    assert_eq!(entropy.consumed_bytes(), 0);
    assert!(matches!(
        open_ready(&fixture, deterministic(Vec::new())).state(),
        AuthorityOpenState::Ready(_)
    ));

    let changed = EnrollStoreRequest::new(
        grant_request(&authorized),
        store_id(2),
        location_material(2),
        location_sha256(2),
        NonZeroU64::new(1).unwrap(),
        Sha256Digest::from_bytes([0x77; 32]),
        issued_at(2) + 960,
    )
    .unwrap();
    let stale = exact_error(store.enroll_store(changed));
    assert_eq!(stale.code, MailErrorCode::AuthorizationContextStale);
    assert_eq!(registry_fingerprint(&connection), later);

    let replay = open_ready(&fixture, deterministic(Vec::new()))
        .verify_proof(VerifyProofRequest {
            proof: authorized.proof,
            observed_at_unix_ms: issued_at(2) + 970,
        })
        .unwrap();
    assert_eq!(replay.state, AuthorizationReceiptState::Expired);

    let fixture = ready_fixture();
    let authorized = Arc::new(authorize(&fixture, 2));
    let response_loss = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(fixture.snapshot.anchor.clone())),
        fixture
            .home
            .clone()
            .with_authority_fault(AuthorityFaultPoint::EnrollmentExpiryAfterCommit),
        deterministic(Vec::new()),
    )
    .unwrap();
    let error = exact_error(response_loss.enroll_store(enrollment_request(
        2,
        &authorized,
        issued_at(2) + 901,
    )));
    assert_eq!(error.code, MailErrorCode::StoreWrite);
    assert!(error.retryable);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let home = fixture.home.clone();
        let snapshot = fixture.snapshot.clone();
        let authorized = Arc::clone(&authorized);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let store = AuthorityStore::open_isolated(
                context(AnchorPresence::Present(snapshot.anchor.clone())),
                home,
                deterministic(Vec::new()),
            )
            .unwrap();
            barrier.wait();
            exact_error(store.enroll_store(enrollment_request(2, &authorized, issued_at(2) + 950)))
        }));
    }
    barrier.wait();
    for handle in handles {
        let error = handle.join().unwrap();
        assert_eq!(error.code, MailErrorCode::AuthorizationExpired);
    }
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM grant_uses"), 0);
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM registered_stores"),
        0
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authority_events WHERE event_code=5"
        ),
        1
    );
}

#[test]
fn enrollment_challenge_read_preserves_store_errors_and_corruption_classification() {
    let source = include_str!("../src/authority.rs");
    let enroll_start = source.find("pub fn enroll_store").unwrap();
    let enroll_end = source[enroll_start..]
        .find("\nfn validate_enroll_store_request")
        .map(|offset| enroll_start + offset)
        .unwrap();
    let enroll_source = &source[enroll_start..enroll_end];
    assert!(enroll_source.contains("classify_enrollment_challenge_result("));
    assert!(enroll_source.contains(".and_then(|()| load_challenge("));
    assert!(!enroll_source.contains(".read_fault(TestFaultPoint::EnrollmentChallengeRead)?;"));

    let fixture = ready_fixture();
    let authorized = authorize(&fixture, 9);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    let before = registry_fingerprint(&connection);
    let entropy = deterministic(Vec::new());
    let store = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(fixture.snapshot.anchor.clone())),
        fixture
            .home
            .clone()
            .with_authority_fault(AuthorityFaultPoint::EnrollmentChallengeRead),
        entropy.clone(),
    )
    .unwrap();
    let error =
        exact_error(store.enroll_store(enrollment_request(9, &authorized, issued_at(9) + 200)));
    assert_eq!(error.code, MailErrorCode::StoreRead);
    assert!(error.retryable);
    assert_eq!(entropy.consumed_bytes(), 0);
    assert_eq!(registry_fingerprint(&connection), before);

    let unknown_receipt =
        kirje_core::AuthorizationReceiptId::from_str("62000000-0000-4000-8000-00000000ffff")
            .unwrap();
    let stale_grant = GrantUseRequest::new(
        authorized.grant_id,
        unknown_receipt,
        SensitiveAction::StoreEnroll,
        TargetKind::Store,
        store_id(9).as_bytes().to_vec(),
        authorized.manifest.sha256(),
    )
    .unwrap();
    let stale = EnrollStoreRequest::new(
        stale_grant,
        store_id(9),
        location_material(9),
        location_sha256(9),
        NonZeroU64::new(1).unwrap(),
        config_sha256(9),
        issued_at(9) + 201,
    )
    .unwrap();
    let error = exact_error(open_ready(&fixture, deterministic(Vec::new())).enroll_store(stale));
    assert_eq!(error.code, MailErrorCode::AuthorizationContextStale);
    assert!(!error.retryable);
    assert_eq!(registry_fingerprint(&connection), before);

    let stale_store = open_ready(&fixture, deterministic(Vec::new()));
    connection
        .execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
        .unwrap();
    connection
        .execute(
            "UPDATE authorization_receipts SET challenge_id=zeroblob(32)
             WHERE receipt_id=?1",
            [authorized.receipt.receipt_id.as_bytes()],
        )
        .unwrap();
    let corrupted = registry_fingerprint(&connection);
    let error = exact_error(stale_store.enroll_store(enrollment_request(
        9,
        &authorized,
        issued_at(9) + 202,
    )));
    assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
    assert!(!error.retryable);
    assert_eq!(registry_fingerprint(&connection), corrupted);
}

#[test]
fn manifest_replay_and_both_alias_directions_have_closed_precedence() {
    let fixture = ready_fixture();
    let first = authorize(&fixture, 0);
    let store_alias = authorize(&fixture, 128);
    let location_alias = authorize(&fixture, 129);
    let store = open_ready(&fixture, deterministic(Vec::new()));

    let stale = EnrollStoreRequest::new(
        grant_request(&first),
        store_id(0),
        location_material(0),
        location_sha256(0),
        NonZeroU64::new(1).unwrap(),
        Sha256Digest::from_bytes([0x66; 32]),
        issued_at(0) + 200,
    )
    .unwrap();
    assert_eq!(
        exact_error(store.enroll_store(stale)).code,
        MailErrorCode::AuthorizationContextStale
    );
    store
        .enroll_store(enrollment_request(0, &first, issued_at(129) + 200))
        .unwrap();

    for (index, value) in [(128, &store_alias), (129, &location_alias)] {
        let connection = Connection::open(fixture.home.database_path()).unwrap();
        let fingerprint = registry_fingerprint(&connection);
        let error =
            exact_error(store.enroll_store(enrollment_request(index, value, issued_at(129) + 201)));
        assert_eq!(error.code, MailErrorCode::ConfigStoreIdentityConflict);
        assert_eq!(registry_fingerprint(&connection), fingerprint);
    }

    let changed_grant = GrantUseRequest::new(
        first.grant_id,
        first.receipt.receipt_id,
        SensitiveAction::StoreEnroll,
        TargetKind::Store,
        store_id(3).as_bytes().to_vec(),
        first.manifest.sha256(),
    )
    .unwrap();
    let changed = EnrollStoreRequest::new(
        changed_grant,
        store_id(0),
        location_material(0),
        location_sha256(0),
        NonZeroU64::new(1).unwrap(),
        config_sha256(0),
        issued_at(129) + 202,
    )
    .unwrap();
    assert_eq!(
        exact_error(store.enroll_store(changed)).code,
        MailErrorCode::GrantAlreadyUsed
    );
}

#[test]
fn fresh_challenge_issuance_rejects_each_occupied_store_alias_without_writes() {
    let fixture = ready_fixture();
    let enrolled = authorize(&fixture, 0);
    open_ready(&fixture, deterministic(Vec::new()))
        .enroll_store(enrollment_request(0, &enrolled, issued_at(0) + 200))
        .unwrap();
    assert_eq!(store_id(128), store_id(0));
    assert_ne!(location_sha256(128), location_sha256(0));
    assert_ne!(store_id(129), store_id(0));
    assert_eq!(location_sha256(129), location_sha256(0));

    let connection = Connection::open(fixture.home.database_path()).unwrap();
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authorization_challenges WHERE state='pending'"
        ),
        0
    );
    let before = issuance_fingerprint(&connection);
    for index in [128, 129] {
        let entropy = deterministic(vec![u8::try_from(index).unwrap(); 48]);
        let error = exact_error(open_ready(&fixture, entropy.clone()).create_challenge(
            CreateChallengeRequest {
                manifest: manifest(index),
                observed_at_unix_ms: issued_at(index),
                expires_at_unix_ms: issued_at(index) + 900,
            },
        ));
        assert_eq!(error.code, MailErrorCode::ConfigStoreIdentityConflict);
        assert!(!error.retryable);
        assert_eq!(entropy.consumed_bytes(), 0);
        assert_eq!(issuance_fingerprint(&connection), before);
    }
}

#[test]
fn enrollment_and_expiry_fault_boundaries_are_atomic_and_zero_entropy() {
    let success_faults = [
        AuthorityFaultPoint::GrantUseInserted,
        AuthorityFaultPoint::GrantUsedEvent,
        AuthorityFaultPoint::RegisteredStoreInserted,
        AuthorityFaultPoint::RegisteredStoreVersionInserted,
        AuthorityFaultPoint::StoreEnrolledEvent,
        AuthorityFaultPoint::EnrollmentClockUpdated,
        AuthorityFaultPoint::EnrollmentBeforeCommit,
    ];
    for fault in success_faults {
        let fixture = ready_fixture();
        let authorized = authorize(&fixture, 3);
        let connection = Connection::open(fixture.home.database_path()).unwrap();
        let before = registry_fingerprint(&connection);
        let entropy = deterministic(Vec::new());
        let store = AuthorityStore::open_isolated(
            context(AnchorPresence::Present(fixture.snapshot.anchor.clone())),
            fixture.home.clone().with_authority_fault(fault),
            entropy.clone(),
        )
        .unwrap();
        assert!(
            store
                .enroll_store(enrollment_request(3, &authorized, issued_at(3) + 200))
                .is_err()
        );
        assert_eq!(entropy.consumed_bytes(), 0);
        assert_eq!(registry_fingerprint(&connection), before);
    }

    let fixture = ready_fixture();
    let authorized = authorize(&fixture, 4);
    let post_commit = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(fixture.snapshot.anchor.clone())),
        fixture
            .home
            .clone()
            .with_authority_fault(AuthorityFaultPoint::EnrollmentAfterCommit),
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(
        post_commit
            .enroll_store(enrollment_request(4, &authorized, issued_at(4) + 200))
            .is_err()
    );
    let recovered = open_ready(&fixture, deterministic(Vec::new()))
        .enroll_store(enrollment_request(4, &authorized, issued_at(4) + 201))
        .unwrap();
    assert_eq!(recovered.store_id, store_id(4));

    for fault in [
        AuthorityFaultPoint::EnrollmentExpiredState,
        AuthorityFaultPoint::EnrollmentExpiryClockUpdated,
        AuthorityFaultPoint::EnrollmentExpiryEvent,
    ] {
        let fixture = ready_fixture();
        let authorized = authorize(&fixture, 5);
        let connection = Connection::open(fixture.home.database_path()).unwrap();
        let before = registry_fingerprint(&connection);
        let entropy = deterministic(Vec::new());
        let store = AuthorityStore::open_isolated(
            context(AnchorPresence::Present(fixture.snapshot.anchor.clone())),
            fixture.home.clone().with_authority_fault(fault),
            entropy.clone(),
        )
        .unwrap();
        assert!(
            store
                .enroll_store(enrollment_request(5, &authorized, issued_at(5) + 901))
                .is_err()
        );
        assert_eq!(entropy.consumed_bytes(), 0);
        assert_eq!(registry_fingerprint(&connection), before);
    }
}

#[test]
fn exact_and_distinct_receipt_concurrency_have_one_durable_winner() {
    let fixture = ready_fixture();
    let authorized = Arc::new(authorize(&fixture, 6));
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let home = fixture.home.clone();
        let snapshot = fixture.snapshot.clone();
        let authorized = Arc::clone(&authorized);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let store = AuthorityStore::open_isolated(
                context(AnchorPresence::Present(snapshot.anchor.clone())),
                home,
                deterministic(Vec::new()),
            )
            .unwrap();
            barrier.wait();
            store.enroll_store(enrollment_request(6, &authorized, issued_at(6) + 200))
        }));
    }
    barrier.wait();
    let left = handles.remove(0).join().unwrap().unwrap();
    let right = handles.remove(0).join().unwrap().unwrap();
    assert_same_projection(&left, &right);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM grant_uses"), 1);
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM registered_stores"),
        1
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM registered_store_versions"
        ),
        1
    );

    let fixture = ready_fixture();
    let first = Arc::new(authorize(&fixture, 130));
    let second = Arc::new(authorize(&fixture, 131));
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for value in [first, second] {
        let home = fixture.home.clone();
        let snapshot = fixture.snapshot.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let store = AuthorityStore::open_isolated(
                context(AnchorPresence::Present(snapshot.anchor.clone())),
                home,
                deterministic(Vec::new()),
            )
            .unwrap();
            barrier.wait();
            store.enroll_store(enrollment_request(130, &value, issued_at(131) + 200))
        }));
    }
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let error = results
        .iter()
        .find_map(|result| result.as_ref().err())
        .unwrap();
    assert_eq!(error.code, MailErrorCode::ConfigStoreIdentityConflict);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM grant_uses"), 1);
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM registered_stores"),
        1
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM registered_store_versions"
        ),
        1
    );
}

#[test]
fn store_and_location_only_contenders_have_stable_losers_without_grants() {
    for contender_index in [128, 129] {
        let fixture = ready_fixture();
        let candidates = [
            Arc::new(authorize(&fixture, 0)),
            Arc::new(authorize(&fixture, contender_index)),
        ];
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for (request_index, candidate) in [0, contender_index].into_iter().zip(candidates.clone()) {
            let home = fixture.home.clone();
            let snapshot = fixture.snapshot.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let store = AuthorityStore::open_isolated(
                    context(AnchorPresence::Present(snapshot.anchor.clone())),
                    home,
                    deterministic(Vec::new()),
                )
                .unwrap();
                barrier.wait();
                store.enroll_store(enrollment_request(
                    request_index,
                    &candidate,
                    issued_at(129) + 200,
                ))
            }));
        }
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let loser = results.iter().position(Result::is_err).unwrap();
        let error = results[loser].as_ref().err().unwrap();
        assert_eq!(error.code, MailErrorCode::ConfigStoreIdentityConflict);
        assert!(!error.retryable);
        let connection = Connection::open(fixture.home.database_path()).unwrap();
        assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM grant_uses"), 1);
        assert_eq!(
            scalar(&connection, "SELECT COUNT(*) FROM registered_stores"),
            1
        );
        assert_eq!(
            scalar(
                &connection,
                "SELECT COUNT(*) FROM registered_store_versions"
            ),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM grant_uses WHERE grant_id=?1",
                    [candidates[loser].grant_id.as_bytes()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }
}

#[test]
fn stale_handles_revalidate_and_historical_siblings_remain_intrinsic() {
    let fixture = ready_fixture();
    let enrolled = authorize(&fixture, 130);
    let successor = create_challenge(&fixture, 131);
    let other_pending = create_challenge(&fixture, 128);
    let stale = open_ready(&fixture, deterministic(Vec::new()));
    let first = open_ready(&fixture, deterministic(Vec::new()))
        .enroll_store(enrollment_request(130, &enrolled, issued_at(131) + 100))
        .unwrap();
    let recovered = stale
        .enroll_store(enrollment_request(130, &enrolled, issued_at(131) + 101))
        .unwrap();
    assert_same_projection(&first, &recovered);
    let reuse_entropy = deterministic(Vec::new());
    let reused = open_ready(&fixture, reuse_entropy.clone())
        .create_challenge(CreateChallengeRequest {
            manifest: manifest(131),
            observed_at_unix_ms: issued_at(131) + 200,
            expires_at_unix_ms: issued_at(131) + 800,
        })
        .unwrap();
    assert_eq!(reused.challenge_id, successor.challenge_id);
    assert_eq!(reuse_entropy.consumed_bytes(), 0);
    assert!(matches!(
        open_ready(&fixture, deterministic(Vec::new())).state(),
        AuthorityOpenState::Ready(_)
    ));
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    for challenge in [successor.challenge_id, other_pending.challenge_id] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT state FROM authorization_challenges WHERE challenge_id=?1",
                    [challenge.as_bytes()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "pending"
        );
    }
}

#[test]
fn successor_before_authorized_final_expiry_is_legal_and_causal() {
    let fixture = ready_fixture();
    let first = authorize(&fixture, 130);
    let successor = create_challenge(&fixture, 131);
    let error = exact_error(
        open_ready(&fixture, deterministic(Vec::new())).enroll_store(enrollment_request(
            130,
            &first,
            issued_at(130) + 901,
        )),
    );
    assert_eq!(error.code, MailErrorCode::AuthorizationExpired);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    let authorized_sequence: i64 = connection
        .query_row(
            "SELECT sequence FROM authority_events WHERE entity_kind=8 AND entity_id=?1 AND event_code=4",
            [first.challenge.challenge_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let successor_sequence: i64 = connection
        .query_row(
            "SELECT created_event_sequence FROM authorization_challenges WHERE challenge_id=?1",
            [successor.challenge_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let final_expiry_sequence: i64 = connection
        .query_row(
            "SELECT sequence FROM authority_events WHERE entity_kind=8 AND entity_id=?1 AND event_code=5",
            [first.challenge.challenge_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(authorized_sequence < successor_sequence);
    assert!(successor_sequence < final_expiry_sequence);
    assert!(matches!(
        open_ready(&fixture, deterministic(Vec::new())).state(),
        AuthorityOpenState::Ready(_)
    ));
}

fn equal_timestamp_final_history() -> (ReadyFixture, Sha256Digest, Sha256Digest) {
    let fixture = ready_fixture();
    let first = authorize(&fixture, 130);
    let effective_time = issued_at(130) + 901;
    let successor = open_ready(&fixture, deterministic(vec![0x83; 48]))
        .create_challenge(CreateChallengeRequest {
            manifest: manifest(131),
            observed_at_unix_ms: effective_time,
            expires_at_unix_ms: effective_time + 900,
        })
        .unwrap();
    let error = exact_error(
        open_ready(&fixture, deterministic(Vec::new())).enroll_store(enrollment_request(
            130,
            &first,
            effective_time,
        )),
    );
    assert_eq!(error.code, MailErrorCode::AuthorizationExpired);
    (
        fixture,
        first.challenge.challenge_id,
        successor.challenge_id,
    )
}

#[test]
fn equal_timestamp_successor_and_final_event_order_is_exact() {
    let (fixture, first, successor) = equal_timestamp_final_history();
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    let (successor_sequence, successor_time): (i64, i64) = connection
        .query_row(
            "SELECT sequence,occurred_at FROM authority_events
             WHERE entity_kind=8 AND entity_id=?1 AND event_code=3",
            [successor.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let (final_sequence, final_time): (i64, i64) = connection
        .query_row(
            "SELECT sequence,occurred_at FROM authority_events
             WHERE entity_kind=8 AND entity_id=?1 AND event_code=5",
            [first.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(successor_time, final_time);
    assert!(successor_sequence < final_sequence);
    drop(connection);
    let reopened = open_ready(&fixture, deterministic(Vec::new()));
    assert!(matches!(reopened.state(), AuthorityOpenState::Ready(_)));

    for mutation in ["swap", "duplicate", "omit"] {
        let (fixture, first, successor) = equal_timestamp_final_history();
        let connection = Connection::open(fixture.home.database_path()).unwrap();
        let successor_sequence: i64 = connection
            .query_row(
                "SELECT sequence FROM authority_events
                 WHERE entity_kind=8 AND entity_id=?1 AND event_code=3",
                [successor.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        let final_sequence: i64 = connection
            .query_row(
                "SELECT sequence FROM authority_events
                 WHERE entity_kind=8 AND entity_id=?1 AND event_code=5",
                [first.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        match mutation {
            "swap" => swap_event_sequences(&connection, successor_sequence, final_sequence),
            "duplicate" => {
                connection
                    .execute(
                        "INSERT INTO authority_events
                         (entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256)
                         SELECT entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256
                         FROM authority_events WHERE sequence=?1",
                        [final_sequence],
                    )
                    .unwrap();
            }
            "omit" => {
                connection
                    .execute(
                        "DELETE FROM authority_events WHERE sequence=?1",
                        [final_sequence],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        drop(connection);
        let reopened = AuthorityStore::open_isolated(
            context(AnchorPresence::Present(fixture.snapshot.anchor.clone())),
            fixture.home.clone(),
            deterministic(Vec::new()),
        )
        .unwrap();
        assert!(
            matches!(reopened.state(), AuthorityOpenState::RecoveryRequired),
            "accepted corruption: {mutation}"
        );
    }
}

fn insert_forbidden_row(connection: &Connection, table: &str) {
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    let sql = match table {
        "registered_accounts" => {
            "INSERT INTO registered_accounts VALUES(zeroblob(16),zeroblob(16),zeroblob(32),1,zeroblob(16),zeroblob(32),'active',zeroblob(16),NULL,1,1,NULL)"
        }
        "registered_credentials" => {
            "INSERT INTO registered_credentials VALUES(zeroblob(16),zeroblob(16),zeroblob(16),zeroblob(16),1)"
        }
        "registered_store_versions" => {
            "INSERT INTO registered_store_versions VALUES(zeroblob(16),zeroblob(32),1,zeroblob(32),zeroblob(16),NULL,1)"
        }
        "registered_account_versions" => {
            "INSERT INTO registered_account_versions VALUES(zeroblob(16),zeroblob(16),1,zeroblob(16),zeroblob(32),zeroblob(16),1)"
        }
        "challenge_effects" => {
            "INSERT INTO challenge_effects VALUES(zeroblob(32),0,zeroblob(16),1)"
        }
        "account_transitions" => {
            "INSERT INTO account_transitions VALUES(zeroblob(16),zeroblob(16),zeroblob(16),zeroblob(16),'account_create',zeroblob(32),zeroblob(32),1,2,zeroblob(32),'prepared',1,NULL,NULL,NULL)"
        }
        "credential_cleanup" => {
            "INSERT INTO credential_cleanup VALUES(zeroblob(16),NULL,'active_v2',x'01',zeroblob(32),'provisional',NULL,1,NULL)"
        }
        "remote_effects" => {
            "INSERT INTO remote_effects VALUES(zeroblob(16),zeroblob(32),zeroblob(16),zeroblob(16),0,1,zeroblob(16),zeroblob(32),zeroblob(16),1,zeroblob(32),1,zeroblob(16),zeroblob(32),zeroblob(32),zeroblob(32),1,zeroblob(32),zeroblob(32),1)"
        }
        "effect_claims" => {
            "INSERT INTO effect_claims VALUES(zeroblob(16),zeroblob(16),zeroblob(16),zeroblob(16),zeroblob(16),zeroblob(32),zeroblob(16),1,zeroblob(32),1,zeroblob(16),zeroblob(32),zeroblob(32),zeroblob(32),1,zeroblob(32),zeroblob(32),x'01',zeroblob(32),1,2)"
        }
        "effect_invocations" => {
            "INSERT INTO effect_invocations VALUES(zeroblob(16),zeroblob(16),zeroblob(16),zeroblob(16),x'01',zeroblob(32),1)"
        }
        "effect_observations" => {
            "INSERT INTO effect_observations VALUES(zeroblob(32),zeroblob(16),zeroblob(16),zeroblob(16),1,x'01',zeroblob(32),1,x'01',1)"
        }
        _ => unreachable!(),
    };
    connection.execute(sql, []).unwrap();
}

#[test]
#[allow(clippy::too_many_lines)]
fn restart_rejects_corruption_oversize_orphans_and_every_later_stage_table() {
    for table in [
        "registered_accounts",
        "registered_credentials",
        "registered_store_versions",
        "registered_account_versions",
        "challenge_effects",
        "account_transitions",
        "credential_cleanup",
        "remote_effects",
        "effect_claims",
        "effect_invocations",
        "effect_observations",
    ] {
        let fixture = ready_fixture();
        insert_forbidden_row(
            &Connection::open(fixture.home.database_path()).unwrap(),
            table,
        );
        let reopened = AuthorityStore::open_isolated(
            context(AnchorPresence::Present(fixture.snapshot.anchor.clone())),
            fixture.home.clone(),
            deterministic(Vec::new()),
        )
        .unwrap();
        assert!(
            matches!(reopened.state(), AuthorityOpenState::RecoveryRequired),
            "unexpectedly accepted isolated row in {table}"
        );
    }

    for mutation in [
        "UPDATE grant_uses SET use_sha256=zeroblob(32)",
        "UPDATE registered_stores SET location_material=zeroblob(4097)",
        "DELETE FROM registered_store_versions",
        "UPDATE registered_store_versions SET config_sha256=zeroblob(32)",
        "UPDATE registered_store_versions SET enrolled_receipt_id=zeroblob(16)",
        "UPDATE registered_store_versions
         SET enrolled_receipt_id=NULL,committed_transition_id=zeroblob(16)",
        "DELETE FROM authority_events WHERE event_code=8",
    ] {
        let fixture = ready_fixture();
        let authorized = authorize(&fixture, 8);
        open_ready(&fixture, deterministic(Vec::new()))
            .enroll_store(enrollment_request(8, &authorized, issued_at(8) + 200))
            .unwrap();
        let connection = Connection::open(fixture.home.database_path()).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        connection.execute(mutation, []).unwrap();
        drop(connection);
        let reopened = AuthorityStore::open_isolated(
            context(AnchorPresence::Present(fixture.snapshot.anchor.clone())),
            fixture.home.clone(),
            deterministic(Vec::new()),
        )
        .unwrap();
        assert!(matches!(
            reopened.state(),
            AuthorityOpenState::RecoveryRequired
        ));
    }

    for (table, mutation, typeof_sql) in [
        (
            "grant_uses",
            "UPDATE grant_uses SET used_at='wrong-storage-class'",
            "SELECT typeof(used_at) FROM grant_uses",
        ),
        (
            "registered_stores",
            "UPDATE registered_stores SET config_generation='wrong-storage-class'",
            "SELECT typeof(config_generation) FROM registered_stores",
        ),
        (
            "registered_store_versions",
            "UPDATE registered_store_versions SET config_generation='wrong-storage-class'",
            "SELECT typeof(config_generation) FROM registered_store_versions",
        ),
    ] {
        let fixture = ready_fixture();
        let authorized = authorize(&fixture, 10);
        open_ready(&fixture, deterministic(Vec::new()))
            .enroll_store(enrollment_request(10, &authorized, issued_at(10) + 200))
            .unwrap();
        install_wrong_storage_class(&fixture.home, table, mutation, typeof_sql);
        assert_recovery_required(&fixture);
    }

    for mutation in [
        "UPDATE grant_uses SET target_id=zeroblob(257)",
        "UPDATE grant_uses SET used_at=-1",
        "UPDATE registered_stores SET location_sha256=zeroblob(31)",
        "UPDATE registered_stores SET config_generation=0",
        "UPDATE registered_stores SET config_sha256=zeroblob(32)",
        "UPDATE registered_store_versions SET location_sha256=zeroblob(31)",
        "UPDATE registered_store_versions SET config_generation=0",
        "UPDATE registered_store_versions SET created_at=-1",
    ] {
        let fixture = ready_fixture();
        let authorized = authorize(&fixture, 10);
        open_ready(&fixture, deterministic(Vec::new()))
            .enroll_store(enrollment_request(10, &authorized, issued_at(10) + 200))
            .unwrap();
        let connection = Connection::open(fixture.home.database_path()).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        connection.execute(mutation, []).unwrap();
        drop(connection);
        let reopened = AuthorityStore::open_isolated(
            context(AnchorPresence::Present(fixture.snapshot.anchor.clone())),
            fixture.home.clone(),
            deterministic(Vec::new()),
        )
        .unwrap();
        assert!(
            matches!(reopened.state(), AuthorityOpenState::RecoveryRequired),
            "accepted bounded corruption: {mutation}"
        );
    }

    for mutation in ["duplicate", "orphan"] {
        let fixture = ready_fixture();
        let authorized = authorize(&fixture, 10);
        open_ready(&fixture, deterministic(Vec::new()))
            .enroll_store(enrollment_request(10, &authorized, issued_at(10) + 200))
            .unwrap();
        let connection = Connection::open(fixture.home.database_path()).unwrap();
        match mutation {
            "duplicate" => {
                connection
                    .execute(
                        "INSERT INTO authority_events
                         (entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256)
                         SELECT entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256
                         FROM authority_events WHERE event_code=7 LIMIT 1",
                        [],
                    )
                    .unwrap();
            }
            "orphan" => {
                connection
                    .execute(
                        "INSERT INTO authority_events
                         (entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256)
                         SELECT entity_kind,?1,event_code,source,occurred_at,detail,detail_sha256
                         FROM authority_events WHERE event_code=7 LIMIT 1",
                        [[0xee; 16]],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        drop(connection);
        assert_recovery_required(&fixture);
    }

    let fixture = ready_fixture();
    let first = authorize(&fixture, 10);
    open_ready(&fixture, deterministic(Vec::new()))
        .enroll_store(enrollment_request(10, &first, issued_at(10) + 200))
        .unwrap();
    let second = authorize(&fixture, 11);
    open_ready(&fixture, deterministic(Vec::new()))
        .enroll_store(enrollment_request(11, &second, issued_at(11) + 200))
        .unwrap();
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
        .unwrap();
    connection
        .execute(
            "UPDATE registered_stores SET enrolled_receipt_id=?1 WHERE store_id=?2",
            params![[0xfa_u8; 16], store_id(10).as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE registered_stores SET enrolled_receipt_id=?1 WHERE store_id=?2",
            params![first.receipt.receipt_id.as_bytes(), store_id(11).as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE registered_stores SET enrolled_receipt_id=?1 WHERE store_id=?2",
            params![
                second.receipt.receipt_id.as_bytes(),
                store_id(10).as_bytes()
            ],
        )
        .unwrap();
    drop(connection);
    assert_recovery_required(&fixture);

    let fixture = ready_fixture();
    let first = authorize(&fixture, 10);
    open_ready(&fixture, deterministic(Vec::new()))
        .enroll_store(enrollment_request(10, &first, issued_at(10) + 200))
        .unwrap();
    let second = authorize(&fixture, 11);
    open_ready(&fixture, deterministic(Vec::new()))
        .enroll_store(enrollment_request(11, &second, issued_at(11) + 200))
        .unwrap();
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
        .unwrap();
    connection
        .execute(
            "UPDATE registered_store_versions SET enrolled_receipt_id=?1 WHERE store_id=?2",
            params![[0xfb_u8; 16], store_id(10).as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE registered_store_versions SET enrolled_receipt_id=?1 WHERE store_id=?2",
            params![first.receipt.receipt_id.as_bytes(), store_id(11).as_bytes()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE registered_store_versions SET enrolled_receipt_id=?1 WHERE store_id=?2",
            params![
                second.receipt.receipt_id.as_bytes(),
                store_id(10).as_bytes()
            ],
        )
        .unwrap();
    drop(connection);
    assert_recovery_required(&fixture);
}

#[test]
fn old_seventeen_table_inventory_is_rejected_without_repair() {
    let fixture = ready_fixture();
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
             DROP TABLE registered_account_versions;
             DROP TABLE registered_store_versions;
             DROP TABLE registered_credentials;",
        )
        .unwrap();
    let before: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='table' AND name NOT LIKE 'sqlite_%'),
                (SELECT application_id FROM pragma_application_id),
                (SELECT user_version FROM pragma_user_version)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(before, (17, 1_263_096_394, 1));
    drop(connection);

    assert_recovery_required(&fixture);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    let after: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='table' AND name NOT LIKE 'sqlite_%'),
                (SELECT application_id FROM pragma_application_id),
                (SELECT user_version FROM pragma_user_version)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(after, before);
}

#[test]
fn complete_128_row_history_restarts_with_indexed_streams() {
    let fixture = ready_fixture();
    for index in 0..128 {
        let authorized = authorize(&fixture, index);
        open_ready(&fixture, deterministic(Vec::new()))
            .enroll_store(enrollment_request(
                index,
                &authorized,
                issued_at(index) + 200,
            ))
            .unwrap();
    }
    reset_authority_validation_query_counts();
    assert!(matches!(
        open_ready(&fixture, deterministic(Vec::new())).state(),
        AuthorityOpenState::Ready(_)
    ));
    let AuthorityValidationQueryCounts {
        challenge_preflight,
        receipt_preflight,
        nonce_preflight,
        grant_preflight,
        store_preflight,
        event_preflight,
        registry_parent_preflight,
        registry_stream,
        bounded_keyed,
    } = take_authority_validation_query_counts();
    assert_eq!(challenge_preflight, 1);
    assert_eq!(receipt_preflight, 1);
    assert_eq!(nonce_preflight, 1);
    assert_eq!(grant_preflight, 1);
    assert_eq!(store_preflight, 1);
    assert_eq!(event_preflight, 1);
    assert_eq!(registry_parent_preflight, 1);
    assert_eq!(registry_stream, 5 + 128);
    assert_eq!(bounded_keyed, 29 * 128);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    assert_eq!(scalar(&connection, "SELECT COUNT(*) FROM grant_uses"), 128);
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM registered_stores"),
        128
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM registered_store_versions"
        ),
        128
    );
    let plans = [
        query_plan(
            &connection,
            "SELECT grant_id FROM grant_uses ORDER BY grant_id",
        ),
        query_plan(
            &connection,
            "SELECT store_id FROM registered_stores ORDER BY store_id",
        ),
        query_plan(
            &connection,
            "SELECT store_id,config_generation FROM registered_store_versions
             WHERE store_id=zeroblob(16) ORDER BY store_id,config_generation",
        ),
        query_plan(
            &connection,
            "SELECT sequence,event_code FROM authority_events INDEXED BY authority_events_entity_sequence WHERE entity_kind=10 AND entity_id=zeroblob(16) ORDER BY sequence",
        ),
    ];
    assert!(
        plans[0]
            .iter()
            .any(|line| line.contains("sqlite_autoindex_grant_uses_1"))
    );
    assert!(
        plans[1]
            .iter()
            .any(|line| line.contains("sqlite_autoindex_registered_stores_1"))
    );
    assert!(
        plans[2]
            .iter()
            .any(|line| line.contains("sqlite_autoindex_registered_store_versions_3"))
    );
    assert!(
        plans[3]
            .iter()
            .any(|line| line.contains("authority_events_entity_sequence"))
    );
    for plan in plans.into_iter().flatten() {
        assert!(!plan.contains("TEMP B-TREE"));
        assert!(!plan.contains("CORRELATED"));
    }
    let source = include_str!("../src/authority.rs");
    let start = source.find("fn validate_registry_history").unwrap();
    let end = source[start..]
        .find("\nfn ")
        .map_or(source.len(), |offset| start + offset);
    assert!(!source[start..end].contains("collect::<Vec"));
}

#[test]
fn c2_transition_surface_and_parent_preflight_counter_are_required() {
    assert_eq!(AccountTransitionKind::AccountCreate.code(), 1);
    assert_eq!(AccountTransitionKind::AccountUpdate.code(), 2);
    assert_eq!(AccountTransitionKind::AccountRemove.code(), 3);
    assert_eq!(AccountTransitionKind::CredentialSet.code(), 4);
    assert_eq!(AccountTransitionKind::CredentialDelete.code(), 5);

    let _: fn(
        &AuthorityStore,
        PrepareAccountTransitionRequest,
    ) -> Result<AccountTransitionProjection, MailError> =
        AuthorityStore::prepare_account_transition;
    let _: fn(
        &AuthorityStore,
        AccountTransitionObservationRequest,
    ) -> Result<AccountTransitionProjection, MailError> = AuthorityStore::mark_config_committed;
    let _: fn(
        &AuthorityStore,
        AccountTransitionObservationRequest,
    ) -> Result<AccountTransitionProjection, MailError> =
        AuthorityStore::finalize_account_transition;
    let _: fn(
        &AuthorityStore,
        AccountTransitionObservationRequest,
    ) -> Result<AccountTransitionProjection, MailError> = AuthorityStore::abort_transition;
    let _: fn(
        &AuthorityStore,
        AccountTransitionObservationRequest,
    ) -> Result<AccountTransitionProjection, MailError> =
        AuthorityStore::mark_transition_recovery_required;

    let fixture = ready_fixture();
    reset_authority_validation_query_counts();
    assert!(matches!(
        open_ready(&fixture, deterministic(Vec::new())).state(),
        AuthorityOpenState::Ready(_)
    ));
    let counts = take_authority_validation_query_counts();
    assert_eq!(counts.registry_parent_preflight, 1);
}

#[test]
fn account_store_events_use_the_bounded_entity_event_stream() {
    let source = include_str!("../src/authority.rs");
    let start = source.find("fn account_store_event_is_exact").unwrap();
    let end = source[start..]
        .find("\nfn ")
        .map_or(source.len(), |offset| start + offset);
    let validator = &source[start..end];
    assert!(validator.contains("FROM authority_events"));
    assert!(validator.contains("authority_events_entity_sequence"));
    assert!(validator.contains("ORDER BY sequence"));
    assert!(!validator.contains("FROM account_transitions"));

    let fixture = account_ready_fixture();
    let (authorized, _) = authorize_account_create(&fixture);
    open_ready(&fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&authorized, 501_200))
        .unwrap();
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    let plan = query_plan(
        &connection,
        "SELECT sequence,event_code,source,occurred_at,detail,detail_sha256
         FROM authority_events INDEXED BY authority_events_entity_sequence
         WHERE entity_kind=4 AND entity_id=zeroblob(16) ORDER BY sequence",
    );
    assert!(
        plan.iter()
            .any(|line| line.contains("authority_events_entity_sequence"))
    );
    for line in plan {
        assert!(!line.contains("TEMP B-TREE"));
        assert!(!line.contains("CORRELATED"));
    }
}

#[test]
fn account_restart_validation_has_a_constant_per_transition_query_slope() {
    let counts = |include_second: bool| {
        let fixture = account_ready_fixture();
        let (first, _) = authorize_account_create(&fixture);
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&first, 501_200))
            .unwrap();
        open_ready(&fixture, deterministic(Vec::new()))
            .mark_config_committed(observe_account(
                AccountTransitionState::Prepared,
                2,
                account_after_config_sha256(),
                501_300,
            ))
            .unwrap();
        open_ready(&fixture, deterministic(Vec::new()))
            .finalize_account_transition(observe_account(
                AccountTransitionState::ConfigCommitted,
                2,
                account_after_config_sha256(),
                501_400,
            ))
            .unwrap();
        if include_second {
            let second = authorize_second_account_create(&fixture);
            open_ready(&fixture, deterministic(Vec::new()))
                .prepare_account_transition(prepare_second_account_request(&second, 501_700))
                .unwrap();
            open_ready(&fixture, deterministic(Vec::new()))
                .mark_config_committed(observe_second_account(
                    AccountTransitionState::Prepared,
                    3,
                    second_account_after_config_sha256(),
                    501_800,
                ))
                .unwrap();
            open_ready(&fixture, deterministic(Vec::new()))
                .finalize_account_transition(observe_second_account(
                    AccountTransitionState::ConfigCommitted,
                    3,
                    second_account_after_config_sha256(),
                    501_900,
                ))
                .unwrap();
        }
        reset_authority_validation_query_counts();
        assert!(matches!(
            open_ready(&fixture, deterministic(Vec::new())).state(),
            AuthorityOpenState::Ready(_)
        ));
        take_authority_validation_query_counts()
    };
    let one = counts(false);
    let two = counts(true);
    assert_eq!(one.registry_parent_preflight, 1);
    assert_eq!(two.registry_parent_preflight, 1);
    assert_eq!(one.registry_stream, 6);
    assert_eq!(two.registry_stream, 6);
    assert_eq!(one.bounded_keyed, 29 + 79);
    assert_eq!(two.bounded_keyed, 29 + 79 * 2);
    assert_eq!(two.bounded_keyed - one.bounded_keyed, 79);
}

#[test]
fn account_create_challenge_is_intrinsic_reusable_and_effect_free() {
    let fixture = ready_fixture();
    let enrolled = authorize(&fixture, 0);
    open_ready(&fixture, deterministic(Vec::new()))
        .enroll_store(enrollment_request(0, &enrolled, issued_at(0) + 200))
        .unwrap();

    let entropy = deterministic(hex::<48>(account_vector("challenge_entropy")).to_vec());
    let request = CreateChallengeRequest {
        manifest: account_manifest(),
        observed_at_unix_ms: 501_000,
        expires_at_unix_ms: 501_900,
    };
    let first = open_ready(&fixture, entropy.clone())
        .create_challenge(request.clone())
        .unwrap();
    assert_eq!(entropy.consumed_bytes(), 48);
    assert_eq!(first.action, SensitiveAction::AccountCreate);
    assert_eq!(first.target_kind, TargetKind::Account);
    assert_eq!(first.target_id, account_id().to_string());

    let retry_entropy = deterministic(Vec::new());
    let retry = open_ready(&fixture, retry_entropy.clone())
        .create_challenge(request)
        .unwrap();
    assert_eq!(retry.challenge_id, first.challenge_id);
    assert_eq!(retry_entropy.consumed_bytes(), 0);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM challenge_effects WHERE challenge_id IN
             (SELECT challenge_id FROM authorization_challenges WHERE action=272)"
        ),
        0
    );
}

#[test]
fn account_create_challenge_requires_the_reentry_state_reason() {
    let fixture = account_ready_fixture();
    enroll_account_fixture_store(&fixture);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    let before = issuance_fingerprint(&connection);
    drop(connection);

    let error = exact_error(
        open_ready(&fixture, deterministic(Vec::new())).create_challenge(CreateChallengeRequest {
            manifest: account_manifest_with_state_reason(None),
            observed_at_unix_ms: 501_000,
            expires_at_unix_ms: 501_900,
        }),
    );

    assert_eq!(error.code, MailErrorCode::AuthorizationContextStale);
    assert_eq!(
        issuance_fingerprint(&Connection::open(fixture.home.database_path()).unwrap()),
        before
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn account_create_challenge_entropy_replacement_and_concurrency_are_exact() {
    let fixture = account_ready_fixture();
    enroll_account_fixture_store(&fixture);
    let before = issuance_fingerprint(&Connection::open(fixture.home.database_path()).unwrap());
    let exhausted = deterministic(hex::<48>(account_vector("challenge_entropy"))[..47].to_vec());
    let error = exact_error(open_ready(&fixture, exhausted.clone()).create_challenge(
        CreateChallengeRequest {
            manifest: account_manifest(),
            observed_at_unix_ms: 501_000,
            expires_at_unix_ms: 501_900,
        },
    ));
    assert_eq!(error.code, MailErrorCode::Internal);
    assert_eq!(exhausted.consumed_bytes(), 16);
    assert_eq!(
        issuance_fingerprint(&Connection::open(fixture.home.database_path()).unwrap()),
        before
    );

    let first = open_ready(
        &fixture,
        deterministic(hex::<48>(account_vector("challenge_entropy")).to_vec()),
    )
    .create_challenge(CreateChallengeRequest {
        manifest: account_manifest(),
        observed_at_unix_ms: 501_000,
        expires_at_unix_ms: 501_900,
    })
    .unwrap();
    let replacement_entropy =
        deterministic(hex::<48>(account_vector("replacement_challenge_entropy")).to_vec());
    let replacement = open_ready(&fixture, replacement_entropy.clone())
        .create_challenge(CreateChallengeRequest {
            manifest: account_manifest(),
            observed_at_unix_ms: 502_000,
            expires_at_unix_ms: 502_900,
        })
        .unwrap();
    assert_ne!(replacement.challenge_id, first.challenge_id);
    assert_eq!(replacement_entropy.consumed_bytes(), 48);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authorization_challenges WHERE action=272 AND state='expired'"
        ),
        1
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authorization_challenges WHERE action=272 AND state='pending'"
        ),
        1
    );
    drop(connection);
    let restart_entropy = deterministic(Vec::new());
    let restart = open_ready(&fixture, restart_entropy.clone())
        .create_challenge(CreateChallengeRequest {
            manifest: account_manifest(),
            observed_at_unix_ms: 502_100,
            expires_at_unix_ms: 502_900,
        })
        .unwrap();
    assert_eq!(restart.challenge_id, replacement.challenge_id);
    assert_eq!(restart_entropy.consumed_bytes(), 0);

    let fixture = account_ready_fixture();
    enroll_account_fixture_store(&fixture);
    let barrier = Arc::new(Barrier::new(3));
    let left_entropy =
        deterministic(hex::<48>(account_vector("concurrent_left_challenge_entropy")).to_vec());
    let right_entropy =
        deterministic(hex::<48>(account_vector("concurrent_right_challenge_entropy")).to_vec());
    let mut workers = Vec::new();
    for entropy in [left_entropy.clone(), right_entropy.clone()] {
        let home = fixture.home.clone();
        let anchor = fixture.snapshot.anchor.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            let store = AuthorityStore::open_isolated(
                context(AnchorPresence::Present(anchor)),
                home,
                entropy,
            )
            .unwrap();
            barrier.wait();
            store.create_challenge(CreateChallengeRequest {
                manifest: account_manifest(),
                observed_at_unix_ms: 501_000,
                expires_at_unix_ms: 501_900,
            })
        }));
    }
    barrier.wait();
    let left = workers.remove(0).join().unwrap().unwrap();
    let right = workers.remove(0).join().unwrap().unwrap();
    assert_eq!(left.challenge_id, right.challenge_id);
    assert_eq!(
        left_entropy.consumed_bytes() + right_entropy.consumed_bytes(),
        48
    );
}

#[test]
fn account_create_prepare_commit_finalize_and_enrollment_retry_are_exact() {
    let fixture = account_ready_fixture();
    let (authorized, enrollment) = authorize_account_create(&fixture);
    let store = open_ready(&fixture, deterministic(Vec::new()));
    let prepared = store
        .prepare_account_transition(prepare_account_request(&authorized, 501_200))
        .unwrap();
    assert_eq!(prepared.transition_id, account_transition_id());
    assert_eq!(prepared.account_id, account_id());
    assert!(prepared.transition_state == AccountTransitionState::Prepared);
    assert!(prepared.account_state == RegisteredAccountState::Proposed);
    assert!(prepared.store_state == RegisteredStoreTransitionState::Blocked);
    assert_eq!(prepared.config_generation.get(), 1);
    assert_eq!(prepared.account_generation.get(), 1);

    let same = open_ready(&fixture, deterministic(Vec::new()))
        .mark_config_committed(observe_account(
            AccountTransitionState::Prepared,
            1,
            config_sha256(0),
            501_250,
        ))
        .unwrap();
    assert!(same.transition_state == AccountTransitionState::Prepared);

    let committed = open_ready(&fixture, deterministic(Vec::new()))
        .mark_config_committed(observe_account(
            AccountTransitionState::Prepared,
            2,
            account_after_config_sha256(),
            501_300,
        ))
        .unwrap();
    assert!(committed.transition_state == AccountTransitionState::ConfigCommitted);
    assert_eq!(committed.config_generation.get(), 2);

    let finalized = open_ready(&fixture, deterministic(Vec::new()))
        .finalize_account_transition(observe_account(
            AccountTransitionState::ConfigCommitted,
            2,
            account_after_config_sha256(),
            501_400,
        ))
        .unwrap();
    assert!(finalized.transition_state == AccountTransitionState::Finalized);
    assert!(finalized.account_state == RegisteredAccountState::Active);
    assert!(finalized.store_state == RegisteredStoreTransitionState::Active);

    let replay = open_ready(&fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&authorized, 501_500))
        .unwrap();
    assert!(replay.transition_state == AccountTransitionState::Finalized);
    let original = open_ready(&fixture, deterministic(Vec::new()))
        .enroll_store(enrollment_request(0, &enrollment, 501_550))
        .unwrap();
    assert_eq!(original.config_generation.get(), 1);
    assert!(matches!(
        open_ready(&fixture, deterministic(Vec::new())).state(),
        AuthorityOpenState::Ready(_)
    ));
}

#[test]
fn account_create_abort_and_terminal_recovery_are_restart_exact() {
    let aborted_fixture = account_ready_fixture();
    let (aborted_authorized, _) = authorize_account_create(&aborted_fixture);
    open_ready(&aborted_fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&aborted_authorized, 501_200))
        .unwrap();
    let aborted = open_ready(&aborted_fixture, deterministic(Vec::new()))
        .abort_transition(observe_account(
            AccountTransitionState::Prepared,
            1,
            config_sha256(0),
            501_300,
        ))
        .unwrap();
    assert!(aborted.transition_state == AccountTransitionState::Aborted);
    assert!(aborted.account_state == RegisteredAccountState::Removed);
    assert!(aborted.store_state == RegisteredStoreTransitionState::Active);
    let abort_retry = open_ready(&aborted_fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&aborted_authorized, 501_400))
        .unwrap();
    assert!(abort_retry.transition_state == AccountTransitionState::Aborted);

    let recovery_fixture = account_ready_fixture();
    let (recovery_authorized, _) = authorize_account_create(&recovery_fixture);
    open_ready(&recovery_fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&recovery_authorized, 501_200))
        .unwrap();
    let recovery = open_ready(&recovery_fixture, deterministic(Vec::new()))
        .mark_transition_recovery_required(observe_account(
            AccountTransitionState::Prepared,
            3,
            account_third_config_sha256(),
            501_300,
        ))
        .unwrap();
    assert!(recovery.transition_state == AccountTransitionState::RecoveryRequired);
    assert!(recovery.account_state == RegisteredAccountState::Blocked);
    assert!(recovery.store_state == RegisteredStoreTransitionState::RecoveryRequired);
    assert_eq!(recovery.config_generation.get(), 3);
    let recovery_retry = open_ready(&recovery_fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&recovery_authorized, 501_400))
        .unwrap();
    assert!(recovery_retry.transition_state == AccountTransitionState::RecoveryRequired);
    let changed = exact_error(
        open_ready(&recovery_fixture, deterministic(Vec::new())).mark_transition_recovery_required(
            observe_account(
                AccountTransitionState::Prepared,
                4,
                account_third_config_sha256(),
                501_500,
            ),
        ),
    );
    assert_eq!(changed.code, MailErrorCode::AccountUpdateConflict);
}

#[test]
fn config_commit_retry_recovers_the_later_terminal_transition() {
    let fixture = account_ready_fixture();
    let (authorized, _) = authorize_account_create(&fixture);
    open_ready(&fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&authorized, 501_200))
        .unwrap();
    open_ready(&fixture, deterministic(Vec::new()))
        .mark_config_committed(observe_account(
            AccountTransitionState::Prepared,
            2,
            account_after_config_sha256(),
            501_300,
        ))
        .unwrap();
    let recovery = open_ready(&fixture, deterministic(Vec::new()))
        .finalize_account_transition(observe_account(
            AccountTransitionState::ConfigCommitted,
            1,
            config_sha256(0),
            501_400,
        ))
        .unwrap();
    assert!(recovery.transition_state == AccountTransitionState::RecoveryRequired);

    let retry = open_ready(&fixture, deterministic(Vec::new()))
        .mark_config_committed(observe_account(
            AccountTransitionState::Prepared,
            2,
            account_after_config_sha256(),
            501_500,
        ))
        .unwrap();
    assert!(retry.transition_state == AccountTransitionState::RecoveryRequired);
    assert_eq!(retry.config_generation.get(), 1);

    let recovery_retry = open_ready(&fixture, deterministic(Vec::new()))
        .mark_transition_recovery_required(observe_account(
            AccountTransitionState::ConfigCommitted,
            1,
            config_sha256(0),
            501_600,
        ))
        .unwrap();
    assert!(recovery_retry.transition_state == AccountTransitionState::RecoveryRequired);
}

#[test]
fn unsafe_config_pairs_take_precedence_over_a_stale_method_state() {
    let prepared_fixture = account_ready_fixture();
    let (prepared_authorized, _) = authorize_account_create(&prepared_fixture);
    open_ready(&prepared_fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&prepared_authorized, 501_200))
        .unwrap();
    let prepared_recovery = open_ready(&prepared_fixture, deterministic(Vec::new()))
        .finalize_account_transition(observe_account(
            AccountTransitionState::ConfigCommitted,
            3,
            account_third_config_sha256(),
            501_300,
        ))
        .unwrap();
    assert!(prepared_recovery.transition_state == AccountTransitionState::RecoveryRequired);
    let prepared_retry = open_ready(&prepared_fixture, deterministic(Vec::new()))
        .finalize_account_transition(observe_account(
            AccountTransitionState::ConfigCommitted,
            3,
            account_third_config_sha256(),
            501_400,
        ))
        .unwrap();
    assert!(prepared_retry.transition_state == AccountTransitionState::RecoveryRequired);

    let committed_fixture = account_ready_fixture();
    let (committed_authorized, _) = authorize_account_create(&committed_fixture);
    open_ready(&committed_fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&committed_authorized, 501_200))
        .unwrap();
    open_ready(&committed_fixture, deterministic(Vec::new()))
        .mark_config_committed(observe_account(
            AccountTransitionState::Prepared,
            2,
            account_after_config_sha256(),
            501_300,
        ))
        .unwrap();
    let committed_recovery = open_ready(&committed_fixture, deterministic(Vec::new()))
        .abort_transition(observe_account(
            AccountTransitionState::Prepared,
            1,
            config_sha256(0),
            501_400,
        ))
        .unwrap();
    assert!(committed_recovery.transition_state == AccountTransitionState::RecoveryRequired);
    let committed_retry = open_ready(&committed_fixture, deterministic(Vec::new()))
        .abort_transition(observe_account(
            AccountTransitionState::Prepared,
            1,
            config_sha256(0),
            501_500,
        ))
        .unwrap();
    assert!(committed_retry.transition_state == AccountTransitionState::RecoveryRequired);
}

#[test]
#[allow(clippy::too_many_lines)]
fn finalized_transition_retries_are_scoped_after_every_second_transition_state() {
    for second_state in [
        AccountTransitionState::Prepared,
        AccountTransitionState::ConfigCommitted,
        AccountTransitionState::Finalized,
        AccountTransitionState::Aborted,
        AccountTransitionState::RecoveryRequired,
    ] {
        let fixture = account_ready_fixture();
        let (first, enrollment) = authorize_account_create(&fixture);
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&first, 501_200))
            .unwrap();
        open_ready(&fixture, deterministic(Vec::new()))
            .mark_config_committed(observe_account(
                AccountTransitionState::Prepared,
                2,
                account_after_config_sha256(),
                501_300,
            ))
            .unwrap();
        open_ready(&fixture, deterministic(Vec::new()))
            .finalize_account_transition(observe_account(
                AccountTransitionState::ConfigCommitted,
                2,
                account_after_config_sha256(),
                501_400,
            ))
            .unwrap();

        let second = authorize_second_account_create(&fixture);
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_second_account_request(&second, 501_700))
            .unwrap();
        match second_state {
            AccountTransitionState::Prepared => {}
            AccountTransitionState::ConfigCommitted | AccountTransitionState::Finalized => {
                open_ready(&fixture, deterministic(Vec::new()))
                    .mark_config_committed(observe_second_account(
                        AccountTransitionState::Prepared,
                        3,
                        second_account_after_config_sha256(),
                        501_800,
                    ))
                    .unwrap();
                if second_state == AccountTransitionState::Finalized {
                    open_ready(&fixture, deterministic(Vec::new()))
                        .finalize_account_transition(observe_second_account(
                            AccountTransitionState::ConfigCommitted,
                            3,
                            second_account_after_config_sha256(),
                            501_900,
                        ))
                        .unwrap();
                }
            }
            AccountTransitionState::Aborted => {
                open_ready(&fixture, deterministic(Vec::new()))
                    .abort_transition(observe_second_account(
                        AccountTransitionState::Prepared,
                        2,
                        account_after_config_sha256(),
                        501_800,
                    ))
                    .unwrap();
            }
            AccountTransitionState::RecoveryRequired => {
                open_ready(&fixture, deterministic(Vec::new()))
                    .mark_transition_recovery_required(observe_second_account(
                        AccountTransitionState::Prepared,
                        4,
                        account_third_config_sha256(),
                        501_800,
                    ))
                    .unwrap();
                let entropy =
                    deterministic(hex::<48>(account_vector("blocked_challenge_entropy")).to_vec());
                let error = exact_error(open_ready(&fixture, entropy.clone()).create_challenge(
                    CreateChallengeRequest {
                        manifest: second_account_manifest(),
                        observed_at_unix_ms: 501_900,
                        expires_at_unix_ms: 502_400,
                    },
                ));
                assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
                assert_eq!(entropy.consumed_bytes(), 0);
            }
        }

        let prepare_retry = open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&first, 502_000))
            .unwrap();
        let commit_retry = open_ready(&fixture, deterministic(Vec::new()))
            .mark_config_committed(observe_account(
                AccountTransitionState::Prepared,
                2,
                account_after_config_sha256(),
                502_100,
            ))
            .unwrap();
        let finalize_retry = open_ready(&fixture, deterministic(Vec::new()))
            .finalize_account_transition(observe_account(
                AccountTransitionState::ConfigCommitted,
                2,
                account_after_config_sha256(),
                502_200,
            ))
            .unwrap();
        for retry in [prepare_retry, commit_retry, finalize_retry] {
            assert!(retry.transition_state == AccountTransitionState::Finalized);
            assert_eq!(retry.config_generation.get(), 2);
        }
        let original = open_ready(&fixture, deterministic(Vec::new()))
            .enroll_store(enrollment_request(0, &enrollment, 502_300))
            .unwrap();
        assert_eq!(original.config_generation.get(), 1);
        assert!(matches!(
            open_ready(&fixture, deterministic(Vec::new())).state(),
            AuthorityOpenState::Ready(_)
        ));
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn aborted_transition_retries_are_scoped_after_every_second_transition_state() {
    for second_state in [
        AccountTransitionState::Prepared,
        AccountTransitionState::ConfigCommitted,
        AccountTransitionState::Finalized,
        AccountTransitionState::Aborted,
        AccountTransitionState::RecoveryRequired,
    ] {
        let fixture = account_ready_fixture();
        let (first, enrollment) = authorize_account_create(&fixture);
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&first, 501_200))
            .unwrap();
        open_ready(&fixture, deterministic(Vec::new()))
            .abort_transition(observe_account(
                AccountTransitionState::Prepared,
                1,
                config_sha256(0),
                501_300,
            ))
            .unwrap();

        let second = authorize_second_account_create_after_abort(&fixture);
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_second_account_request_after_abort(
                &second, 501_600,
            ))
            .unwrap();
        match second_state {
            AccountTransitionState::Prepared => {}
            AccountTransitionState::ConfigCommitted | AccountTransitionState::Finalized => {
                open_ready(&fixture, deterministic(Vec::new()))
                    .mark_config_committed(observe_second_account(
                        AccountTransitionState::Prepared,
                        2,
                        second_account_after_config_sha256(),
                        501_700,
                    ))
                    .unwrap();
                if second_state == AccountTransitionState::Finalized {
                    open_ready(&fixture, deterministic(Vec::new()))
                        .finalize_account_transition(observe_second_account(
                            AccountTransitionState::ConfigCommitted,
                            2,
                            second_account_after_config_sha256(),
                            501_800,
                        ))
                        .unwrap();
                }
            }
            AccountTransitionState::Aborted => {
                open_ready(&fixture, deterministic(Vec::new()))
                    .abort_transition(observe_second_account(
                        AccountTransitionState::Prepared,
                        1,
                        config_sha256(0),
                        501_700,
                    ))
                    .unwrap();
            }
            AccountTransitionState::RecoveryRequired => {
                open_ready(&fixture, deterministic(Vec::new()))
                    .mark_transition_recovery_required(observe_second_account(
                        AccountTransitionState::Prepared,
                        3,
                        account_third_config_sha256(),
                        501_700,
                    ))
                    .unwrap();
            }
        }

        let prepare_retry = open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&first, 501_900))
            .unwrap();
        let abort_retry = open_ready(&fixture, deterministic(Vec::new()))
            .abort_transition(observe_account(
                AccountTransitionState::Prepared,
                1,
                config_sha256(0),
                502_000,
            ))
            .unwrap();
        for retry in [prepare_retry, abort_retry] {
            assert!(retry.transition_state == AccountTransitionState::Aborted);
            assert_eq!(retry.config_generation.get(), 1);
        }
        let original = open_ready(&fixture, deterministic(Vec::new()))
            .enroll_store(enrollment_request(0, &enrollment, 502_100))
            .unwrap();
        assert_eq!(original.config_generation.get(), 1);
        assert!(matches!(
            open_ready(&fixture, deterministic(Vec::new())).state(),
            AuthorityOpenState::Ready(_)
        ));
    }
}

#[test]
fn account_prepare_and_config_commit_fault_boundaries_are_atomic() {
    for fault in [
        AuthorityFaultPoint::GrantUseInserted,
        AuthorityFaultPoint::GrantUsedEvent,
        AuthorityFaultPoint::AccountStoreBlocked,
        AuthorityFaultPoint::AccountForeignKeysDeferred,
        AuthorityFaultPoint::RegisteredAccountInserted,
        AuthorityFaultPoint::AccountTransitionInserted,
        AuthorityFaultPoint::RegisteredCredentialInserted,
        AuthorityFaultPoint::AccountForeignKeyChecked,
        AuthorityFaultPoint::AccountStoreBlockedEvent,
        AuthorityFaultPoint::AccountTransitionPreparedEvent,
        AuthorityFaultPoint::AccountPrepareClockUpdated,
        AuthorityFaultPoint::AccountPrepareBeforeCommit,
    ] {
        let fixture = account_ready_fixture();
        let (authorized, _) = authorize_account_create(&fixture);
        let before =
            account_registry_fingerprint(&Connection::open(fixture.home.database_path()).unwrap());
        let error = exact_error(
            open_ready_with_fault(&fixture, fault)
                .prepare_account_transition(prepare_account_request(&authorized, 501_200)),
        );
        assert_eq!(error.code, MailErrorCode::StoreWrite);
        assert_eq!(
            account_registry_fingerprint(&Connection::open(fixture.home.database_path()).unwrap()),
            before
        );
        assert!(matches!(
            open_ready(&fixture, deterministic(Vec::new())).state(),
            AuthorityOpenState::Ready(_)
        ));
    }

    for fault in [
        AuthorityFaultPoint::AccountStoreVersionInserted,
        AuthorityFaultPoint::AccountVersionInserted,
        AuthorityFaultPoint::AccountTransitionCommitted,
        AuthorityFaultPoint::AccountStoreCommitted,
        AuthorityFaultPoint::AccountConfigCommittedEvent,
        AuthorityFaultPoint::AccountConfigClockUpdated,
        AuthorityFaultPoint::AccountConfigBeforeCommit,
    ] {
        let fixture = account_ready_fixture();
        let (authorized, _) = authorize_account_create(&fixture);
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&authorized, 501_200))
            .unwrap();
        let before =
            account_registry_fingerprint(&Connection::open(fixture.home.database_path()).unwrap());
        let error = exact_error(
            open_ready_with_fault(&fixture, fault).mark_config_committed(observe_account(
                AccountTransitionState::Prepared,
                2,
                account_after_config_sha256(),
                501_300,
            )),
        );
        assert_eq!(error.code, MailErrorCode::StoreWrite);
        assert_eq!(
            account_registry_fingerprint(&Connection::open(fixture.home.database_path()).unwrap()),
            before
        );
        assert!(matches!(
            open_ready(&fixture, deterministic(Vec::new())).state(),
            AuthorityOpenState::Ready(_)
        ));
    }

    let fixture = account_ready_fixture();
    let (authorized, _) = authorize_account_create(&fixture);
    let error = exact_error(
        open_ready_with_fault(&fixture, AuthorityFaultPoint::AccountPrepareAfterCommit)
            .prepare_account_transition(prepare_account_request(&authorized, 501_200)),
    );
    assert_eq!(error.code, MailErrorCode::StoreWrite);
    let retry = open_ready(&fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&authorized, 501_300))
        .unwrap();
    assert!(retry.transition_state == AccountTransitionState::Prepared);

    let error = exact_error(
        open_ready_with_fault(&fixture, AuthorityFaultPoint::AccountConfigAfterCommit)
            .mark_config_committed(observe_account(
                AccountTransitionState::Prepared,
                2,
                account_after_config_sha256(),
                501_400,
            )),
    );
    assert_eq!(error.code, MailErrorCode::StoreWrite);
    let retry = open_ready(&fixture, deterministic(Vec::new()))
        .mark_config_committed(observe_account(
            AccountTransitionState::Prepared,
            2,
            account_after_config_sha256(),
            501_500,
        ))
        .unwrap();
    assert!(retry.transition_state == AccountTransitionState::ConfigCommitted);
}

#[test]
fn account_prepare_expiry_is_committed_once_before_occupancy() {
    let fixture = account_ready_fixture();
    let (authorized, _) = authorize_account_create(&fixture);
    let first = exact_error(
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&authorized, 502_000)),
    );
    assert_eq!(first.code, MailErrorCode::AuthorizationExpired);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM account_transitions"),
        0
    );
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM authority_events WHERE entity_kind=8 AND event_code=5"
        ),
        1
    );
    drop(connection);
    let retry = exact_error(
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&authorized, 502_100)),
    );
    assert_eq!(retry.code, MailErrorCode::AuthorizationExpired);
    assert!(matches!(
        open_ready(&fixture, deterministic(Vec::new())).state(),
        AuthorityOpenState::Ready(_)
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn account_terminal_lifecycle_precommit_faults_rollback_exactly() {
    for fault in [
        AuthorityFaultPoint::AccountFinalizeAccountUpdated,
        AuthorityFaultPoint::AccountFinalizeTransitionUpdated,
        AuthorityFaultPoint::AccountFinalizeStoreUpdated,
        AuthorityFaultPoint::AccountFinalizeTransitionEvent,
        AuthorityFaultPoint::AccountFinalizeStoreEvent,
        AuthorityFaultPoint::AccountFinalizeClockUpdated,
        AuthorityFaultPoint::AccountFinalizeBeforeCommit,
    ] {
        let fixture = account_ready_fixture();
        let (authorized, _) = authorize_account_create(&fixture);
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&authorized, 501_200))
            .unwrap();
        open_ready(&fixture, deterministic(Vec::new()))
            .mark_config_committed(observe_account(
                AccountTransitionState::Prepared,
                2,
                account_after_config_sha256(),
                501_300,
            ))
            .unwrap();
        let before =
            account_registry_fingerprint(&Connection::open(fixture.home.database_path()).unwrap());
        let error = exact_error(
            open_ready_with_fault(&fixture, fault).finalize_account_transition(observe_account(
                AccountTransitionState::ConfigCommitted,
                2,
                account_after_config_sha256(),
                501_400,
            )),
        );
        assert_eq!(error.code, MailErrorCode::StoreWrite);
        assert_eq!(
            account_registry_fingerprint(&Connection::open(fixture.home.database_path()).unwrap()),
            before
        );
    }

    for fault in [
        AuthorityFaultPoint::AccountAbortAccountUpdated,
        AuthorityFaultPoint::AccountAbortTransitionUpdated,
        AuthorityFaultPoint::AccountAbortStoreUpdated,
        AuthorityFaultPoint::AccountAbortTransitionEvent,
        AuthorityFaultPoint::AccountAbortStoreEvent,
        AuthorityFaultPoint::AccountAbortClockUpdated,
        AuthorityFaultPoint::AccountAbortBeforeCommit,
    ] {
        let fixture = account_ready_fixture();
        let (authorized, _) = authorize_account_create(&fixture);
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&authorized, 501_200))
            .unwrap();
        let before =
            account_registry_fingerprint(&Connection::open(fixture.home.database_path()).unwrap());
        let error = exact_error(open_ready_with_fault(&fixture, fault).abort_transition(
            observe_account(
                AccountTransitionState::Prepared,
                1,
                config_sha256(0),
                501_300,
            ),
        ));
        assert_eq!(error.code, MailErrorCode::StoreWrite);
        assert_eq!(
            account_registry_fingerprint(&Connection::open(fixture.home.database_path()).unwrap()),
            before
        );
    }

    for fault in [
        AuthorityFaultPoint::AccountRecoveryAccountUpdated,
        AuthorityFaultPoint::AccountRecoveryTransitionUpdated,
        AuthorityFaultPoint::AccountRecoveryStoreUpdated,
        AuthorityFaultPoint::AccountRecoveryStoreEvent,
        AuthorityFaultPoint::AccountRecoveryTransitionEvent,
        AuthorityFaultPoint::AccountRecoveryClockUpdated,
        AuthorityFaultPoint::AccountRecoveryBeforeCommit,
    ] {
        let fixture = account_ready_fixture();
        let (authorized, _) = authorize_account_create(&fixture);
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&authorized, 501_200))
            .unwrap();
        let before =
            account_registry_fingerprint(&Connection::open(fixture.home.database_path()).unwrap());
        let error = exact_error(
            open_ready_with_fault(&fixture, fault).mark_transition_recovery_required(
                observe_account(
                    AccountTransitionState::Prepared,
                    3,
                    account_third_config_sha256(),
                    501_300,
                ),
            ),
        );
        assert_eq!(error.code, MailErrorCode::StoreWrite);
        assert_eq!(
            account_registry_fingerprint(&Connection::open(fixture.home.database_path()).unwrap()),
            before
        );
    }

    let fixture = account_ready_fixture();
    let (authorized, _) = authorize_account_create(&fixture);
    open_ready(&fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&authorized, 501_200))
        .unwrap();
    open_ready(&fixture, deterministic(Vec::new()))
        .mark_config_committed(observe_account(
            AccountTransitionState::Prepared,
            2,
            account_after_config_sha256(),
            501_300,
        ))
        .unwrap();
    assert_eq!(
        exact_error(
            open_ready_with_fault(&fixture, AuthorityFaultPoint::AccountFinalizeAfterCommit)
                .finalize_account_transition(observe_account(
                    AccountTransitionState::ConfigCommitted,
                    2,
                    account_after_config_sha256(),
                    501_400,
                ))
        )
        .code,
        MailErrorCode::StoreWrite
    );
    let retry = open_ready(&fixture, deterministic(Vec::new()))
        .finalize_account_transition(observe_account(
            AccountTransitionState::ConfigCommitted,
            2,
            account_after_config_sha256(),
            501_500,
        ))
        .unwrap();
    assert!(retry.transition_state == AccountTransitionState::Finalized);

    let fixture = account_ready_fixture();
    let (authorized, _) = authorize_account_create(&fixture);
    open_ready(&fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&authorized, 501_200))
        .unwrap();
    assert_eq!(
        exact_error(
            open_ready_with_fault(&fixture, AuthorityFaultPoint::AccountAbortAfterCommit)
                .abort_transition(observe_account(
                    AccountTransitionState::Prepared,
                    1,
                    config_sha256(0),
                    501_300,
                ))
        )
        .code,
        MailErrorCode::StoreWrite
    );
    let retry = open_ready(&fixture, deterministic(Vec::new()))
        .abort_transition(observe_account(
            AccountTransitionState::Prepared,
            1,
            config_sha256(0),
            501_400,
        ))
        .unwrap();
    assert!(retry.transition_state == AccountTransitionState::Aborted);

    let fixture = account_ready_fixture();
    let (authorized, _) = authorize_account_create(&fixture);
    open_ready(&fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&authorized, 501_200))
        .unwrap();
    assert_eq!(
        exact_error(
            open_ready_with_fault(&fixture, AuthorityFaultPoint::AccountRecoveryAfterCommit)
                .mark_transition_recovery_required(observe_account(
                    AccountTransitionState::Prepared,
                    3,
                    account_third_config_sha256(),
                    501_300,
                ))
        )
        .code,
        MailErrorCode::StoreWrite
    );
    let retry = open_ready(&fixture, deterministic(Vec::new()))
        .mark_transition_recovery_required(observe_account(
            AccountTransitionState::Prepared,
            3,
            account_third_config_sha256(),
            501_400,
        ))
        .unwrap();
    assert!(retry.transition_state == AccountTransitionState::RecoveryRequired);
}

#[test]
fn account_rows_events_and_versions_fail_closed_on_corruption() {
    for (table, mutation, typeof_sql) in [
        (
            "registered_accounts",
            "UPDATE registered_accounts SET account_generation='wrong-storage-class'",
            "SELECT typeof(account_generation) FROM registered_accounts",
        ),
        (
            "account_transitions",
            "UPDATE account_transitions SET expected_generation='wrong-storage-class'",
            "SELECT typeof(expected_generation) FROM account_transitions",
        ),
    ] {
        let fixture = account_ready_fixture();
        let (authorized, _) = authorize_account_create(&fixture);
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&authorized, 501_200))
            .unwrap();
        install_wrong_storage_class(&fixture.home, table, mutation, typeof_sql);
        assert_recovery_required(&fixture);
    }

    for mutation in [
        "UPDATE account_transitions SET transition_sha256=zeroblob(32)",
        "DELETE FROM registered_credentials",
        "UPDATE authority_events SET detail=zeroblob(length(detail)),
         detail_sha256=zeroblob(32) WHERE event_code=10",
    ] {
        let fixture = account_ready_fixture();
        let (authorized, _) = authorize_account_create(&fixture);
        open_ready(&fixture, deterministic(Vec::new()))
            .prepare_account_transition(prepare_account_request(&authorized, 501_200))
            .unwrap();
        let connection = Connection::open(fixture.home.database_path()).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        connection.execute(mutation, []).unwrap();
        drop(connection);
        assert_recovery_required(&fixture);
    }

    let fixture = account_ready_fixture();
    let (authorized, _) = authorize_account_create(&fixture);
    open_ready(&fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&authorized, 501_200))
        .unwrap();
    open_ready(&fixture, deterministic(Vec::new()))
        .mark_config_committed(observe_account(
            AccountTransitionState::Prepared,
            2,
            account_after_config_sha256(),
            501_300,
        ))
        .unwrap();
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    connection
        .execute(
            "DELETE FROM registered_account_versions WHERE committed_transition_id=?1",
            [account_transition_id().as_bytes()],
        )
        .unwrap();
    drop(connection);
    assert_recovery_required(&fixture);
}

#[test]
fn finalized_account_history_rejects_a_tampered_current_store_pair() {
    let fixture = account_ready_fixture();
    let (authorized, _) = authorize_account_create(&fixture);
    open_ready(&fixture, deterministic(Vec::new()))
        .prepare_account_transition(prepare_account_request(&authorized, 501_200))
        .unwrap();
    open_ready(&fixture, deterministic(Vec::new()))
        .mark_config_committed(observe_account(
            AccountTransitionState::Prepared,
            2,
            account_after_config_sha256(),
            501_300,
        ))
        .unwrap();
    open_ready(&fixture, deterministic(Vec::new()))
        .finalize_account_transition(observe_account(
            AccountTransitionState::ConfigCommitted,
            2,
            account_after_config_sha256(),
            501_400,
        ))
        .unwrap();

    let connection = Connection::open(fixture.home.database_path()).unwrap();
    connection
        .execute(
            "UPDATE registered_stores SET config_generation=3,config_sha256=?1",
            [account_third_config_sha256().as_bytes()],
        )
        .unwrap();
    drop(connection);

    assert_recovery_required(&fixture);
}

#[test]
fn concurrent_account_prepare_has_one_graph_and_exact_loser_recovery() {
    let fixture = account_ready_fixture();
    let (authorized, _) = authorize_account_create(&fixture);
    let request = prepare_account_request(&authorized, 501_200);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let home = fixture.home.clone();
        let anchor = fixture.snapshot.anchor.clone();
        let request = request.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            AuthorityStore::open_isolated(
                context(AnchorPresence::Present(anchor)),
                home,
                deterministic(Vec::new()),
            )
            .unwrap()
            .prepare_account_transition(request)
        }));
    }
    barrier.wait();
    let left = workers.remove(0).join().unwrap().unwrap();
    let right = workers.remove(0).join().unwrap().unwrap();
    assert!(left.transition_state == AccountTransitionState::Prepared);
    assert!(right.transition_state == AccountTransitionState::Prepared);
    assert_eq!(left.transition_id, right.transition_id);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM grant_uses WHERE action=272"
        ),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM account_transitions"),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM registered_accounts"),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM registered_credentials"),
        1
    );
}

#[test]
fn distinct_account_prepare_contenders_have_one_store_wide_winner() {
    let fixture = account_ready_fixture();
    let (first, _) = authorize_account_create(&fixture);
    let second = authorize_second_account_create_after_abort(&fixture);
    let requests = [
        prepare_account_request(&first, 501_600),
        prepare_second_account_request_after_abort(&second, 501_600),
    ];
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for request in requests {
        let home = fixture.home.clone();
        let anchor = fixture.snapshot.anchor.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            AuthorityStore::open_isolated(
                context(AnchorPresence::Present(anchor)),
                home,
                deterministic(Vec::new()),
            )
            .unwrap()
            .prepare_account_transition(request)
        }));
    }
    barrier.wait();
    let results = [
        workers.remove(0).join().unwrap(),
        workers.remove(0).join().unwrap(),
    ];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let loser = results.into_iter().find_map(Result::err).unwrap();
    assert_eq!(loser.code, MailErrorCode::AccountUpdateConflict);
    assert!(!loser.retryable);
    let connection = Connection::open(fixture.home.database_path()).unwrap();
    assert_eq!(
        scalar(
            &connection,
            "SELECT COUNT(*) FROM grant_uses WHERE action=272"
        ),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM account_transitions"),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM registered_accounts"),
        1
    );
    assert_eq!(
        scalar(&connection, "SELECT COUNT(*) FROM registered_credentials"),
        1
    );
}
