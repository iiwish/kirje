#![cfg(feature = "test-support")]
#![allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::needless_pass_by_value
)]

use std::{
    num::NonZeroU64,
    str::FromStr,
    sync::atomic::{AtomicU8, Ordering},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use kirje_core::{
    AccountBinding, AccountId, AccountMutationManifest, AccountSnapshot, ActionManifest,
    AuthoritySessionId, AuthorizationGrantId, AuthorizationProof, BindingState, ConfigCas,
    CredentialId, CredentialKind, Endpoint, EndpointSnapshot, HostKind, MailAccountConfig,
    MailErrorCode, ManifestAddress, ManifestContext, ManifestPayload, ManifestTarget,
    MimeBuilderVersion, ObservationCertainty, ObservationSource, OperationId, OwnerPublicKey,
    PlatformLocationMaterial, Protocol, RemoteEffectId, SendSubmitManifest, SensitiveAction,
    Sha256Digest, StoreEnrollManifest, StoreEnrollmentState, StoreId, StoredCredentialState,
    TargetKind, TransitionId, TransportSecurity,
};
use kirje_store::{
    AccountTransitionKind, AccountTransitionObservationRequest, AccountTransitionState,
    AnchorPresence, AuthorityOpenContext, AuthorityOpenState, AuthorityStore,
    AuthorizationChallengeExport, BeginInvocationRequest, BootstrapInput, BootstrapSnapshot,
    CreateChallengeRequest, DeterministicEntropy, EffectClaimRequest, EnrollStoreRequest,
    GrantUseRequest, IsolatedAuthorityHome, JournalLocationDigest, PrepareAccountTransitionRequest,
    RecordObservationRequest, VerifyProofRequest,
};
use rusqlite::Connection;
use tempfile::TempDir;
use uuid::Uuid;

fn hex<const N: usize>(value: &str) -> [u8; N] {
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

fn location() -> JournalLocationDigest {
    JournalLocationDigest::from_bytes([0x91; 32])
}

fn synthetic_uuid_v4(byte: u8) -> Uuid {
    let mut b = [byte; 16];
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Uuid::from_bytes(b)
}

fn context(anchor: AnchorPresence) -> AuthorityOpenContext {
    AuthorityOpenContext {
        anchor,
        journal_location_sha256: location(),
    }
}

static ENTROPY_COUNTER: AtomicU8 = AtomicU8::new(1);

fn deterministic(mut bytes: Vec<u8>) -> DeterministicEntropy {
    let seed = ENTROPY_COUNTER.fetch_add(1, Ordering::Relaxed);
    while bytes.len() < 8192 {
        bytes.push(seed.wrapping_add(bytes.len() as u8));
    }
    DeterministicEntropy::new(bytes).unwrap()
}

fn sign_challenge(
    signing_key: &SigningKey,
    challenge: &AuthorizationChallengeExport,
) -> AuthorizationProof {
    let payload = URL_SAFE_NO_PAD
        .decode(&challenge.signing_payload_base64url)
        .unwrap();
    let signature = signing_key.sign(&payload).to_bytes();
    AuthorizationProof::new(
        challenge.challenge_id,
        challenge.key_id,
        challenge.signing_payload_sha256,
        signature,
    )
}

fn display_id_sha256(display_id: &str) -> Sha256Digest {
    let mut out = Vec::new();
    out.extend_from_slice(b"KIRJE-ACCOUNT-DISPLAY-ID-V1\0");
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&(display_id.len() as u32).to_be_bytes());
    out.extend_from_slice(display_id.as_bytes());
    Sha256Digest::digest(&out)
}

struct TestHarness {
    _temp: TempDir,
    home: IsolatedAuthorityHome,
    snapshot: BootstrapSnapshot,
    signing_key: SigningKey,
    store_id: StoreId,
    location_sha256: Sha256Digest,
    account_id: AccountId,
    credential_id: CredentialId,
    binding_sha256: Sha256Digest,
    account_after_config_sha256: Sha256Digest,
}

fn setup_test_harness() -> TestHarness {
    let signing_key = SigningKey::from_bytes(&hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let owner_public_key =
        OwnerPublicKey::try_from(signing_key.verifying_key().to_bytes()).unwrap();
    let recovery_public_key = OwnerPublicKey::try_from(hex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    ))
    .unwrap();

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
        owner_public_key,
        recovery_public_key,
        observed_at_unix_ms: 500_000,
    })
    .unwrap();

    let store = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(pending.anchor.clone())),
        home.clone(),
        deterministic(Vec::new()),
    )
    .unwrap();
    store.confirm_anchor(&pending.anchor, 500_000).unwrap();
    let store = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(pending.anchor.clone())),
        home.clone(),
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(matches!(store.state(), AuthorityOpenState::Ready(_)));

    // 1. Enroll store
    let store_id = StoreId::from_str("50000000-0000-4000-8000-000000000001").unwrap();
    let loc_mat = PlatformLocationMaterial::Unix {
        parent_device: 0x1001,
        parent_inode: 0x2001,
        final_component: b"test-store-1".to_vec(),
    };
    let location_sha256 = Sha256Digest::digest(&loc_mat.canonical_bytes().unwrap());
    let store_config_sha256 = Sha256Digest::digest(b"test-config-1");
    let enroll_trans_id = TransitionId::from_str("52000000-0000-4000-8000-000000000001").unwrap();

    let enroll_manifest = ActionManifest::new(
        ManifestContext {
            target: ManifestTarget::Store(store_id),
            store_id: Some(store_id),
            account_id: None,
            account_binding_sha256: None,
            policy_sha256: None,
            effect_id: None,
        },
        ManifestPayload::StoreEnroll(StoreEnrollManifest {
            transition_id: enroll_trans_id,
            config_cas: ConfigCas {
                store_id,
                generation: NonZeroU64::new(1).unwrap(),
                exact_content_sha256: store_config_sha256,
                location_sha256,
            },
            expected_store_state: StoreEnrollmentState::Unregistered,
        }),
    )
    .unwrap();

    let enroll_challenge = store
        .create_challenge(CreateChallengeRequest {
            manifest: enroll_manifest.clone(),
            observed_at_unix_ms: 500_100,
            expires_at_unix_ms: 500_900,
        })
        .unwrap();
    let enroll_proof = sign_challenge(&signing_key, &enroll_challenge);
    let enroll_receipt = store
        .verify_proof(VerifyProofRequest {
            proof: enroll_proof,
            observed_at_unix_ms: 500_200,
        })
        .unwrap();

    let conn = Connection::open(home.database_path()).unwrap();
    let grant_blob: Vec<u8> = conn
        .query_row(
            "SELECT grant_id FROM authorization_challenges WHERE challenge_id=?1",
            [enroll_challenge.challenge_id.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    let enroll_grant_id =
        AuthorizationGrantId::try_from(Uuid::from_slice(&grant_blob).unwrap()).unwrap();

    store
        .enroll_store(
            EnrollStoreRequest::new(
                GrantUseRequest::new(
                    enroll_grant_id,
                    enroll_receipt.receipt_id,
                    SensitiveAction::StoreEnroll,
                    TargetKind::Store,
                    store_id.as_bytes().to_vec(),
                    enroll_manifest.sha256(),
                )
                .unwrap(),
                store_id,
                loc_mat,
                location_sha256,
                NonZeroU64::new(1).unwrap(),
                store_config_sha256,
                500_300,
            )
            .unwrap(),
        )
        .unwrap();

    // 2. Create account
    let account_id = AccountId::from_str("51000000-0000-4000-8000-000000000001").unwrap();
    let credential_id = CredentialId::from_str("53000000-0000-4000-8000-000000000001").unwrap();
    let acct_trans_id = TransitionId::from_str("54000000-0000-4000-8000-000000000001").unwrap();
    let account_after_config_sha256 = Sha256Digest::digest(b"test-acct-after-cfg");

    let account_config = MailAccountConfig {
        id: "test-account-1".to_owned(),
        email: "test@example.invalid".to_owned(),
        username: "test-account-1".to_owned(),
        incoming: Endpoint {
            protocol: Protocol::Imap,
            host: "imap.example.invalid".to_owned(),
            port: 993,
            security: TransportSecurity::ImplicitTls,
        },
        outgoing: Some(Endpoint {
            protocol: Protocol::Smtp,
            host: "smtp.example.invalid".to_owned(),
            port: 465,
            security: TransportSecurity::ImplicitTls,
        }),
        credential_kind: CredentialKind::AppPassword,
    };
    let binding = AccountBinding::from_config(&account_config).unwrap();
    let binding_sha256 = binding.sha256();

    let after_snapshot = AccountSnapshot {
        display_id: "test-account-1".to_owned(),
        account_id,
        generation: NonZeroU64::new(1).unwrap(),
        email: "test@example.invalid".to_owned(),
        username: "test-account-1".to_owned(),
        credential_kind: CredentialKind::AppPassword,
        credential_id,
        binding_version: 1,
        binding_sha256,
        binding_state: BindingState::Proposed,
        credential_state: StoredCredentialState::ReentryRequired,
        state_reason: Some(kirje_core::AccountStateReason::CredentialReentryRequired),
        incoming: EndpointSnapshot {
            protocol: Protocol::Imap,
            exact_host: "imap.example.invalid".to_owned(),
            host_kind: HostKind::Dns,
            canonical_host: "imap.example.invalid".to_owned(),
            port: 993,
            security: TransportSecurity::ImplicitTls,
        },
        outgoing: Some(EndpointSnapshot {
            protocol: Protocol::Smtp,
            exact_host: "smtp.example.invalid".to_owned(),
            host_kind: HostKind::Dns,
            canonical_host: "smtp.example.invalid".to_owned(),
            port: 465,
            security: TransportSecurity::ImplicitTls,
        }),
        cleanup_ids: Vec::new(),
    };

    let create_manifest = ActionManifest::new(
        ManifestContext {
            target: ManifestTarget::Account(account_id),
            store_id: Some(store_id),
            account_id: Some(account_id),
            account_binding_sha256: Some(binding_sha256),
            policy_sha256: None,
            effect_id: None,
        },
        ManifestPayload::AccountCreate(AccountMutationManifest {
            transition_id: acct_trans_id,
            config_cas: ConfigCas {
                store_id,
                generation: NonZeroU64::new(1).unwrap(),
                exact_content_sha256: store_config_sha256,
                location_sha256,
            },
            before: None,
            after: Some(after_snapshot),
            next_config_generation: NonZeroU64::new(2).unwrap(),
            after_config_sha256: account_after_config_sha256,
            cleanup: Vec::new(),
        }),
    )
    .unwrap();

    let acct_challenge = store
        .create_challenge(CreateChallengeRequest {
            manifest: create_manifest.clone(),
            observed_at_unix_ms: 501_000,
            expires_at_unix_ms: 501_900,
        })
        .unwrap();
    let acct_proof = sign_challenge(&signing_key, &acct_challenge);
    let acct_receipt = store
        .verify_proof(VerifyProofRequest {
            proof: acct_proof,
            observed_at_unix_ms: 501_100,
        })
        .unwrap();

    let grant_blob: Vec<u8> = conn
        .query_row(
            "SELECT grant_id FROM authorization_challenges WHERE challenge_id=?1",
            [acct_challenge.challenge_id.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    let acct_grant_id =
        AuthorizationGrantId::try_from(Uuid::from_slice(&grant_blob).unwrap()).unwrap();

    store
        .prepare_account_transition(
            PrepareAccountTransitionRequest::new(
                GrantUseRequest::new(
                    acct_grant_id,
                    acct_receipt.receipt_id,
                    SensitiveAction::AccountCreate,
                    TargetKind::Account,
                    account_id.as_bytes().to_vec(),
                    create_manifest.sha256(),
                )
                .unwrap(),
                acct_trans_id,
                store_id,
                account_id,
                AccountTransitionKind::AccountCreate,
                store_config_sha256,
                account_after_config_sha256,
                NonZeroU64::new(1).unwrap(),
                NonZeroU64::new(2).unwrap(),
                display_id_sha256("test-account-1"),
                NonZeroU64::new(1).unwrap(),
                credential_id,
                binding_sha256,
                501_200,
            )
            .unwrap(),
        )
        .unwrap();

    store
        .mark_config_committed(
            AccountTransitionObservationRequest::new(
                acct_trans_id,
                AccountTransitionState::Prepared,
                NonZeroU64::new(2).unwrap(),
                account_after_config_sha256,
                501_300,
            )
            .unwrap(),
        )
        .unwrap();

    store
        .finalize_account_transition(
            AccountTransitionObservationRequest::new(
                acct_trans_id,
                AccountTransitionState::ConfigCommitted,
                NonZeroU64::new(2).unwrap(),
                account_after_config_sha256,
                501_400,
            )
            .unwrap(),
        )
        .unwrap();

    TestHarness {
        _temp: temp,
        home,
        snapshot: pending,
        signing_key,
        store_id,
        location_sha256,
        account_id,
        credential_id,
        binding_sha256,
        account_after_config_sha256,
    }
}

fn open_store(harness: &TestHarness) -> AuthorityStore {
    let store = AuthorityStore::open_isolated(
        context(AnchorPresence::Present(harness.snapshot.anchor.clone())),
        harness.home.clone(),
        deterministic(Vec::new()),
    )
    .unwrap();
    assert!(matches!(store.state(), AuthorityOpenState::Ready(_)));
    store
}

fn synthetic_remote_send_manifest(
    index: u32,
    store_id: StoreId,
    account_id: AccountId,
    binding_sha256: Sha256Digest,
    policy_sha256: Sha256Digest,
) -> (ActionManifest, RemoteEffectId, OperationId) {
    let mut op_bytes = [0_u8; 16];
    op_bytes[0..4].copy_from_slice(&0x5600_0000_u32.to_be_bytes());
    op_bytes[12..16].copy_from_slice(&index.to_be_bytes());
    op_bytes[6] = (op_bytes[6] & 0x0f) | 0x40;
    op_bytes[8] = (op_bytes[8] & 0x3f) | 0x80;
    let operation_id = OperationId::try_from(Uuid::from_bytes(op_bytes)).unwrap();

    let mut eff_bytes = [0_u8; 16];
    eff_bytes[0..4].copy_from_slice(&0x5700_0000_u32.to_be_bytes());
    eff_bytes[12..16].copy_from_slice(&index.to_be_bytes());
    eff_bytes[6] = (eff_bytes[6] & 0x0f) | 0x40;
    eff_bytes[8] = (eff_bytes[8] & 0x3f) | 0x80;
    let effect_id = RemoteEffectId::try_from(Uuid::from_bytes(eff_bytes)).unwrap();

    let context = ManifestContext {
        target: ManifestTarget::Operation(operation_id),
        store_id: Some(store_id),
        account_id: Some(account_id),
        account_binding_sha256: Some(binding_sha256),
        policy_sha256: Some(policy_sha256),
        effect_id: Some(effect_id),
    };
    let payload = ManifestPayload::SendSubmit(SendSubmitManifest {
        account_generation: NonZeroU64::new(1).unwrap(),
        from: ManifestAddress::new(
            Some("Sender".to_owned()),
            "sender@example.invalid".to_owned(),
        )
        .unwrap(),
        to: vec![ManifestAddress::new(None, "dest@example.invalid".to_owned()).unwrap()],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: "Subject".to_owned(),
        text: Some("Body".to_owned()),
        html: None,
        attachments: Vec::new(),
        message_id: "<msg@example.invalid>".to_owned(),
        date_unix_ms: 1_700_000_000_000,
        mime_builder_version: MimeBuilderVersion::KirjeMimeV1,
        mime_boundary: "boundary".to_owned(),
        in_reply_to: None,
        references: Vec::new(),
        canonical_rfc822_sha256: None,
    });
    (
        ActionManifest::new(context, payload).unwrap(),
        effect_id,
        operation_id,
    )
}

#[test]
fn t202d_complete_effect_claim_invocation_and_observation_lifecycle() {
    let harness = setup_test_harness();
    let store = open_store(&harness);
    let policy_digest = Sha256Digest::digest(b"test-remote-policy-1");

    let (manifest, effect_id, operation_id) = synthetic_remote_send_manifest(
        1,
        harness.store_id,
        harness.account_id,
        harness.binding_sha256,
        policy_digest,
    );

    let challenge = store
        .create_challenge(CreateChallengeRequest {
            manifest: manifest.clone(),
            observed_at_unix_ms: 502_000,
            expires_at_unix_ms: 502_900,
        })
        .unwrap();

    let proof = sign_challenge(&harness.signing_key, &challenge);
    let receipt = store
        .verify_proof(VerifyProofRequest {
            proof,
            observed_at_unix_ms: 502_100,
        })
        .unwrap();

    let conn = Connection::open(harness.home.database_path()).unwrap();
    let grant_blob: Vec<u8> = conn
        .query_row(
            "SELECT grant_id FROM authorization_challenges WHERE challenge_id=?1",
            [challenge.challenge_id.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    let grant_id = AuthorizationGrantId::try_from(Uuid::from_slice(&grant_blob).unwrap()).unwrap();

    let grant_use = GrantUseRequest::new(
        grant_id,
        receipt.receipt_id,
        challenge.action,
        challenge.target_kind,
        operation_id.as_bytes().to_vec(),
        manifest.sha256(),
    )
    .unwrap();

    let claim_request = EffectClaimRequest::new(
        grant_use,
        effect_id,
        operation_id,
        harness.store_id,
        harness.location_sha256,
        harness.account_id,
        NonZeroU64::new(2).unwrap(), // config generation is now 2 after account create
        harness.account_after_config_sha256,
        NonZeroU64::new(1).unwrap(),
        harness.credential_id,
        manifest.sha256(),
        harness.binding_sha256,
        policy_digest,
        NonZeroU64::new(1).unwrap(),
        harness.snapshot.trust_bundle_sha256,
        harness.snapshot.owner_key_id,
        502_200,
    )
    .unwrap();

    // 1. First claim
    let claim_projection = store.claim_effect(claim_request.clone()).unwrap();
    assert_eq!(claim_projection.effect_id, effect_id);
    assert_eq!(claim_projection.operation_id, operation_id);
    assert_eq!(claim_projection.grant_id, grant_id);
    assert_eq!(claim_projection.store_id, harness.store_id);
    assert_eq!(claim_projection.account_id, harness.account_id);

    // 2. Exact replay returns identical projection
    let replay_claim = store.claim_effect(claim_request.clone()).unwrap();
    assert_eq!(replay_claim, claim_projection);

    // 3. Invocation start
    let session_id = AuthoritySessionId::try_from(synthetic_uuid_v4(0x77)).unwrap();
    let invocation_request =
        BeginInvocationRequest::new(effect_id, claim_projection.claim_id, session_id, 502_300)
            .unwrap();

    let begin_result = store.start_invocation(invocation_request.clone()).unwrap();
    assert_eq!(begin_result.projection.effect_id, effect_id);
    assert_eq!(begin_result.projection.claim_id, claim_projection.claim_id);
    assert_eq!(begin_result.projection.session_id, session_id);
    assert!(begin_result.permit.is_some());
    let permit = begin_result.permit.unwrap();
    assert_eq!(permit.effect_id(), effect_id);
    assert_eq!(permit.claim_id(), claim_projection.claim_id);
    assert_eq!(permit.session_id(), session_id);

    // 4. Exact replay start_invocation returns projection but permit: None
    let replay_inv = store.start_invocation(invocation_request).unwrap();
    assert_eq!(replay_inv.projection, begin_result.projection);
    assert!(replay_inv.permit.is_none());

    // 5. Attempting to record observation without permit fails
    let result_data = b"smtp 250 ok message queued".to_vec();
    let obs_request = RecordObservationRequest::new(
        effect_id,
        claim_projection.claim_id,
        begin_result.projection.invocation_id,
        ObservationCertainty::Succeeded,
        result_data.clone(),
        ObservationSource::AdapterResult,
        502_400,
    )
    .unwrap();

    let missing_permit_err = store
        .record_observation(obs_request.clone(), None)
        .unwrap_err();
    assert_eq!(
        missing_permit_err.code,
        MailErrorCode::AuthorizationRequired
    );

    // 6. Record observation with permit succeeds
    let obs_projection = store
        .record_observation(obs_request.clone(), Some(permit))
        .unwrap();
    assert_eq!(obs_projection.effect_id, effect_id);
    assert_eq!(obs_projection.claim_id, claim_projection.claim_id);
    assert_eq!(
        obs_projection.invocation_id,
        begin_result.projection.invocation_id
    );
    assert_eq!(obs_projection.certainty, ObservationCertainty::Succeeded);
    assert_eq!(obs_projection.source, ObservationSource::AdapterResult);

    // 7. Exact replay observation returns identical projection (permit not required for replay)
    let replay_obs = store.record_observation(obs_request, None).unwrap();
    assert_eq!(replay_obs, obs_projection);
}

#[test]
fn t202d_crashed_invocation_recovery() {
    let harness = setup_test_harness();
    let store = open_store(&harness);
    let policy_digest = Sha256Digest::digest(b"test-remote-policy-crash");

    let (manifest, effect_id, operation_id) = synthetic_remote_send_manifest(
        2,
        harness.store_id,
        harness.account_id,
        harness.binding_sha256,
        policy_digest,
    );

    let challenge = store
        .create_challenge(CreateChallengeRequest {
            manifest: manifest.clone(),
            observed_at_unix_ms: 503_000,
            expires_at_unix_ms: 503_900,
        })
        .unwrap();

    let proof = sign_challenge(&harness.signing_key, &challenge);
    let receipt = store
        .verify_proof(VerifyProofRequest {
            proof,
            observed_at_unix_ms: 503_100,
        })
        .unwrap();

    let conn = Connection::open(harness.home.database_path()).unwrap();
    let grant_blob: Vec<u8> = conn
        .query_row(
            "SELECT grant_id FROM authorization_challenges WHERE challenge_id=?1",
            [challenge.challenge_id.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    let grant_id = AuthorizationGrantId::try_from(Uuid::from_slice(&grant_blob).unwrap()).unwrap();

    let grant_use = GrantUseRequest::new(
        grant_id,
        receipt.receipt_id,
        challenge.action,
        challenge.target_kind,
        operation_id.as_bytes().to_vec(),
        manifest.sha256(),
    )
    .unwrap();

    let claim_request = EffectClaimRequest::new(
        grant_use,
        effect_id,
        operation_id,
        harness.store_id,
        harness.location_sha256,
        harness.account_id,
        NonZeroU64::new(2).unwrap(),
        harness.account_after_config_sha256,
        NonZeroU64::new(1).unwrap(),
        harness.credential_id,
        manifest.sha256(),
        harness.binding_sha256,
        policy_digest,
        NonZeroU64::new(1).unwrap(),
        harness.snapshot.trust_bundle_sha256,
        harness.snapshot.owner_key_id,
        503_200,
    )
    .unwrap();

    let claim_proj = store.claim_effect(claim_request).unwrap();

    let session_id = AuthoritySessionId::try_from(synthetic_uuid_v4(0x88)).unwrap();
    let invocation_request =
        BeginInvocationRequest::new(effect_id, claim_proj.claim_id, session_id, 503_300).unwrap();

    let begin_result = store.start_invocation(invocation_request).unwrap();
    let permit = begin_result.permit.unwrap();

    // Now simulate process crash: invocation started, but observation never recorded.
    // Call recover_crashed_invocations
    let recovered = store.recover_crashed_invocations(503_500).unwrap();
    assert_eq!(recovered.len(), 1);
    let rec = &recovered[0];
    assert_eq!(rec.effect_id, effect_id);
    assert_eq!(rec.claim_id, claim_proj.claim_id);
    assert_eq!(rec.invocation_id, begin_result.projection.invocation_id);
    assert_eq!(rec.certainty, ObservationCertainty::Ambiguous);
    assert_eq!(rec.source, ObservationSource::InvocationRecovery);

    // Calling recover again returns empty because all are observed
    let second_recovery = store.recover_crashed_invocations(503_600).unwrap();
    assert!(second_recovery.is_empty());

    // Attempting to record observation using the old permit fails due to projection conflict (already observed as Ambiguous)
    let obs_request = RecordObservationRequest::new(
        effect_id,
        claim_proj.claim_id,
        begin_result.projection.invocation_id,
        ObservationCertainty::Succeeded,
        b"delayed success".to_vec(),
        ObservationSource::AdapterResult,
        503_700,
    )
    .unwrap();

    let err = store
        .record_observation(obs_request, Some(permit))
        .unwrap_err();
    assert_eq!(err.code, MailErrorCode::AuthorityProjectionConflict);
}
