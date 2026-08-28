use std::{
    num::{NonZeroU32, NonZeroU64},
    str::FromStr,
};

use chrono::{TimeZone as _, Utc};
use kirje_core::{
    AccountBinding, AccountId, AccountMutationManifest, AccountSnapshot, AccountStateReason,
    ActionManifest, AmbiguousAssertion, AmbiguousCloseManifest, AmbiguousTerminal,
    AuthorizationContext, AuthorizationGrantId, AuthorizationPayload, AuthorizationProof,
    AuthorizationReceiptId, AuthorizationReceiptProjection, AuthorizationReceiptState,
    BindingState, CleanupDescriptor, CleanupId, CleanupState, ConfigCas, CredentialCleanupManifest,
    CredentialId, CredentialKind, CredentialMutationManifest, EffectKind, Endpoint,
    EndpointSnapshot, HostKind, InvalidationScope, InvocationId, JournalId, LocatorKind,
    MailAccountConfig, MailboxManifest, MailboxSpecialUseInput, MailboxStrategy, ManifestAddress,
    ManifestContext, ManifestPayload, ManifestSupport, ManifestTarget, McpMutationPolicy,
    MimeBuilderVersion, OperationId, OwnerKeyRole, OwnerRealmId, OwnerRecoverManifest, Protocol,
    RemoteEffectId, SendSubmitManifest, SensitiveAction, Sha256Digest, StoreEnrollManifest,
    StoreEnrollmentState, StoreId, StoredCredentialState, TargetKind, TransitionId,
    TransportSecurity, TrustPermissionMask, TrustRotationManifest, owner_key_id,
    verify_authorization_signature,
};

const GOLDEN_MANIFEST_HEX: &str = "4b49524a452d4d414e49464553542d5631000019000100000002000100020000000200010003000000103333333333334333833333333333333300040000001011111111111141118111111111111111000500000010222222222222422282222222222222220006000000203333333333333333333333333333333333333333333333333333333333333333000700000020444444444444444444444444444444444444444444444444444444444444444400080000000200010009000000104444444444444444844444444444444401000000000800000000000000070101000000354b49524a452d414444524553532d5631000002000100000002014600020000001466726f6d406578616d706c652e696e76616c696401020000003a00010000000000324b49524a452d414444524553532d563100000200010000000100000200000012746f406578616d706c652e696e76616c6964010300000002000001040000000200000105000000015301060000000201420107000000010001080000000200000109000000133c6d406578616d706c652e696e76616c69643e010a00000008000001a3185c5000010b000000020001010c0000000162010d0000000100010e000000020000010f00000000";
const GOLDEN_MANIFEST_SHA256: &str =
    "9ee6725292cf57770f72d576ca34cecbd0c6775792de23a3a30a3350219d50a4";
const GOLDEN_AUTHORIZATION_HEX: &str = "4b49524a452d415554484f52495a4154494f4e2d56310000110001000000207777777777777777777777777777777777777777777777777777777777777777000200000002000100030000000200010004000000103333333333334333833333333333333300050000001011111111111141118111111111111111000600000010222222222222422282222222222222220007000000209ee6725292cf57770f72d576ca34cecbd0c6775792de23a3a30a3350219d50a400080000002033333333333333333333333333333333333333333333333333333333333333330009000000204444444444444444444444444444444444444444444444444444444444444444000a000000205555555555555555555555555555555555555555555555555555555555555555000b000000206666666666666666666666666666666666666666666666666666666666666666000c000000080000000000000007000d0000001055555555555545558555555555555555000e000000208888888888888888888888888888888888888888888888888888888888888888000f00000008000001a3185c5000001000000008000001a3186a0ba000110000003800010000000000304b49524a452d4546464543542d5631000002000100000010444444444444444484444444444444440002000000020001";
const GOLDEN_CHALLENGE_ID: &str =
    "ec781b17b5220460048f63bac55b8ab0149c5377ba4dc25d28e66f217766941e";

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn synthetic_endpoint() -> EndpointSnapshot {
    EndpointSnapshot {
        protocol: Protocol::Imap,
        exact_host: "IMAP.Example.Invalid".to_owned(),
        host_kind: HostKind::Dns,
        canonical_host: "imap.example.invalid".to_owned(),
        port: 993,
        security: TransportSecurity::ImplicitTls,
    }
}

fn synthetic_snapshot(
    account_id: AccountId,
    credential_id: CredentialId,
    generation: u64,
    username: &str,
    binding_state: BindingState,
    credential_state: StoredCredentialState,
) -> AccountSnapshot {
    let incoming = synthetic_endpoint();
    let config = MailAccountConfig {
        id: "synthetic".to_owned(),
        email: "owner@example.invalid".to_owned(),
        username: username.to_owned(),
        incoming: Endpoint {
            protocol: incoming.protocol,
            host: incoming.exact_host.clone(),
            port: incoming.port,
            security: incoming.security,
        },
        outgoing: None,
        credential_kind: CredentialKind::AppPassword,
    };
    AccountSnapshot {
        display_id: config.id.clone(),
        account_id,
        generation: NonZeroU64::new(generation).unwrap(),
        email: config.email.clone(),
        username: config.username.clone(),
        credential_kind: config.credential_kind,
        credential_id,
        binding_version: 1,
        binding_sha256: AccountBinding::from_config(&config).unwrap().sha256(),
        binding_state,
        credential_state,
        state_reason: None,
        incoming,
        outgoing: None,
        cleanup_ids: Vec::new(),
    }
}

fn recompute_snapshot_binding(snapshot: &mut AccountSnapshot) {
    let config = MailAccountConfig {
        id: snapshot.display_id.clone(),
        email: snapshot.email.clone(),
        username: snapshot.username.clone(),
        incoming: Endpoint {
            protocol: snapshot.incoming.protocol,
            host: snapshot.incoming.exact_host.clone(),
            port: snapshot.incoming.port,
            security: snapshot.incoming.security,
        },
        outgoing: snapshot.outgoing.as_ref().map(|endpoint| Endpoint {
            protocol: endpoint.protocol,
            host: endpoint.exact_host.clone(),
            port: endpoint.port,
            security: endpoint.security,
        }),
        credential_kind: snapshot.credential_kind,
    };
    snapshot.binding_sha256 = AccountBinding::from_config(&config).unwrap().sha256();
}

fn synthetic_config_cas(store_id: StoreId, generation: u64) -> ConfigCas {
    ConfigCas {
        store_id,
        generation: NonZeroU64::new(generation).unwrap(),
        exact_content_sha256: digest(0x71),
        location_sha256: digest(0x72),
    }
}

fn synthetic_account_mutation(
    config_cas: ConfigCas,
    before: Option<AccountSnapshot>,
    after: Option<AccountSnapshot>,
    next_config_generation: u64,
) -> AccountMutationManifest {
    AccountMutationManifest {
        transition_id: id("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        config_cas,
        before,
        after,
        next_config_generation: NonZeroU64::new(next_config_generation).unwrap(),
        after_config_sha256: digest(0x73),
        cleanup: Vec::new(),
    }
}

fn synthetic_control_context(
    target: ManifestTarget,
    store_id: StoreId,
    account_id: AccountId,
    binding: Sha256Digest,
) -> ManifestContext {
    ManifestContext {
        target,
        store_id: Some(store_id),
        account_id: Some(account_id),
        account_binding_sha256: Some(binding),
        policy_sha256: None,
        effect_id: None,
    }
}

fn manifest() -> ActionManifest {
    let context = ManifestContext {
        target: ManifestTarget::Operation(id("33333333-3333-4333-8333-333333333333")),
        store_id: Some(id("11111111-1111-4111-8111-111111111111")),
        account_id: Some(id("22222222-2222-4222-8222-222222222222")),
        account_binding_sha256: Some(digest(0x33)),
        policy_sha256: Some(digest(0x44)),
        effect_id: Some(id("44444444-4444-4444-8444-444444444444")),
    };
    let payload = SendSubmitManifest {
        account_generation: NonZeroU64::new(7).unwrap(),
        from: ManifestAddress::new(Some("F".to_owned()), "from@example.invalid".to_owned())
            .unwrap(),
        to: vec![ManifestAddress::new(None, "to@example.invalid".to_owned()).unwrap()],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: "S".to_owned(),
        text: Some("B".to_owned()),
        html: None,
        attachments: Vec::new(),
        message_id: "<m@example.invalid>".to_owned(),
        date_unix_ms: 1_800_000_000_000,
        mime_builder_version: MimeBuilderVersion::KirjeMimeV1,
        mime_boundary: "b".to_owned(),
        in_reply_to: None,
        references: Vec::new(),
        canonical_rfc822_sha256: None,
    };
    ActionManifest::new(context, ManifestPayload::SendSubmit(payload)).unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn sensitive_action_policy_is_explicit_nonsequential_and_fail_closed() {
    let expected = [
        (
            SensitiveAction::SendSubmit,
            0x0001,
            TargetKind::Operation,
            EffectKind::SmtpSubmit,
            OwnerKeyRole::Owner,
            McpMutationPolicy::ApplyOnly,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::MailSeen,
            0x0010,
            TargetKind::Operation,
            EffectKind::ImapSeen,
            OwnerKeyRole::Owner,
            McpMutationPolicy::ApplyOnly,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::MailStarred,
            0x0011,
            TargetKind::Operation,
            EffectKind::ImapStarred,
            OwnerKeyRole::Owner,
            McpMutationPolicy::ApplyOnly,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::MailMove,
            0x0012,
            TargetKind::Operation,
            EffectKind::ImapMove,
            OwnerKeyRole::Owner,
            McpMutationPolicy::ApplyOnly,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::MailArchive,
            0x0013,
            TargetKind::Operation,
            EffectKind::ImapArchive,
            OwnerKeyRole::Owner,
            McpMutationPolicy::ApplyOnly,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::MailSafeDelete,
            0x0014,
            TargetKind::Operation,
            EffectKind::ImapSafeDelete,
            OwnerKeyRole::Owner,
            McpMutationPolicy::ApplyOnly,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::StoreEnroll,
            0x0100,
            TargetKind::Store,
            EffectKind::None,
            OwnerKeyRole::Owner,
            McpMutationPolicy::Prohibited,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::AccountCreate,
            0x0110,
            TargetKind::Account,
            EffectKind::None,
            OwnerKeyRole::Owner,
            McpMutationPolicy::Prohibited,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::AccountUpdate,
            0x0111,
            TargetKind::Account,
            EffectKind::None,
            OwnerKeyRole::Owner,
            McpMutationPolicy::Prohibited,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::AccountRemove,
            0x0112,
            TargetKind::Account,
            EffectKind::None,
            OwnerKeyRole::Owner,
            McpMutationPolicy::Prohibited,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::CredentialSet,
            0x0120,
            TargetKind::Credential,
            EffectKind::None,
            OwnerKeyRole::Owner,
            McpMutationPolicy::Prohibited,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::CredentialDelete,
            0x0121,
            TargetKind::Credential,
            EffectKind::None,
            OwnerKeyRole::Owner,
            McpMutationPolicy::Prohibited,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::CredentialCleanup,
            0x0122,
            TargetKind::Cleanup,
            EffectKind::None,
            OwnerKeyRole::Owner,
            McpMutationPolicy::Prohibited,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::PolicyUpdate,
            0x0200,
            TargetKind::Policy,
            EffectKind::None,
            OwnerKeyRole::Owner,
            McpMutationPolicy::Prohibited,
            ManifestSupport::UnsupportedCapability,
        ),
        (
            SensitiveAction::AssuranceUpdate,
            0x0201,
            TargetKind::Assurance,
            EffectKind::None,
            OwnerKeyRole::Owner,
            McpMutationPolicy::Prohibited,
            ManifestSupport::UnsupportedCapability,
        ),
        (
            SensitiveAction::OwnerRotate,
            0x0210,
            TargetKind::TrustEpoch,
            EffectKind::None,
            OwnerKeyRole::Owner,
            McpMutationPolicy::Prohibited,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::RecoveryRotate,
            0x0211,
            TargetKind::TrustEpoch,
            EffectKind::None,
            OwnerKeyRole::Owner,
            McpMutationPolicy::Prohibited,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::OwnerRecover,
            0x0212,
            TargetKind::TrustEpoch,
            EffectKind::None,
            OwnerKeyRole::Recovery,
            McpMutationPolicy::Prohibited,
            ManifestSupport::Supported,
        ),
        (
            SensitiveAction::AmbiguousClose,
            0x0220,
            TargetKind::RemoteEffect,
            EffectKind::None,
            OwnerKeyRole::Owner,
            McpMutationPolicy::Prohibited,
            ManifestSupport::Supported,
        ),
    ];
    assert_eq!(SensitiveAction::ALL.len(), expected.len());
    for (action, code, target, effect, role, mcp, support) in expected {
        assert_eq!(action.code(), code);
        assert_eq!(SensitiveAction::from_code(code).unwrap(), action);
        let policy = action.policy();
        assert!(policy.owner_receipt_required);
        assert_eq!(policy.target_kind, target);
        assert_eq!(policy.effect_kind, effect);
        assert_eq!(policy.required_role, role);
        assert_eq!(policy.mcp_mutation, mcp);
        assert_eq!(policy.manifest_support, support);
    }
    assert!(SensitiveAction::from_code(0xffff).is_err());
    assert!(serde_json::from_str::<SensitiveAction>("\"future_action\"").is_err());
}

#[test]
fn send_manifest_has_golden_bytes_and_strict_round_trip() {
    let manifest = manifest();
    assert_eq!(hex(manifest.canonical_bytes()), GOLDEN_MANIFEST_HEX);
    assert_eq!(manifest.sha256().to_string(), GOLDEN_MANIFEST_SHA256);
    assert_eq!(
        ActionManifest::parse(manifest.canonical_bytes()).unwrap(),
        manifest
    );

    let mut trailing = manifest.canonical_bytes().to_vec();
    trailing.push(0);
    assert!(ActionManifest::parse(&trailing).is_err());
    let mut wrong_domain = manifest.canonical_bytes().to_vec();
    wrong_domain[0] ^= 1;
    assert!(ActionManifest::parse(&wrong_domain).is_err());
}

#[test]
fn mailbox_action_shape_is_closed() {
    let context = ManifestContext {
        target: ManifestTarget::Operation(id("33333333-3333-4333-8333-333333333333")),
        store_id: Some(id("11111111-1111-4111-8111-111111111111")),
        account_id: Some(id("22222222-2222-4222-8222-222222222222")),
        account_binding_sha256: Some(digest(0x33)),
        policy_sha256: Some(digest(0x44)),
        effect_id: Some(id("44444444-4444-4444-8444-444444444444")),
    };
    let seen = MailboxManifest {
        account_generation: NonZeroU64::new(7).unwrap(),
        source_mailbox: "INBOX".to_owned(),
        uid_validity: NonZeroU32::new(11).unwrap(),
        uid: NonZeroU32::new(12).unwrap(),
        requested_value: Some(true),
        requested_destination: None,
        special_use: MailboxSpecialUseInput::None,
        resolved_destination: None,
        strategy: MailboxStrategy::Store,
        capability_sha256: digest(0x99),
        capability_complete: true,
    };
    let encoded =
        ActionManifest::new(context.clone(), ManifestPayload::MailSeen(seen.clone())).unwrap();
    assert_eq!(
        ActionManifest::parse(encoded.canonical_bytes()).unwrap(),
        encoded
    );

    let mut invalid = seen;
    invalid.requested_destination = Some("Elsewhere".to_owned());
    assert!(ActionManifest::new(context, ManifestPayload::MailSeen(invalid)).is_err());
}

#[test]
#[allow(clippy::too_many_lines)]
fn every_supported_control_action_has_a_sealed_round_trip() {
    let store_id = id::<StoreId>("11111111-1111-4111-8111-111111111111");
    let account_id = id::<AccountId>("22222222-2222-4222-8222-222222222222");
    let old_credential = id::<CredentialId>("66666666-6666-4666-8666-666666666666");
    let new_credential = id::<CredentialId>("99999999-9999-4999-8999-999999999999");
    let transition_id = id::<TransitionId>("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let config_cas = ConfigCas {
        store_id,
        generation: NonZeroU64::new(7).unwrap(),
        exact_content_sha256: digest(0x71),
        location_sha256: digest(0x72),
    };
    let before = synthetic_snapshot(
        account_id,
        old_credential,
        1,
        "owner",
        BindingState::Authorized,
        StoredCredentialState::Bound,
    );
    let created = synthetic_snapshot(
        account_id,
        new_credential,
        1,
        "owner",
        BindingState::Proposed,
        StoredCredentialState::ReentryRequired,
    );
    let updated = synthetic_snapshot(
        account_id,
        new_credential,
        2,
        "owner.updated",
        BindingState::Authorized,
        StoredCredentialState::ReentryRequired,
    );
    let set_before = synthetic_snapshot(
        account_id,
        new_credential,
        1,
        "owner",
        BindingState::Authorized,
        StoredCredentialState::ReentryRequired,
    );
    let set_after = synthetic_snapshot(
        account_id,
        new_credential,
        2,
        "owner",
        BindingState::Authorized,
        StoredCredentialState::Bound,
    );
    let delete_after = synthetic_snapshot(
        account_id,
        old_credential,
        2,
        "owner",
        BindingState::Authorized,
        StoredCredentialState::Missing,
    );
    let cleanup = CleanupDescriptor {
        cleanup_id: id("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        locator_kind: LocatorKind::ActiveV2,
        locator_sha256: digest(0x81),
        expected_state: CleanupState::Ready,
    };
    let account_mutation =
        |before: Option<AccountSnapshot>, after: Option<AccountSnapshot>| AccountMutationManifest {
            transition_id,
            config_cas: config_cas.clone(),
            before,
            after,
            next_config_generation: NonZeroU64::new(8).unwrap(),
            after_config_sha256: digest(0x73),
            cleanup: vec![cleanup.clone()],
        };
    let control_context = |target, binding| ManifestContext {
        target,
        store_id: Some(store_id),
        account_id: Some(account_id),
        account_binding_sha256: Some(binding),
        policy_sha256: None,
        effect_id: None,
    };
    let cases = vec![
        (
            ManifestContext {
                target: ManifestTarget::Store(store_id),
                store_id: Some(store_id),
                account_id: None,
                account_binding_sha256: None,
                policy_sha256: None,
                effect_id: None,
            },
            ManifestPayload::StoreEnroll(StoreEnrollManifest {
                transition_id,
                config_cas: config_cas.clone(),
                expected_store_state: StoreEnrollmentState::Unregistered,
            }),
        ),
        (
            control_context(ManifestTarget::Account(account_id), created.binding_sha256),
            ManifestPayload::AccountCreate(account_mutation(None, Some(created))),
        ),
        (
            control_context(ManifestTarget::Account(account_id), updated.binding_sha256),
            ManifestPayload::AccountUpdate(account_mutation(Some(before.clone()), Some(updated))),
        ),
        (
            control_context(ManifestTarget::Account(account_id), before.binding_sha256),
            ManifestPayload::AccountRemove(account_mutation(Some(before.clone()), None)),
        ),
        (
            control_context(
                ManifestTarget::Credential(new_credential),
                set_after.binding_sha256,
            ),
            ManifestPayload::CredentialSet(CredentialMutationManifest {
                account: account_mutation(Some(set_before), Some(set_after)),
                active_locator_sha256: digest(0x82),
            }),
        ),
        (
            control_context(
                ManifestTarget::Credential(old_credential),
                before.binding_sha256,
            ),
            ManifestPayload::CredentialDelete(CredentialMutationManifest {
                account: account_mutation(Some(before.clone()), Some(delete_after)),
                active_locator_sha256: digest(0x82),
            }),
        ),
        (
            control_context(ManifestTarget::Cleanup(cleanup.cleanup_id), digest(0x31)),
            ManifestPayload::CredentialCleanup(CredentialCleanupManifest {
                cleanup_id: cleanup.cleanup_id,
                locator_kind: LocatorKind::ActiveV2,
                locator_sha256: digest(0x81),
                tombstone_sha256: digest(0x83),
                transition_id: Some(transition_id),
                expected_state: CleanupState::Ready,
            }),
        ),
        (
            ManifestContext {
                target: ManifestTarget::TrustEpoch(NonZeroU64::new(7).unwrap()),
                store_id: None,
                account_id: None,
                account_binding_sha256: None,
                policy_sha256: None,
                effect_id: None,
            },
            ManifestPayload::OwnerRotate(TrustRotationManifest {
                transition_id,
                role: OwnerKeyRole::Owner,
                old_key_id: owner_key_id(OwnerKeyRole::Owner, &[0x11; 32]),
                old_public_key: [0x11; 32],
                new_key_id: owner_key_id(OwnerKeyRole::Owner, &[0x12; 32]),
                new_public_key: [0x12; 32],
                old_epoch: NonZeroU64::new(7).unwrap(),
                new_epoch: NonZeroU64::new(8).unwrap(),
                old_bundle: digest(0x93),
                new_bundle: digest(0x94),
                permissions: TrustPermissionMask::Owner,
            }),
        ),
        (
            ManifestContext {
                target: ManifestTarget::TrustEpoch(NonZeroU64::new(7).unwrap()),
                store_id: None,
                account_id: None,
                account_binding_sha256: None,
                policy_sha256: None,
                effect_id: None,
            },
            ManifestPayload::RecoveryRotate(TrustRotationManifest {
                transition_id,
                role: OwnerKeyRole::Recovery,
                old_key_id: owner_key_id(OwnerKeyRole::Recovery, &[0x21; 32]),
                old_public_key: [0x21; 32],
                new_key_id: owner_key_id(OwnerKeyRole::Recovery, &[0x22; 32]),
                new_public_key: [0x22; 32],
                old_epoch: NonZeroU64::new(7).unwrap(),
                new_epoch: NonZeroU64::new(8).unwrap(),
                old_bundle: digest(0xa3),
                new_bundle: digest(0xa4),
                permissions: TrustPermissionMask::Recovery,
            }),
        ),
        (
            ManifestContext {
                target: ManifestTarget::TrustEpoch(NonZeroU64::new(7).unwrap()),
                store_id: None,
                account_id: None,
                account_binding_sha256: None,
                policy_sha256: None,
                effect_id: None,
            },
            ManifestPayload::OwnerRecover(OwnerRecoverManifest {
                transition_id,
                journal_id: id::<JournalId>("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
                old_epoch: NonZeroU64::new(7).unwrap(),
                new_epoch: NonZeroU64::new(8).unwrap(),
                old_bundle: digest(0xb1),
                new_owner_id: owner_key_id(OwnerKeyRole::Owner, &[0x31; 32]),
                new_owner_key: [0x31; 32],
                new_recovery_id: owner_key_id(OwnerKeyRole::Recovery, &[0x32; 32]),
                new_recovery_key: [0x32; 32],
                new_bundle: digest(0xb4),
                invalidation_scope: InvalidationScope::All,
            }),
        ),
        (
            ManifestContext {
                target: ManifestTarget::RemoteEffect(id::<RemoteEffectId>(
                    "44444444-4444-4444-8444-444444444444",
                )),
                store_id: Some(store_id),
                account_id: Some(account_id),
                account_binding_sha256: Some(digest(0x31)),
                policy_sha256: Some(digest(0x44)),
                effect_id: None,
            },
            ManifestPayload::AmbiguousClose(AmbiguousCloseManifest {
                operation_id: id::<OperationId>("33333333-3333-4333-8333-333333333333"),
                invocation_id: id::<InvocationId>("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
                original_manifest_sha256: digest(0xc1),
                claim_sha256: digest(0xc2),
                observation_sha256: Some(digest(0xc3)),
                assertion: AmbiguousAssertion::Occurred,
                assertion_text: "synthetic controlled observation".to_owned(),
                terminal: AmbiguousTerminal::Succeeded,
            }),
        ),
    ];

    for (context, payload) in cases {
        let manifest = ActionManifest::new(context, payload).unwrap();
        assert_eq!(
            ActionManifest::parse(manifest.canonical_bytes()).unwrap(),
            manifest
        );
    }
}

#[test]
fn account_snapshots_recompute_binding_and_reject_invalid_endpoint_state_and_cleanup() {
    let store_id = id::<StoreId>("11111111-1111-4111-8111-111111111111");
    let account_id = id::<AccountId>("22222222-2222-4222-8222-222222222222");
    let credential_id = id::<CredentialId>("66666666-6666-4666-8666-666666666666");
    let base = synthetic_snapshot(
        account_id,
        credential_id,
        1,
        "owner",
        BindingState::Proposed,
        StoredCredentialState::ReentryRequired,
    );
    let cleanup_id = id::<CleanupId>("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");

    let mut invalid_binding = base.clone();
    invalid_binding.binding_sha256 = digest(0xee);
    let mut invalid_endpoint = base.clone();
    invalid_endpoint.incoming.protocol = Protocol::Smtp;
    let mut invalid_state = base.clone();
    invalid_state.binding_state = BindingState::Authorized;
    invalid_state.credential_state = StoredCredentialState::LegacyQuarantined;
    let mut duplicate_cleanup = base.clone();
    duplicate_cleanup.cleanup_ids = vec![cleanup_id, cleanup_id];
    let mut future_binding = base;
    future_binding.binding_version = 2;

    for snapshot in [
        invalid_binding,
        invalid_endpoint,
        invalid_state,
        duplicate_cleanup,
        future_binding,
    ] {
        let context = synthetic_control_context(
            ManifestTarget::Account(account_id),
            store_id,
            account_id,
            snapshot.binding_sha256,
        );
        let payload = ManifestPayload::AccountCreate(synthetic_account_mutation(
            synthetic_config_cas(store_id, 7),
            None,
            Some(snapshot),
            8,
        ));
        assert!(
            ActionManifest::new(context, payload).is_err(),
            "invalid account snapshot was accepted"
        );
    }
}

#[test]
fn endpoint_snapshot_host_kind_cannot_disguise_dns_or_ip_literals() {
    let store_id = id::<StoreId>("11111111-1111-4111-8111-111111111111");
    let account_id = id::<AccountId>("22222222-2222-4222-8222-222222222222");
    let credential_id = id::<CredentialId>("66666666-6666-4666-8666-666666666666");
    let base = synthetic_snapshot(
        account_id,
        credential_id,
        1,
        "owner",
        BindingState::Authorized,
        StoredCredentialState::Bound,
    );
    let cases = [
        (HostKind::Dns, "127.0.0.1", "127.0.0.1"),
        (HostKind::Dns, "::1", "::1"),
        (
            HostKind::Ipv4,
            "imap.example.invalid",
            "imap.example.invalid",
        ),
        (
            HostKind::Ipv6,
            "imap.example.invalid",
            "imap.example.invalid",
        ),
        (HostKind::Ipv4, "::1", "::1"),
        (HostKind::Ipv6, "127.0.0.1", "127.0.0.1"),
    ];

    for (host_kind, exact_host, canonical_host) in cases {
        let mut snapshot = base.clone();
        snapshot.incoming.host_kind = host_kind;
        snapshot.incoming.exact_host = exact_host.to_owned();
        snapshot.incoming.canonical_host = canonical_host.to_owned();
        recompute_snapshot_binding(&mut snapshot);
        let context = synthetic_control_context(
            ManifestTarget::Account(account_id),
            store_id,
            account_id,
            snapshot.binding_sha256,
        );
        let payload = ManifestPayload::AccountRemove(synthetic_account_mutation(
            synthetic_config_cas(store_id, 7),
            Some(snapshot),
            None,
            8,
        ));
        assert!(
            ActionManifest::new(context, payload).is_err(),
            "accepted {host_kind:?} host kind for {exact_host}"
        );
    }
}

#[test]
fn mismatch_bound_snapshot_round_trips_but_invalidated_bound_is_rejected() {
    let store_id = id::<StoreId>("11111111-1111-4111-8111-111111111111");
    let account_id = id::<AccountId>("22222222-2222-4222-8222-222222222222");
    let credential_id = id::<CredentialId>("66666666-6666-4666-8666-666666666666");
    let mut mismatch = synthetic_snapshot(
        account_id,
        credential_id,
        1,
        "owner",
        BindingState::Mismatch,
        StoredCredentialState::Bound,
    );
    mismatch.state_reason = Some(AccountStateReason::AuthorityMismatch);
    let mismatch_context = synthetic_control_context(
        ManifestTarget::Account(account_id),
        store_id,
        account_id,
        mismatch.binding_sha256,
    );
    let manifest = ActionManifest::new(
        mismatch_context,
        ManifestPayload::AccountRemove(synthetic_account_mutation(
            synthetic_config_cas(store_id, 7),
            Some(mismatch),
            None,
            8,
        )),
    )
    .expect("mismatch-bound status/recovery snapshot");
    assert_eq!(
        ActionManifest::parse(manifest.canonical_bytes()).unwrap(),
        manifest
    );

    let mut invalidated = synthetic_snapshot(
        account_id,
        credential_id,
        1,
        "owner",
        BindingState::Invalidated,
        StoredCredentialState::Bound,
    );
    invalidated.state_reason = Some(AccountStateReason::OwnerRecovery);
    let invalidated_context = synthetic_control_context(
        ManifestTarget::Account(account_id),
        store_id,
        account_id,
        invalidated.binding_sha256,
    );
    assert!(
        ActionManifest::new(
            invalidated_context,
            ManifestPayload::AccountRemove(synthetic_account_mutation(
                synthetic_config_cas(store_id, 7),
                Some(invalidated),
                None,
                8,
            )),
        )
        .is_err()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn account_and_credential_lifecycle_is_closed() {
    let store_id = id::<StoreId>("11111111-1111-4111-8111-111111111111");
    let account_id = id::<AccountId>("22222222-2222-4222-8222-222222222222");
    let credential_id = id::<CredentialId>("66666666-6666-4666-8666-666666666666");
    let bound = synthetic_snapshot(
        account_id,
        credential_id,
        1,
        "owner",
        BindingState::Authorized,
        StoredCredentialState::Bound,
    );

    let create_context = synthetic_control_context(
        ManifestTarget::Account(account_id),
        store_id,
        account_id,
        bound.binding_sha256,
    );
    assert!(
        ActionManifest::new(
            create_context,
            ManifestPayload::AccountCreate(synthetic_account_mutation(
                synthetic_config_cas(store_id, 7),
                None,
                Some(bound.clone()),
                8,
            )),
        )
        .is_err(),
        "create accepted an active bound account"
    );

    let mut unchanged_update = bound.clone();
    unchanged_update.generation = NonZeroU64::new(2).unwrap();
    let update_context = synthetic_control_context(
        ManifestTarget::Account(account_id),
        store_id,
        account_id,
        unchanged_update.binding_sha256,
    );
    assert!(
        ActionManifest::new(
            update_context,
            ManifestPayload::AccountUpdate(synthetic_account_mutation(
                synthetic_config_cas(store_id, 7),
                Some(bound.clone()),
                Some(unchanged_update),
                8,
            )),
        )
        .is_err(),
        "update accepted no credential transition"
    );

    let mut invalid_set_after = bound.clone();
    invalid_set_after.generation = NonZeroU64::new(2).unwrap();
    invalid_set_after.credential_state = StoredCredentialState::ReentryRequired;
    let set_context = synthetic_control_context(
        ManifestTarget::Credential(credential_id),
        store_id,
        account_id,
        bound.binding_sha256,
    );
    assert!(
        ActionManifest::new(
            set_context,
            ManifestPayload::CredentialSet(CredentialMutationManifest {
                account: synthetic_account_mutation(
                    synthetic_config_cas(store_id, 7),
                    Some(bound.clone()),
                    Some(invalid_set_after),
                    8,
                ),
                active_locator_sha256: digest(0x82),
            }),
        )
        .is_err(),
        "credential set accepted an invalid bound-to-reentry transition"
    );

    let mut invalid_delete_before = bound.clone();
    invalid_delete_before.credential_state = StoredCredentialState::Missing;
    let mut invalid_delete_after = bound;
    invalid_delete_after.generation = NonZeroU64::new(2).unwrap();
    let delete_context = synthetic_control_context(
        ManifestTarget::Credential(credential_id),
        store_id,
        account_id,
        invalid_delete_before.binding_sha256,
    );
    assert!(
        ActionManifest::new(
            delete_context,
            ManifestPayload::CredentialDelete(CredentialMutationManifest {
                account: synthetic_account_mutation(
                    synthetic_config_cas(store_id, 7),
                    Some(invalid_delete_before),
                    Some(invalid_delete_after),
                    8,
                ),
                active_locator_sha256: digest(0x82),
            }),
        )
        .is_err(),
        "credential delete accepted a missing-to-bound transition"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn exact_generation_and_trust_epoch_increments_reject_u64_max() {
    let store_id = id::<StoreId>("11111111-1111-4111-8111-111111111111");
    let account_id = id::<AccountId>("22222222-2222-4222-8222-222222222222");
    let credential_id = id::<CredentialId>("66666666-6666-4666-8666-666666666666");
    let created = synthetic_snapshot(
        account_id,
        credential_id,
        1,
        "owner",
        BindingState::Proposed,
        StoredCredentialState::ReentryRequired,
    );
    let create_context = synthetic_control_context(
        ManifestTarget::Account(account_id),
        store_id,
        account_id,
        created.binding_sha256,
    );
    assert!(
        ActionManifest::new(
            create_context,
            ManifestPayload::AccountCreate(synthetic_account_mutation(
                synthetic_config_cas(store_id, u64::MAX),
                None,
                Some(created),
                u64::MAX,
            )),
        )
        .is_err(),
        "config generation overflow was accepted"
    );

    let transition_id = id::<TransitionId>("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    let trust_context = ManifestContext {
        target: ManifestTarget::TrustEpoch(NonZeroU64::new(u64::MAX).unwrap()),
        store_id: None,
        account_id: None,
        account_binding_sha256: None,
        policy_sha256: None,
        effect_id: None,
    };
    assert!(
        ActionManifest::new(
            trust_context,
            ManifestPayload::OwnerRotate(TrustRotationManifest {
                transition_id,
                role: OwnerKeyRole::Owner,
                old_key_id: owner_key_id(OwnerKeyRole::Owner, &[0x11; 32]),
                old_public_key: [0x11; 32],
                new_key_id: owner_key_id(OwnerKeyRole::Owner, &[0x12; 32]),
                new_public_key: [0x12; 32],
                old_epoch: NonZeroU64::new(u64::MAX).unwrap(),
                new_epoch: NonZeroU64::new(u64::MAX).unwrap(),
                old_bundle: digest(0x93),
                new_bundle: digest(0x94),
                permissions: TrustPermissionMask::Owner,
            }),
        )
        .is_err(),
        "trust epoch overflow was accepted"
    );

    let next_credential = id::<CredentialId>("99999999-9999-4999-8999-999999999999");
    let account_before = synthetic_snapshot(
        account_id,
        credential_id,
        u64::MAX,
        "owner",
        BindingState::Authorized,
        StoredCredentialState::Bound,
    );
    let account_after = synthetic_snapshot(
        account_id,
        next_credential,
        u64::MAX,
        "owner.updated",
        BindingState::Authorized,
        StoredCredentialState::ReentryRequired,
    );
    let update_context = synthetic_control_context(
        ManifestTarget::Account(account_id),
        store_id,
        account_id,
        account_after.binding_sha256,
    );
    assert!(
        ActionManifest::new(
            update_context,
            ManifestPayload::AccountUpdate(synthetic_account_mutation(
                synthetic_config_cas(store_id, 7),
                Some(account_before),
                Some(account_after),
                8,
            )),
        )
        .is_err(),
        "account generation overflow was accepted"
    );

    let set_before = synthetic_snapshot(
        account_id,
        credential_id,
        u64::MAX,
        "owner",
        BindingState::Authorized,
        StoredCredentialState::ReentryRequired,
    );
    let set_after = synthetic_snapshot(
        account_id,
        credential_id,
        u64::MAX,
        "owner",
        BindingState::Authorized,
        StoredCredentialState::Bound,
    );
    let set_context = synthetic_control_context(
        ManifestTarget::Credential(credential_id),
        store_id,
        account_id,
        set_after.binding_sha256,
    );
    assert!(
        ActionManifest::new(
            set_context,
            ManifestPayload::CredentialSet(CredentialMutationManifest {
                account: synthetic_account_mutation(
                    synthetic_config_cas(store_id, 7),
                    Some(set_before),
                    Some(set_after),
                    8,
                ),
                active_locator_sha256: digest(0x82),
            }),
        )
        .is_err(),
        "credential mutation generation overflow was accepted"
    );

    let recover_context = ManifestContext {
        target: ManifestTarget::TrustEpoch(NonZeroU64::new(u64::MAX).unwrap()),
        store_id: None,
        account_id: None,
        account_binding_sha256: None,
        policy_sha256: None,
        effect_id: None,
    };
    assert!(
        ActionManifest::new(
            recover_context,
            ManifestPayload::OwnerRecover(OwnerRecoverManifest {
                transition_id,
                journal_id: id("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
                old_epoch: NonZeroU64::new(u64::MAX).unwrap(),
                new_epoch: NonZeroU64::new(u64::MAX).unwrap(),
                old_bundle: digest(0xb1),
                new_owner_id: owner_key_id(OwnerKeyRole::Owner, &[0x31; 32]),
                new_owner_key: [0x31; 32],
                new_recovery_id: owner_key_id(OwnerKeyRole::Recovery, &[0x32; 32]),
                new_recovery_key: [0x32; 32],
                new_bundle: digest(0xb4),
                invalidation_scope: InvalidationScope::All,
            }),
        )
        .is_err(),
        "owner recovery epoch overflow was accepted"
    );
}

#[test]
fn authorization_transcript_is_derived_from_manifest_and_has_golden_bytes() {
    let payload = AuthorizationPayload::new(
        &manifest(),
        AuthorizationContext {
            owner_realm: OwnerRealmId::from_bytes([0x77; 32]),
            trust_bundle_sha256: digest(0x55),
            owner_key_id: digest(0x66),
            trust_epoch: NonZeroU64::new(7).unwrap(),
            grant_id: id::<AuthorizationGrantId>("55555555-5555-4555-8555-555555555555"),
            nonce: [0x88; 32],
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_000_900_000,
        },
    )
    .unwrap();
    assert_eq!(hex(&payload.canonical_bytes()), GOLDEN_AUTHORIZATION_HEX);
    assert_eq!(payload.challenge_id().to_string(), GOLDEN_CHALLENGE_ID);
    assert_eq!(
        AuthorizationPayload::parse(&payload.canonical_bytes()).unwrap(),
        payload
    );

    let mut trailing = payload.canonical_bytes();
    trailing.push(0);
    assert!(AuthorizationPayload::parse(&trailing).is_err());
}

#[test]
fn strict_ed25519_verification_accepts_rfc8032_and_rejects_tampering() {
    let public_key =
        decode_hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = decode_hex::<64>(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            .replace(char::is_whitespace, "")
            .as_str(),
    );
    verify_authorization_signature(&public_key, b"", &signature).expect("RFC8032 vector");
    let mut tampered = signature;
    tampered[0] ^= 1;
    assert!(verify_authorization_signature(&public_key, b"", &tampered).is_err());
    let mut non_canonical = signature;
    non_canonical[63] |= 0x80;
    assert!(verify_authorization_signature(&public_key, b"", &non_canonical).is_err());
    assert!(verify_authorization_signature(&[0x42; 32], b"", &signature).is_err());
}

#[test]
fn proof_and_receipt_schemas_are_private_material_free() {
    let unknown = r#"{
        "contract_version":"kirje.authorization-proof.v1",
        "challenge_id":"0000000000000000000000000000000000000000000000000000000000000000",
        "key_id":"0000000000000000000000000000000000000000000000000000000000000000",
        "signing_payload_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
        "signature_base64url":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "action":"send_submit"
    }"#;
    assert!(serde_json::from_str::<AuthorizationProof>(unknown).is_err());

    let projection = AuthorizationReceiptProjection {
        contract_version: "kirje.authorization-receipt.v1".to_owned(),
        receipt_id: id::<AuthorizationReceiptId>("55555555-5555-4555-8555-555555555555"),
        challenge_id: digest(0x10),
        action: SensitiveAction::SendSubmit,
        target_kind: TargetKind::Operation,
        target_id: "33333333-3333-4333-8333-333333333333".to_owned(),
        key_fingerprint: owner_key_id(OwnerKeyRole::Owner, &[0x19; 32]).fingerprint(),
        trust_epoch: NonZeroU64::new(7).unwrap(),
        manifest_sha256: digest(0x20),
        receipt_sha256: digest(0x30),
        verified_at: Utc.with_ymd_and_hms(2027, 1, 15, 8, 0, 0).unwrap(),
        expires_at: Utc.with_ymd_and_hms(2027, 1, 15, 8, 15, 0).unwrap(),
        state: AuthorizationReceiptState::Unclaimed,
    };
    let value = serde_json::to_value(&projection).unwrap();
    let object = value.as_object().unwrap();
    for forbidden in [
        "signature",
        "proof",
        "signing_payload",
        "manifest_base64url",
        "public_key",
        "realm",
        "nonce",
        "locator",
        "credential",
    ] {
        assert!(!object.keys().any(|key| key.contains(forbidden)));
    }
}

#[test]
fn owner_key_identity_is_role_separated() {
    let public_key = [0x19; 32];
    assert_ne!(
        owner_key_id(OwnerKeyRole::Owner, &public_key),
        owner_key_id(OwnerKeyRole::Recovery, &public_key)
    );
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        },
    )
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut output = [0; N];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}
