use chrono::{TimeZone as _, Utc};
use kirje_core::{
    AccountId, GovernedOperationAuthorization, GovernedOperationStatus, MailError, MailErrorCode,
    OperationAuthorizationState, OperationId, SensitiveAction, Sha256Digest,
};
use uuid::Uuid;

const SECURITY_ERROR_NAMES: &[&str] = &[
    "account_already_exists",
    "account_identity_conflict",
    "account_update_conflict",
    "config_store_identity_conflict",
    "config_migration_failed",
    "config_version_unsupported",
    "config_concurrent_update",
    "credential_legacy_quarantined",
    "credential_reentry_required",
    "credential_binding_invalid",
    "credential_cleanup_invalid",
    "secure_file_semantics_unsupported",
    "owner_authorization_required",
    "owner_trust_not_configured",
    "owner_recovery_required",
    "owner_key_inactive",
    "trust_epoch_stale",
    "trust_bundle_mismatch",
    "clock_rollback_detected",
    "authorization_required",
    "authorization_expired",
    "authorization_invalidated",
    "authorization_malformed",
    "authorization_signature_invalid",
    "authorization_replayed",
    "authorization_context_stale",
    "grant_already_used",
    "effect_already_claimed",
    "effect_already_invoked",
    "authority_projection_conflict",
    "unsupported_capability",
    "input_not_regular_file",
    "input_link_rejected",
    "input_document_incomplete",
    "input_nesting_limit",
    "mcp_frame_too_large",
    "mcp_request_id_invalid",
    "mcp_duplicate_request_id",
    "mcp_session_busy",
    "mcp_output_too_large",
    "remote_response_too_large",
    "remote_capability_incomplete",
];

#[test]
fn security_error_catalog_and_retryability_are_stable() {
    let codes = MailErrorCode::SECURITY_CONTRACT_CODES;
    assert_eq!(codes.len(), SECURITY_ERROR_NAMES.len());

    for (code, expected) in codes.iter().copied().zip(SECURITY_ERROR_NAMES) {
        assert_eq!(code.to_string(), *expected);
        assert_eq!(
            serde_json::to_string(&code).unwrap(),
            format!("\"{expected}\"")
        );
        assert!(!code.retryable_by_default());
        assert!(!MailError::stable(code, "bounded diagnostic").retryable);
        assert!(!MailError::new(code, "bounded diagnostic", true).retryable);
    }
}

#[test]
fn operation_authorization_projection_uses_governed_states_without_private_material() {
    let projection = GovernedOperationAuthorization {
        contract_version: "kirje.operation-authorization.v1".to_owned(),
        operation_id: OperationId::try_from(
            Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
        )
        .unwrap(),
        account_id: AccountId::try_from(
            Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
        )
        .unwrap(),
        action: SensitiveAction::SendSubmit,
        status: GovernedOperationStatus::AuthorizationRequired,
        authorization_state: OperationAuthorizationState::Pending,
        manifest_sha256: Sha256Digest::from_bytes([0x20; 32]),
        challenge_id: Some(Sha256Digest::from_bytes([0x10; 32])),
        receipt_id: None,
        expires_at: Some(Utc.with_ymd_and_hms(2027, 1, 15, 8, 15, 0).unwrap()),
    };

    let value = serde_json::to_value(&projection).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(object.get("status").unwrap(), "authorization_required");
    assert_eq!(object.get("authorization_state").unwrap(), "pending");
    let mut invalid_operation = value.clone();
    invalid_operation["operation_id"] = serde_json::json!("op-0001");
    assert!(
        serde_json::from_value::<GovernedOperationAuthorization>(invalid_operation).is_err(),
        "arbitrary operation identifiers must not deserialize"
    );
    let schema =
        serde_json::to_value(schemars::schema_for!(GovernedOperationAuthorization)).unwrap();
    let operation_schema = &schema["properties"]["operation_id"];
    let operation_format = operation_schema["format"].as_str().or_else(|| {
        operation_schema["$ref"]
            .as_str()
            .and_then(|reference| reference.rsplit('/').next())
            .and_then(|name| schema["$defs"][name]["format"].as_str())
    });
    assert_eq!(operation_format, Some("uuid"));
    for forbidden in [
        "signature",
        "proof",
        "nonce",
        "public_key",
        "private_key",
        "credential",
        "locator",
        "manifest_base64url",
        "signing_payload",
    ] {
        assert!(!object.keys().any(|key| key.contains(forbidden)));
    }
}
