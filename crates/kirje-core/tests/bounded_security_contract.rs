use kirje_core::{
    BoundedUntrustedText, CapabilitySupport, KnownCapability, MAX_ADAPTER_DIAGNOSTIC_BYTES,
    MAX_AUTHORIZATION_MANIFEST_BYTES, MAX_AUTHORIZATION_PROOF_BYTES, MAX_CONFIG_BYTES,
    MAX_IMAP_CAPABILITIES, MAX_IMAP_CAPABILITIES_TOTAL_BYTES, MAX_IMAP_CAPABILITY_BYTES,
    MAX_IMAP_RESPONSE_BYTES, MAX_JSON_NESTING_DEPTH, MAX_JSON_RPC_ID_BYTES,
    MAX_JSON_RPC_METHOD_BYTES, MAX_MACHINE_RESULT_BYTES, MAX_MCP_ACTIVE_IDS,
    MAX_MCP_CONTROL_IN_FLIGHT, MAX_MCP_DELIVERED_TASKS, MAX_MCP_ENVELOPE_OVERHEAD_BYTES,
    MAX_MCP_FRAME_BYTES, MAX_MCP_HANDLER_IN_FLIGHT, MAX_MCP_OUTPUT_FRAME_BYTES,
    MAX_MCP_OUTPUT_WIRE_BYTES, MAX_MCP_QUEUE_ITEMS, MAX_MCP_QUEUED_OUTPUT_BYTES,
    MAX_MCP_RESERVED_OUTPUT_BYTES, MAX_MCP_RESPONSE_HANDOFF_MILLIS, MAX_MCP_SESSION_TASKS,
    MAX_OPERATION_INPUT_BYTES, MAX_READ_SCRATCH_BYTES, MAX_REMOTE_VALUE_BYTES,
    MAX_SEND_OR_DRAFT_INPUT_BYTES, MAX_SMTP_RECEIPT_BYTES, MAX_UNTRUSTED_RESULT_BYTES,
    ProtocolCapabilities, Sha256Digest, ValueDisposition,
};

#[test]
fn boundary_budget_snapshot_is_exact() {
    assert_eq!(MAX_CONFIG_BYTES, 1024 * 1024);
    assert_eq!(MAX_OPERATION_INPUT_BYTES, 1024 * 1024);
    assert_eq!(MAX_SEND_OR_DRAFT_INPUT_BYTES, 24 * 1024 * 1024);
    assert_eq!(MAX_AUTHORIZATION_PROOF_BYTES, 4 * 1024);
    assert_eq!(MAX_AUTHORIZATION_MANIFEST_BYTES, 4 * 1024 * 1024);
    assert_eq!(MAX_READ_SCRATCH_BYTES, 64 * 1024);
    assert_eq!(MAX_JSON_NESTING_DEPTH, 32);
    assert_eq!(MAX_JSON_RPC_ID_BYTES, 128);
    assert_eq!(MAX_JSON_RPC_METHOD_BYTES, 128);
    assert_eq!(MAX_MCP_ENVELOPE_OVERHEAD_BYTES, 4 * 1024);
    assert_eq!(MAX_MCP_FRAME_BYTES, 24 * 1024 * 1024 + 4 * 1024);
    assert_eq!(MAX_MCP_OUTPUT_FRAME_BYTES, 16 * 1024 * 1024 + 4 * 1024);
    assert_eq!(MAX_MCP_OUTPUT_WIRE_BYTES, MAX_MCP_OUTPUT_FRAME_BYTES + 1);
    assert_eq!(MAX_MCP_HANDLER_IN_FLIGHT, 4);
    assert_eq!(MAX_MCP_CONTROL_IN_FLIGHT, 1);
    assert_eq!(MAX_MCP_ACTIVE_IDS, 4);
    assert_eq!(MAX_MCP_DELIVERED_TASKS, 5);
    assert_eq!(MAX_MCP_QUEUE_ITEMS, 5);
    assert_eq!(MAX_MCP_QUEUED_OUTPUT_BYTES, 2 * MAX_MCP_OUTPUT_WIRE_BYTES);
    assert_eq!(
        MAX_MCP_RESERVED_OUTPUT_BYTES,
        4 * MAX_MCP_OUTPUT_FRAME_BYTES
    );
    assert_eq!(MAX_MCP_SESSION_TASKS, 16);
    assert_eq!(MAX_MCP_RESPONSE_HANDOFF_MILLIS, 1000);
    assert_eq!(MAX_IMAP_RESPONSE_BYTES, 12 * 1024 * 1024);
    assert_eq!(MAX_IMAP_CAPABILITIES, 128);
    assert_eq!(MAX_IMAP_CAPABILITY_BYTES, 256);
    assert_eq!(MAX_IMAP_CAPABILITIES_TOTAL_BYTES, 16 * 1024);
    assert_eq!(MAX_REMOTE_VALUE_BYTES, 4 * 1024);
    assert_eq!(MAX_ADAPTER_DIAGNOSTIC_BYTES, 1024);
    assert_eq!(MAX_SMTP_RECEIPT_BYTES, 256);
    assert_eq!(MAX_MACHINE_RESULT_BYTES, 16 * 1024 * 1024);
    assert_eq!(MAX_UNTRUSTED_RESULT_BYTES, 8 * 1024 * 1024);
}

#[test]
fn bounded_untrusted_text_keeps_disposition_separate_from_content() {
    let complete = BoundedUntrustedText::from_utf8_bytes(b"complete", 8);
    assert_eq!(complete.text(), "complete");
    assert_eq!(complete.disposition(), ValueDisposition::Complete);
    assert!(complete.untrusted());
    assert_eq!(complete.original_bytes(), Some(8));

    let truncated = BoundedUntrustedText::from_utf8_bytes("abéz".as_bytes(), 3);
    assert_eq!(truncated.text(), "ab");
    assert_eq!(truncated.disposition(), ValueDisposition::Truncated);
    assert_eq!(truncated.original_bytes(), Some(5));

    let rejected = BoundedUntrustedText::from_utf8_bytes(&[0xff, b'x'], 16);
    assert!(rejected.text().is_empty());
    assert_eq!(rejected.disposition(), ValueDisposition::Rejected);
    assert!(rejected.untrusted());

    let omitted = BoundedUntrustedText::omitted(Some(99));
    assert!(omitted.text().is_empty());
    assert_eq!(omitted.disposition(), ValueDisposition::Omitted);
    assert_eq!(omitted.original_bytes(), Some(99));
}

#[test]
fn capability_completeness_controls_security_decisions() {
    let complete = ProtocolCapabilities::new(
        vec![KnownCapability::Move, KnownCapability::UidPlus],
        Vec::new(),
        true,
        Sha256Digest::from_bytes([0x11; 32]),
    )
    .unwrap();
    assert_eq!(
        complete.support(KnownCapability::Move),
        CapabilitySupport::Supported
    );
    assert_eq!(
        complete.support(KnownCapability::Idle),
        CapabilitySupport::Unsupported
    );

    let incomplete = ProtocolCapabilities::new(
        vec![KnownCapability::UidPlus],
        vec![BoundedUntrustedText::from_utf8_bytes(
            b"X-SYNTHETIC",
            MAX_IMAP_CAPABILITY_BYTES,
        )],
        false,
        Sha256Digest::from_bytes([0x22; 32]),
    )
    .unwrap();
    assert_eq!(
        incomplete.support(KnownCapability::Move),
        CapabilitySupport::Unknown
    );
    assert!(incomplete.unknown_display()[0].untrusted());
}

#[test]
fn capability_projection_rejects_item_count_and_total_overflow() {
    let too_many = vec![BoundedUntrustedText::omitted(None); MAX_IMAP_CAPABILITIES + 1];
    assert!(
        ProtocolCapabilities::new(
            Vec::new(),
            too_many,
            false,
            Sha256Digest::from_bytes([0x33; 32])
        )
        .is_err()
    );

    let overlong = BoundedUntrustedText::from_utf8_bytes(
        &vec![b'x'; MAX_IMAP_CAPABILITY_BYTES + 1],
        MAX_IMAP_CAPABILITY_BYTES + 1,
    );
    assert!(
        ProtocolCapabilities::new(
            Vec::new(),
            vec![overlong],
            false,
            Sha256Digest::from_bytes([0x44; 32])
        )
        .is_err()
    );

    let total = vec![
        BoundedUntrustedText::from_utf8_bytes(
            &vec![b'x'; MAX_IMAP_CAPABILITY_BYTES],
            MAX_IMAP_CAPABILITY_BYTES,
        );
        MAX_IMAP_CAPABILITIES
    ];
    assert!(
        ProtocolCapabilities::new(
            Vec::new(),
            total,
            false,
            Sha256Digest::from_bytes([0x55; 32])
        )
        .is_err()
    );
}

#[test]
fn bounded_projection_construction_and_schema_are_not_bypassable() {
    let source = include_str!("../src/bounded.rs");
    assert!(!source.contains("pub text: String"));
    assert!(!source.contains("pub known: Vec<KnownCapability>"));
    assert!(!source.contains("pub unknown_display: Vec<BoundedUntrustedText>"));
    assert!(!source.contains("pub complete: bool"));
    assert!(!source.contains("pub sha256: Sha256Digest"));
    assert!(source.contains("original_bytes: Option<u64>"));

    let bounded_derive = source
        .split_once("pub struct BoundedUntrustedText")
        .unwrap()
        .0
        .rsplit_once("#[derive(")
        .unwrap()
        .1;
    assert!(!bounded_derive.contains("Deserialize"));
    let capabilities_derive = source
        .split_once("pub struct ProtocolCapabilities")
        .unwrap()
        .0
        .rsplit_once("#[derive(")
        .unwrap()
        .1;
    assert!(!capabilities_derive.contains("Deserialize"));

    let schema = serde_json::to_value(schemars::schema_for!(ProtocolCapabilities)).unwrap();
    let properties = schema["properties"].as_object().unwrap();
    assert!(properties.contains_key("source_sha256"));
    assert!(!properties.contains_key("sha256"));
}

#[test]
fn capability_projection_canonicalizes_known_values_and_rejects_control_display() {
    let projection = ProtocolCapabilities::new(
        vec![
            KnownCapability::Idle,
            KnownCapability::UidPlus,
            KnownCapability::Move,
        ],
        Vec::new(),
        true,
        Sha256Digest::from_bytes([0x66; 32]),
    )
    .unwrap();
    assert_eq!(
        projection.known(),
        &[
            KnownCapability::Move,
            KnownCapability::UidPlus,
            KnownCapability::Idle,
        ]
    );

    let control = BoundedUntrustedText::from_utf8_bytes(
        b"X-SYNTHETIC\nCAPABILITY",
        MAX_IMAP_CAPABILITY_BYTES,
    );
    assert!(
        ProtocolCapabilities::new(
            Vec::new(),
            vec![control],
            true,
            Sha256Digest::from_bytes([0x77; 32]),
        )
        .is_err()
    );
}

#[test]
fn largest_valid_send_model_fits_the_service_and_mcp_contracts() {
    let attachments_base64 = 4 * kirje_core::MAX_TOTAL_ATTACHMENT_BYTES.div_ceil(3);
    let worst_case_bodies = 2 * kirje_core::MAX_SEND_BODY_CHARS * 12;
    let recipient_budget = kirje_core::MAX_SEND_RECIPIENTS * (320 * 6 + 256 * 12 + 64);
    let attachment_metadata = kirje_core::MAX_ATTACHMENTS
        * (kirje_core::MAX_ATTACHMENT_FILENAME_CHARS * 12
            + kirje_core::MAX_ATTACHMENT_MIME_CHARS
            + 256);
    let fixed_service_overhead = 32 * 1024;
    let service_total = attachments_base64
        + worst_case_bodies
        + recipient_budget
        + attachment_metadata
        + fixed_service_overhead;
    assert!(service_total <= MAX_SEND_OR_DRAFT_INPUT_BYTES);
    const {
        assert!(
            MAX_SEND_OR_DRAFT_INPUT_BYTES + MAX_MCP_ENVELOPE_OVERHEAD_BYTES <= MAX_MCP_FRAME_BYTES
        );
        assert!(
            MAX_MACHINE_RESULT_BYTES + MAX_MCP_ENVELOPE_OVERHEAD_BYTES
                <= MAX_MCP_OUTPUT_FRAME_BYTES
        );
    }
}
