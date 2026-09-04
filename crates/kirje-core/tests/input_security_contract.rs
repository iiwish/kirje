use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use kirje_core::{
    AttachmentRead, AuthorizationProof, DraftInput, LocalMessageSearch, MAX_SEND_ATTACHMENT_BYTES,
    MAX_SEND_BODY_CHARS, MAX_SEND_RECIPIENTS, MAX_SEND_SUBJECT_CHARS, MAX_TOTAL_ATTACHMENT_BYTES,
    MailErrorCode, MailboxOperationRequest, MailboxSyncRequest, MessageRead, MessageSearch,
    SendRequest, parse_bounded_json,
};

fn send_json(subject: &str, text: &str, recipient_count: usize, attachments: &[String]) -> Vec<u8> {
    let recipients = (0..recipient_count)
        .map(|index| format!(r#"{{"name":null,"email":"r{index}@example.invalid"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let attachments = attachments.join(",");
    format!(
        r#"{{"account_id":"synthetic","to":[{recipients}],"cc":[],"bcc":[],"subject":"{subject}","text":"{text}","html":null,"attachments":[{attachments}]}}"#
    )
    .into_bytes()
}

fn attachment_json(content: &[u8], index: usize) -> String {
    format!(
        r#"{{"filename":"a{index}.bin","mime_type":"application/octet-stream","content_base64":"{}"}}"#,
        STANDARD.encode(content)
    )
}

#[test]
fn send_string_and_recipient_bounds_are_enforced_before_acceptance() {
    let valid = send_json(&"s".repeat(MAX_SEND_SUBJECT_CHARS), "b", 1, &[]);
    assert!(parse_bounded_json::<SendRequest>(&valid).is_ok());

    let escaped_astral = "\\uD83D\\uDE00".repeat(MAX_SEND_SUBJECT_CHARS);
    assert!(parse_bounded_json::<SendRequest>(&send_json(&escaped_astral, "b", 1, &[])).is_ok());

    let subject_over = send_json(&"s".repeat(MAX_SEND_SUBJECT_CHARS + 1), "b", 1, &[]);
    assert_eq!(
        parse_bounded_json::<SendRequest>(&subject_over)
            .unwrap_err()
            .code,
        MailErrorCode::ResourceLimit
    );

    let body_over = send_json("s", &"b".repeat(MAX_SEND_BODY_CHARS + 1), 1, &[]);
    assert_eq!(
        parse_bounded_json::<SendRequest>(&body_over)
            .unwrap_err()
            .code,
        MailErrorCode::ResourceLimit
    );

    assert!(
        parse_bounded_json::<SendRequest>(&send_json("s", "b", MAX_SEND_RECIPIENTS, &[])).is_ok()
    );
    assert_eq!(
        parse_bounded_json::<SendRequest>(&send_json("s", "b", MAX_SEND_RECIPIENTS + 1, &[]))
            .unwrap_err()
            .code,
        MailErrorCode::ResourceLimit
    );
}

#[test]
fn attachment_base64_and_running_decoded_total_are_bounded() {
    let one_max = vec![0x5a; MAX_SEND_ATTACHMENT_BYTES];
    let valid_attachment = attachment_json(&one_max, 0);
    assert!(
        parse_bounded_json::<SendRequest>(&send_json("s", "b", 1, &[valid_attachment])).is_ok()
    );

    let one_over = attachment_json(&vec![0x5a; MAX_SEND_ATTACHMENT_BYTES + 1], 0);
    assert_eq!(
        parse_bounded_json::<SendRequest>(&send_json("s", "b", 1, &[one_over]))
            .unwrap_err()
            .code,
        MailErrorCode::ResourceLimit
    );

    let count_at_total = MAX_TOTAL_ATTACHMENT_BYTES / MAX_SEND_ATTACHMENT_BYTES;
    let at_total = (0..count_at_total)
        .map(|index| attachment_json(&one_max, index))
        .collect::<Vec<_>>();
    assert!(parse_bounded_json::<SendRequest>(&send_json("s", "b", 1, &at_total)).is_ok());

    let over_total = (0..=count_at_total)
        .map(|index| attachment_json(&one_max, index))
        .collect::<Vec<_>>();
    assert_eq!(
        parse_bounded_json::<SendRequest>(&send_json("s", "b", 1, &over_total))
            .unwrap_err()
            .code,
        MailErrorCode::ResourceLimit
    );
}

#[test]
fn nesting_unknown_duplicate_and_trailing_data_fail_closed() {
    let mut nested = String::from(r#"{"extra":"#);
    nested.push_str(&"[".repeat(33));
    nested.push('0');
    nested.push_str(&"]".repeat(33));
    nested.push('}');
    assert_eq!(
        parse_bounded_json::<SendRequest>(nested.as_bytes())
            .unwrap_err()
            .code,
        MailErrorCode::InputNestingLimit
    );

    let unknown = br#"{"account_id":"synthetic","to":[{"name":null,"email":"r@example.invalid"}],"subject":"s","text":"b","html":null,"attachments":[],"future":true}"#;
    assert!(parse_bounded_json::<SendRequest>(unknown).is_err());

    let duplicate = br#"{"account_id":"synthetic","account_id":"other","to":[{"name":null,"email":"r@example.invalid"}],"subject":"s","text":"b","html":null,"attachments":[]}"#;
    assert!(parse_bounded_json::<SendRequest>(duplicate).is_err());

    let mut trailing = send_json("s", "b", 1, &[]);
    trailing.extend_from_slice(b" true");
    assert!(parse_bounded_json::<SendRequest>(&trailing).is_err());
}

#[test]
fn authorization_proof_uses_exact_bounded_base64url() {
    let signature = URL_SAFE_NO_PAD.encode([0x5a; 64]);
    let proof = format!(
        r#"{{"contract_version":"kirje.authorization-proof.v1","challenge_id":"{}","key_id":"{}","signing_payload_sha256":"{}","signature_base64url":"{signature}"}}"#,
        "11".repeat(32),
        "22".repeat(32),
        "33".repeat(32),
    );
    assert!(parse_bounded_json::<AuthorizationProof>(proof.as_bytes()).is_ok());

    let padded = proof.replace(&signature, &format!("{signature}="));
    assert!(parse_bounded_json::<AuthorizationProof>(padded.as_bytes()).is_err());
    let short = proof.replace(&signature, &URL_SAFE_NO_PAD.encode([0x5a; 63]));
    assert!(parse_bounded_json::<AuthorizationProof>(short.as_bytes()).is_err());
}

#[test]
fn search_address_filters_are_bounded_at_the_first_json_boundary() {
    for field in ["from", "to"] {
        let at_limit = "x".repeat(1_024);
        let over_limit = "x".repeat(1_025);
        let remote_at_limit = format!(
            r#"{{"account_id":"synthetic","mailbox":"INBOX","{field}":"{at_limit}","limit":25}}"#
        );
        let remote_over_limit = format!(
            r#"{{"account_id":"synthetic","mailbox":"INBOX","{field}":"{over_limit}","limit":25}}"#
        );
        assert!(parse_bounded_json::<MessageSearch>(remote_at_limit.as_bytes()).is_ok());
        assert_eq!(
            parse_bounded_json::<MessageSearch>(remote_over_limit.as_bytes())
                .unwrap_err()
                .code,
            MailErrorCode::ResourceLimit
        );

        let local_at_limit = format!(
            r#"{{"account_id":"synthetic","mailbox":"INBOX","{field}":"{at_limit}","limit":25}}"#
        );
        let local_over_limit = format!(
            r#"{{"account_id":"synthetic","mailbox":"INBOX","{field}":"{over_limit}","limit":25}}"#
        );
        assert!(parse_bounded_json::<LocalMessageSearch>(local_at_limit.as_bytes()).is_ok());
        assert_eq!(
            parse_bounded_json::<LocalMessageSearch>(local_over_limit.as_bytes())
                .unwrap_err()
                .code,
            MailErrorCode::ResourceLimit
        );
    }
}

#[test]
fn every_t201_input_type_has_the_sealed_parser_path() {
    let reference = r#"{"account_id":"synthetic","mailbox":"INBOX","uid_validity":1,"uid":1}"#;
    let cases: &[(&str, bool)] = &[
        (r#"{"account_id":"synthetic","mode":"new","source":null,"to":[{"name":null,"email":"r@example.invalid"}],"cc":[],"bcc":[],"subject":"s","text":"b","html":null,"attachments":[]}"#, parse_bounded_json::<DraftInput>(br#"{"account_id":"synthetic","mode":"new","source":null,"to":[{"name":null,"email":"r@example.invalid"}],"cc":[],"bcc":[],"subject":"s","text":"b","html":null,"attachments":[]}"#).is_ok()),
        ("message_search", parse_bounded_json::<MessageSearch>(br#"{"account_id":"synthetic","mailbox":"INBOX","from":null,"to":null,"subject":null,"text":null,"unread":null,"limit":25}"#).is_ok()),
        ("mailbox_sync", parse_bounded_json::<MailboxSyncRequest>(br#"{"account_id":"synthetic","mailbox":"INBOX","cursor":null,"limit":25}"#).is_ok()),
        ("local_search", parse_bounded_json::<LocalMessageSearch>(br#"{"account_id":"synthetic","mailbox":"INBOX","from":null,"to":null,"subject":null,"unread":null,"limit":25}"#).is_ok()),
        ("attachment_read", parse_bounded_json::<AttachmentRead>(format!(r#"{{"reference":{reference},"part_id":"attachment-1","max_bytes":1024}}"#).as_bytes()).is_ok()),
        ("message_read", parse_bounded_json::<MessageRead>(format!(r#"{{"reference":{reference},"max_body_chars":1024}}"#).as_bytes()).is_ok()),
        ("mailbox_operation", parse_bounded_json::<MailboxOperationRequest>(format!(r#"{{"account_id":"synthetic","kind":"set_read","reference":{reference},"value":true,"destination":null}}"#).as_bytes()).is_ok()),
    ];
    for (name, accepted) in cases {
        assert!(*accepted, "sealed parser rejected {name}");
    }
}
