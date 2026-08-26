use chrono::{TimeZone as _, Utc};
use kirje_core::{
    MAX_SEND_ATTACHMENT_BYTES, MailAddress, MailErrorCode, SendAttachment, SendPlan,
    SendPlanStatus, SendRequest,
};

fn request() -> SendRequest {
    SendRequest {
        account_id: "personal".to_owned(),
        to: vec![MailAddress {
            name: Some("Kirje Test".to_owned()),
            email: "agent@163.com".to_owned(),
        }],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: "Governed send test".to_owned(),
        text: Some("This is a bounded test body.".to_owned()),
        html: None,
        attachments: Vec::new(),
    }
}

#[test]
fn request_requires_recipients_and_a_body() {
    let mut candidate = request();
    candidate.to.clear();
    assert_eq!(
        candidate.validate().unwrap_err().code,
        MailErrorCode::InvalidInput
    );

    candidate = request();
    candidate.text = None;
    assert_eq!(
        candidate.validate().unwrap_err().code,
        MailErrorCode::InvalidInput
    );
}

#[test]
fn request_rejects_header_injection_and_excessive_recipients() {
    let mut candidate = request();
    candidate.subject = "hello\r\nBcc: attacker@example.com".to_owned();
    assert_eq!(
        candidate.validate().unwrap_err().code,
        MailErrorCode::InvalidInput
    );

    candidate = request();
    candidate.to = (0..51)
        .map(|index| MailAddress {
            name: None,
            email: format!("user{index}@example.com"),
        })
        .collect();
    assert_eq!(
        candidate.validate().unwrap_err().code,
        MailErrorCode::ResourceLimit
    );

    candidate = request();
    candidate.to[0].email = "victim@example.com@attacker.example".to_owned();
    assert_eq!(
        candidate.validate().unwrap_err().code,
        MailErrorCode::InvalidInput
    );
}

#[test]
fn attachment_metadata_is_bounded_and_mime_safe() {
    let mut candidate = request();
    candidate.attachments.push(SendAttachment {
        filename: "report.pdf".to_owned(),
        mime_type: "application/pdf".to_owned(),
        content_base64: "AQID".to_owned(),
    });
    assert!(candidate.validate().is_ok());

    candidate.attachments[0].mime_type = "text/plain\r\nX-Injected: yes".to_owned();
    assert_eq!(
        candidate.validate().unwrap_err().code,
        MailErrorCode::InvalidInput
    );

    candidate.attachments[0].mime_type = "text/plain".to_owned();
    candidate.attachments[0].content_base64 =
        "A".repeat(4 * MAX_SEND_ATTACHMENT_BYTES.div_ceil(3) + 4);
    assert_eq!(
        candidate.validate().unwrap_err().code,
        MailErrorCode::ResourceLimit
    );
}

#[test]
fn planning_creates_an_immutable_identity_and_expiry() {
    let now = Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap();
    let plan = SendPlan::create(request(), now).expect("valid plan");

    assert_eq!(plan.status, SendPlanStatus::Planned);
    assert_eq!(plan.created_at, now);
    assert_eq!(plan.expires_at, now + chrono::Duration::hours(24));
    assert_eq!(plan.content_sha256.len(), 64);
    assert!(plan.message_id.starts_with('<'));
    assert!(plan.message_id.ends_with("@163.com>"));
    assert_eq!(plan.attempt_count, 0);

    let same_content = SendPlan::create(request(), now).expect("valid plan");
    assert_eq!(plan.content_sha256, same_content.content_sha256);
    assert_ne!(plan.id, same_content.id);
    assert_ne!(plan.message_id, same_content.message_id);
}
