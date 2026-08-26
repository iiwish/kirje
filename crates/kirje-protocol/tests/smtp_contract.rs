use chrono::{TimeZone as _, Utc};
use kirje_core::{
    CredentialKind, Endpoint, MailAccountConfig, MailAddress, MailSender, Protocol, SendPlan,
    SendRequest, TransportSecurity,
};
use kirje_protocol::LettreSmtpSender;
use secrecy::SecretString;

fn plan() -> SendPlan {
    SendPlan::create(
        SendRequest {
            account_id: "personal".to_owned(),
            to: vec![MailAddress {
                name: None,
                email: "agent@163.com".to_owned(),
            }],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: "SMTP contract".to_owned(),
            text: Some("body".to_owned()),
            html: None,
        },
        Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap(),
    )
    .expect("plan")
}

fn account() -> MailAccountConfig {
    MailAccountConfig {
        id: "personal".to_owned(),
        email: "agent@163.com".to_owned(),
        username: "agent@163.com".to_owned(),
        incoming: Endpoint {
            protocol: Protocol::Imap,
            host: "imap.163.com".to_owned(),
            port: 993,
            security: TransportSecurity::ImplicitTls,
        },
        outgoing: None,
        credential_kind: CredentialKind::AppPassword,
    }
}

#[test]
fn missing_smtp_endpoint_fails_before_delivery_starts() {
    let error = LettreSmtpSender
        .send(&account(), &SecretString::from("not-used"), &plan())
        .unwrap_err();
    assert!(!error.delivery_started);
}
