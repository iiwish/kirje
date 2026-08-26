use std::time::Duration;

use chrono::Utc;
use kirje_core::{
    MailAccountConfig, MailAddress, MailError, MailErrorCode, MailSender, Protocol,
    SendAttemptError, SendPlan, SendReceipt, TransportSecurity,
};
use lettre::{
    Address, Message, SmtpTransport, Transport,
    message::{Attachment, Mailbox, MultiPart, SinglePart, header::ContentType},
    transport::smtp::{Error as SmtpError, authentication::Credentials},
};
use secrecy::{ExposeSecret as _, SecretString};

const SMTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_CHARS: usize = 256;

#[derive(Clone, Copy, Debug, Default)]
pub struct LettreSmtpSender;

impl MailSender for LettreSmtpSender {
    fn send(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        plan: &SendPlan,
    ) -> Result<SendReceipt, SendAttemptError> {
        account
            .validate()
            .map_err(SendAttemptError::before_delivery)?;
        plan.request
            .validate()
            .map_err(SendAttemptError::before_delivery)?;
        if plan.request.account_id != account.id {
            return Err(SendAttemptError::before_delivery(MailError::invalid_input(
                "send plan account does not match the selected account",
            )));
        }
        let endpoint = account.outgoing.as_ref().ok_or_else(|| {
            SendAttemptError::before_delivery(MailError::invalid_input(
                "account has no SMTP endpoint",
            ))
        })?;
        if endpoint.protocol != Protocol::Smtp {
            return Err(SendAttemptError::before_delivery(MailError::invalid_input(
                "outgoing endpoint must use SMTP",
            )));
        }

        let message = build_message(account, plan).map_err(SendAttemptError::before_delivery)?;
        let builder = match endpoint.security {
            TransportSecurity::ImplicitTls => SmtpTransport::relay(&endpoint.host),
            TransportSecurity::StartTls => SmtpTransport::starttls_relay(&endpoint.host),
            TransportSecurity::Https => {
                return Err(SendAttemptError::before_delivery(MailError::invalid_input(
                    "SMTP transport must use implicit TLS or STARTTLS",
                )));
            }
        }
        .map_err(|error| SendAttemptError::before_delivery(map_smtp_error(&error)))?;
        let transport = builder
            .port(endpoint.port)
            .credentials(Credentials::new(
                account.username.clone(),
                secret.expose_secret().to_owned(),
            ))
            .timeout(Some(SMTP_TIMEOUT))
            .build();

        let response = transport
            .send(&message)
            .map_err(|error| SendAttemptError::after_delivery_started(map_smtp_error(&error)))?;
        Ok(SendReceipt {
            accepted: response.is_positive(),
            server_response: Some(sanitize_response(&format!(
                "{} {}",
                response.code(),
                response.first_line().unwrap_or("accepted")
            ))),
            sent_at: Utc::now(),
        })
    }
}

fn build_message(account: &MailAccountConfig, plan: &SendPlan) -> Result<Message, MailError> {
    let from = Mailbox::new(None, parse_address(&account.email)?);
    let mut builder = Message::builder()
        .from(from)
        .subject(plan.request.subject.clone())
        .message_id(Some(plan.message_id.clone()));
    for address in &plan.request.to {
        builder = builder.to(mailbox(address)?);
    }
    for address in &plan.request.cc {
        builder = builder.cc(mailbox(address)?);
    }
    for address in &plan.request.bcc {
        builder = builder.bcc(mailbox(address)?);
    }

    if plan.request.attachments.is_empty() {
        return match (&plan.request.text, &plan.request.html) {
            (Some(text), Some(html)) => builder
                .multipart(MultiPart::alternative_plain_html(
                    text.clone(),
                    html.clone(),
                ))
                .map_err(|_| MailError::invalid_input("cannot construct MIME message")),
            (Some(text), None) => builder
                .body(text.clone())
                .map_err(|_| MailError::invalid_input("cannot construct MIME message")),
            (None, Some(html)) => builder
                .singlepart(SinglePart::html(html.clone()))
                .map_err(|_| MailError::invalid_input("cannot construct MIME message")),
            (None, None) => Err(MailError::invalid_input(
                "send request requires a non-empty text or HTML body",
            )),
        };
    }

    let mut mixed = match (&plan.request.text, &plan.request.html) {
        (Some(text), Some(html)) => MultiPart::mixed().multipart(
            MultiPart::alternative_plain_html(text.clone(), html.clone()),
        ),
        (Some(text), None) => MultiPart::mixed().singlepart(SinglePart::plain(text.clone())),
        (None, Some(html)) => MultiPart::mixed().singlepart(SinglePart::html(html.clone())),
        (None, None) => {
            return Err(MailError::invalid_input(
                "send request requires a non-empty text or HTML body",
            ));
        }
    };
    for attachment in &plan.request.attachments {
        let bytes = attachment.validate()?;
        let content_type = ContentType::parse(&attachment.mime_type)
            .map_err(|_| MailError::invalid_input("attachment MIME type is invalid"))?;
        mixed = mixed
            .singlepart(Attachment::new(attachment.filename.clone()).body(bytes, content_type));
    }
    builder
        .multipart(mixed)
        .map_err(|_| MailError::invalid_input("cannot construct MIME message"))
}

fn mailbox(address: &MailAddress) -> Result<Mailbox, MailError> {
    Ok(Mailbox::new(
        address.name.clone(),
        parse_address(&address.email)?,
    ))
}

fn parse_address(value: &str) -> Result<Address, MailError> {
    value
        .parse()
        .map_err(|_| MailError::invalid_input("email address cannot be encoded for SMTP"))
}

fn map_smtp_error(error: &SmtpError) -> MailError {
    if error.is_tls() {
        MailError::new(MailErrorCode::Tls, "SMTP TLS negotiation failed", false)
    } else if error
        .status()
        .is_some_and(|status| status.to_string().starts_with("53"))
    {
        MailError::new(
            MailErrorCode::Authentication,
            "SMTP authentication failed",
            false,
        )
    } else if error.is_transient() || error.is_timeout() {
        MailError::new(
            MailErrorCode::Network,
            "SMTP delivery failed transiently",
            true,
        )
    } else if error.is_permanent() {
        MailError::new(
            MailErrorCode::Protocol,
            "SMTP server rejected the message",
            false,
        )
    } else {
        MailError::new(MailErrorCode::Network, "SMTP delivery failed", true)
    }
}

fn sanitize_response(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_RESPONSE_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Utc};
    use kirje_core::{CredentialKind, Endpoint, MailAddress, SendAttachment, SendRequest};

    use super::*;

    fn fixture() -> (MailAccountConfig, SendPlan) {
        let account = MailAccountConfig {
            id: "personal".to_owned(),
            email: "agent@163.com".to_owned(),
            username: "agent@163.com".to_owned(),
            incoming: Endpoint {
                protocol: Protocol::Imap,
                host: "imap.163.com".to_owned(),
                port: 993,
                security: TransportSecurity::ImplicitTls,
            },
            outgoing: Some(Endpoint {
                protocol: Protocol::Smtp,
                host: "smtp.163.com".to_owned(),
                port: 465,
                security: TransportSecurity::ImplicitTls,
            }),
            credential_kind: CredentialKind::AppPassword,
        };
        let plan = SendPlan::create(
            SendRequest {
                account_id: account.id.clone(),
                to: vec![MailAddress {
                    name: Some("收件人".to_owned()),
                    email: account.email.clone(),
                }],
                cc: Vec::new(),
                bcc: vec![MailAddress {
                    name: None,
                    email: "hidden@example.com".to_owned(),
                }],
                subject: "Kirje 世界".to_owned(),
                text: Some("plain body".to_owned()),
                html: Some("<p>HTML body</p>".to_owned()),
                attachments: Vec::new(),
            },
            Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap(),
        )
        .expect("plan");
        (account, plan)
    }

    #[test]
    fn mime_preserves_identity_and_hides_bcc_header() {
        let (account, plan) = fixture();
        let message = build_message(&account, &plan).expect("message");
        let formatted = String::from_utf8(message.formatted()).expect("UTF-8 MIME");
        assert!(formatted.contains(&format!("Message-ID: {}", plan.message_id)));
        assert!(formatted.contains("multipart/alternative"));
        assert!(!formatted.contains("Bcc:"));
        assert_eq!(message.envelope().to().len(), 2);
    }

    #[test]
    fn server_responses_are_bounded_and_single_line() {
        let response = sanitize_response(&format!("250 queued\r\n{}", "x".repeat(400)));
        assert!(response.chars().count() <= MAX_RESPONSE_CHARS);
        assert!(!response.contains('\n'));
    }

    #[test]
    fn attachments_are_encoded_as_mixed_mime_parts() {
        let (account, mut plan) = fixture();
        plan.request.attachments.push(SendAttachment {
            filename: "note.txt".to_owned(),
            mime_type: "text/plain".to_owned(),
            content_base64: "aGVsbG8=".to_owned(),
        });
        let message = build_message(&account, &plan).expect("message");
        let formatted = String::from_utf8(message.formatted()).expect("UTF-8 MIME");
        assert!(formatted.contains("multipart/mixed"));
        assert!(formatted.contains("note.txt"));
        assert!(formatted.contains("hello"));
    }
}
