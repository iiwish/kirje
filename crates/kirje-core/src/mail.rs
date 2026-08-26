use std::{fmt, net::IpAddr};

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CredentialKind, Endpoint, Protocol, TransportSecurity};

pub const DEFAULT_MESSAGE_LIMIT: u16 = 25;
pub const MAX_MESSAGE_LIMIT: u16 = 100;
pub const DEFAULT_BODY_CHARS: u32 = 32_768;
pub const MAX_BODY_CHARS: u32 = 65_536;
const MAX_MAILBOX_CHARS: usize = 4_096;
const MAX_SEARCH_VALUE_CHARS: usize = 1_024;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MailAccountConfig {
    pub id: String,
    pub email: String,
    pub username: String,
    pub incoming: Endpoint,
    pub credential_kind: CredentialKind,
}

impl MailAccountConfig {
    /// Validate values before they reach a protocol adapter or persistent store.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::InvalidInput`] for malformed identifiers,
    /// addresses, or insecure/non-IMAP endpoints.
    pub fn validate(&self) -> Result<(), MailError> {
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(MailError::invalid_input(
                "account id must use 1-64 ASCII letters, numbers, '-' or '_'",
            ));
        }

        let Some((local, domain)) = self.email.rsplit_once('@') else {
            return Err(MailError::invalid_input("email address must contain '@'"));
        };
        if local.is_empty()
            || domain.is_empty()
            || !domain.contains('.')
            || self.email.len() > 320
            || self.email.chars().any(char::is_whitespace)
            || self.email.chars().any(char::is_control)
        {
            return Err(MailError::invalid_input("email address is malformed"));
        }
        if self.username.trim().is_empty()
            || self.username.len() > 1_024
            || self.username.chars().any(char::is_control)
        {
            return Err(MailError::invalid_input(
                "username must contain 1-1024 characters",
            ));
        }
        if self.incoming.protocol != Protocol::Imap {
            return Err(MailError::invalid_input(
                "read-only MVP accounts require an IMAP incoming endpoint",
            ));
        }
        if !valid_host(&self.incoming.host) || self.incoming.port == 0 {
            return Err(MailError::invalid_input(
                "IMAP host must contain 1-253 characters and port must be positive",
            ));
        }
        if !matches!(
            self.incoming.security,
            TransportSecurity::ImplicitTls | TransportSecurity::StartTls
        ) {
            return Err(MailError::invalid_input(
                "IMAP transport must use implicit TLS or STARTTLS",
            ));
        }
        if self.credential_kind == CredentialKind::OAuth2 {
            return Err(MailError::invalid_input(
                "OAuth2 is not available in the read-only MVP",
            ));
        }

        Ok(())
    }
}

fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.trim() != host {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Mailbox {
    pub id: String,
    pub name: String,
    pub total: Option<u64>,
    pub unread: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MailboxPage {
    pub mailboxes: Vec<Mailbox>,
    pub returned: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MessageReference {
    pub account_id: String,
    pub mailbox: String,
    pub uid_validity: Option<u32>,
    #[schemars(range(min = 1))]
    pub uid: u32,
}

impl MessageReference {
    /// Validate that the reference remains scoped to one account and mailbox.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::InvalidInput`] for an empty scope or UID zero.
    pub fn validate(&self) -> Result<(), MailError> {
        if self.account_id.trim().is_empty()
            || self.account_id.len() > 64
            || self.mailbox.trim().is_empty()
            || self.mailbox.chars().count() > MAX_MAILBOX_CHARS
            || self.uid == 0
        {
            return Err(MailError::invalid_input(
                "message reference requires account, mailbox, and positive UID",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MailAddress {
    pub name: Option<String>,
    pub email: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MessageEnvelope {
    pub reference: MessageReference,
    pub message_id: Option<String>,
    pub in_reply_to: Vec<String>,
    pub subject: String,
    pub from: Vec<MailAddress>,
    pub to: Vec<MailAddress>,
    pub sent_at: Option<DateTime<Utc>>,
    pub size: u64,
    pub is_read: bool,
    pub is_starred: bool,
    pub has_attachment: Option<bool>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MessageSearch {
    pub account_id: String,
    pub mailbox: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub text: Option<String>,
    pub unread: Option<bool>,
    #[serde(default = "default_message_limit")]
    #[schemars(range(min = 1, max = 100))]
    pub limit: u16,
}

const fn default_message_limit() -> u16 {
    DEFAULT_MESSAGE_LIMIT
}

impl MessageSearch {
    /// Validate bounded structured search input.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::InvalidInput`] when required scope is absent or
    /// the result limit exceeds the public contract.
    pub fn validate(&self) -> Result<(), MailError> {
        if self.account_id.trim().is_empty()
            || self.account_id.len() > 64
            || self.mailbox.trim().is_empty()
            || self.mailbox.chars().count() > MAX_MAILBOX_CHARS
        {
            return Err(MailError::invalid_input(
                "search requires an account id and mailbox",
            ));
        }
        if self.limit == 0 || self.limit > MAX_MESSAGE_LIMIT {
            return Err(MailError::invalid_input(format!(
                "limit must be between 1 and {MAX_MESSAGE_LIMIT}"
            )));
        }
        if [&self.from, &self.to, &self.subject, &self.text]
            .into_iter()
            .flatten()
            .any(|value| value.chars().count() > MAX_SEARCH_VALUE_CHARS)
        {
            return Err(MailError::invalid_input(
                "search filter values cannot exceed 1024 characters",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MessagePage {
    pub messages: Vec<MessageEnvelope>,
    pub returned: u16,
    pub limit: u16,
    pub has_more: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AttachmentMetadata {
    pub part_id: String,
    pub filename: Option<String>,
    pub mime_type: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MessageContent {
    pub reference: MessageReference,
    pub subject: String,
    pub from: Vec<MailAddress>,
    pub to: Vec<MailAddress>,
    pub cc: Vec<MailAddress>,
    pub sent_at: Option<DateTime<Utc>>,
    pub text: Option<String>,
    pub sanitized_html: Option<String>,
    pub attachments: Vec<AttachmentMetadata>,
    pub untrusted: bool,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MessageRead {
    pub reference: MessageReference,
    #[serde(default = "default_body_chars")]
    #[schemars(range(min = 1, max = 65_536))]
    pub max_body_chars: u32,
}

const fn default_body_chars() -> u32 {
    DEFAULT_BODY_CHARS
}

impl MessageRead {
    /// Validate scoped and bounded message-reading input.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::InvalidInput`] when the reference or body bound
    /// is invalid.
    pub fn validate(&self) -> Result<(), MailError> {
        self.reference.validate()?;
        if self.max_body_chars == 0 || self.max_body_chars > MAX_BODY_CHARS {
            return Err(MailError::invalid_input(format!(
                "max_body_chars must be between 1 and {MAX_BODY_CHARS}"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ConnectionReport {
    pub account_id: String,
    pub protocol: Protocol,
    pub host: String,
    pub authenticated: bool,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MailErrorCode {
    InvalidInput,
    AccountNotFound,
    ConfigRead,
    ConfigWrite,
    SecretMissing,
    SecretStoreUnavailable,
    Network,
    Tls,
    Authentication,
    Protocol,
    MessageNotFound,
    ResourceLimit,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, Error, JsonSchema, PartialEq, Serialize)]
#[error("{code}: {message}")]
pub struct MailError {
    pub code: MailErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl MailError {
    #[must_use]
    pub fn new(code: MailErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            retryable,
        }
    }

    #[must_use]
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(MailErrorCode::InvalidInput, message, false)
    }
}

impl fmt::Display for MailErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = serde_variant_name(*self);
        f.write_str(value)
    }
}

const fn serde_variant_name(code: MailErrorCode) -> &'static str {
    match code {
        MailErrorCode::InvalidInput => "invalid_input",
        MailErrorCode::AccountNotFound => "account_not_found",
        MailErrorCode::ConfigRead => "config_read",
        MailErrorCode::ConfigWrite => "config_write",
        MailErrorCode::SecretMissing => "secret_missing",
        MailErrorCode::SecretStoreUnavailable => "secret_store_unavailable",
        MailErrorCode::Network => "network",
        MailErrorCode::Tls => "tls",
        MailErrorCode::Authentication => "authentication",
        MailErrorCode::Protocol => "protocol",
        MailErrorCode::MessageNotFound => "message_not_found",
        MailErrorCode::ResourceLimit => "resource_limit",
        MailErrorCode::Internal => "internal",
    }
}

pub trait MailboxReader: Send + Sync {
    /// Check TLS, protocol negotiation, and authentication without reading mail.
    ///
    /// # Errors
    ///
    /// Returns a stable [`MailError`] for validation, transport, TLS,
    /// authentication, or protocol failures.
    fn check(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
    ) -> Result<ConnectionReport, MailError>;

    /// List selectable mailboxes for one account.
    ///
    /// # Errors
    ///
    /// Returns a stable [`MailError`] when validation or the remote operation
    /// fails.
    fn list_mailboxes(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        include_counts: bool,
    ) -> Result<Vec<Mailbox>, MailError>;

    /// Search bounded envelope metadata without fetching message bodies.
    ///
    /// # Errors
    ///
    /// Returns a stable [`MailError`] when validation or the remote operation
    /// fails.
    fn search_messages(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        search: &MessageSearch,
    ) -> Result<MessagePage, MailError>;

    /// Read one message without changing its seen state.
    ///
    /// # Errors
    ///
    /// Returns a stable [`MailError`] when validation, lookup, parsing, or the
    /// remote operation fails.
    fn read_message(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        read: &MessageRead,
    ) -> Result<MessageContent, MailError>;
}

#[cfg(test)]
mod tests {
    use super::*;

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
            credential_kind: CredentialKind::AppPassword,
        }
    }

    #[test]
    fn account_rejects_cleartext_or_non_imap_endpoints() {
        let mut candidate = account();
        candidate.incoming.security = TransportSecurity::Https;
        assert_eq!(
            candidate.validate().unwrap_err().code,
            MailErrorCode::InvalidInput
        );

        candidate = account();
        candidate.incoming.protocol = Protocol::Smtp;
        assert_eq!(
            candidate.validate().unwrap_err().code,
            MailErrorCode::InvalidInput
        );

        candidate = account();
        candidate.incoming.host = "imap.163.com@attacker.example".to_owned();
        assert_eq!(
            candidate.validate().unwrap_err().code,
            MailErrorCode::InvalidInput
        );
    }

    #[test]
    fn message_limits_are_bounded() {
        let search = MessageSearch {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            from: None,
            to: None,
            subject: None,
            text: None,
            unread: None,
            limit: MAX_MESSAGE_LIMIT + 1,
        };
        assert_eq!(
            search.validate().unwrap_err().code,
            MailErrorCode::InvalidInput
        );
    }

    #[test]
    fn message_reference_is_scoped() {
        let reference = MessageReference {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            uid_validity: Some(42),
            uid: 7,
        };
        assert!(reference.validate().is_ok());
    }
}
