use std::{fmt, net::IpAddr};

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CredentialKind, Endpoint, MailboxOperationReceipt, MailboxOperationRequest, Protocol,
    TransportSecurity,
};

pub const DEFAULT_MESSAGE_LIMIT: u16 = 25;
pub const MAX_MESSAGE_LIMIT: u16 = 100;
pub const DEFAULT_BODY_CHARS: u32 = 32_768;
pub const MAX_BODY_CHARS: u32 = 65_536;
pub const DEFAULT_SYNC_LIMIT: u16 = 250;
pub const MAX_SYNC_LIMIT: u16 = 500;
pub const DEFAULT_ATTACHMENT_BYTES: u32 = 256 * 1024;
pub const MAX_ATTACHMENT_BYTES: u32 = 1024 * 1024;
const MAX_MAILBOX_CHARS: usize = 4_096;
const MAX_SEARCH_VALUE_CHARS: usize = 1_024;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MailAccountConfig {
    pub id: String,
    pub email: String,
    pub username: String,
    pub incoming: Endpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outgoing: Option<Endpoint>,
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
                "accounts require an IMAP incoming endpoint",
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
        if let Some(outgoing) = &self.outgoing {
            if outgoing.protocol != Protocol::Smtp {
                return Err(MailError::invalid_input("outgoing endpoint must use SMTP"));
            }
            if !valid_host(&outgoing.host) || outgoing.port == 0 {
                return Err(MailError::invalid_input(
                    "SMTP host must contain 1-253 characters and port must be positive",
                ));
            }
            if !matches!(
                outgoing.security,
                TransportSecurity::ImplicitTls | TransportSecurity::StartTls
            ) {
                return Err(MailError::invalid_input(
                    "SMTP transport must use implicit TLS or STARTTLS",
                ));
            }
        }
        if self.credential_kind == CredentialKind::OAuth2 {
            return Err(MailError::invalid_input(
                "OAuth2 is not available in this release",
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxSpecialUse {
    Archive,
    Trash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteAttemptError {
    pub error: MailError,
    pub mutation_started: bool,
}

impl RemoteAttemptError {
    #[must_use]
    pub fn before_mutation(error: MailError) -> Self {
        Self {
            error,
            mutation_started: false,
        }
    }

    #[must_use]
    pub fn after_mutation(error: MailError) -> Self {
        Self {
            error,
            mutation_started: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MailboxPage {
    pub mailboxes: Vec<Mailbox>,
    pub returned: u16,
    pub untrusted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    pub untrusted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncCursor {
    #[schemars(range(min = 1))]
    pub uid_validity: u32,
    pub highest_uid: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxSyncRequest {
    pub account_id: String,
    pub mailbox: String,
    pub cursor: Option<SyncCursor>,
    #[serde(default = "default_sync_limit")]
    #[schemars(range(min = 1, max = 500))]
    pub limit: u16,
}

const fn default_sync_limit() -> u16 {
    DEFAULT_SYNC_LIMIT
}

impl MailboxSyncRequest {
    /// Validate a bounded, mailbox-scoped synchronization request.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::InvalidInput`] for invalid scope or limits.
    pub fn validate(&self) -> Result<(), MailError> {
        validate_scope(&self.account_id, &self.mailbox)?;
        if self.limit == 0 || self.limit > MAX_SYNC_LIMIT {
            return Err(MailError::invalid_input(format!(
                "sync limit must be between 1 and {MAX_SYNC_LIMIT}"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MailboxSyncBatch {
    pub account_id: String,
    pub mailbox: String,
    #[schemars(range(min = 1))]
    pub uid_validity: u32,
    pub messages: Vec<MessageEnvelope>,
    pub remote_total: Option<u64>,
    pub has_more: bool,
    pub reset_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MailboxSyncState {
    pub account_id: String,
    pub mailbox: String,
    #[schemars(range(min = 1))]
    pub uid_validity: u32,
    pub highest_uid: Option<u32>,
    pub indexed_messages: u64,
    pub initial_window_complete: bool,
    pub remote_total: Option<u64>,
    pub last_synced_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MailboxSyncReport {
    pub state: MailboxSyncState,
    pub fetched: u16,
    pub stored: u16,
    pub reset: bool,
    pub has_more: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalMessageSearch {
    pub account_id: String,
    pub mailbox: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub unread: Option<bool>,
    #[serde(default = "default_message_limit")]
    #[schemars(range(min = 1, max = 100))]
    pub limit: u16,
}

impl LocalMessageSearch {
    /// Validate bounded metadata-only local search input.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::InvalidInput`] for invalid scope, filters, or limit.
    pub fn validate(&self) -> Result<(), MailError> {
        validate_scope(&self.account_id, &self.mailbox)?;
        if self.limit == 0 || self.limit > MAX_MESSAGE_LIMIT {
            return Err(MailError::invalid_input(format!(
                "limit must be between 1 and {MAX_MESSAGE_LIMIT}"
            )));
        }
        if [&self.from, &self.to, &self.subject]
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

pub trait MessageIndex: Send + Sync {
    /// Return the stored cursor and coverage for one mailbox.
    ///
    /// # Errors
    ///
    /// Returns stable validation or store-read errors.
    fn state(&self, account_id: &str, mailbox: &str)
    -> Result<Option<MailboxSyncState>, MailError>;

    /// Transactionally apply one remote batch, replacing the mailbox scope when requested.
    ///
    /// # Errors
    ///
    /// Returns stable validation, store-read, or store-write errors.
    fn apply_sync(
        &self,
        batch: &MailboxSyncBatch,
        replace: bool,
    ) -> Result<MailboxSyncReport, MailError>;

    /// Search bounded indexed envelope metadata without network or credentials.
    ///
    /// # Errors
    ///
    /// Returns stable validation or store-read errors.
    fn search(&self, search: &LocalMessageSearch) -> Result<MessagePage, MailError>;
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentMetadata {
    pub part_id: String,
    pub filename: Option<String>,
    pub mime_type: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentRead {
    pub reference: MessageReference,
    pub part_id: String,
    #[serde(default = "default_attachment_bytes")]
    #[schemars(range(min = 1, max = 1_048_576))]
    pub max_bytes: u32,
}

const fn default_attachment_bytes() -> u32 {
    DEFAULT_ATTACHMENT_BYTES
}

impl AttachmentRead {
    /// Validate scoped and bounded attachment input.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::InvalidInput`] for invalid references, part ids, or limits.
    pub fn validate(&self) -> Result<(), MailError> {
        self.reference.validate()?;
        parse_attachment_index(&self.part_id)?;
        if self.max_bytes == 0 || self.max_bytes > MAX_ATTACHMENT_BYTES {
            return Err(MailError::invalid_input(format!(
                "max_bytes must be between 1 and {MAX_ATTACHMENT_BYTES}"
            )));
        }
        Ok(())
    }

    /// Return the zero-based MIME attachment index encoded by `part_id`.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::InvalidInput`] when the id is not `attachment-N`.
    pub fn attachment_index(&self) -> Result<usize, MailError> {
        parse_attachment_index(&self.part_id)
    }
}

fn parse_attachment_index(part_id: &str) -> Result<usize, MailError> {
    let value = part_id
        .strip_prefix("attachment-")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (1..=100).contains(value))
        .ok_or_else(|| {
            MailError::invalid_input(
                "attachment part id must match attachment-1 through attachment-100",
            )
        })?;
    Ok(value - 1)
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AttachmentContent {
    pub reference: MessageReference,
    pub part_id: String,
    pub filename: Option<String>,
    pub mime_type: String,
    pub size: u64,
    pub content_base64: String,
    pub untrusted: bool,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageContent {
    pub reference: MessageReference,
    #[serde(default)]
    pub message_id: Option<String>,
    pub subject: String,
    pub from: Vec<MailAddress>,
    pub to: Vec<MailAddress>,
    pub cc: Vec<MailAddress>,
    #[serde(default)]
    pub reply_to: Vec<MailAddress>,
    pub sent_at: Option<DateTime<Utc>>,
    pub text: Option<String>,
    pub sanitized_html: Option<String>,
    pub attachments: Vec<AttachmentMetadata>,
    pub untrusted: bool,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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
    AccountAlreadyExists,
    AccountIdentityConflict,
    AccountUpdateConflict,
    ConfigRead,
    ConfigWrite,
    ConfigStoreIdentityConflict,
    ConfigMigrationFailed,
    ConfigVersionUnsupported,
    ConfigConcurrentUpdate,
    SecretMissing,
    SecretStoreUnavailable,
    CredentialLegacyQuarantined,
    CredentialReentryRequired,
    CredentialBindingInvalid,
    CredentialCleanupInvalid,
    SecureFileSemanticsUnsupported,
    OwnerAuthorizationRequired,
    OwnerTrustNotConfigured,
    OwnerRecoveryRequired,
    OwnerKeyInactive,
    TrustEpochStale,
    TrustBundleMismatch,
    ClockRollbackDetected,
    AuthorizationRequired,
    AuthorizationExpired,
    AuthorizationInvalidated,
    AuthorizationMalformed,
    AuthorizationSignatureInvalid,
    AuthorizationReplayed,
    AuthorizationContextStale,
    GrantAlreadyUsed,
    EffectAlreadyClaimed,
    EffectAlreadyInvoked,
    AuthorityProjectionConflict,
    UnsupportedCapability,
    InputNotRegularFile,
    InputLinkRejected,
    InputDocumentIncomplete,
    InputNestingLimit,
    McpFrameTooLarge,
    McpRequestIdInvalid,
    McpDuplicateRequestId,
    McpSessionBusy,
    McpOutputTooLarge,
    RemoteResponseTooLarge,
    RemoteCapabilityIncomplete,
    Network,
    Tls,
    Authentication,
    Protocol,
    MessageNotFound,
    AttachmentNotFound,
    ResourceLimit,
    StoreRead,
    StoreWrite,
    StoreMigration,
    SendPlanNotFound,
    SendPlanState,
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
            retryable: retryable && code.retryable_by_default(),
        }
    }

    #[must_use]
    pub fn stable(code: MailErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, message, code.retryable_by_default())
    }

    #[must_use]
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(MailErrorCode::InvalidInput, message, false)
    }
}

impl MailErrorCode {
    pub const SECURITY_CONTRACT_CODES: &'static [Self] = &[
        Self::AccountAlreadyExists,
        Self::AccountIdentityConflict,
        Self::AccountUpdateConflict,
        Self::ConfigStoreIdentityConflict,
        Self::ConfigMigrationFailed,
        Self::ConfigVersionUnsupported,
        Self::ConfigConcurrentUpdate,
        Self::CredentialLegacyQuarantined,
        Self::CredentialReentryRequired,
        Self::CredentialBindingInvalid,
        Self::CredentialCleanupInvalid,
        Self::SecureFileSemanticsUnsupported,
        Self::OwnerAuthorizationRequired,
        Self::OwnerTrustNotConfigured,
        Self::OwnerRecoveryRequired,
        Self::OwnerKeyInactive,
        Self::TrustEpochStale,
        Self::TrustBundleMismatch,
        Self::ClockRollbackDetected,
        Self::AuthorizationRequired,
        Self::AuthorizationExpired,
        Self::AuthorizationInvalidated,
        Self::AuthorizationMalformed,
        Self::AuthorizationSignatureInvalid,
        Self::AuthorizationReplayed,
        Self::AuthorizationContextStale,
        Self::GrantAlreadyUsed,
        Self::EffectAlreadyClaimed,
        Self::EffectAlreadyInvoked,
        Self::AuthorityProjectionConflict,
        Self::UnsupportedCapability,
        Self::InputNotRegularFile,
        Self::InputLinkRejected,
        Self::InputDocumentIncomplete,
        Self::InputNestingLimit,
        Self::McpFrameTooLarge,
        Self::McpRequestIdInvalid,
        Self::McpDuplicateRequestId,
        Self::McpSessionBusy,
        Self::McpOutputTooLarge,
        Self::RemoteResponseTooLarge,
        Self::RemoteCapabilityIncomplete,
    ];

    #[must_use]
    pub const fn retryable_by_default(self) -> bool {
        matches!(
            self,
            Self::Network
                | Self::Tls
                | Self::Protocol
                | Self::StoreRead
                | Self::StoreWrite
                | Self::SecretStoreUnavailable
        )
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
        MailErrorCode::AccountAlreadyExists => "account_already_exists",
        MailErrorCode::AccountIdentityConflict => "account_identity_conflict",
        MailErrorCode::AccountUpdateConflict => "account_update_conflict",
        MailErrorCode::ConfigRead => "config_read",
        MailErrorCode::ConfigWrite => "config_write",
        MailErrorCode::ConfigStoreIdentityConflict => "config_store_identity_conflict",
        MailErrorCode::ConfigMigrationFailed => "config_migration_failed",
        MailErrorCode::ConfigVersionUnsupported => "config_version_unsupported",
        MailErrorCode::ConfigConcurrentUpdate => "config_concurrent_update",
        MailErrorCode::SecretMissing => "secret_missing",
        MailErrorCode::SecretStoreUnavailable => "secret_store_unavailable",
        MailErrorCode::CredentialLegacyQuarantined => "credential_legacy_quarantined",
        MailErrorCode::CredentialReentryRequired => "credential_reentry_required",
        MailErrorCode::CredentialBindingInvalid => "credential_binding_invalid",
        MailErrorCode::CredentialCleanupInvalid => "credential_cleanup_invalid",
        MailErrorCode::SecureFileSemanticsUnsupported => "secure_file_semantics_unsupported",
        MailErrorCode::OwnerAuthorizationRequired => "owner_authorization_required",
        MailErrorCode::OwnerTrustNotConfigured => "owner_trust_not_configured",
        MailErrorCode::OwnerRecoveryRequired => "owner_recovery_required",
        MailErrorCode::OwnerKeyInactive => "owner_key_inactive",
        MailErrorCode::TrustEpochStale => "trust_epoch_stale",
        MailErrorCode::TrustBundleMismatch => "trust_bundle_mismatch",
        MailErrorCode::ClockRollbackDetected => "clock_rollback_detected",
        MailErrorCode::AuthorizationRequired => "authorization_required",
        MailErrorCode::AuthorizationExpired => "authorization_expired",
        MailErrorCode::AuthorizationInvalidated => "authorization_invalidated",
        MailErrorCode::AuthorizationMalformed => "authorization_malformed",
        MailErrorCode::AuthorizationSignatureInvalid => "authorization_signature_invalid",
        MailErrorCode::AuthorizationReplayed => "authorization_replayed",
        MailErrorCode::AuthorizationContextStale => "authorization_context_stale",
        MailErrorCode::GrantAlreadyUsed => "grant_already_used",
        MailErrorCode::EffectAlreadyClaimed => "effect_already_claimed",
        MailErrorCode::EffectAlreadyInvoked => "effect_already_invoked",
        MailErrorCode::AuthorityProjectionConflict => "authority_projection_conflict",
        MailErrorCode::UnsupportedCapability => "unsupported_capability",
        MailErrorCode::InputNotRegularFile => "input_not_regular_file",
        MailErrorCode::InputLinkRejected => "input_link_rejected",
        MailErrorCode::InputDocumentIncomplete => "input_document_incomplete",
        MailErrorCode::InputNestingLimit => "input_nesting_limit",
        MailErrorCode::McpFrameTooLarge => "mcp_frame_too_large",
        MailErrorCode::McpRequestIdInvalid => "mcp_request_id_invalid",
        MailErrorCode::McpDuplicateRequestId => "mcp_duplicate_request_id",
        MailErrorCode::McpSessionBusy => "mcp_session_busy",
        MailErrorCode::McpOutputTooLarge => "mcp_output_too_large",
        MailErrorCode::RemoteResponseTooLarge => "remote_response_too_large",
        MailErrorCode::RemoteCapabilityIncomplete => "remote_capability_incomplete",
        MailErrorCode::Network => "network",
        MailErrorCode::Tls => "tls",
        MailErrorCode::Authentication => "authentication",
        MailErrorCode::Protocol => "protocol",
        MailErrorCode::MessageNotFound => "message_not_found",
        MailErrorCode::AttachmentNotFound => "attachment_not_found",
        MailErrorCode::ResourceLimit => "resource_limit",
        MailErrorCode::StoreRead => "store_read",
        MailErrorCode::StoreWrite => "store_write",
        MailErrorCode::StoreMigration => "store_migration",
        MailErrorCode::SendPlanNotFound => "send_plan_not_found",
        MailErrorCode::SendPlanState => "send_plan_state",
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

    /// Fetch one bounded mailbox metadata batch without changing remote state.
    ///
    /// # Errors
    ///
    /// Returns a stable validation, transport, authentication, or protocol error.
    fn sync_mailbox(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        request: &MailboxSyncRequest,
    ) -> Result<MailboxSyncBatch, MailError>;

    /// Read one bounded attachment without changing the message seen state.
    ///
    /// # Errors
    ///
    /// Returns a stable validation, transport, parsing, lookup, or resource error.
    fn read_attachment(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        read: &AttachmentRead,
    ) -> Result<AttachmentContent, MailError>;

    /// Resolve one server-declared special-use mailbox without guessing names.
    /// Implementations return `None` when the server did not declare the use.
    ///
    /// # Errors
    ///
    /// Returns a stable account, credential, network, or protocol error when
    /// resolution cannot be completed.
    fn special_mailbox(
        &self,
        _account: &MailAccountConfig,
        _secret: &SecretString,
        _use_kind: MailboxSpecialUse,
    ) -> Result<Option<String>, MailError> {
        Ok(None)
    }
}

pub trait MailboxMutator: Send + Sync {
    /// Apply one exact, already approved IMAP mutation.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteAttemptError`] with the mutation boundary explicitly
    /// marked when the remote result is known or ambiguous.
    fn apply(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        operation_id: &str,
        operation: &MailboxOperationRequest,
    ) -> Result<MailboxOperationReceipt, RemoteAttemptError>;
}

fn validate_scope(account_id: &str, mailbox: &str) -> Result<(), MailError> {
    if account_id.trim().is_empty()
        || account_id.len() > 64
        || mailbox.trim().is_empty()
        || mailbox.chars().count() > MAX_MAILBOX_CHARS
    {
        return Err(MailError::invalid_input(
            "operation requires an account id and mailbox",
        ));
    }
    Ok(())
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
            outgoing: Some(Endpoint {
                protocol: Protocol::Smtp,
                host: "smtp.163.com".to_owned(),
                port: 465,
                security: TransportSecurity::ImplicitTls,
            }),
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

        candidate = account();
        candidate.outgoing.as_mut().expect("SMTP endpoint").protocol = Protocol::Imap;
        assert_eq!(
            candidate.validate().unwrap_err().code,
            MailErrorCode::InvalidInput
        );

        candidate = account();
        candidate.outgoing.as_mut().expect("SMTP endpoint").security = TransportSecurity::Https;
        assert_eq!(
            candidate.validate().unwrap_err().code,
            MailErrorCode::InvalidInput
        );
    }

    #[test]
    fn legacy_account_without_outgoing_endpoint_remains_valid() {
        let serialized = r#"
            id = "personal"
            email = "agent@163.com"
            username = "agent@163.com"
            credential_kind = "app_password"

            [incoming]
            protocol = "imap"
            host = "imap.163.com"
            port = 993
            security = "implicit_tls"
        "#;
        let parsed: MailAccountConfig = toml::from_str(serialized).expect("legacy config");
        assert!(parsed.outgoing.is_none());
        assert!(parsed.validate().is_ok());
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

    #[test]
    fn sync_and_local_search_limits_are_bounded() {
        let request = MailboxSyncRequest {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            cursor: None,
            limit: MAX_SYNC_LIMIT + 1,
        };
        assert_eq!(
            request.validate().unwrap_err().code,
            MailErrorCode::InvalidInput
        );

        let search = LocalMessageSearch {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            from: None,
            to: None,
            subject: None,
            unread: None,
            limit: 0,
        };
        assert_eq!(
            search.validate().unwrap_err().code,
            MailErrorCode::InvalidInput
        );
    }

    #[test]
    fn attachment_reads_require_server_returned_ids_and_strict_bounds() {
        let reference = MessageReference {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            uid_validity: Some(7),
            uid: 2,
        };
        let valid = AttachmentRead {
            reference: reference.clone(),
            part_id: "attachment-2".to_owned(),
            max_bytes: DEFAULT_ATTACHMENT_BYTES,
        };
        assert_eq!(valid.attachment_index().expect("index"), 1);

        let invalid = AttachmentRead {
            reference,
            part_id: "2".to_owned(),
            max_bytes: MAX_ATTACHMENT_BYTES + 1,
        };
        assert_eq!(
            invalid.validate().unwrap_err().code,
            MailErrorCode::InvalidInput
        );
    }
}
