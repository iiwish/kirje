use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use secrecy::SecretString;

use crate::{MailAccountConfig, MailAddress, MailError, MailErrorCode};

pub const MAX_SEND_RECIPIENTS: usize = 50;
pub const MAX_SEND_SUBJECT_CHARS: usize = 998;
pub const MAX_SEND_BODY_CHARS: usize = 262_144;
pub const MAX_ATTACHMENTS: usize = 25;
pub const MAX_SEND_ATTACHMENT_BYTES: usize = 1024 * 1024;
pub const MAX_TOTAL_ATTACHMENT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ATTACHMENT_FILENAME_CHARS: usize = 255;
pub const MAX_ATTACHMENT_MIME_CHARS: usize = 127;
pub const SEND_PLAN_TTL_HOURS: i64 = 24;
pub const DEFAULT_SEND_PLAN_LIMIT: u16 = 25;
pub const MAX_SEND_PLAN_LIMIT: u16 = 100;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SendRequest {
    pub account_id: String,
    pub to: Vec<MailAddress>,
    #[serde(default)]
    pub cc: Vec<MailAddress>,
    #[serde(default)]
    pub bcc: Vec<MailAddress>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    #[serde(default)]
    pub attachments: Vec<SendAttachment>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SendAttachment {
    pub filename: String,
    pub mime_type: String,
    pub content_base64: String,
}

impl SendAttachment {
    /// Validate a bounded base64 attachment snapshot.
    ///
    /// # Errors
    ///
    /// Returns a stable validation or resource-limit error when metadata or
    /// decoded content is unsafe or too large.
    pub fn validate(&self) -> Result<Vec<u8>, MailError> {
        if self.filename.is_empty()
            || self.filename.chars().count() > MAX_ATTACHMENT_FILENAME_CHARS
            || self.filename.chars().any(char::is_control)
            || self.filename.contains(['/', '\\'])
            || self.mime_type.is_empty()
            || self.mime_type.chars().count() > MAX_ATTACHMENT_MIME_CHARS
            || self.mime_type.chars().any(char::is_control)
            || !valid_mime_type(&self.mime_type)
        {
            return Err(MailError::invalid_input("attachment metadata is malformed"));
        }
        let max_encoded_bytes = 4 * MAX_SEND_ATTACHMENT_BYTES.div_ceil(3);
        if self.content_base64.len() > max_encoded_bytes {
            return Err(MailError::new(
                MailErrorCode::ResourceLimit,
                format!("each attachment cannot exceed {MAX_SEND_ATTACHMENT_BYTES} bytes"),
                false,
            ));
        }
        let bytes = BASE64_STANDARD.decode(&self.content_base64).map_err(|_| {
            MailError::invalid_input("attachment content_base64 must be valid base64")
        })?;
        if bytes.len() > MAX_SEND_ATTACHMENT_BYTES {
            return Err(MailError::new(
                MailErrorCode::ResourceLimit,
                format!("each attachment cannot exceed {MAX_SEND_ATTACHMENT_BYTES} bytes"),
                false,
            ));
        }
        Ok(bytes)
    }

    /// Produce a deterministic, bounded summary without invoking a model.
    ///
    /// # Errors
    ///
    /// Returns the same validation or resource-limit error as [`Self::validate`].
    pub fn summary(&self) -> Result<crate::AttachmentSummary, MailError> {
        let bytes = self.validate()?;
        let text_preview = std::str::from_utf8(&bytes).ok().map(|text| {
            text.chars()
                .take(crate::MAX_SUMMARY_CHARS)
                .collect::<String>()
        });
        Ok(crate::AttachmentSummary {
            filename: self.filename.clone(),
            mime_type: self.mime_type.clone(),
            size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            text_preview,
            untrusted: true,
        })
    }
}

fn valid_mime_type(value: &str) -> bool {
    let mut parts = value.split('/');
    let Some(top_level) = parts.next() else {
        return false;
    };
    let Some(subtype) = parts.next() else {
        return false;
    };
    !top_level.is_empty()
        && !subtype.is_empty()
        && parts.next().is_none()
        && top_level
            .bytes()
            .chain(subtype.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

impl SendRequest {
    /// Validate the complete immutable content covered by send approval.
    ///
    /// # Errors
    ///
    /// Returns a stable input or resource-limit error for unsafe or unbounded
    /// message content.
    pub fn validate(&self) -> Result<(), MailError> {
        if self.account_id.is_empty()
            || self.account_id.len() > 64
            || !self
                .account_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(MailError::invalid_input(
                "account id must use 1-64 ASCII letters, numbers, '-' or '_'",
            ));
        }

        let recipients = self.to.len() + self.cc.len() + self.bcc.len();
        if recipients == 0 {
            return Err(MailError::invalid_input(
                "send request requires at least one recipient",
            ));
        }
        if recipients > MAX_SEND_RECIPIENTS {
            return Err(MailError::new(
                MailErrorCode::ResourceLimit,
                format!("send request cannot exceed {MAX_SEND_RECIPIENTS} recipients"),
                false,
            ));
        }
        for address in self.to.iter().chain(&self.cc).chain(&self.bcc) {
            validate_address(address)?;
        }

        if self.subject.chars().count() > MAX_SEND_SUBJECT_CHARS
            || self.subject.chars().any(char::is_control)
        {
            return Err(MailError::invalid_input(
                "subject must be free of control characters and at most 998 characters",
            ));
        }
        if self.text.as_deref().is_none_or(str::is_empty)
            && self.html.as_deref().is_none_or(str::is_empty)
        {
            return Err(MailError::invalid_input(
                "send request requires a non-empty text or HTML body",
            ));
        }
        if self
            .text
            .as_ref()
            .is_some_and(|body| body.chars().count() > MAX_SEND_BODY_CHARS)
            || self
                .html
                .as_ref()
                .is_some_and(|body| body.chars().count() > MAX_SEND_BODY_CHARS)
        {
            return Err(MailError::new(
                MailErrorCode::ResourceLimit,
                format!("each send body cannot exceed {MAX_SEND_BODY_CHARS} characters"),
                false,
            ));
        }
        if self.attachments.len() > MAX_ATTACHMENTS {
            return Err(MailError::new(
                MailErrorCode::ResourceLimit,
                format!("send request cannot exceed {MAX_ATTACHMENTS} attachments"),
                false,
            ));
        }
        let total_attachment_bytes = self
            .attachments
            .iter()
            .map(SendAttachment::validate)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|bytes| bytes.len())
            .sum::<usize>();
        if total_attachment_bytes > MAX_TOTAL_ATTACHMENT_BYTES {
            return Err(MailError::new(
                MailErrorCode::ResourceLimit,
                format!("attachments cannot exceed {MAX_TOTAL_ATTACHMENT_BYTES} bytes in total"),
                false,
            ));
        }
        Ok(())
    }

    /// Return deterministic summaries for every imported attachment.
    ///
    /// # Errors
    ///
    /// Returns a stable validation or resource-limit error when an attachment
    /// snapshot is invalid.
    pub fn attachment_summaries(&self) -> Result<Vec<crate::AttachmentSummary>, MailError> {
        self.attachments
            .iter()
            .map(SendAttachment::summary)
            .collect()
    }
}

fn validate_address(address: &MailAddress) -> Result<(), MailError> {
    let Some((local, domain)) = address.email.rsplit_once('@') else {
        return Err(MailError::invalid_input(
            "recipient email address is malformed",
        ));
    };
    if local.is_empty()
        || domain.is_empty()
        || local.contains('@')
        || domain.contains('@')
        || !domain.contains('.')
        || address.email.len() > 320
        || address.email.chars().any(char::is_whitespace)
        || address.email.chars().any(char::is_control)
        || address
            .name
            .as_ref()
            .is_some_and(|name| name.chars().count() > 256 || name.chars().any(char::is_control))
    {
        return Err(MailError::invalid_input(
            "recipient email address is malformed",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SendPlanStatus {
    Planned,
    Approved,
    Applying,
    Sent,
    Failed,
    Ambiguous,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SendReceipt {
    pub accepted: bool,
    pub server_response: Option<String>,
    pub sent_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendAttemptError {
    pub error: MailError,
    pub delivery_started: bool,
}

impl SendAttemptError {
    #[must_use]
    pub fn before_delivery(error: MailError) -> Self {
        Self {
            error,
            delivery_started: false,
        }
    }

    #[must_use]
    pub fn after_delivery_started(error: MailError) -> Self {
        Self {
            error,
            delivery_started: true,
        }
    }
}

pub trait MailSender: Send + Sync {
    /// Submit one already claimed plan through the configured outgoing endpoint.
    ///
    /// # Errors
    ///
    /// Distinguishes local construction failures from errors after the SMTP
    /// delivery invocation has begun.
    fn send(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        plan: &SendPlan,
    ) -> Result<SendReceipt, SendAttemptError>;
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SendPlan {
    pub id: String,
    pub request: SendRequest,
    pub content_sha256: String,
    pub message_id: String,
    #[serde(default)]
    pub attachment_summaries: Vec<crate::AttachmentSummary>,
    pub status: SendPlanStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub attempt_count: u32,
    pub last_error: Option<MailError>,
    pub receipt: Option<SendReceipt>,
}

impl SendPlan {
    /// Create a new immutable plan identity from a validated request.
    ///
    /// # Errors
    ///
    /// Returns request validation or serialization errors.
    pub fn create(request: SendRequest, now: DateTime<Utc>) -> Result<Self, MailError> {
        request.validate()?;
        let attachment_summaries = request.attachment_summaries()?;
        let canonical = serde_json::to_vec(&request).map_err(|_| {
            MailError::new(
                MailErrorCode::Internal,
                "cannot serialize the send request",
                false,
            )
        })?;
        let content_sha256 = format!("{:x}", Sha256::digest(canonical));
        let domain = request
            .to
            .first()
            .and_then(|address| address.email.rsplit_once('@'))
            .map_or("kirje.local", |(_, domain)| domain);
        let id = Uuid::new_v4().to_string();
        let message_id = format!("<{}@{}>", Uuid::new_v4(), domain.to_ascii_lowercase());

        Ok(Self {
            id,
            request,
            content_sha256,
            message_id,
            attachment_summaries,
            status: SendPlanStatus::Planned,
            created_at: now,
            expires_at: now + Duration::hours(SEND_PLAN_TTL_HOURS),
            approved_at: None,
            updated_at: now,
            attempt_count: 0,
            last_error: None,
            receipt: None,
        })
    }

    #[must_use]
    pub fn summary(&self) -> SendPlanSummary {
        SendPlanSummary {
            id: self.id.clone(),
            account_id: self.request.account_id.clone(),
            recipient_count: self.request.to.len() + self.request.cc.len() + self.request.bcc.len(),
            subject: self.request.subject.clone(),
            content_sha256: self.content_sha256.clone(),
            message_id: self.message_id.clone(),
            attachment_summaries: self.attachment_summaries.clone(),
            status: self.status,
            created_at: self.created_at,
            expires_at: self.expires_at,
            approved_at: self.approved_at,
            updated_at: self.updated_at,
            attempt_count: self.attempt_count,
            last_error: self.last_error.clone(),
            receipt: self.receipt.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SendPlanSummary {
    pub id: String,
    pub account_id: String,
    pub recipient_count: usize,
    pub subject: String,
    pub content_sha256: String,
    pub message_id: String,
    #[serde(default)]
    pub attachment_summaries: Vec<crate::AttachmentSummary>,
    pub status: SendPlanStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub attempt_count: u32,
    pub last_error: Option<MailError>,
    pub receipt: Option<SendReceipt>,
}

pub trait Outbox: crate::OperationLedger + Send + Sync {
    /// Persist a newly planned immutable message.
    ///
    /// # Errors
    ///
    /// Returns stable validation or store errors.
    fn create(&self, plan: &SendPlan) -> Result<SendPlan, MailError>;

    /// Read one plan and reconcile expiry or stale in-flight state.
    ///
    /// # Errors
    ///
    /// Returns stable store errors.
    fn get(&self, plan_id: &str, now: DateTime<Utc>) -> Result<Option<SendPlan>, MailError>;

    /// List bounded plan summaries without exposing message bodies.
    ///
    /// # Errors
    ///
    /// Returns stable validation or store errors.
    fn list(
        &self,
        account_id: Option<&str>,
        limit: u16,
        now: DateTime<Utc>,
    ) -> Result<Vec<SendPlanSummary>, MailError>;

    /// Atomically approve one unexpired planned message.
    ///
    /// # Errors
    ///
    /// Returns not-found, invalid-state, or store errors.
    fn approve(&self, plan_id: &str, now: DateTime<Utc>) -> Result<SendPlan, MailError>;

    /// Atomically claim an approved plan for its only SMTP invocation.
    ///
    /// # Errors
    ///
    /// Returns not-found, invalid-state, or store errors.
    fn claim(&self, plan_id: &str, now: DateTime<Utc>) -> Result<SendPlan, MailError>;

    /// Finish an applying plan with an accepted SMTP receipt.
    ///
    /// # Errors
    ///
    /// Returns not-found, invalid-state, or store errors.
    fn mark_sent(&self, plan_id: &str, receipt: SendReceipt) -> Result<SendPlan, MailError>;

    /// Finish an applying plan before any SMTP delivery invocation began.
    ///
    /// # Errors
    ///
    /// Returns not-found, invalid-state, or store errors.
    fn mark_failed(
        &self,
        plan_id: &str,
        error: MailError,
        now: DateTime<Utc>,
    ) -> Result<SendPlan, MailError>;

    /// Finish an applying plan whose SMTP delivery outcome is unknown.
    ///
    /// # Errors
    ///
    /// Returns not-found, invalid-state, or store errors.
    fn mark_ambiguous(
        &self,
        plan_id: &str,
        error: MailError,
        now: DateTime<Utc>,
    ) -> Result<SendPlan, MailError>;
}
