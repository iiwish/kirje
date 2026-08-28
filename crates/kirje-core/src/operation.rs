use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    MailAddress, MailError, MailErrorCode, MessageContent, MessageReference, SendAttachment,
    SendRequest,
};

pub const OPERATION_TTL_HOURS: i64 = 24;
pub const MAX_DRAFTS: u16 = 100;
pub const DEFAULT_OPERATION_LIMIT: u16 = 25;
pub const MAX_OPERATION_LIMIT: u16 = 100;
pub const MAX_SUMMARY_CHARS: usize = 4_096;
const MAX_OPERATION_MAILBOX_CHARS: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftMode {
    New,
    Reply,
    ReplyAll,
    Forward,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DraftInput {
    pub account_id: String,
    pub mode: DraftMode,
    #[serde(default)]
    pub source: Option<MessageContent>,
    #[serde(default)]
    pub to: Vec<MailAddress>,
    #[serde(default)]
    pub cc: Vec<MailAddress>,
    #[serde(default)]
    pub bcc: Vec<MailAddress>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub attachments: Vec<SendAttachment>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftStatus {
    Draft,
    Discarded,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Draft {
    pub id: String,
    pub account_id: String,
    pub mode: DraftMode,
    pub source: Option<MessageReference>,
    pub request: SendRequest,
    pub attachment_summaries: Vec<AttachmentSummary>,
    pub status: DraftStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DraftSummary {
    pub id: String,
    pub account_id: String,
    pub mode: DraftMode,
    pub source: Option<MessageReference>,
    pub subject: String,
    pub recipient_count: usize,
    pub attachment_summaries: Vec<AttachmentSummary>,
    pub status: DraftStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Draft {
    /// Compose and validate a private local draft from a bounded input.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error when composition, recipients, or
    /// attachment bounds are invalid.
    pub fn create(
        input: DraftInput,
        account_email: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, MailError> {
        let request = compose_request(&input, account_email)?;
        let source = input
            .source
            .as_ref()
            .map(|message| message.reference.clone());
        let attachment_summaries = request.attachment_summaries()?;
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            account_id: input.account_id,
            mode: input.mode,
            source,
            request,
            attachment_summaries,
            status: DraftStatus::Draft,
            created_at: now,
            updated_at: now,
        })
    }

    /// Replace a draft's mutable content while preserving its identity.
    ///
    /// # Errors
    ///
    /// Returns a stable state or validation error when the draft is discarded
    /// or the replacement content is invalid.
    pub fn update(
        &self,
        input: DraftInput,
        account_email: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, MailError> {
        if self.status != DraftStatus::Draft {
            return Err(operation_state_error("discarded draft cannot be edited"));
        }
        let mut updated = Self::create(input, account_email, now)?;
        updated.id.clone_from(&self.id);
        updated.created_at = self.created_at;
        Ok(updated)
    }

    #[must_use]
    pub fn summary(&self) -> DraftSummary {
        DraftSummary {
            id: self.id.clone(),
            account_id: self.account_id.clone(),
            mode: self.mode,
            source: self.source.clone(),
            subject: self.request.subject.clone(),
            recipient_count: self.request.to.len() + self.request.cc.len() + self.request.bcc.len(),
            attachment_summaries: self.attachment_summaries.clone(),
            status: self.status,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AttachmentSummary {
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_preview: Option<String>,
    pub untrusted: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MailOperationKind {
    SetRead,
    SetStarred,
    Move,
    Archive,
    Delete,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxOperationRequest {
    pub account_id: String,
    pub kind: MailOperationKind,
    pub reference: MessageReference,
    #[serde(default)]
    pub value: Option<bool>,
    #[serde(default)]
    pub destination: Option<String>,
}

impl MailboxOperationRequest {
    /// Validate an exact, bounded remote mutation payload.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error for mismatched scope, flags, or
    /// destinations.
    pub fn validate(&self) -> Result<(), MailError> {
        validate_account_id(&self.account_id)?;
        self.reference.validate()?;
        if self.reference.uid_validity.is_none() {
            return Err(MailError::invalid_input(
                "remote mailbox operations require UIDVALIDITY",
            ));
        }
        if self.reference.account_id != self.account_id {
            return Err(MailError::invalid_input(
                "operation account does not match message reference",
            ));
        }
        match self.kind {
            MailOperationKind::SetRead | MailOperationKind::SetStarred => {
                if self.value.is_none() || self.destination.is_some() {
                    return Err(MailError::invalid_input(
                        "flag operations require value and no destination",
                    ));
                }
            }
            MailOperationKind::Move | MailOperationKind::Archive | MailOperationKind::Delete => {
                if self.destination.as_deref().is_some_and(|destination| {
                    destination.trim().is_empty()
                        || destination.chars().count() > MAX_OPERATION_MAILBOX_CHARS
                        || destination.chars().any(char::is_control)
                }) {
                    return Err(MailError::invalid_input(
                        "destination mailbox is empty or malformed",
                    ));
                }
                if matches!(self.kind, MailOperationKind::Move) && self.destination.is_none() {
                    return Err(MailError::invalid_input(
                        "move operations require a destination mailbox",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct MailboxOperationReceipt {
    pub operation_id: String,
    pub kind: MailOperationKind,
    pub account_id: String,
    pub reference: MessageReference,
    pub destination: Option<String>,
    pub changed: bool,
    pub applied_at: DateTime<Utc>,
    pub untrusted: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Planned,
    Approved,
    Applying,
    Succeeded,
    Failed,
    Ambiguous,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct OperationRecord {
    pub id: String,
    pub kind: String,
    pub account_id: String,
    #[serde(default)]
    pub message_id: Option<String>,
    pub payload_json: String,
    pub payload_sha256: String,
    pub status: OperationStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub approved_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub attempt_count: u32,
    pub last_error: Option<MailError>,
    pub receipt_json: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct OperationSummary {
    pub id: String,
    pub kind: String,
    pub account_id: String,
    pub message_id: Option<String>,
    pub payload_sha256: String,
    pub status: OperationStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub approved_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub attempt_count: u32,
    pub last_error: Option<MailError>,
}

impl OperationRecord {
    #[must_use]
    pub fn summary(&self) -> OperationSummary {
        OperationSummary {
            id: self.id.clone(),
            kind: self.kind.clone(),
            account_id: self.account_id.clone(),
            message_id: self.message_id.clone(),
            payload_sha256: self.payload_sha256.clone(),
            status: self.status,
            created_at: self.created_at,
            expires_at: self.expires_at,
            approved_at: self.approved_at,
            updated_at: self.updated_at,
            attempt_count: self.attempt_count,
            last_error: self.last_error.clone(),
        }
    }
}

#[allow(clippy::missing_errors_doc)]
pub trait OperationLedger: Send + Sync {
    fn create_operation(&self, operation: &OperationRecord) -> Result<OperationRecord, MailError>;
    fn get_operation(
        &self,
        operation_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<OperationRecord>, MailError>;
    fn list_operations(
        &self,
        account_id: Option<&str>,
        kind: Option<&str>,
        limit: u16,
        now: DateTime<Utc>,
    ) -> Result<Vec<OperationRecord>, MailError>;
    fn approve_operation(
        &self,
        operation_id: &str,
        now: DateTime<Utc>,
    ) -> Result<OperationRecord, MailError>;
    fn claim_operation(
        &self,
        operation_id: &str,
        now: DateTime<Utc>,
    ) -> Result<OperationRecord, MailError>;
    fn succeed_operation(
        &self,
        operation_id: &str,
        receipt_json: String,
        now: DateTime<Utc>,
    ) -> Result<OperationRecord, MailError>;
    fn fail_operation(
        &self,
        operation_id: &str,
        error: MailError,
        now: DateTime<Utc>,
    ) -> Result<OperationRecord, MailError>;
    fn ambiguous_operation(
        &self,
        operation_id: &str,
        error: MailError,
        now: DateTime<Utc>,
    ) -> Result<OperationRecord, MailError>;
    fn audit(&self, operation_id: &str, limit: u16) -> Result<Vec<OperationEvent>, MailError>;
    fn create_draft(&self, draft: &Draft) -> Result<Draft, MailError>;
    fn get_draft(&self, draft_id: &str) -> Result<Option<Draft>, MailError>;
    fn list_drafts(&self, account_id: &str, limit: u16) -> Result<Vec<Draft>, MailError>;
    fn update_draft(&self, draft: &Draft) -> Result<Draft, MailError>;
    fn discard_draft(&self, draft_id: &str, now: DateTime<Utc>) -> Result<Draft, MailError>;
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct OperationEvent {
    pub sequence: i64,
    pub operation_id: String,
    pub event: String,
    pub status: Option<OperationStatus>,
    pub occurred_at: DateTime<Utc>,
    pub payload_sha256: String,
    pub detail: Option<String>,
}

pub fn operation_record(
    id: String,
    kind: impl Into<String>,
    account_id: String,
    payload_json: String,
    payload_sha256: String,
    now: DateTime<Utc>,
) -> OperationRecord {
    OperationRecord {
        id,
        kind: kind.into(),
        account_id,
        message_id: None,
        payload_json,
        payload_sha256,
        status: OperationStatus::Planned,
        created_at: now,
        expires_at: Some(now + Duration::hours(OPERATION_TTL_HOURS)),
        approved_at: None,
        updated_at: now,
        attempt_count: 0,
        last_error: None,
        receipt_json: None,
    }
}

/// Serialize a payload using the stable JSON representation used by the ledger.
///
/// # Errors
///
/// Returns an internal error when the payload cannot be serialized.
pub fn digest_json<T: Serialize>(value: &T) -> Result<(String, String), MailError> {
    let payload_json = serde_json::to_string(value).map_err(|_| {
        MailError::new(
            MailErrorCode::Internal,
            "cannot serialize operation payload",
            false,
        )
    })?;
    let payload_sha256 = format!("{:x}", Sha256::digest(payload_json.as_bytes()));
    Ok((payload_json, payload_sha256))
}

/// Compose a deterministic send request from a new, reply, reply-all, or
/// forward draft input.
///
/// # Errors
///
/// Returns a stable validation error when the source, recipients, body, or
/// attachments are invalid.
pub fn compose_request(input: &DraftInput, account_email: &str) -> Result<SendRequest, MailError> {
    validate_account_id(&input.account_id)?;
    let source = input.source.as_ref();
    if let Some(source) = source
        && source.reference.account_id != input.account_id
    {
        return Err(MailError::invalid_input(
            "draft source message must belong to the draft account",
        ));
    }
    match (input.mode, source.is_some()) {
        (DraftMode::New, true) => {
            return Err(MailError::invalid_input(
                "new drafts cannot include a source message",
            ));
        }
        (DraftMode::Reply | DraftMode::ReplyAll | DraftMode::Forward, false) => {
            return Err(MailError::invalid_input(
                "this draft mode requires a source message",
            ));
        }
        _ => {}
    }

    let mut to = input.to.clone();
    let mut cc = input.cc.clone();
    if to.is_empty()
        && let Some(source) = source
    {
        to = match input.mode {
            DraftMode::Reply => source
                .reply_to
                .first()
                .cloned()
                .or_else(|| source.from.first().cloned())
                .into_iter()
                .collect(),
            DraftMode::ReplyAll => reply_all_to(source, account_email),
            DraftMode::Forward | DraftMode::New => Vec::new(),
        };
    }
    if matches!(input.mode, DraftMode::ReplyAll)
        && input.cc.is_empty()
        && let Some(source) = source
    {
        cc = reply_all_cc(source, account_email);
    }
    let subject = input.subject.clone().unwrap_or_else(|| {
        source.map_or_else(String::new, |source| {
            let prefix = if matches!(input.mode, DraftMode::Forward) {
                "Fwd: "
            } else {
                "Re: "
            };
            if source
                .subject
                .to_ascii_lowercase()
                .starts_with(&prefix.to_ascii_lowercase())
            {
                source.subject.clone()
            } else {
                format!("{prefix}{}", source.subject)
            }
        })
    });
    let text = input
        .text
        .clone()
        .or_else(|| source.and_then(|source| quote_source(input.mode, source)));
    let request = SendRequest {
        account_id: input.account_id.clone(),
        to,
        cc,
        bcc: input.bcc.clone(),
        subject,
        text,
        html: input.html.clone(),
        attachments: input.attachments.clone(),
    };
    request.validate()?;
    Ok(request)
}

fn reply_all_to(source: &MessageContent, account_email: &str) -> Vec<MailAddress> {
    let mut seen = HashSet::new();
    source
        .from
        .iter()
        .filter(|address| !same_address(address, account_email))
        .filter(|address| seen.insert(address.email.to_ascii_lowercase()))
        .cloned()
        .collect()
}

fn reply_all_cc(source: &MessageContent, account_email: &str) -> Vec<MailAddress> {
    let mut seen = HashSet::new();
    source
        .to
        .iter()
        .chain(source.cc.iter())
        .filter(|address| !same_address(address, account_email))
        .filter(|address| seen.insert(address.email.to_ascii_lowercase()))
        .cloned()
        .collect()
}

fn same_address(address: &MailAddress, account_email: &str) -> bool {
    address
        .email
        .trim()
        .eq_ignore_ascii_case(account_email.trim())
}

fn quote_source(mode: DraftMode, source: &MessageContent) -> Option<String> {
    let body = source.text.as_deref().unwrap_or_default();
    if body.is_empty() && matches!(mode, DraftMode::Reply | DraftMode::ReplyAll) {
        return None;
    }
    let from = source
        .from
        .first()
        .map_or("unknown sender", |address| address.email.as_str());
    let header = if matches!(mode, DraftMode::Forward) {
        format!(
            "\n\n----- Forwarded message -----\nFrom: {from}\nSubject: {}\n\n",
            source.subject
        )
    } else {
        format!("\n\nOn behalf of {from}, wrote:\n")
    };
    let mut quoted = String::new();
    for line in body.lines() {
        quoted.push_str("> ");
        quoted.push_str(line);
        quoted.push('\n');
    }
    Some(format!("{header}{quoted}"))
}

fn validate_account_id(value: &str) -> Result<(), MailError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(MailError::invalid_input(
            "account id must use 1-64 safe characters",
        ));
    }
    Ok(())
}

fn operation_state_error(message: impl Into<String>) -> MailError {
    MailError::new(MailErrorCode::SendPlanState, message, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    fn source() -> MessageContent {
        MessageContent {
            reference: MessageReference {
                account_id: "personal".to_owned(),
                mailbox: "INBOX".to_owned(),
                uid_validity: Some(7),
                uid: 42,
            },
            message_id: Some("<source@example.com>".to_owned()),
            subject: "Quarterly report".to_owned(),
            from: vec![MailAddress {
                name: Some("Alice".to_owned()),
                email: "alice@example.com".to_owned(),
            }],
            to: vec![MailAddress {
                name: None,
                email: "agent@example.com".to_owned(),
            }],
            cc: vec![MailAddress {
                name: None,
                email: "bob@example.com".to_owned(),
            }],
            reply_to: Vec::new(),
            sent_at: None,
            text: Some("hello\nworld".to_owned()),
            sanitized_html: None,
            attachments: Vec::new(),
            untrusted: true,
            truncated: false,
        }
    }

    fn input(mode: DraftMode) -> DraftInput {
        DraftInput {
            account_id: "personal".to_owned(),
            mode,
            source: Some(source()),
            to: Vec::new(),
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: None,
            text: None,
            html: None,
            attachments: Vec::new(),
        }
    }

    #[test]
    fn reply_all_removes_self_and_deduplicates_recipients() {
        let request =
            compose_request(&input(DraftMode::ReplyAll), "agent@example.com").expect("reply-all");

        assert_eq!(request.to[0].email, "alice@example.com");
        assert_eq!(request.cc.len(), 1);
        assert_eq!(request.cc[0].email, "bob@example.com");
        assert_eq!(request.subject, "Re: Quarterly report");
        assert!(request.text.expect("quoted text").contains("> hello"));
    }

    #[test]
    fn forward_requires_explicit_recipient() {
        let error = compose_request(&input(DraftMode::Forward), "agent@example.com").unwrap_err();
        assert_eq!(error.code, MailErrorCode::InvalidInput);

        let mut forwarded = input(DraftMode::Forward);
        forwarded.to.push(MailAddress {
            name: None,
            email: "recipient@example.com".to_owned(),
        });
        let request = compose_request(&forwarded, "agent@example.com").expect("forward");
        assert_eq!(request.subject, "Fwd: Quarterly report");
    }

    #[test]
    fn attachment_summary_is_bounded_and_deterministic() {
        let attachment = SendAttachment {
            filename: "note.txt".to_owned(),
            mime_type: "text/plain".to_owned(),
            content_base64: "aGVsbG8=".to_owned(),
        };
        let summary = attachment.summary().expect("summary");
        assert_eq!(summary.size, 5);
        assert_eq!(summary.sha256.len(), 64);
        assert_eq!(summary.text_preview.as_deref(), Some("hello"));
        assert!(summary.untrusted);
    }

    #[test]
    fn draft_keeps_private_identity_and_attachment_snapshot() {
        let mut draft_input = input(DraftMode::Reply);
        draft_input.attachments.push(SendAttachment {
            filename: "note.txt".to_owned(),
            mime_type: "text/plain".to_owned(),
            content_base64: "aGVsbG8=".to_owned(),
        });
        let draft = Draft::create(
            draft_input,
            "agent@example.com",
            Utc.with_ymd_and_hms(2026, 8, 27, 0, 0, 0).unwrap(),
        )
        .expect("draft");
        assert_eq!(draft.status, DraftStatus::Draft);
        assert_eq!(draft.attachment_summaries[0].filename, "note.txt");
        assert_eq!(draft.source.expect("source").uid, 42);
    }

    #[test]
    fn remote_operations_require_uid_validity() {
        let mut operation = MailboxOperationRequest {
            account_id: "personal".to_owned(),
            kind: MailOperationKind::SetRead,
            reference: source().reference,
            value: Some(true),
            destination: None,
        };
        operation.reference.uid_validity = None;
        let error = operation.validate().expect_err("missing UIDVALIDITY");
        assert_eq!(error.code, MailErrorCode::InvalidInput);
    }
}
