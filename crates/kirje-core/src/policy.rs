use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    MailError, MailErrorCode, MailOperationKind, MailboxOperationRequest, SendRequest, digest_json,
};

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountPolicy {
    pub account_id: String,
    #[serde(default)]
    pub allow_remote_write: bool,
    #[serde(default)]
    pub allowed_operations: Vec<MailOperationKind>,
    #[serde(default)]
    pub recipient_allowlist: Vec<String>,
    #[serde(default)]
    pub mailbox_allowlist: Vec<String>,
    #[serde(default)]
    pub max_recipients_per_send: Option<u16>,
    #[serde(default)]
    pub max_send_bytes: Option<u64>,
}

impl AccountPolicy {
    /// Validate the policy fields before storage or activation.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::InvalidInput`] if the account identifier is empty.
    pub fn validate(&self) -> Result<(), MailError> {
        if self.account_id.trim().is_empty() {
            return Err(MailError::invalid_input("account id cannot be empty"));
        }
        Ok(())
    }

    /// Return the safe default read-only policy for a newly created or unconfigured account.
    #[must_use]
    pub fn default_read_only(account_id: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            allow_remote_write: false,
            allowed_operations: Vec::new(),
            recipient_allowlist: Vec::new(),
            mailbox_allowlist: Vec::new(),
            max_recipients_per_send: Some(50),
            max_send_bytes: Some(10 * 1024 * 1024),
        }
    }

    /// Return a governed read-write policy where remote operations are permitted.
    #[must_use]
    pub fn default_governed(account_id: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            allow_remote_write: true,
            allowed_operations: vec![
                MailOperationKind::SetRead,
                MailOperationKind::SetStarred,
                MailOperationKind::Move,
                MailOperationKind::Archive,
                MailOperationKind::Delete,
            ],
            recipient_allowlist: Vec::new(),
            mailbox_allowlist: Vec::new(),
            max_recipients_per_send: Some(50),
            max_send_bytes: Some(10 * 1024 * 1024),
        }
    }

    /// Compute the immutable SHA256 digest of this policy.
    ///
    /// # Errors
    ///
    /// Returns serialization errors if the policy cannot be formatted as JSON.
    pub fn digest(&self) -> Result<String, MailError> {
        let (_, sha256) = digest_json(self)?;
        Ok(sha256)
    }

    /// Evaluate whether a send request complies with this account policy.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::UnsupportedCapability`] if remote write is disabled or a recipient is forbidden,
    /// or [`MailErrorCode::ResourceLimit`] if recipient count exceeds limits.
    pub fn check_send(&self, request: &SendRequest) -> Result<(), MailError> {
        if !self.allow_remote_write {
            return Err(MailError::new(
                MailErrorCode::UnsupportedCapability,
                format!(
                    "account '{}' policy forbids remote write: send is disabled",
                    self.account_id
                ),
                false,
            ));
        }

        let total_recipients = request.to.len() + request.cc.len() + request.bcc.len();
        if let Some(limit) = self.max_recipients_per_send
            && total_recipients > usize::from(limit)
        {
            return Err(MailError::new(
                MailErrorCode::ResourceLimit,
                format!(
                    "send request has {total_recipients} recipients, exceeding the policy limit of {limit}"
                ),
                false,
            ));
        }

        if !self.recipient_allowlist.is_empty() {
            let all_recipients = request.to.iter().chain(&request.cc).chain(&request.bcc);

            for recipient in all_recipients {
                let email = recipient.email.to_ascii_lowercase();
                let allowed = self.recipient_allowlist.iter().any(|allowed_rule| {
                    let rule = allowed_rule.trim().to_ascii_lowercase();
                    if rule.starts_with('@') {
                        email.ends_with(&rule)
                    } else if rule.contains('@') {
                        email == rule
                    } else {
                        email.ends_with(&format!("@{rule}"))
                    }
                });

                if !allowed {
                    return Err(MailError::new(
                        MailErrorCode::UnsupportedCapability,
                        format!(
                            "recipient '{}' is not permitted by account policy",
                            recipient.email
                        ),
                        false,
                    ));
                }
            }
        }

        Ok(())
    }

    /// Evaluate whether a mailbox mutation complies with this account policy.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::UnsupportedCapability`] if remote write is disabled or the operation/mailbox is forbidden.
    pub fn check_mail_operation(&self, request: &MailboxOperationRequest) -> Result<(), MailError> {
        if !self.allow_remote_write {
            return Err(MailError::new(
                MailErrorCode::UnsupportedCapability,
                format!(
                    "account '{}' policy forbids remote write: mailbox mutation is disabled",
                    self.account_id
                ),
                false,
            ));
        }

        if !self.allowed_operations.is_empty() && !self.allowed_operations.contains(&request.kind) {
            return Err(MailError::new(
                MailErrorCode::UnsupportedCapability,
                format!(
                    "operation '{:?}' is not permitted by account policy",
                    request.kind
                ),
                false,
            ));
        }

        if !self.mailbox_allowlist.is_empty() {
            let mailbox = &request.reference.mailbox;
            let source_allowed = self
                .mailbox_allowlist
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(mailbox));
            if !source_allowed {
                return Err(MailError::new(
                    MailErrorCode::UnsupportedCapability,
                    format!("mailbox '{mailbox}' is not permitted by account policy"),
                    false,
                ));
            }

            if let Some(destination) = &request.destination {
                let dest_allowed = self
                    .mailbox_allowlist
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(destination));
                if !dest_allowed {
                    return Err(MailError::new(
                        MailErrorCode::UnsupportedCapability,
                        format!(
                            "destination mailbox '{destination}' is not permitted by account policy"
                        ),
                        false,
                    ));
                }
            }
        }

        Ok(())
    }
}
