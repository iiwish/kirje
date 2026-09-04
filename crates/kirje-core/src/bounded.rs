use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{MailError, MailErrorCode, Sha256Digest};

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_OPERATION_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_SEND_OR_DRAFT_INPUT_BYTES: usize = 24 * 1024 * 1024;
pub const MAX_AUTHORIZATION_PROOF_BYTES: usize = 4 * 1024;
pub const MAX_AUTHORIZATION_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_READ_SCRATCH_BYTES: usize = 64 * 1024;
pub const MAX_JSON_NESTING_DEPTH: usize = 32;
pub const MAX_JSON_RPC_ID_BYTES: usize = 128;
pub const MAX_JSON_RPC_METHOD_BYTES: usize = 128;
pub const MAX_MCP_ENVELOPE_OVERHEAD_BYTES: usize = 4 * 1024;
pub const MAX_MCP_FRAME_BYTES: usize =
    MAX_SEND_OR_DRAFT_INPUT_BYTES + MAX_MCP_ENVELOPE_OVERHEAD_BYTES;
pub const MAX_MCP_OUTPUT_FRAME_BYTES: usize = 16 * 1024 * 1024 + 4 * 1024;
pub const MAX_MCP_OUTPUT_WIRE_BYTES: usize = MAX_MCP_OUTPUT_FRAME_BYTES + 1;
pub const MAX_MCP_HANDLER_IN_FLIGHT: usize = 4;
pub const MAX_MCP_CONTROL_IN_FLIGHT: usize = 1;
pub const MAX_MCP_ACTIVE_IDS: usize = 4;
pub const MAX_MCP_DELIVERED_TASKS: usize = 5;
pub const MAX_MCP_QUEUE_ITEMS: usize = 5;
pub const MAX_MCP_QUEUED_OUTPUT_BYTES: usize = 2 * MAX_MCP_OUTPUT_WIRE_BYTES;
pub const MAX_MCP_RESERVED_OUTPUT_BYTES: usize = 4 * MAX_MCP_OUTPUT_FRAME_BYTES;
pub const MAX_MCP_SESSION_TASKS: usize = 16;
pub const MAX_MCP_RESPONSE_HANDOFF_MILLIS: u64 = 1_000;
pub const MAX_IMAP_RESPONSE_BYTES: usize = 12 * 1024 * 1024;
pub const MAX_IMAP_CAPABILITIES: usize = 128;
pub const MAX_IMAP_CAPABILITY_BYTES: usize = 256;
pub const MAX_IMAP_CAPABILITIES_TOTAL_BYTES: usize = 16 * 1024;
pub const MAX_REMOTE_VALUE_BYTES: usize = 4 * 1024;
pub const MAX_ADAPTER_DIAGNOSTIC_BYTES: usize = 1024;
pub const MAX_SMTP_RECEIPT_BYTES: usize = 256;
pub const MAX_MACHINE_RESULT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_UNTRUSTED_RESULT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueDisposition {
    Complete,
    Truncated,
    Omitted,
    Rejected,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct BoundedUntrustedText {
    text: String,
    disposition: ValueDisposition,
    untrusted: bool,
    original_bytes: Option<u64>,
}

impl BoundedUntrustedText {
    #[must_use]
    pub fn from_utf8_bytes(bytes: &[u8], max_bytes: usize) -> Self {
        let original_bytes = Some(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Self {
                text: String::new(),
                disposition: ValueDisposition::Rejected,
                untrusted: true,
                original_bytes,
            };
        };
        if bytes.len() <= max_bytes {
            return Self {
                text: text.to_owned(),
                disposition: ValueDisposition::Complete,
                untrusted: true,
                original_bytes,
            };
        }
        let mut end = max_bytes.min(text.len());
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        Self {
            text: text[..end].to_owned(),
            disposition: ValueDisposition::Truncated,
            untrusted: true,
            original_bytes,
        }
    }

    #[must_use]
    pub fn omitted(original_bytes: Option<u64>) -> Self {
        Self {
            text: String::new(),
            disposition: ValueDisposition::Omitted,
            untrusted: true,
            original_bytes,
        }
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn disposition(&self) -> ValueDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn untrusted(&self) -> bool {
        self.untrusted
    }

    #[must_use]
    pub const fn original_bytes(&self) -> Option<u64> {
        self.original_bytes
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum KnownCapability {
    Move,
    UidPlus,
    Idle,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySupport {
    Supported,
    Unsupported,
    Unknown,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProtocolCapabilities {
    known: Vec<KnownCapability>,
    unknown_display: Vec<BoundedUntrustedText>,
    complete: bool,
    source_sha256: Sha256Digest,
}

impl ProtocolCapabilities {
    /// Construct a bounded capability projection suitable for security decisions.
    ///
    /// # Errors
    ///
    /// Returns a resource or validation error when counts, values, or totals overflow.
    pub fn new(
        mut known: Vec<KnownCapability>,
        unknown_display: Vec<BoundedUntrustedText>,
        complete: bool,
        source_sha256: Sha256Digest,
    ) -> Result<Self, MailError> {
        if known
            .len()
            .checked_add(unknown_display.len())
            .is_none_or(|count| count > MAX_IMAP_CAPABILITIES)
        {
            return Err(limit_error("too many protocol capabilities"));
        }
        known.sort_unstable();
        if known.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(MailError::invalid_input(
                "known protocol capabilities must be unique",
            ));
        }
        let mut total = 0usize;
        for value in &unknown_display {
            if value.text.len() > MAX_IMAP_CAPABILITY_BYTES {
                return Err(limit_error("protocol capability is too large"));
            }
            if value.text.chars().any(char::is_control) {
                return Err(MailError::invalid_input(
                    "protocol capability display contains control characters",
                ));
            }
            total = total
                .checked_add(value.text.len())
                .ok_or_else(|| limit_error("protocol capability total is too large"))?;
            if total > MAX_IMAP_CAPABILITIES_TOTAL_BYTES {
                return Err(limit_error("protocol capability total is too large"));
            }
        }
        Ok(Self {
            known,
            unknown_display,
            complete,
            source_sha256,
        })
    }

    #[must_use]
    pub fn support(&self, capability: KnownCapability) -> CapabilitySupport {
        if self.known.binary_search(&capability).is_ok() {
            CapabilitySupport::Supported
        } else if self.complete {
            CapabilitySupport::Unsupported
        } else {
            CapabilitySupport::Unknown
        }
    }

    #[must_use]
    pub fn known(&self) -> &[KnownCapability] {
        &self.known
    }

    #[must_use]
    pub fn unknown_display(&self) -> &[BoundedUntrustedText] {
        &self.unknown_display
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub const fn source_sha256(&self) -> Sha256Digest {
        self.source_sha256
    }
}

fn limit_error(message: &'static str) -> MailError {
    MailError::stable(MailErrorCode::ResourceLimit, message)
}
