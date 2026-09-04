use serde::de::DeserializeOwned;

use crate::{
    AttachmentRead, AuthorizationProof, DraftInput, LocalMessageSearch, MailError, MailErrorCode,
    MailboxOperationRequest, MailboxSyncRequest, MessageRead, MessageSearch, SendRequest,
};

#[derive(Clone, Copy)]
pub(crate) enum InputShape {
    Send,
    Draft,
    Search,
    Sync,
    LocalSearch,
    MailboxOperation,
    AttachmentRead,
    MessageRead,
    AuthorizationProof,
}

mod sealed {
    use super::{InputShape, MailError};

    pub(crate) trait Sealed {
        const SHAPE: InputShape;
        const MAX_BYTES: usize;
        fn validate_input(&self) -> Result<(), MailError>;
    }
}

/// Marker for request types with one sealed allocation and validation contract.
#[allow(private_bounds)]
pub trait BoundedJsonInput: sealed::Sealed + DeserializeOwned {}

macro_rules! bounded_input {
    ($type:ty, $shape:ident, $maximum:expr, $validate:expr) => {
        impl sealed::Sealed for $type {
            const SHAPE: InputShape = InputShape::$shape;
            const MAX_BYTES: usize = $maximum;

            fn validate_input(&self) -> Result<(), MailError> {
                ($validate)(self)
            }
        }

        impl BoundedJsonInput for $type {}
    };
}

bounded_input!(
    SendRequest,
    Send,
    crate::MAX_SEND_OR_DRAFT_INPUT_BYTES,
    SendRequest::validate
);
bounded_input!(
    DraftInput,
    Draft,
    crate::MAX_SEND_OR_DRAFT_INPUT_BYTES,
    validate_draft_input
);
bounded_input!(
    MessageSearch,
    Search,
    crate::MAX_OPERATION_INPUT_BYTES,
    MessageSearch::validate
);
bounded_input!(
    MailboxSyncRequest,
    Sync,
    crate::MAX_OPERATION_INPUT_BYTES,
    MailboxSyncRequest::validate
);
bounded_input!(
    LocalMessageSearch,
    LocalSearch,
    crate::MAX_OPERATION_INPUT_BYTES,
    LocalMessageSearch::validate
);
bounded_input!(
    MailboxOperationRequest,
    MailboxOperation,
    crate::MAX_OPERATION_INPUT_BYTES,
    MailboxOperationRequest::validate
);
bounded_input!(
    AttachmentRead,
    AttachmentRead,
    crate::MAX_OPERATION_INPUT_BYTES,
    AttachmentRead::validate
);
bounded_input!(
    MessageRead,
    MessageRead,
    crate::MAX_OPERATION_INPUT_BYTES,
    MessageRead::validate
);
bounded_input!(
    AuthorizationProof,
    AuthorizationProof,
    crate::MAX_AUTHORIZATION_PROOF_BYTES,
    validate_authorization_proof
);

/// Parse one complete JSON request through the shape owned by its sealed type.
///
/// The lexical pass enforces byte, nesting, string, Base64, and decoded-total
/// budgets before serde constructs the typed request. No JSON DOM is built.
///
/// # Errors
///
/// Returns stable input, nesting, or resource-limit errors.
pub fn parse_bounded_json<T: BoundedJsonInput>(bytes: &[u8]) -> Result<T, MailError> {
    if bytes.len() > T::MAX_BYTES {
        return Err(resource("input document exceeds its byte budget"));
    }
    lexical_preflight(bytes, T::SHAPE)?;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)
        .map_err(|_| MailError::invalid_input("JSON input does not match the request contract"))?;
    deserializer
        .end()
        .map_err(|_| MailError::invalid_input("JSON input contains trailing data"))?;
    value.validate_input()?;
    Ok(value)
}

fn validate_draft_input(input: &DraftInput) -> Result<(), MailError> {
    if input.account_id.is_empty()
        || input.account_id.len() > 64
        || !input
            .account_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(MailError::invalid_input("draft account id is malformed"));
    }
    let recipient_count = input.to.len() + input.cc.len() + input.bcc.len();
    if recipient_count > crate::MAX_SEND_RECIPIENTS {
        return Err(resource("draft has too many recipients"));
    }
    if input.attachments.len() > crate::MAX_ATTACHMENTS {
        return Err(resource("draft has too many attachments"));
    }
    let mut total = 0usize;
    for attachment in &input.attachments {
        let decoded = attachment.validate()?;
        total = total
            .checked_add(decoded.len())
            .ok_or_else(|| resource("draft attachment total overflowed"))?;
        if total > crate::MAX_TOTAL_ATTACHMENT_BYTES {
            return Err(resource(
                "draft attachments exceed the decoded-total budget",
            ));
        }
    }
    Ok(())
}

fn validate_authorization_proof(proof: &AuthorizationProof) -> Result<(), MailError> {
    if proof.contract_version != "kirje.authorization-proof.v1" {
        return Err(MailError::stable(
            MailErrorCode::AuthorizationMalformed,
            "authorization proof contract version is unsupported",
        ));
    }
    proof.signature_bytes().map(|_| ())
}

#[allow(clippy::too_many_lines)]
fn lexical_preflight(bytes: &[u8], shape: InputShape) -> Result<(), MailError> {
    enum Container {
        Object {
            members: usize,
        },
        Array {
            field: Option<String>,
            items: usize,
            maximum: usize,
            counts_as_recipient: bool,
        },
    }

    let mut cursor = 0usize;
    let mut depth = 0usize;
    let mut containers = Vec::with_capacity(crate::MAX_JSON_NESTING_DEPTH);
    let mut current_key: Option<String> = None;
    let mut decoded_attachment_total = 0usize;
    let mut recipient_items = 0usize;

    while cursor < bytes.len() {
        match bytes[cursor] {
            b'{' => {
                depth += 1;
                if depth > crate::MAX_JSON_NESTING_DEPTH {
                    return Err(MailError::stable(
                        MailErrorCode::InputNestingLimit,
                        "JSON nesting exceeds the contract",
                    ));
                }
                containers.push(Container::Object { members: 0 });
                cursor += 1;
            }
            b'[' => {
                depth += 1;
                if depth > crate::MAX_JSON_NESTING_DEPTH {
                    return Err(MailError::stable(
                        MailErrorCode::InputNestingLimit,
                        "JSON nesting exceeds the contract",
                    ));
                }
                let field = current_key.clone();
                let top_level = containers.len() == 1;
                let maximum = match field.as_deref() {
                    Some("to" | "cc" | "bcc") => crate::MAX_SEND_RECIPIENTS,
                    Some("attachments") if top_level => crate::MAX_ATTACHMENTS,
                    Some("attachments" | "from" | "reply_to" | "references") => 100,
                    _ => crate::MAX_SYNC_LIMIT as usize,
                };
                let next = skip_whitespace(bytes, cursor + 1);
                let items = usize::from(bytes.get(next) != Some(&b']'));
                containers.push(Container::Array {
                    field,
                    items,
                    maximum,
                    counts_as_recipient: top_level
                        && matches!(current_key.as_deref(), Some("to" | "cc" | "bcc")),
                });
                cursor += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                match containers.pop() {
                    Some(Container::Object { .. }) => {}
                    _ => return Err(MailError::invalid_input("JSON delimiters are mismatched")),
                }
                cursor += 1;
            }
            b']' => {
                depth = depth.saturating_sub(1);
                let Some(Container::Array {
                    field,
                    items,
                    maximum,
                    counts_as_recipient,
                }) = containers.pop()
                else {
                    return Err(MailError::invalid_input("JSON delimiters are mismatched"));
                };
                if items > maximum {
                    return Err(resource("JSON sequence exceeds its item boundary"));
                }
                if counts_as_recipient && matches!(field.as_deref(), Some("to" | "cc" | "bcc")) {
                    recipient_items = recipient_items
                        .checked_add(items)
                        .ok_or_else(|| resource("recipient count overflowed"))?;
                    if recipient_items > crate::MAX_SEND_RECIPIENTS {
                        return Err(resource("recipient lists exceed their combined boundary"));
                    }
                }
                cursor += 1;
            }
            b',' => {
                if let Some(Container::Array { items, maximum, .. }) = containers.last_mut() {
                    *items = items
                        .checked_add(1)
                        .ok_or_else(|| resource("JSON sequence count overflowed"))?;
                    if *items > *maximum {
                        return Err(resource("JSON sequence exceeds its item boundary"));
                    }
                }
                cursor += 1;
            }
            b'"' => {
                let start = cursor;
                let (end, has_escape) = scan_json_string(bytes, cursor)?;
                cursor = end + 1;
                let next = skip_whitespace(bytes, cursor);
                if bytes.get(next) == Some(&b':') {
                    let raw_length = end.saturating_sub(start + 1);
                    if raw_length > 128 {
                        return Err(resource("JSON field name exceeds the boundary"));
                    }
                    current_key = Some(
                        serde_json::from_slice::<String>(&bytes[start..=end]).map_err(|_| {
                            MailError::invalid_input("JSON field name is malformed")
                        })?,
                    );
                    if let Some(Container::Object { members }) = containers.last_mut() {
                        *members = members
                            .checked_add(1)
                            .ok_or_else(|| resource("JSON object member count overflowed"))?;
                        if *members > 128 {
                            return Err(resource("JSON object has too many members"));
                        }
                    }
                } else if let Some(key) = current_key.as_deref() {
                    let raw = &bytes[start + 1..end];
                    let characters = decoded_json_string_chars(raw)?;
                    enforce_string_limit(shape, key, raw, characters, has_escape)?;
                    if key == "content_base64" {
                        if has_escape {
                            return Err(MailError::invalid_input(
                                "attachment Base64 cannot use JSON escapes",
                            ));
                        }
                        let decoded = canonical_base64_decoded_len(raw)?;
                        if decoded > crate::MAX_SEND_ATTACHMENT_BYTES {
                            return Err(resource("one attachment exceeds its decoded byte budget"));
                        }
                        decoded_attachment_total = decoded_attachment_total
                            .checked_add(decoded)
                            .ok_or_else(|| resource("attachment decoded-total overflowed"))?;
                        if decoded_attachment_total > crate::MAX_TOTAL_ATTACHMENT_BYTES {
                            return Err(resource(
                                "attachments exceed the decoded-total byte budget",
                            ));
                        }
                    }
                }
            }
            _ => cursor += 1,
        }
    }
    if !containers.is_empty() {
        return Err(MailError::stable(
            MailErrorCode::InputDocumentIncomplete,
            "JSON document is incomplete",
        ));
    }
    Ok(())
}

fn scan_json_string(bytes: &[u8], start: usize) -> Result<(usize, bool), MailError> {
    let mut cursor = start + 1;
    let mut escaped = false;
    let mut has_escape = false;
    while let Some(&byte) = bytes.get(cursor) {
        if escaped {
            escaped = false;
            has_escape = true;
            cursor += 1;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'"' => return Ok((cursor, has_escape)),
            0x00..=0x1f => {
                return Err(MailError::invalid_input(
                    "JSON strings cannot contain control bytes",
                ));
            }
            _ => {}
        }
        cursor += 1;
    }
    Err(MailError::stable(
        MailErrorCode::InputDocumentIncomplete,
        "JSON string is incomplete",
    ))
}

fn skip_whitespace(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes
        .get(cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
    {
        cursor += 1;
    }
    cursor
}

fn decoded_json_string_chars(raw: &[u8]) -> Result<usize, MailError> {
    if !raw.contains(&b'\\') {
        return std::str::from_utf8(raw)
            .map(str::chars)
            .map(Iterator::count)
            .map_err(|_| MailError::invalid_input("JSON string is not UTF-8"));
    }
    let mut cursor = 0usize;
    let mut characters = 0usize;
    while cursor < raw.len() {
        if raw[cursor] == b'\\' {
            let escape = *raw
                .get(cursor + 1)
                .ok_or_else(|| MailError::invalid_input("JSON escape is incomplete"))?;
            match escape {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => cursor += 2,
                b'u' => {
                    let digits = raw.get(cursor + 2..cursor + 6).ok_or_else(|| {
                        MailError::invalid_input("JSON Unicode escape is incomplete")
                    })?;
                    let unit = parse_hex_unit(digits)?;
                    cursor += 6;
                    if (0xd800..=0xdbff).contains(&unit) {
                        let low_escape = raw.get(cursor..cursor + 6).ok_or_else(|| {
                            MailError::invalid_input("JSON surrogate pair is incomplete")
                        })?;
                        if !low_escape.starts_with(br"\u") {
                            return Err(MailError::invalid_input(
                                "JSON high surrogate is not paired",
                            ));
                        }
                        let low = parse_hex_unit(&low_escape[2..])?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return Err(MailError::invalid_input(
                                "JSON high surrogate has an invalid pair",
                            ));
                        }
                        cursor += 6;
                    } else if (0xdc00..=0xdfff).contains(&unit) {
                        return Err(MailError::invalid_input("JSON low surrogate is not paired"));
                    }
                }
                _ => return Err(MailError::invalid_input("JSON escape is malformed")),
            }
            characters += 1;
        } else {
            let segment_end = raw[cursor..]
                .iter()
                .position(|byte| *byte == b'\\')
                .map_or(raw.len(), |offset| cursor + offset);
            let segment = std::str::from_utf8(&raw[cursor..segment_end])
                .map_err(|_| MailError::invalid_input("JSON string is not UTF-8"))?;
            characters += segment.chars().count();
            cursor = segment_end;
        }
    }
    Ok(characters)
}

fn parse_hex_unit(digits: &[u8]) -> Result<u16, MailError> {
    if digits.len() != 4 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(MailError::invalid_input("JSON Unicode escape is malformed"));
    }
    digits.iter().try_fold(0_u16, |value, digit| {
        let nibble = match digit {
            b'0'..=b'9' => u16::from(*digit - b'0'),
            b'a'..=b'f' => u16::from(*digit - b'a' + 10),
            b'A'..=b'F' => u16::from(*digit - b'A' + 10),
            _ => {
                return Err(MailError::invalid_input("JSON Unicode escape is malformed"));
            }
        };
        Ok((value << 4) | nibble)
    })
}

fn enforce_string_limit(
    shape: InputShape,
    key: &str,
    raw: &[u8],
    characters: usize,
    _has_escape: bool,
) -> Result<(), MailError> {
    let maximum = match key {
        "subject" => match shape {
            InputShape::Search | InputShape::LocalSearch => 1_024,
            _ => crate::MAX_SEND_SUBJECT_CHARS,
        },
        "from" | "to" if matches!(shape, InputShape::Search | InputShape::LocalSearch) => 1_024,
        "text" => match shape {
            InputShape::Search | InputShape::LocalSearch => 1_024,
            _ => crate::MAX_SEND_BODY_CHARS,
        },
        "html" | "sanitized_html" => crate::MAX_SEND_BODY_CHARS,
        "name" => 256,
        "email" => 320,
        "filename" => crate::MAX_ATTACHMENT_FILENAME_CHARS,
        "mime_type" => crate::MAX_ATTACHMENT_MIME_CHARS,
        "account_id" => 64,
        "mailbox" | "destination" => 4_096,
        "part_id" => 128,
        "message_id" | "in_reply_to" => crate::MAX_SEND_SUBJECT_CHARS,
        "signature_base64url" => 86,
        "content_base64" => 4 * crate::MAX_SEND_ATTACHMENT_BYTES.div_ceil(3),
        _ => crate::MAX_REMOTE_VALUE_BYTES.max(crate::MAX_SEND_BODY_CHARS),
    };
    if characters > maximum || raw.len() > maximum.saturating_mul(12) {
        return Err(resource("JSON string exceeds its field boundary"));
    }
    Ok(())
}

fn canonical_base64_decoded_len(raw: &[u8]) -> Result<usize, MailError> {
    if raw.is_empty() {
        return Ok(0);
    }
    if !raw.len().is_multiple_of(4) {
        return Err(MailError::invalid_input(
            "attachment content is not canonical Base64",
        ));
    }
    let padding = match raw {
        [.., b'=', b'='] => 2,
        [.., b'='] => 1,
        _ => 0,
    };
    let content_length = raw.len() - padding;
    if raw[..content_length]
        .iter()
        .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'/'))
        || raw[content_length..].iter().any(|byte| *byte != b'=')
    {
        return Err(MailError::invalid_input(
            "attachment content is not canonical Base64",
        ));
    }
    raw.len()
        .checked_div(4)
        .and_then(|groups| groups.checked_mul(3))
        .and_then(|bytes| bytes.checked_sub(padding))
        .ok_or_else(|| resource("attachment Base64 length overflowed"))
}

fn resource(message: &'static str) -> MailError {
    MailError::stable(MailErrorCode::ResourceLimit, message)
}
