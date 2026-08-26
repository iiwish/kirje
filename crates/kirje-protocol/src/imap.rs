use std::{collections::BTreeMap, net::IpAddr, num::NonZeroU32, str::from_utf8};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Utc};
use io_imap::{
    client::{ImapClient as _, ImapClientError, ImapClientStd},
    rfc3501::{
        examine::ImapMailboxExamineOptions, fetch::ImapMessageFetchOptions,
        search::ImapMessageSearchOptions,
    },
    session::ImapSessionOpenOptions,
    types::{
        body::BodyStructure,
        core::{AString, IString, NString, Vec1},
        envelope::Address as ImapAddress,
        fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName},
        flag::{Flag as ImapFlag, FlagFetch, FlagNameAttribute},
        mailbox::{ListMailbox, Mailbox as ImapMailbox},
        response::Capability,
        search::SearchKey,
        sequence::SequenceSet,
        status::{StatusDataItem, StatusDataItemName},
    },
};
use io_sasl::{mechanism::Sasl, rfc4616::plain::SaslPlainCreds};
use kirje_core::{
    AttachmentContent, AttachmentMetadata, AttachmentRead, ConnectionReport, MailAccountConfig,
    MailAddress, MailError, MailErrorCode, Mailbox, MailboxReader, MailboxSyncBatch,
    MailboxSyncRequest, MessageContent, MessageEnvelope, MessagePage, MessageRead,
    MessageReference, MessageSearch, Protocol, TransportSecurity,
};
use mail_parser::{Addr, Address, MessageParser, MimeHeaders};
use pimalaya_stream::tls::{Rustls, Tls};
use rfc2047_decoder::{Decoder, RecoverStrategy};
use secrecy::SecretString;
use url::Url;

const MAX_RAW_MESSAGE_BYTES: usize = 10 * 1024 * 1024;
const MAX_ATTACHMENTS: usize = 100;
const MAX_MAILBOXES: usize = 1_000;
const MAX_MAILBOX_CHARS: usize = 4_096;
const MAX_ADDRESSES: usize = 100;
const MAX_HEADER_CHARS: usize = 4_096;
const MAX_MESSAGE_IDS: usize = 100;

#[derive(Clone, Copy, Debug, Default)]
pub struct PimalayaImapReader;

impl MailboxReader for PimalayaImapReader {
    fn check(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
    ) -> Result<ConnectionReport, MailError> {
        account.validate()?;
        let (_client, capabilities) = connect(account, secret)?;

        Ok(ConnectionReport {
            account_id: account.id.clone(),
            protocol: Protocol::Imap,
            host: account.incoming.host.clone(),
            authenticated: true,
            capabilities: capabilities
                .into_iter()
                .map(|capability| format!("{capability:?}"))
                .collect(),
        })
    }

    fn list_mailboxes(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        include_counts: bool,
    ) -> Result<Vec<Mailbox>, MailError> {
        account.validate()?;
        let (mut client, _) = connect(account, secret)?;
        let reference: ImapMailbox<'static> = ""
            .try_into()
            .map_err(|_| protocol_error("invalid IMAP list reference"))?;
        let pattern: ListMailbox<'static> = "*"
            .try_into()
            .map_err(|_| protocol_error("invalid IMAP list pattern"))?;

        let rows = client
            .list(reference, pattern)
            .map_err(|error| classify_error(&error))?;
        if rows.len() > MAX_MAILBOXES {
            return Err(MailError::new(
                MailErrorCode::ResourceLimit,
                "account exceeds the 1000-mailbox read-only MVP limit",
                false,
            ));
        }
        let mut mailboxes: Vec<Mailbox> = rows
            .into_iter()
            .filter(|(_, _, attributes)| !attributes.contains(&FlagNameAttribute::Noselect))
            .map(|(mailbox, _, _)| {
                let name = mailbox_name(mailbox);
                if name.chars().count() > MAX_MAILBOX_CHARS {
                    return Err(MailError::new(
                        MailErrorCode::ResourceLimit,
                        "mailbox name exceeds the 4096-character limit",
                        false,
                    ));
                }
                Ok(Mailbox {
                    id: name.clone(),
                    name,
                    total: None,
                    unread: None,
                })
            })
            .collect::<Result<_, _>>()?;

        if include_counts {
            for mailbox in &mut mailboxes {
                let selected = parse_mailbox(&mailbox.id)?;
                let items = client
                    .status(
                        selected,
                        vec![StatusDataItemName::Messages, StatusDataItemName::Unseen].into(),
                    )
                    .map_err(|error| classify_error(&error))?;
                apply_status(mailbox, items);
            }
        }

        Ok(mailboxes)
    }

    fn search_messages(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        search: &MessageSearch,
    ) -> Result<MessagePage, MailError> {
        account.validate()?;
        search.validate()?;
        ensure_account_scope(account, &search.account_id)?;

        let (mut client, _) = connect(account, secret)?;
        let mailbox = parse_mailbox(&search.mailbox)?;
        let selected = client
            .examine(mailbox, ImapMailboxExamineOptions::default())
            .map_err(|error| classify_error(&error))?;
        if selected.exists.unwrap_or(0) == 0 {
            return Ok(MessagePage {
                messages: Vec::new(),
                returned: 0,
                limit: search.limit,
                has_more: false,
                untrusted: true,
            });
        }

        let mut uids = client
            .search(
                build_search_keys(search)?,
                ImapMessageSearchOptions { uid: true },
            )
            .map_err(|error| classify_error(&error))?;
        uids.sort_unstable_by(|left, right| right.cmp(left));

        let fetch_count = usize::from(search.limit).saturating_add(1);
        uids.truncate(fetch_count);
        let has_more = uids.len() > usize::from(search.limit);
        if has_more {
            uids.pop();
        }

        if uids.is_empty() {
            return Ok(MessagePage {
                messages: Vec::new(),
                returned: 0,
                limit: search.limit,
                has_more,
                untrusted: true,
            });
        }

        let uid_validity = selected.uid_validity.map(NonZeroU32::get);
        let sequence_set = SequenceSet::try_from(uids.clone())
            .map_err(|_| protocol_error("server returned an invalid IMAP UID set"))?;
        let fetched = client
            .fetch(
                sequence_set,
                envelope_fetch_items(),
                ImapMessageFetchOptions {
                    uid: true,
                    ..Default::default()
                },
            )
            .map_err(|error| classify_error(&error))?;
        let mut by_uid: BTreeMap<u32, MessageEnvelope> = fetched
            .into_iter()
            .map(|(sequence, items)| {
                let envelope = envelope_from(
                    account,
                    &search.mailbox,
                    uid_validity,
                    sequence.get(),
                    items.into_inner(),
                );
                (envelope.reference.uid, envelope)
            })
            .collect();
        let messages: Vec<MessageEnvelope> = uids
            .into_iter()
            .filter_map(|uid| by_uid.remove(&uid.get()))
            .collect();
        let returned = u16::try_from(messages.len()).unwrap_or(search.limit);

        Ok(MessagePage {
            messages,
            returned,
            limit: search.limit,
            has_more,
            untrusted: true,
        })
    }

    fn read_message(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        read: &MessageRead,
    ) -> Result<MessageContent, MailError> {
        account.validate()?;
        read.validate()?;
        ensure_account_scope(account, &read.reference.account_id)?;

        let raw = fetch_raw_message(account, secret, &read.reference)?;
        parse_message(&read.reference, &raw, read.max_body_chars)
    }

    fn sync_mailbox(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        request: &MailboxSyncRequest,
    ) -> Result<MailboxSyncBatch, MailError> {
        account.validate()?;
        request.validate()?;
        ensure_account_scope(account, &request.account_id)?;

        let (mut client, _) = connect(account, secret)?;
        let mailbox = parse_mailbox(&request.mailbox)?;
        let selected = client
            .examine(mailbox, ImapMailboxExamineOptions::default())
            .map_err(|error| classify_error(&error))?;
        let uid_validity = selected
            .uid_validity
            .map(NonZeroU32::get)
            .ok_or_else(|| protocol_error("IMAP mailbox did not provide UIDVALIDITY"))?;
        let reset_required = request
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.uid_validity != uid_validity);
        let highest_uid = request
            .cursor
            .as_ref()
            .filter(|_| !reset_required)
            .and_then(|cursor| cursor.highest_uid);

        let mut uids = if highest_uid == Some(u32::MAX) {
            Vec::new()
        } else {
            client
                .search(
                    sync_search_keys(highest_uid)?,
                    ImapMessageSearchOptions { uid: true },
                )
                .map_err(|error| classify_error(&error))?
        };
        let incremental = highest_uid.is_some();
        let has_more = select_sync_uids(&mut uids, request.limit, incremental);
        let messages = if uids.is_empty() {
            Vec::new()
        } else {
            let sequence_set = SequenceSet::try_from(uids.clone())
                .map_err(|_| protocol_error("server returned an invalid IMAP UID set"))?;
            let fetched = client
                .fetch(
                    sequence_set,
                    envelope_fetch_items(),
                    ImapMessageFetchOptions {
                        uid: true,
                        ..Default::default()
                    },
                )
                .map_err(|error| classify_error(&error))?;
            let mut by_uid: BTreeMap<u32, MessageEnvelope> = fetched
                .into_iter()
                .map(|(sequence, items)| {
                    let envelope = envelope_from(
                        account,
                        &request.mailbox,
                        Some(uid_validity),
                        sequence.get(),
                        items.into_inner(),
                    );
                    (envelope.reference.uid, envelope)
                })
                .collect();
            uids.into_iter()
                .filter_map(|uid| by_uid.remove(&uid.get()))
                .collect()
        };

        Ok(MailboxSyncBatch {
            account_id: request.account_id.clone(),
            mailbox: request.mailbox.clone(),
            uid_validity,
            messages,
            remote_total: selected.exists.map(u64::from),
            has_more,
            reset_required,
        })
    }

    fn read_attachment(
        &self,
        account: &MailAccountConfig,
        secret: &SecretString,
        read: &AttachmentRead,
    ) -> Result<AttachmentContent, MailError> {
        account.validate()?;
        read.validate()?;
        ensure_account_scope(account, &read.reference.account_id)?;
        let raw = fetch_raw_message(account, secret, &read.reference)?;
        parse_attachment(read, &raw)
    }
}

fn fetch_raw_message(
    account: &MailAccountConfig,
    secret: &SecretString,
    reference: &MessageReference,
) -> Result<Vec<u8>, MailError> {
    let (mut client, _) = connect(account, secret)?;
    let mailbox = parse_mailbox(&reference.mailbox)?;
    let selected = client
        .examine(mailbox, ImapMailboxExamineOptions::default())
        .map_err(|error| classify_error(&error))?;
    let selected_uid_validity = selected.uid_validity.map(NonZeroU32::get);
    ensure_uid_validity(reference.uid_validity, selected_uid_validity)?;

    let uid = NonZeroU32::new(reference.uid)
        .ok_or_else(|| MailError::invalid_input("message UID must be positive"))?;
    let sequence_set = SequenceSet::try_from(vec![uid])
        .map_err(|_| MailError::invalid_input("invalid message UID"))?;
    let fetched = client
        .fetch(
            sequence_set,
            body_peek_fetch_items(),
            ImapMessageFetchOptions {
                uid: true,
                ..Default::default()
            },
        )
        .map_err(|error| classify_error(&error))?;
    let raw = fetched
        .into_values()
        .flat_map(io_imap::types::core::VecN::into_inner)
        .find_map(|item| match item {
            MessageDataItem::BodyExt { data, .. } => data.0.map(|bytes| bytes.as_ref().to_vec()),
            _ => None,
        })
        .ok_or_else(|| {
            MailError::new(
                MailErrorCode::MessageNotFound,
                "server returned no body for the requested message",
                false,
            )
        })?;

    if raw.len() > MAX_RAW_MESSAGE_BYTES {
        return Err(MailError::new(
            MailErrorCode::ResourceLimit,
            "message exceeds the 10 MiB read limit",
            false,
        ));
    }
    Ok(raw)
}

fn connect(
    account: &MailAccountConfig,
    secret: &SecretString,
) -> Result<(ImapClientStd, Vec<Capability<'static>>), MailError> {
    let scheme = match account.incoming.security {
        TransportSecurity::ImplicitTls => "imaps",
        TransportSecurity::StartTls => "imap",
        TransportSecurity::Https => {
            return Err(MailError::invalid_input(
                "IMAP transport must use implicit TLS or STARTTLS",
            ));
        }
    };
    let host = if account
        .incoming
        .host
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_ipv6())
    {
        format!("[{}]", account.incoming.host)
    } else {
        account.incoming.host.clone()
    };
    let url = Url::parse(&format!("{scheme}://{host}:{}", account.incoming.port))
        .map_err(|_| MailError::invalid_input("IMAP endpoint is not a valid URL authority"))?;
    let tls = Tls {
        rustls: Rustls {
            alpn: io_imap::client::default_alpn(),
            ..Default::default()
        },
        ..Default::default()
    };
    let sasl = Sasl::Plain(SaslPlainCreds {
        authzid: None,
        authcid: account.username.clone(),
        passwd: secret.clone(),
    });
    let options = session_options(account)?;

    ImapClientStd::connect(&url, &tls, Some(sasl), options).map_err(|error| classify_error(&error))
}

fn session_options(account: &MailAccountConfig) -> Result<ImapSessionOpenOptions, MailError> {
    let host = account.incoming.host.to_ascii_lowercase();
    let sasl_ir = matches!(
        host.as_str(),
        "imap.163.com" | "imap.126.com" | "imap.yeah.net"
    )
    .then_some(false);
    let auto_id = matches!(host.as_str(), "imap.qq.com" | "imap.fastmail.com")
        .then(build_client_id)
        .transpose()?;

    Ok(ImapSessionOpenOptions {
        starttls: matches!(account.incoming.security, TransportSecurity::StartTls),
        auto_id,
        sasl_ir,
    })
}

fn build_client_id() -> Result<Vec<(IString<'static>, NString<'static>)>, MailError> {
    [
        ("name", "kirje"),
        ("version", env!("CARGO_PKG_VERSION")),
        ("vendor", "Kirje contributors"),
        ("support-url", "https://github.com/iiwish/kirje"),
    ]
    .into_iter()
    .map(|(key, value)| {
        let key = IString::try_from(key.to_owned())
            .map_err(|_| protocol_error("Kirje IMAP ID key is invalid"))?;
        let value = NString::try_from(value.to_owned())
            .map_err(|_| protocol_error("Kirje IMAP ID value is invalid"))?;
        Ok((key, value))
    })
    .collect()
}

fn classify_error(error: &ImapClientError) -> MailError {
    let (code, message, retryable) = match error {
        ImapClientError::AuthLogin(_)
        | ImapClientError::AuthPlain(_)
        | ImapClientError::AuthAnonymous(_)
        | ImapClientError::AuthOAuthBearer(_)
        | ImapClientError::AuthXOAuth2(_)
        | ImapClientError::InvalidLoginCredentials(_) => (
            MailErrorCode::Authentication,
            "IMAP authentication failed",
            false,
        ),
        ImapClientError::Tls(_) | ImapClientError::StartTls(_) => {
            (MailErrorCode::Tls, "IMAP TLS negotiation failed", false)
        }
        ImapClientError::Io(_) | ImapClientError::Transport(_) => (
            MailErrorCode::Network,
            "IMAP network connection failed",
            true,
        ),
        _ => (
            MailErrorCode::Protocol,
            "IMAP server returned an unsupported or invalid response",
            false,
        ),
    };
    MailError::new(code, message, retryable)
}

fn protocol_error(message: impl Into<String>) -> MailError {
    MailError::new(MailErrorCode::Protocol, message, false)
}

fn ensure_account_scope(account: &MailAccountConfig, requested: &str) -> Result<(), MailError> {
    if account.id == requested {
        Ok(())
    } else {
        Err(MailError::invalid_input(
            "request account does not match the selected account",
        ))
    }
}

fn ensure_uid_validity(expected: Option<u32>, actual: Option<u32>) -> Result<(), MailError> {
    if expected.is_some() && expected != actual {
        return Err(MailError::new(
            MailErrorCode::MessageNotFound,
            "message reference expired because mailbox UIDVALIDITY changed",
            false,
        ));
    }
    Ok(())
}

fn parse_mailbox(name: &str) -> Result<ImapMailbox<'static>, MailError> {
    String::from(name)
        .try_into()
        .map_err(|_| MailError::invalid_input("invalid IMAP mailbox name"))
}

fn mailbox_name(mailbox: ImapMailbox<'_>) -> String {
    match mailbox {
        ImapMailbox::Inbox => "INBOX".to_owned(),
        ImapMailbox::Other(other) => bytes_to_string(other.inner().as_ref()),
    }
}

fn apply_status(mailbox: &mut Mailbox, items: Vec<StatusDataItem>) {
    for item in items {
        match item {
            StatusDataItem::Messages(count) => mailbox.total = Some(u64::from(count)),
            StatusDataItem::Unseen(count) => mailbox.unread = Some(u64::from(count)),
            _ => {}
        }
    }
}

fn build_search_keys(search: &MessageSearch) -> Result<Vec1<SearchKey<'static>>, MailError> {
    let mut keys = Vec::new();
    if let Some(value) = non_empty(search.from.as_deref()) {
        keys.push(SearchKey::From(astring(value)?));
    }
    if let Some(value) = non_empty(search.to.as_deref()) {
        keys.push(SearchKey::To(astring(value)?));
    }
    if let Some(value) = non_empty(search.subject.as_deref()) {
        keys.push(SearchKey::Subject(astring(value)?));
    }
    if let Some(value) = non_empty(search.text.as_deref()) {
        keys.push(SearchKey::Text(astring(value)?));
    }
    if let Some(unread) = search.unread {
        keys.push(if unread {
            SearchKey::Unseen
        } else {
            SearchKey::Seen
        });
    }
    if keys.is_empty() {
        keys.push(SearchKey::All);
    }

    Vec1::try_from(keys).map_err(|_| MailError::invalid_input("search criteria cannot be empty"))
}

fn sync_search_keys(highest_uid: Option<u32>) -> Result<Vec1<SearchKey<'static>>, MailError> {
    let key = match highest_uid {
        Some(highest_uid) => {
            let start = NonZeroU32::new(highest_uid.saturating_add(1)).ok_or_else(|| {
                MailError::invalid_input("sync cursor cannot advance past UID max")
            })?;
            SearchKey::Uid(SequenceSet::from(start..))
        }
        None => SearchKey::All,
    };
    Ok(Vec1::from(key))
}

fn select_sync_uids(uids: &mut Vec<NonZeroU32>, limit: u16, incremental: bool) -> bool {
    if incremental {
        uids.sort_unstable();
    } else {
        uids.sort_unstable_by(|left, right| right.cmp(left));
    }
    let fetch_count = usize::from(limit).saturating_add(1);
    uids.truncate(fetch_count);
    let has_more = uids.len() > usize::from(limit);
    if has_more {
        uids.pop();
    }
    has_more
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn astring(value: &str) -> Result<AString<'static>, MailError> {
    AString::try_from(value.to_owned())
        .map_err(|_| MailError::invalid_input("search value contains invalid IMAP characters"))
}

fn envelope_fetch_items() -> MacroOrMessageDataItemNames<'static> {
    MacroOrMessageDataItemNames::MessageDataItemNames(vec![
        MessageDataItemName::Uid,
        MessageDataItemName::Flags,
        MessageDataItemName::Envelope,
        MessageDataItemName::Rfc822Size,
        MessageDataItemName::BodyStructure,
    ])
}

fn body_peek_fetch_items() -> MacroOrMessageDataItemNames<'static> {
    MacroOrMessageDataItemNames::MessageDataItemNames(vec![MessageDataItemName::BodyExt {
        section: None,
        partial: Some((
            0,
            NonZeroU32::new(
                u32::try_from(MAX_RAW_MESSAGE_BYTES + 1).expect("raw message bound fits u32"),
            )
            .expect("raw message bound is positive"),
        )),
        peek: true,
    }])
}

fn envelope_from(
    account: &MailAccountConfig,
    mailbox: &str,
    uid_validity: Option<u32>,
    sequence: u32,
    items: Vec<MessageDataItem<'static>>,
) -> MessageEnvelope {
    let mut uid = sequence;
    let mut message_id = None;
    let mut in_reply_to = Vec::new();
    let mut subject = String::new();
    let mut from = Vec::new();
    let mut to = Vec::new();
    let mut sent_at = None;
    let mut size = 0;
    let mut is_read = false;
    let mut is_starred = false;
    let mut has_attachment = None;
    let mut truncated = false;

    for item in items {
        match item {
            MessageDataItem::Uid(value) => uid = value.get(),
            MessageDataItem::Flags(flags) => {
                for flag in flags {
                    if let FlagFetch::Flag(flag) = flag {
                        is_read |= matches!(flag, ImapFlag::Seen);
                        is_starred |= matches!(flag, ImapFlag::Flagged);
                    }
                }
            }
            MessageDataItem::Envelope(envelope) => {
                subject = envelope
                    .subject
                    .into_option()
                    .map(|value| decode_mime_bytes(value.as_ref()))
                    .unwrap_or_default();
                sent_at = envelope
                    .date
                    .into_option()
                    .and_then(|value| parse_rfc2822_date(&bytes_to_string(value.as_ref())));
                message_id = envelope
                    .message_id
                    .into_option()
                    .and_then(|value| normalize_message_id(&bytes_to_string(value.as_ref())));
                in_reply_to = envelope
                    .in_reply_to
                    .into_option()
                    .map(|value| parse_message_ids(&bytes_to_string(value.as_ref())))
                    .unwrap_or_default();
                from = envelope.from.iter().map(imap_address).collect();
                to = envelope.to.iter().map(imap_address).collect();
            }
            MessageDataItem::Rfc822Size(value) => size = u64::from(value),
            MessageDataItem::BodyStructure(structure) => {
                has_attachment = Some(body_structure_has_attachment(&structure));
            }
            _ => {}
        }
    }

    let (bounded_subject, subject_truncated) = truncate(Some(&subject), MAX_HEADER_CHARS);
    subject = bounded_subject.unwrap_or_default();
    truncated |= subject_truncated;
    if let Some(value) = message_id.as_mut() {
        let (bounded, value_truncated) = truncate(Some(value), MAX_HEADER_CHARS);
        *value = bounded.unwrap_or_default();
        truncated |= value_truncated;
    }
    if in_reply_to.len() > MAX_MESSAGE_IDS {
        in_reply_to.truncate(MAX_MESSAGE_IDS);
        truncated = true;
    }
    for value in &mut in_reply_to {
        let (bounded, value_truncated) = truncate(Some(value), MAX_HEADER_CHARS);
        *value = bounded.unwrap_or_default();
        truncated |= value_truncated;
    }
    truncated |= bound_addresses(&mut from);
    truncated |= bound_addresses(&mut to);

    MessageEnvelope {
        reference: MessageReference {
            account_id: account.id.clone(),
            mailbox: mailbox.to_owned(),
            uid_validity,
            uid,
        },
        message_id,
        in_reply_to,
        subject,
        from,
        to,
        sent_at,
        size,
        is_read,
        is_starred,
        has_attachment,
        truncated,
    }
}

fn imap_address(address: &ImapAddress<'_>) -> MailAddress {
    let name = address
        .name
        .0
        .as_ref()
        .map(|value| decode_mime_bytes(value.as_ref()))
        .filter(|value| !value.is_empty());
    let mailbox = address
        .mailbox
        .0
        .as_ref()
        .map(|value| bytes_to_string(value.as_ref()))
        .unwrap_or_default();
    let host = address
        .host
        .0
        .as_ref()
        .map(|value| bytes_to_string(value.as_ref()))
        .unwrap_or_default();
    let email = match (mailbox.is_empty(), host.is_empty()) {
        (false, false) => format!("{mailbox}@{host}"),
        (false, true) => mailbox,
        (true, _) => host,
    };
    MailAddress { name, email }
}

fn body_structure_has_attachment(structure: &BodyStructure<'_>) -> bool {
    match structure {
        BodyStructure::Single { extension_data, .. } => extension_data
            .as_ref()
            .and_then(|extension| extension.tail.as_ref())
            .and_then(|disposition| disposition.disposition.as_ref())
            .is_some_and(|(kind, _)| kind.as_ref().eq_ignore_ascii_case(b"attachment")),
        BodyStructure::Multi { bodies, .. } => {
            bodies.as_ref().iter().any(body_structure_has_attachment)
        }
    }
}

fn parse_message(
    reference: &MessageReference,
    raw: &[u8],
    max_body_chars: u32,
) -> Result<MessageContent, MailError> {
    let message = MessageParser::default().parse(raw).ok_or_else(|| {
        MailError::new(
            MailErrorCode::Protocol,
            "message is not valid RFC 5322/MIME content",
            false,
        )
    })?;
    let limit = usize::try_from(max_body_chars).unwrap_or(usize::MAX);
    let (text, text_truncated) = truncate(message.body_text(0).as_deref(), limit);
    let sanitized = message
        .body_html(0)
        .map(|html| ammonia::Builder::default().clean(&html).to_string());
    let (sanitized_html, html_truncated) = truncate(sanitized.as_deref(), limit);
    let mut attachments = Vec::new();
    let mut attachment_truncated = message.attachment_count() > MAX_ATTACHMENTS;
    for (index, part) in message.attachments().take(MAX_ATTACHMENTS).enumerate() {
        let (filename, filename_truncated) = truncate(part.attachment_name(), MAX_HEADER_CHARS);
        let raw_mime_type = part_mime_type(part);
        let (mime_type, mime_truncated) = truncate(Some(&raw_mime_type), MAX_HEADER_CHARS);
        attachment_truncated |= filename_truncated || mime_truncated;
        attachments.push(AttachmentMetadata {
            part_id: format!("attachment-{}", index + 1),
            filename,
            mime_type: mime_type.unwrap_or_else(|| "application/octet-stream".to_owned()),
            size: u64::try_from(part.len()).unwrap_or(u64::MAX),
        });
    }
    let (subject, subject_truncated) = truncate(message.subject(), MAX_HEADER_CHARS);
    let mut from = message.from().map(parser_addresses).unwrap_or_default();
    let mut to = message.to().map(parser_addresses).unwrap_or_default();
    let mut cc = message.cc().map(parser_addresses).unwrap_or_default();
    let address_truncated =
        bound_addresses(&mut from) | bound_addresses(&mut to) | bound_addresses(&mut cc);

    Ok(MessageContent {
        reference: reference.clone(),
        subject: subject.unwrap_or_default(),
        from,
        to,
        cc,
        sent_at: message
            .date()
            .and_then(|date| DateTime::from_timestamp(date.to_timestamp(), 0)),
        text,
        sanitized_html,
        attachments,
        untrusted: true,
        truncated: text_truncated
            || html_truncated
            || attachment_truncated
            || subject_truncated
            || address_truncated,
    })
}

fn parse_attachment(read: &AttachmentRead, raw: &[u8]) -> Result<AttachmentContent, MailError> {
    let message = MessageParser::default().parse(raw).ok_or_else(|| {
        MailError::new(
            MailErrorCode::Protocol,
            "message is not valid RFC 5322/MIME content",
            false,
        )
    })?;
    let index = read.attachment_index()?;
    let part = message
        .attachment(u32::try_from(index).map_err(|_| {
            MailError::invalid_input("attachment index exceeds the supported range")
        })?)
        .ok_or_else(|| {
            MailError::new(
                MailErrorCode::AttachmentNotFound,
                "requested attachment does not exist",
                false,
            )
        })?;
    let bytes = part.contents();
    let limit = usize::try_from(read.max_bytes).unwrap_or(usize::MAX);
    let truncated = bytes.len() > limit;
    let (filename, filename_truncated) = truncate(part.attachment_name(), MAX_HEADER_CHARS);
    let raw_mime_type = part_mime_type(part);
    let (mime_type, mime_truncated) = truncate(Some(&raw_mime_type), MAX_HEADER_CHARS);

    Ok(AttachmentContent {
        reference: read.reference.clone(),
        part_id: read.part_id.clone(),
        filename,
        mime_type: mime_type.unwrap_or_else(|| "application/octet-stream".to_owned()),
        size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        content_base64: BASE64_STANDARD.encode(&bytes[..bytes.len().min(limit)]),
        untrusted: true,
        truncated: truncated || filename_truncated || mime_truncated,
    })
}

fn truncate(value: Option<&str>, max_chars: usize) -> (Option<String>, bool) {
    let Some(value) = value else {
        return (None, false);
    };
    let mut chars = value.chars();
    let output: String = chars.by_ref().take(max_chars).collect();
    let truncated = chars.next().is_some();
    (Some(output), truncated)
}

fn parser_addresses(addresses: &Address<'_>) -> Vec<MailAddress> {
    match addresses {
        Address::List(list) => list.iter().map(parser_address).collect(),
        Address::Group(groups) => groups
            .iter()
            .flat_map(|group| group.addresses.iter())
            .map(parser_address)
            .collect(),
    }
}

fn parser_address(address: &Addr<'_>) -> MailAddress {
    MailAddress {
        name: address.name.as_deref().map(str::to_owned),
        email: address.address.as_deref().unwrap_or_default().to_owned(),
    }
}

fn bound_addresses(addresses: &mut Vec<MailAddress>) -> bool {
    let mut truncated = addresses.len() > MAX_ADDRESSES;
    addresses.truncate(MAX_ADDRESSES);
    for address in addresses {
        if let Some(name) = address.name.as_mut() {
            let (bounded, value_truncated) = truncate(Some(name), MAX_HEADER_CHARS);
            *name = bounded.unwrap_or_default();
            truncated |= value_truncated;
        }
        let (bounded, value_truncated) = truncate(Some(&address.email), MAX_HEADER_CHARS);
        address.email = bounded.unwrap_or_default();
        truncated |= value_truncated;
    }
    truncated
}

fn part_mime_type(part: &mail_parser::MessagePart<'_>) -> String {
    let Some(content_type) = part.content_type() else {
        return "application/octet-stream".to_owned();
    };
    match content_type.c_subtype.as_deref() {
        Some(subtype) => format!("{}/{subtype}", content_type.c_type),
        None => content_type.c_type.to_string(),
    }
}

fn parse_rfc2822_date(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(raw.trim())
        .or_else(|_| DateTime::parse_from_rfc2822(strip_weekday(raw.trim())))
        .ok()
        .map(|date| date.with_timezone(&Utc))
}

fn strip_weekday(value: &str) -> &str {
    match value.split_once(", ") {
        Some((weekday, rest))
            if weekday.len() == 3 && weekday.bytes().all(|byte| byte.is_ascii_alphabetic()) =>
        {
            rest
        }
        _ => value,
    }
}

fn normalize_message_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
        .unwrap_or(trimmed)
        .trim();
    (!inner.is_empty()).then(|| inner.to_owned())
}

fn parse_message_ids(raw: &str) -> Vec<String> {
    if raw.contains('<') {
        return raw
            .split('<')
            .filter_map(|rest| rest.split_once('>'))
            .filter_map(|(id, _)| normalize_message_id(id))
            .collect();
    }
    raw.split_whitespace()
        .filter_map(normalize_message_id)
        .collect()
}

fn bytes_to_string(bytes: &[u8]) -> String {
    from_utf8(bytes).map_or_else(
        |_| {
            bytes
                .iter()
                .map(|byte| char::from(*byte))
                .collect::<String>()
        },
        str::to_owned,
    )
}

fn decode_mime_bytes(bytes: &[u8]) -> String {
    Decoder::new()
        .too_long_encoded_word_strategy(RecoverStrategy::Decode)
        .decode(bytes)
        .unwrap_or_else(|_| bytes_to_string(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use io_imap::{
        codec::fragmentizer::Fragmentizer,
        coroutine::{ImapCoroutine, ImapCoroutineState, ImapYield},
        rfc3501::{fetch::ImapMessageFetch, search::ImapMessageSearch},
        types::sequence::SeqOrUid,
    };
    use kirje_core::{CredentialKind, Endpoint};

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
    fn search_keys_are_structured_and_bounded_upstream() {
        let search = MessageSearch {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            from: Some("alice@example.com".to_owned()),
            to: None,
            subject: Some("invoice".to_owned()),
            text: None,
            unread: Some(true),
            limit: 20,
        };
        let keys = build_search_keys(&search).expect("structured query");
        assert_eq!(keys.as_ref().len(), 3);
    }

    #[test]
    fn sync_uses_newest_initial_window_and_oldest_incremental_batch() {
        let mut initial = [1, 2, 3, 4]
            .into_iter()
            .map(|uid| NonZeroU32::new(uid).expect("uid"))
            .collect();
        assert!(select_sync_uids(&mut initial, 2, false));
        assert_eq!(
            initial.iter().map(|uid| uid.get()).collect::<Vec<_>>(),
            vec![4, 3]
        );

        let mut incremental = [7, 5, 6]
            .into_iter()
            .map(|uid| NonZeroU32::new(uid).expect("uid"))
            .collect();
        assert!(select_sync_uids(&mut incremental, 2, true));
        assert_eq!(
            incremental.iter().map(|uid| uid.get()).collect::<Vec<_>>(),
            vec![5, 6]
        );
    }

    #[test]
    fn incremental_sync_search_starts_above_high_water_uid() {
        let keys = sync_search_keys(Some(41)).expect("sync keys");
        assert!(matches!(&keys.as_ref()[0], SearchKey::Uid(_)));
    }

    #[test]
    fn incremental_sync_search_round_trips_a_uid_range_transcript() {
        let mut coroutine = ImapMessageSearch::new(
            sync_search_keys(Some(41)).expect("sync keys"),
            ImapMessageSearchOptions { uid: true },
        );
        let mut fragmentizer = Fragmentizer::new(1024);
        let transcript = b"* SEARCH 42 43\r\nA001 OK SEARCH completed\r\n";
        let mut input = None;
        let mut fed = false;
        let mut command = Vec::new();

        let ids = loop {
            match coroutine.resume(&mut fragmentizer, input.take()) {
                ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                    command.extend(bytes);
                }
                ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                    input = Some(if fed { b"" } else { transcript });
                    fed = true;
                }
                ImapCoroutineState::Complete(Ok(ids)) => break ids,
                ImapCoroutineState::Complete(Err(error)) => {
                    panic!("transcript failed: {error}")
                }
            }
        };

        let wire = String::from_utf8(command).expect("ASCII command");
        assert!(wire.contains("UID SEARCH UID 42:*"));
        assert_eq!(
            ids.iter().map(|uid| uid.get()).collect::<Vec<_>>(),
            vec![42, 43]
        );
    }

    #[test]
    fn raw_message_is_sanitized_bounded_and_untrusted() {
        let raw = b"From: Alice <alice@example.com>\r\nTo: Agent <agent@163.com>\r\nSubject: Test\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hello</p><script>alert('x')</script>world";
        let reference = MessageReference {
            account_id: account().id,
            mailbox: "INBOX".to_owned(),
            uid_validity: Some(1),
            uid: 2,
        };
        let parsed = parse_message(&reference, raw, 8).expect("parse message");

        assert!(parsed.untrusted);
        assert!(parsed.truncated);
        assert!(
            parsed
                .sanitized_html
                .as_deref()
                .is_some_and(|html| !html.contains("script"))
        );
    }

    #[test]
    fn attachment_selection_is_bounded_base64_and_untrusted() {
        let raw = concat!(
            "From: Alice <alice@example.com>\r\n",
            "To: Agent <agent@163.com>\r\n",
            "Subject: Files\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=x\r\n\r\n",
            "--x\r\nContent-Type: text/plain\r\n\r\nHello\r\n",
            "--x\r\nContent-Type: application/octet-stream\r\n",
            "Content-Disposition: attachment; filename=test.bin\r\n",
            "Content-Transfer-Encoding: base64\r\n\r\n",
            "AQIDBAU=\r\n--x--\r\n"
        );
        let read = AttachmentRead {
            reference: MessageReference {
                account_id: "personal".to_owned(),
                mailbox: "INBOX".to_owned(),
                uid_validity: Some(1),
                uid: 2,
            },
            part_id: "attachment-1".to_owned(),
            max_bytes: 3,
        };
        let attachment = parse_attachment(&read, raw.as_bytes()).expect("attachment");
        assert_eq!(attachment.content_base64, "AQID");
        assert_eq!(attachment.size, 5);
        assert!(attachment.truncated);
        assert!(attachment.untrusted);
        assert_eq!(attachment.filename.as_deref(), Some("test.bin"));
    }

    #[test]
    fn truncation_counts_characters_not_utf8_bytes() {
        let (value, truncated) = truncate(Some("邮件内容"), 2);
        assert_eq!(value.as_deref(), Some("邮件"));
        assert!(truncated);
    }

    #[test]
    fn message_references_reject_cross_account_use() {
        assert_eq!(
            ensure_account_scope(&account(), "other").unwrap_err().code,
            MailErrorCode::InvalidInput
        );
    }

    #[test]
    fn stale_uid_validity_is_rejected() {
        assert_eq!(
            ensure_uid_validity(Some(10), Some(11)).unwrap_err().code,
            MailErrorCode::MessageNotFound
        );
        assert!(ensure_uid_validity(None, Some(11)).is_ok());
    }

    #[test]
    fn body_fetch_is_peek_and_bounded_before_allocation() {
        let MacroOrMessageDataItemNames::MessageDataItemNames(items) = body_peek_fetch_items()
        else {
            panic!("expected explicit body item");
        };
        let MessageDataItemName::BodyExt { partial, peek, .. } = &items[0] else {
            panic!("expected body extension item");
        };
        assert!(*peek);
        assert_eq!(
            partial.map(|(_, length)| length.get()),
            Some(u32::try_from(MAX_RAW_MESSAGE_BYTES + 1).expect("bound fits u32"))
        );
    }

    #[test]
    fn provider_quirks_are_applied_by_the_adapter() {
        let netease = session_options(&account()).expect("NetEase options");
        assert_eq!(netease.sasl_ir, Some(false));

        let mut qq = account();
        qq.incoming.host = "imap.qq.com".to_owned();
        let qq = session_options(&qq).expect("QQ options");
        assert!(qq.auto_id.is_some());
    }

    #[test]
    fn bounded_peek_fetch_round_trips_a_server_transcript() {
        let uid = NonZeroU32::new(42).expect("positive uid");
        let mut coroutine = ImapMessageFetch::new(
            SequenceSet::from(SeqOrUid::from(uid)),
            body_peek_fetch_items(),
            ImapMessageFetchOptions {
                uid: true,
                ..Default::default()
            },
        );
        let mut fragmentizer = Fragmentizer::new(11 * 1024 * 1024);
        let transcript = b"* 1 FETCH (UID 42 BODY[]<0> {4}\r\nTest)\r\nA001 OK FETCH completed\r\n";
        let mut input = None;
        let mut fed = false;
        let mut command = Vec::new();

        let fetched = loop {
            match coroutine.resume(&mut fragmentizer, input.take()) {
                ImapCoroutineState::Yielded(ImapYield::WantsWrite(bytes)) => {
                    command.extend(bytes);
                }
                ImapCoroutineState::Yielded(ImapYield::WantsRead) => {
                    input = Some(if fed { b"" } else { transcript });
                    fed = true;
                }
                ImapCoroutineState::Complete(Ok(messages)) => break messages,
                ImapCoroutineState::Complete(Err(error)) => {
                    panic!("transcript failed: {error}")
                }
            }
        };

        let wire = String::from_utf8(command).expect("ASCII command");
        assert!(wire.contains("UID FETCH 42"));
        assert!(wire.contains("BODY.PEEK[]<0.10485761>"));
        assert_eq!(fetched.len(), 1);
    }
}
