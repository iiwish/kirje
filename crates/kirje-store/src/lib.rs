//! Transactional `SQLite` message index for Kirje.

mod authority;
mod outbox;

pub use authority::*;
pub use outbox::{SqliteOutbox, SqliteOutbox as SqliteOperationLedger};

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::{DateTime, SecondsFormat, Utc};
use kirje_core::{
    LocalMessageSearch, MAX_SYNC_LIMIT, MailError, MailErrorCode, MailboxSyncBatch,
    MailboxSyncReport, MailboxSyncState, MessageEnvelope, MessageIndex, MessagePage,
    MessageReference,
};
use rusqlite::{
    Connection, OptionalExtension as _, Transaction, params, params_from_iter, types::Value,
};

const SCHEMA_VERSION: i64 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct SqliteMessageIndex {
    path: PathBuf,
}

impl SqliteMessageIndex {
    /// Open or initialize a local Kirje message index.
    ///
    /// # Errors
    ///
    /// Returns a stable store or migration error without exposing `SQLite` details.
    pub fn open(path: PathBuf) -> Result<Self, MailError> {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(MailError::invalid_input(
                    "message index path must be a regular file",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(store_read_error()),
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            let created = !parent.exists();
            std::fs::create_dir_all(parent).map_err(|_| store_write_error())?;
            secure_created_directory(parent, created)?;
        }
        let index = Self { path };
        let mut connection = index.connection()?;
        migrate(&mut connection)?;
        index.secure_files()?;
        Ok(index)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn connection(&self) -> Result<Connection, MailError> {
        let connection = Connection::open(&self.path).map_err(|_| store_read_error())?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|_| store_read_error())?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .map_err(|_| store_read_error())?;
        self.secure_files()?;
        Ok(connection)
    }

    #[cfg(unix)]
    fn secure_files(&self) -> Result<(), MailError> {
        use std::os::unix::fs::PermissionsExt as _;

        for suffix in ["", "-wal", "-shm"] {
            let mut name = self.path.as_os_str().to_owned();
            name.push(suffix);
            let path = PathBuf::from(name);
            if path.exists() {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|_| store_write_error())?;
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn secure_files(&self) -> Result<(), MailError> {
        Ok(())
    }
}

#[cfg(unix)]
fn secure_created_directory(path: &Path, created: bool) -> Result<(), MailError> {
    use std::os::unix::fs::PermissionsExt as _;

    if created {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| store_write_error())?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_created_directory(_path: &Path, _created: bool) -> Result<(), MailError> {
    Ok(())
}

impl MessageIndex for SqliteMessageIndex {
    fn state(
        &self,
        account_id: &str,
        mailbox: &str,
    ) -> Result<Option<MailboxSyncState>, MailError> {
        validate_lookup_scope(account_id, mailbox)?;
        let connection = self.connection()?;
        let stored = connection
            .query_row(
                "SELECT s.uid_validity, s.highest_uid,
                        (SELECT COUNT(*) FROM messages m
                         WHERE m.account_id = s.account_id AND m.mailbox = s.mailbox),
                        s.initial_window_complete, s.remote_total, s.last_synced_at
                 FROM mailbox_sync_state s
                 WHERE s.account_id = ?1 AND s.mailbox = ?2",
                params![account_id, mailbox],
                stored_state_from_row,
            )
            .optional()
            .map_err(|_| store_read_error())?;
        stored
            .map(|state| state.into_domain(account_id, mailbox))
            .transpose()
    }

    fn apply_sync(
        &self,
        batch: &MailboxSyncBatch,
        replace: bool,
    ) -> Result<MailboxSyncReport, MailError> {
        validate_batch(batch)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(|_| store_write_error())?;
        let previous = state_in_transaction(&transaction, &batch.account_id, &batch.mailbox)?;
        let reset = replace
            || batch.reset_required
            || previous
                .as_ref()
                .is_some_and(|state| state.uid_validity != batch.uid_validity);

        if reset {
            transaction
                .execute(
                    "DELETE FROM messages WHERE account_id = ?1 AND mailbox = ?2",
                    params![batch.account_id, batch.mailbox],
                )
                .map_err(|_| store_write_error())?;
        }

        let indexed_at = now_string();
        for message in &batch.messages {
            upsert_message(&transaction, message, &indexed_at)?;
        }

        let batch_highest = batch
            .messages
            .iter()
            .map(|message| message.reference.uid)
            .max();
        let highest_uid = if reset {
            batch_highest
        } else {
            previous
                .as_ref()
                .and_then(|state| state.highest_uid)
                .into_iter()
                .chain(batch_highest)
                .max()
        };
        let initial_window_complete = if reset || previous.is_none() {
            !batch.has_more
        } else {
            previous
                .as_ref()
                .is_some_and(|state| state.initial_window_complete)
        };

        transaction
            .execute(
                "INSERT INTO mailbox_sync_state (
                    account_id, mailbox, uid_validity, highest_uid,
                    initial_window_complete, remote_total, last_synced_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(account_id, mailbox) DO UPDATE SET
                    uid_validity = excluded.uid_validity,
                    highest_uid = excluded.highest_uid,
                    initial_window_complete = excluded.initial_window_complete,
                    remote_total = excluded.remote_total,
                    last_synced_at = excluded.last_synced_at",
                params![
                    batch.account_id,
                    batch.mailbox,
                    batch.uid_validity,
                    highest_uid,
                    initial_window_complete,
                    batch.remote_total,
                    indexed_at,
                ],
            )
            .map_err(|_| store_write_error())?;

        let indexed_messages: u64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE account_id = ?1 AND mailbox = ?2",
                params![batch.account_id, batch.mailbox],
                |row| row.get(0),
            )
            .map_err(|_| store_read_error())?;
        transaction.commit().map_err(|_| store_write_error())?;

        let fetched = u16::try_from(batch.messages.len()).unwrap_or(MAX_SYNC_LIMIT);
        Ok(MailboxSyncReport {
            state: MailboxSyncState {
                account_id: batch.account_id.clone(),
                mailbox: batch.mailbox.clone(),
                uid_validity: batch.uid_validity,
                highest_uid,
                indexed_messages,
                initial_window_complete,
                remote_total: batch.remote_total,
                last_synced_at: parse_timestamp(&indexed_at)?,
            },
            fetched,
            stored: fetched,
            reset,
            has_more: batch.has_more,
        })
    }

    fn search(&self, search: &LocalMessageSearch) -> Result<MessagePage, MailError> {
        search.validate()?;
        let connection = self.connection()?;
        let mut sql = String::from(
            "SELECT uid_validity, uid, message_id, in_reply_to_json, subject,
                    from_json, to_json, sent_at, size, is_read, is_starred,
                    has_attachment, truncated
             FROM messages WHERE account_id = ? AND mailbox = ?",
        );
        let mut values = vec![
            Value::Text(search.account_id.clone()),
            Value::Text(search.mailbox.clone()),
        ];
        add_like_filter(&mut sql, &mut values, "from_json", search.from.as_deref());
        add_like_filter(&mut sql, &mut values, "to_json", search.to.as_deref());
        add_like_filter(&mut sql, &mut values, "subject", search.subject.as_deref());
        if let Some(unread) = search.unread {
            sql.push_str(" AND is_read = ?");
            values.push(Value::Integer(i64::from(!unread)));
        }
        sql.push_str(" ORDER BY sent_at IS NULL, sent_at DESC, uid DESC LIMIT ?");
        values.push(Value::Integer(i64::from(search.limit) + 1));

        let mut statement = connection.prepare(&sql).map_err(|_| store_read_error())?;
        let rows = statement
            .query_map(params_from_iter(values), |row| {
                message_from_row(&search.account_id, &search.mailbox, row)
            })
            .map_err(|_| store_read_error())?;
        let mut messages = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| store_read_error())?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = messages.len() > usize::from(search.limit);
        messages.truncate(usize::from(search.limit));

        Ok(MessagePage {
            returned: u16::try_from(messages.len()).unwrap_or(search.limit),
            messages,
            limit: search.limit,
            has_more,
            untrusted: true,
        })
    }
}

fn migrate(connection: &mut Connection) -> Result<(), MailError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| migration_error())?;
    if version > SCHEMA_VERSION {
        return Err(MailError::new(
            MailErrorCode::StoreMigration,
            "message index schema is newer than this Kirje version",
            false,
        ));
    }
    if version == SCHEMA_VERSION {
        return Ok(());
    }

    let transaction = connection.transaction().map_err(|_| migration_error())?;
    transaction
        .execute_batch(
            "CREATE TABLE mailbox_sync_state (
                account_id TEXT NOT NULL,
                mailbox TEXT NOT NULL,
                uid_validity INTEGER NOT NULL CHECK(uid_validity > 0),
                highest_uid INTEGER,
                initial_window_complete INTEGER NOT NULL,
                remote_total INTEGER,
                last_synced_at TEXT NOT NULL,
                PRIMARY KEY(account_id, mailbox)
             );
             CREATE TABLE messages (
                account_id TEXT NOT NULL,
                mailbox TEXT NOT NULL,
                uid_validity INTEGER NOT NULL CHECK(uid_validity > 0),
                uid INTEGER NOT NULL CHECK(uid > 0),
                message_id TEXT,
                in_reply_to_json TEXT NOT NULL,
                subject TEXT NOT NULL,
                from_json TEXT NOT NULL,
                to_json TEXT NOT NULL,
                sent_at TEXT,
                size INTEGER NOT NULL,
                is_read INTEGER NOT NULL,
                is_starred INTEGER NOT NULL,
                has_attachment INTEGER,
                truncated INTEGER NOT NULL,
                indexed_at TEXT NOT NULL,
                PRIMARY KEY(account_id, mailbox, uid_validity, uid)
             );
             CREATE INDEX messages_search_order
                ON messages(account_id, mailbox, sent_at DESC, uid DESC);
             PRAGMA user_version = 1;",
        )
        .map_err(|_| migration_error())?;
    transaction.commit().map_err(|_| migration_error())
}

fn validate_lookup_scope(account_id: &str, mailbox: &str) -> Result<(), MailError> {
    LocalMessageSearch {
        account_id: account_id.to_owned(),
        mailbox: mailbox.to_owned(),
        from: None,
        to: None,
        subject: None,
        unread: None,
        limit: 1,
    }
    .validate()
}

fn validate_batch(batch: &MailboxSyncBatch) -> Result<(), MailError> {
    validate_lookup_scope(&batch.account_id, &batch.mailbox)?;
    if batch.uid_validity == 0 || batch.messages.len() > usize::from(MAX_SYNC_LIMIT) {
        return Err(MailError::invalid_input(
            "sync batch requires positive UIDVALIDITY and at most 500 messages",
        ));
    }
    for message in &batch.messages {
        message.reference.validate()?;
        if message.reference.account_id != batch.account_id
            || message.reference.mailbox != batch.mailbox
            || message.reference.uid_validity != Some(batch.uid_validity)
        {
            return Err(MailError::invalid_input(
                "sync batch contains a message outside its mailbox UID namespace",
            ));
        }
    }
    Ok(())
}

fn state_in_transaction(
    transaction: &Transaction<'_>,
    account_id: &str,
    mailbox: &str,
) -> Result<Option<MailboxSyncState>, MailError> {
    let stored = transaction
        .query_row(
            "SELECT s.uid_validity, s.highest_uid,
                    (SELECT COUNT(*) FROM messages m
                     WHERE m.account_id = s.account_id AND m.mailbox = s.mailbox),
                    s.initial_window_complete, s.remote_total, s.last_synced_at
             FROM mailbox_sync_state s WHERE s.account_id = ?1 AND s.mailbox = ?2",
            params![account_id, mailbox],
            stored_state_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())?;
    stored
        .map(|state| state.into_domain(account_id, mailbox))
        .transpose()
}

struct StoredSyncState {
    uid_validity: u32,
    highest_uid: Option<u32>,
    indexed_messages: u64,
    initial_window_complete: bool,
    remote_total: Option<u64>,
    last_synced_at: String,
}

impl StoredSyncState {
    fn into_domain(self, account_id: &str, mailbox: &str) -> Result<MailboxSyncState, MailError> {
        Ok(MailboxSyncState {
            account_id: account_id.to_owned(),
            mailbox: mailbox.to_owned(),
            uid_validity: self.uid_validity,
            highest_uid: self.highest_uid,
            indexed_messages: self.indexed_messages,
            initial_window_complete: self.initial_window_complete,
            remote_total: self.remote_total,
            last_synced_at: parse_timestamp(&self.last_synced_at)?,
        })
    }
}

fn stored_state_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredSyncState> {
    Ok(StoredSyncState {
        uid_validity: row.get(0)?,
        highest_uid: row.get(1)?,
        indexed_messages: row.get(2)?,
        initial_window_complete: row.get(3)?,
        remote_total: row.get(4)?,
        last_synced_at: row.get(5)?,
    })
}

fn upsert_message(
    transaction: &Transaction<'_>,
    message: &MessageEnvelope,
    indexed_at: &str,
) -> Result<(), MailError> {
    let in_reply_to =
        serde_json::to_string(&message.in_reply_to).map_err(|_| store_write_error())?;
    let from = serde_json::to_string(&message.from).map_err(|_| store_write_error())?;
    let to = serde_json::to_string(&message.to).map_err(|_| store_write_error())?;
    transaction
        .execute(
            "INSERT INTO messages (
                account_id, mailbox, uid_validity, uid, message_id,
                in_reply_to_json, subject, from_json, to_json, sent_at, size,
                is_read, is_starred, has_attachment, truncated, indexed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
             ON CONFLICT(account_id, mailbox, uid_validity, uid) DO UPDATE SET
                message_id = excluded.message_id,
                in_reply_to_json = excluded.in_reply_to_json,
                subject = excluded.subject,
                from_json = excluded.from_json,
                to_json = excluded.to_json,
                sent_at = excluded.sent_at,
                size = excluded.size,
                is_read = excluded.is_read,
                is_starred = excluded.is_starred,
                has_attachment = excluded.has_attachment,
                truncated = excluded.truncated,
                indexed_at = excluded.indexed_at",
            params![
                message.reference.account_id,
                message.reference.mailbox,
                message.reference.uid_validity,
                message.reference.uid,
                message.message_id,
                in_reply_to,
                message.subject,
                from,
                to,
                message
                    .sent_at
                    .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true)),
                message.size,
                message.is_read,
                message.is_starred,
                message.has_attachment,
                message.truncated,
                indexed_at,
            ],
        )
        .map_err(|_| store_write_error())?;
    Ok(())
}

fn add_like_filter(sql: &mut String, values: &mut Vec<Value>, column: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        sql.push_str(" AND lower(");
        sql.push_str(column);
        sql.push_str(") LIKE ? ESCAPE '\\'");
        values.push(Value::Text(format!(
            "%{}%",
            escape_like(&value.to_lowercase())
        )));
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn message_from_row(
    account_id: &str,
    mailbox: &str,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<MessageEnvelope, MailError>> {
    let uid_validity = row.get(0)?;
    let uid = row.get(1)?;
    let in_reply_to_json: String = row.get(3)?;
    let from_json: String = row.get(5)?;
    let to_json: String = row.get(6)?;
    let sent_at: Option<String> = row.get(7)?;
    Ok((|| {
        Ok(MessageEnvelope {
            reference: MessageReference {
                account_id: account_id.to_owned(),
                mailbox: mailbox.to_owned(),
                uid_validity: Some(uid_validity),
                uid,
            },
            message_id: row.get(2).map_err(|_| store_read_error())?,
            in_reply_to: serde_json::from_str(&in_reply_to_json).map_err(|_| store_read_error())?,
            subject: row.get(4).map_err(|_| store_read_error())?,
            from: serde_json::from_str(&from_json).map_err(|_| store_read_error())?,
            to: serde_json::from_str(&to_json).map_err(|_| store_read_error())?,
            sent_at: sent_at.as_deref().map(parse_timestamp).transpose()?,
            size: row.get(8).map_err(|_| store_read_error())?,
            is_read: row.get(9).map_err(|_| store_read_error())?,
            is_starred: row.get(10).map_err(|_| store_read_error())?,
            has_attachment: row.get(11).map_err(|_| store_read_error())?,
            truncated: row.get(12).map_err(|_| store_read_error())?,
        })
    })())
}

fn now_string() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, MailError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| store_read_error())
}

fn store_read_error() -> MailError {
    MailError::new(
        MailErrorCode::StoreRead,
        "cannot read the local message index",
        false,
    )
}

fn store_write_error() -> MailError {
    MailError::new(
        MailErrorCode::StoreWrite,
        "cannot update the local message index",
        false,
    )
}

fn migration_error() -> MailError {
    MailError::new(
        MailErrorCode::StoreMigration,
        "cannot migrate the local message index",
        false,
    )
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use kirje_core::{MailAddress, MessageIndex as _};

    use super::*;

    fn index() -> (tempfile::TempDir, SqliteMessageIndex) {
        let directory = tempfile::tempdir().expect("temp dir");
        let index =
            SqliteMessageIndex::open(directory.path().join("index.sqlite3")).expect("open index");
        (directory, index)
    }

    fn message(uid_validity: u32, uid: u32, subject: &str, unread: bool) -> MessageEnvelope {
        MessageEnvelope {
            reference: MessageReference {
                account_id: "personal".to_owned(),
                mailbox: "INBOX".to_owned(),
                uid_validity: Some(uid_validity),
                uid,
            },
            message_id: Some(format!("{uid}@example.com")),
            in_reply_to: Vec::new(),
            subject: subject.to_owned(),
            from: vec![MailAddress {
                name: Some("Alice".to_owned()),
                email: "alice@example.com".to_owned(),
            }],
            to: vec![MailAddress {
                name: None,
                email: "agent@example.com".to_owned(),
            }],
            sent_at: Utc.with_ymd_and_hms(2026, 8, 26, 1, 2, uid).single(),
            size: 42,
            is_read: !unread,
            is_starred: false,
            has_attachment: Some(false),
            truncated: false,
        }
    }

    fn batch(uid_validity: u32, messages: Vec<MessageEnvelope>) -> MailboxSyncBatch {
        MailboxSyncBatch {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            uid_validity,
            messages,
            remote_total: Some(20),
            has_more: false,
            reset_required: false,
        }
    }

    #[test]
    fn opens_and_migrates_an_empty_database() {
        let (_directory, index) = index();
        assert!(index.state("personal", "INBOX").expect("state").is_none());
    }

    #[test]
    fn sync_upsert_is_idempotent_and_advances_cursor() {
        let (_directory, index) = index();
        let first = batch(7, vec![message(7, 10, "First", true)]);
        index.apply_sync(&first, false).expect("first sync");
        index.apply_sync(&first, false).expect("repeat sync");
        let second = batch(7, vec![message(7, 11, "Second", false)]);
        let report = index.apply_sync(&second, false).expect("second sync");

        assert_eq!(report.state.highest_uid, Some(11));
        assert_eq!(report.state.indexed_messages, 2);
    }

    #[test]
    fn uidvalidity_change_removes_stale_rows_atomically() {
        let (_directory, index) = index();
        index
            .apply_sync(&batch(7, vec![message(7, 10, "Old", true)]), false)
            .expect("old sync");
        let mut replacement = batch(8, vec![message(8, 1, "New", true)]);
        replacement.reset_required = true;
        let report = index.apply_sync(&replacement, false).expect("reset sync");

        assert!(report.reset);
        assert_eq!(report.state.uid_validity, 8);
        assert_eq!(report.state.indexed_messages, 1);
        let page = index.search(&search(None, None, 10)).expect("search");
        assert_eq!(page.messages[0].subject, "New");
    }

    #[test]
    fn local_search_filters_and_orders_without_network_state() {
        let (_directory, index) = index();
        index
            .apply_sync(
                &batch(
                    7,
                    vec![
                        message(7, 10, "Invoice", true),
                        message(7, 11, "Other", false),
                    ],
                ),
                false,
            )
            .expect("sync");

        let page = index
            .search(&search(Some("invoice"), Some(true), 1))
            .expect("search");
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].reference.uid, 10);
        assert!(!page.has_more);
    }

    #[test]
    fn newer_schema_is_rejected_without_downgrade() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("future.sqlite3");
        let connection = Connection::open(&path).expect("sqlite");
        connection
            .pragma_update(None, "user_version", 99)
            .expect("version");
        drop(connection);

        let error = SqliteMessageIndex::open(path).expect_err("reject future schema");
        assert_eq!(error.code, MailErrorCode::StoreMigration);
    }

    #[cfg(unix)]
    #[test]
    fn index_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_directory, index) = index();
        for suffix in ["", "-wal", "-shm"] {
            let mut name = index.path().as_os_str().to_owned();
            name.push(suffix);
            let path = PathBuf::from(name);
            if path.exists() {
                let mode = std::fs::metadata(path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn newly_created_index_directory_is_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temp dir");
        let directory = root.path().join("private-index");
        SqliteMessageIndex::open(directory.join("index.sqlite3")).expect("index");
        let mode = std::fs::metadata(directory)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_index_path_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temp dir");
        let target = directory.path().join("target.sqlite3");
        Connection::open(&target).expect("target");
        let link = directory.path().join("link.sqlite3");
        symlink(target, &link).expect("symlink");

        let error = SqliteMessageIndex::open(link).expect_err("reject symlink");
        assert_eq!(error.code, MailErrorCode::InvalidInput);
    }

    fn search(subject: Option<&str>, unread: Option<bool>, limit: u16) -> LocalMessageSearch {
        LocalMessageSearch {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            from: None,
            to: None,
            subject: subject.map(str::to_owned),
            unread,
            limit,
        }
    }
}
