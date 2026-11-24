//! Transactional `SQLite` message index for Kirje.

mod authority;
mod outbox;

pub use authority::*;
pub use outbox::{SqliteOutbox, SqliteOutbox as SqliteOperationLedger};

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::{DateTime, SecondsFormat, Utc};
use kirje_core::{
    LocalMessageSearch, MAX_SYNC_LIMIT, MailError, MailErrorCode, MailboxSyncBatch,
    MailboxSyncReport, MailboxSyncState, MessageEnvelope, MessageIndex, MessagePage,
    MessageReference, ThreadGraph, ThreadNode, ThreadQuery,
};
use rusqlite::{
    Connection, OptionalExtension as _, Transaction, params, params_from_iter, types::Value,
};

const SCHEMA_VERSION: i64 = 2;
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
                "SELECT s.uid_validity, s.highest_uid, s.lowest_uid,
                        (SELECT COUNT(*) FROM messages m
                         WHERE m.account_id = s.account_id AND m.mailbox = s.mailbox AND m.is_deleted = 0),
                        s.initial_window_complete, s.backfill_complete, s.remote_total, s.last_synced_at
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

    #[allow(clippy::too_many_lines)]
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

        for uid in &batch.tombstones {
            transaction
                .execute(
                    "UPDATE messages SET is_deleted = 1
                     WHERE account_id = ?1 AND mailbox = ?2 AND uid_validity = ?3 AND uid = ?4",
                    params![batch.account_id, batch.mailbox, batch.uid_validity, uid],
                )
                .map_err(|_| store_write_error())?;
        }

        let batch_highest = batch
            .messages
            .iter()
            .map(|message| message.reference.uid)
            .max();
        let batch_lowest = batch
            .messages
            .iter()
            .map(|message| message.reference.uid)
            .min()
            .or(batch.lowest_uid);

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
        let lowest_uid = if reset {
            batch_lowest
        } else {
            previous
                .as_ref()
                .and_then(|state| state.lowest_uid)
                .into_iter()
                .chain(batch_lowest)
                .min()
        };
        let initial_window_complete = if reset || previous.is_none() {
            !batch.has_more
        } else {
            previous
                .as_ref()
                .is_some_and(|state| state.initial_window_complete)
        };
        let backfill_complete = if reset {
            batch.backfill_complete
        } else {
            previous
                .as_ref()
                .is_some_and(|state| state.backfill_complete)
                || batch.backfill_complete
        };

        transaction
            .execute(
                "INSERT INTO mailbox_sync_state (
                    account_id, mailbox, uid_validity, highest_uid, lowest_uid,
                    initial_window_complete, backfill_complete, remote_total, last_synced_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(account_id, mailbox) DO UPDATE SET
                    uid_validity = excluded.uid_validity,
                    highest_uid = excluded.highest_uid,
                    lowest_uid = excluded.lowest_uid,
                    initial_window_complete = excluded.initial_window_complete,
                    backfill_complete = excluded.backfill_complete,
                    remote_total = excluded.remote_total,
                    last_synced_at = excluded.last_synced_at",
                params![
                    batch.account_id,
                    batch.mailbox,
                    batch.uid_validity,
                    highest_uid,
                    lowest_uid,
                    initial_window_complete,
                    backfill_complete,
                    batch.remote_total,
                    indexed_at,
                ],
            )
            .map_err(|_| store_write_error())?;

        let indexed_messages: u64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE account_id = ?1 AND mailbox = ?2 AND is_deleted = 0",
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
                lowest_uid,
                indexed_messages,
                initial_window_complete,
                backfill_complete,
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
             FROM messages WHERE account_id = ? AND mailbox = ? AND is_deleted = 0",
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

    #[allow(clippy::too_many_lines)]
    fn thread(&self, query: &ThreadQuery) -> Result<Option<ThreadGraph>, MailError> {
        query.validate()?;
        let connection = self.connection()?;

        let target = fetch_target_envelope(&connection, query)?;
        let Some(target) = target else {
            return Ok(None);
        };

        let state = self.state(&query.account_id, &query.mailbox)?;
        let backfill_complete = state.as_ref().is_some_and(|s| s.backfill_complete);

        let collected =
            collect_thread_envelopes(&connection, &query.account_id, &query.mailbox, &target)?;
        let (root, provisional) = build_thread_tree(&collected, &target, backfill_complete);
        let total_messages = count_messages(&root);
        let subject = root
            .subject
            .clone()
            .unwrap_or_else(|| target.subject.clone());
        let thread_id = root
            .message_id
            .clone()
            .or_else(|| target.message_id.clone())
            .unwrap_or_else(|| format!("uid-{}", target.reference.uid));

        Ok(Some(ThreadGraph {
            account_id: query.account_id.clone(),
            mailbox: query.mailbox.clone(),
            thread_id,
            subject,
            total_messages,
            provisional,
            root,
        }))
    }
}

const SELECT_ENVELOPE_COLUMNS: &str = "uid_validity, uid, message_id, in_reply_to_json, subject, from_json, to_json, sent_at, size, is_read, is_starred, has_attachment, truncated";

fn fetch_target_envelope(
    connection: &Connection,
    query: &ThreadQuery,
) -> Result<Option<MessageEnvelope>, MailError> {
    if let Some(uid) = query.uid {
        let sql = format!(
            "SELECT {SELECT_ENVELOPE_COLUMNS} FROM messages
             WHERE account_id = ?1 AND mailbox = ?2 AND uid = ?3 AND is_deleted = 0"
        );
        let mut statement = connection.prepare(&sql).map_err(|_| store_read_error())?;
        let mut rows = statement
            .query_map(params![query.account_id, query.mailbox, uid], |row| {
                message_from_row(&query.account_id, &query.mailbox, row)
            })
            .map_err(|_| store_read_error())?;
        match rows.next() {
            Some(row) => row.map_err(|_| store_read_error())?.map(Some),
            None => Ok(None),
        }
    } else if let Some(message_id) = &query.message_id {
        let sql = format!(
            "SELECT {SELECT_ENVELOPE_COLUMNS} FROM messages
             WHERE account_id = ?1 AND mailbox = ?2 AND message_id = ?3 AND is_deleted = 0
             ORDER BY sent_at IS NULL, sent_at DESC, uid DESC LIMIT 1"
        );
        let mut statement = connection.prepare(&sql).map_err(|_| store_read_error())?;
        let mut rows = statement
            .query_map(
                params![query.account_id, query.mailbox, message_id],
                |row| message_from_row(&query.account_id, &query.mailbox, row),
            )
            .map_err(|_| store_read_error())?;
        match rows.next() {
            Some(row) => row.map_err(|_| store_read_error())?.map(Some),
            None => Ok(None),
        }
    } else {
        Ok(None)
    }
}

fn collect_thread_envelopes(
    connection: &Connection,
    account_id: &str,
    mailbox: &str,
    target: &MessageEnvelope,
) -> Result<Vec<MessageEnvelope>, MailError> {
    let mut collected: Vec<MessageEnvelope> = vec![target.clone()];
    let mut seen_uids: HashSet<u32> = HashSet::new();
    seen_uids.insert(target.reference.uid);

    let mut queue: VecDeque<String> = VecDeque::new();
    let mut queued_ids: HashSet<String> = HashSet::new();

    if let Some(mid) = &target.message_id {
        queued_ids.insert(mid.clone());
        queue.push_back(mid.clone());
    }
    for parent in &target.in_reply_to {
        if queued_ids.insert(parent.clone()) {
            queue.push_back(parent.clone());
        }
    }

    let mut iterations = 0;
    while let Some(current_id) = queue.pop_front() {
        iterations += 1;
        if iterations > 200 {
            break;
        }

        let sql_up = format!(
            "SELECT {SELECT_ENVELOPE_COLUMNS} FROM messages
             WHERE account_id = ?1 AND mailbox = ?2 AND message_id = ?3 AND is_deleted = 0"
        );
        let mut stmt_up = connection
            .prepare(&sql_up)
            .map_err(|_| store_read_error())?;
        let rows_up = stmt_up
            .query_map(params![account_id, mailbox, current_id], |row| {
                message_from_row(account_id, mailbox, row)
            })
            .map_err(|_| store_read_error())?;
        for row in rows_up {
            let env = row.map_err(|_| store_read_error())??;
            if seen_uids.insert(env.reference.uid) {
                for parent in &env.in_reply_to {
                    if queued_ids.insert(parent.clone()) {
                        queue.push_back(parent.clone());
                    }
                }
                collected.push(env);
            }
        }

        let sql_down = format!(
            "SELECT {SELECT_ENVELOPE_COLUMNS} FROM messages
             WHERE account_id = ?1 AND mailbox = ?2 AND in_reply_to_json LIKE ?3 AND is_deleted = 0"
        );
        let mut stmt_down = connection
            .prepare(&sql_down)
            .map_err(|_| store_read_error())?;
        let pattern = format!("%\"{}\"%", current_id.replace('"', ""));
        let rows_down = stmt_down
            .query_map(params![account_id, mailbox, pattern], |row| {
                message_from_row(account_id, mailbox, row)
            })
            .map_err(|_| store_read_error())?;
        for row in rows_down {
            let env = row.map_err(|_| store_read_error())??;
            if seen_uids.insert(env.reference.uid) {
                if let Some(child_id) = env
                    .message_id
                    .as_ref()
                    .filter(|id| queued_ids.insert((*id).clone()))
                {
                    queue.push_back(child_id.clone());
                }
                collected.push(env);
            }
        }
    }

    Ok(collected)
}

fn build_thread_tree(
    messages: &[MessageEnvelope],
    target: &MessageEnvelope,
    backfill_complete: bool,
) -> (ThreadNode, bool) {
    let mut by_id: HashMap<String, Vec<&MessageEnvelope>> = HashMap::new();
    for msg in messages {
        if let Some(mid) = &msg.message_id {
            by_id.entry(mid.clone()).or_default().push(msg);
        }
    }
    for list in by_id.values_mut() {
        list.sort_unstable_by_key(|m| (m.sent_at, m.reference.uid));
    }

    let mut missing_parents: HashSet<String> = HashSet::new();
    let mut children_map: HashMap<String, Vec<&MessageEnvelope>> = HashMap::new();
    let mut roots: Vec<&MessageEnvelope> = Vec::new();

    for msg in messages {
        let parent_id = msg.in_reply_to.last().cloned();
        match parent_id {
            Some(pid) => {
                if by_id.contains_key(&pid) {
                    children_map.entry(pid).or_default().push(msg);
                } else {
                    missing_parents.insert(pid.clone());
                    children_map.entry(pid).or_default().push(msg);
                }
            }
            None => {
                roots.push(msg);
            }
        }
    }

    let has_missing = !missing_parents.is_empty();
    let provisional = !backfill_complete || has_missing;

    if let Some(first_missing) = missing_parents.iter().next() {
        let ancestor_missing = find_missing_ancestor_of_target(target, &missing_parents, &by_id)
            .unwrap_or_else(|| first_missing.clone());
        let mut path = HashSet::new();
        let root = build_node_for_missing(&ancestor_missing, &children_map, &mut path);
        return (root, provisional);
    }

    roots.sort_unstable_by_key(|m| (m.sent_at, m.reference.uid));
    let target_root = find_root_for_target(target, &roots, &by_id)
        .or_else(|| roots.first().copied())
        .unwrap_or(target);

    let mut path = HashSet::new();
    let root = build_node_for_message(target_root, &children_map, &mut path);
    (root, provisional)
}

fn build_node_for_message(
    msg: &MessageEnvelope,
    children_map: &HashMap<String, Vec<&MessageEnvelope>>,
    path: &mut HashSet<String>,
) -> ThreadNode {
    let mid_str = msg
        .message_id
        .clone()
        .unwrap_or_else(|| format!("uid:{}", msg.reference.uid));
    path.insert(mid_str.clone());

    let mut children = Vec::new();
    let child_msgs = msg
        .message_id
        .as_ref()
        .and_then(|mid| children_map.get(mid));
    if let Some(child_msgs) = child_msgs {
        let mut sorted = child_msgs.clone();
        sorted.sort_unstable_by_key(|m| (m.sent_at, m.reference.uid));
        for child in sorted {
            let child_id = child
                .message_id
                .clone()
                .unwrap_or_else(|| format!("uid:{}", child.reference.uid));
            if !path.contains(&child_id) {
                children.push(build_node_for_message(child, children_map, path));
            }
        }
    }

    path.remove(&mid_str);

    ThreadNode {
        message_id: msg.message_id.clone(),
        uid: Some(msg.reference.uid),
        subject: Some(msg.subject.clone()),
        from: msg.from.clone(),
        sent_at: msg.sent_at,
        is_read: Some(msg.is_read),
        missing: false,
        children,
    }
}

fn build_node_for_missing(
    missing_id: &str,
    children_map: &HashMap<String, Vec<&MessageEnvelope>>,
    path: &mut HashSet<String>,
) -> ThreadNode {
    path.insert(missing_id.to_owned());

    let mut children = Vec::new();
    if let Some(child_msgs) = children_map.get(missing_id) {
        let mut sorted = child_msgs.clone();
        sorted.sort_unstable_by_key(|m| (m.sent_at, m.reference.uid));
        for child in sorted {
            let child_id = child
                .message_id
                .clone()
                .unwrap_or_else(|| format!("uid:{}", child.reference.uid));
            if !path.contains(&child_id) {
                children.push(build_node_for_message(child, children_map, path));
            }
        }
    }

    path.remove(missing_id);

    ThreadNode {
        message_id: Some(missing_id.to_owned()),
        uid: None,
        subject: None,
        from: Vec::new(),
        sent_at: None,
        is_read: None,
        missing: true,
        children,
    }
}

fn count_messages(node: &ThreadNode) -> usize {
    let self_count = usize::from(!node.missing);
    let child_count: usize = node.children.iter().map(count_messages).sum();
    self_count + child_count
}

fn find_missing_ancestor_of_target(
    target: &MessageEnvelope,
    missing_parents: &HashSet<String>,
    by_id: &HashMap<String, Vec<&MessageEnvelope>>,
) -> Option<String> {
    let mut current_refs = target.in_reply_to.clone();
    let mut visited = HashSet::new();
    while let Some(parent_id) = current_refs.pop() {
        if !visited.insert(parent_id.clone()) {
            continue;
        }
        if missing_parents.contains(&parent_id) {
            return Some(parent_id);
        }
        if let Some(parents) = by_id.get(&parent_id) {
            for p in parents {
                for p_ref in &p.in_reply_to {
                    current_refs.push(p_ref.clone());
                }
            }
        }
    }
    None
}

fn find_root_for_target<'a>(
    target: &'a MessageEnvelope,
    roots: &[&'a MessageEnvelope],
    by_id: &HashMap<String, Vec<&'a MessageEnvelope>>,
) -> Option<&'a MessageEnvelope> {
    let mut current_refs = target.in_reply_to.clone();
    let mut visited = HashSet::new();
    while let Some(parent_id) = current_refs.pop() {
        if !visited.insert(parent_id.clone()) {
            continue;
        }
        for root in roots {
            if root.message_id.as_deref() == Some(&parent_id) {
                return Some(root);
            }
        }
        if let Some(parents) = by_id.get(&parent_id) {
            for p in parents {
                for p_ref in &p.in_reply_to {
                    current_refs.push(p_ref.clone());
                }
            }
        }
    }
    None
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
    if version == 0 {
        transaction
            .execute_batch(
                "CREATE TABLE mailbox_sync_state (
                    account_id TEXT NOT NULL,
                    mailbox TEXT NOT NULL,
                    uid_validity INTEGER NOT NULL CHECK(uid_validity > 0),
                    highest_uid INTEGER,
                    lowest_uid INTEGER,
                    initial_window_complete INTEGER NOT NULL,
                    backfill_complete INTEGER NOT NULL DEFAULT 0,
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
                    is_deleted INTEGER NOT NULL DEFAULT 0,
                    indexed_at TEXT NOT NULL,
                    PRIMARY KEY(account_id, mailbox, uid_validity, uid)
                 );
                 CREATE INDEX messages_search_order
                    ON messages(account_id, mailbox, sent_at DESC, uid DESC);
                 PRAGMA user_version = 2;",
            )
            .map_err(|_| migration_error())?;
    } else if version == 1 {
        transaction
            .execute_batch(
                "ALTER TABLE mailbox_sync_state ADD COLUMN lowest_uid INTEGER;
                 ALTER TABLE mailbox_sync_state ADD COLUMN backfill_complete INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE messages ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;
                 PRAGMA user_version = 2;",
            )
            .map_err(|_| migration_error())?;
    }
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
            "SELECT s.uid_validity, s.highest_uid, s.lowest_uid,
                    (SELECT COUNT(*) FROM messages m
                     WHERE m.account_id = s.account_id AND m.mailbox = s.mailbox AND m.is_deleted = 0),
                    s.initial_window_complete, s.backfill_complete, s.remote_total, s.last_synced_at
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
    lowest_uid: Option<u32>,
    indexed_messages: u64,
    initial_window_complete: bool,
    backfill_complete: bool,
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
            lowest_uid: self.lowest_uid,
            indexed_messages: self.indexed_messages,
            initial_window_complete: self.initial_window_complete,
            backfill_complete: self.backfill_complete,
            remote_total: self.remote_total,
            last_synced_at: parse_timestamp(&self.last_synced_at)?,
        })
    }
}

fn stored_state_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredSyncState> {
    Ok(StoredSyncState {
        uid_validity: row.get(0)?,
        highest_uid: row.get(1)?,
        lowest_uid: row.get(2)?,
        indexed_messages: row.get(3)?,
        initial_window_complete: row.get(4)?,
        backfill_complete: row.get(5)?,
        remote_total: row.get(6)?,
        last_synced_at: row.get(7)?,
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
            tombstones: Vec::new(),
            lowest_uid: None,
            remote_total: Some(20),
            has_more: false,
            reset_required: false,
            backfill_complete: false,
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
    fn backfill_sync_tracks_lowest_uid_and_completion() {
        let (_directory, index) = index();
        let mut first = batch(7, vec![message(7, 20, "Recent", true)]);
        first.has_more = true;
        let report = index.apply_sync(&first, false).expect("initial sync");
        assert_eq!(report.state.highest_uid, Some(20));
        assert_eq!(report.state.lowest_uid, Some(20));
        assert!(!report.state.backfill_complete);

        let mut backfill = batch(7, vec![message(7, 15, "Older", true)]);
        backfill.lowest_uid = Some(15);
        backfill.backfill_complete = true;
        let report = index.apply_sync(&backfill, false).expect("backfill sync");
        assert_eq!(report.state.highest_uid, Some(20));
        assert_eq!(report.state.lowest_uid, Some(15));
        assert!(report.state.backfill_complete);
        assert_eq!(report.state.indexed_messages, 2);
    }

    #[test]
    fn tombstones_mark_disappeared_messages_and_exclude_from_search() {
        let (_directory, index) = index();
        let initial = batch(
            7,
            vec![
                message(7, 10, "Keep", true),
                message(7, 11, "DeleteMe", true),
            ],
        );
        index.apply_sync(&initial, false).expect("initial sync");

        let mut reconciliation = batch(7, Vec::new());
        reconciliation.tombstones = vec![11];
        let report = index
            .apply_sync(&reconciliation, false)
            .expect("reconciliation");

        assert_eq!(report.state.indexed_messages, 1);
        let page = index.search(&search(None, None, 10)).expect("search");
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].subject, "Keep");
    }

    #[test]
    fn schema_v1_to_v2_migration_preserves_existing_data() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("v1.sqlite3");
        let connection = Connection::open(&path).expect("open");
        connection
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
                 PRAGMA user_version = 1;
                 INSERT INTO mailbox_sync_state VALUES ('personal', 'INBOX', 7, 100, 1, 10, '2026-08-26T01:02:03Z');
                 INSERT INTO messages VALUES ('personal', 'INBOX', 7, 100, 'msg-100', '[]', 'Subject', '[]', '[]', '2026-08-26T01:02:03Z', 50, 0, 0, 0, 0, '2026-08-26T01:02:03Z');",
            )
            .expect("init v1");
        drop(connection);

        let index = SqliteMessageIndex::open(path).expect("migrate to v2");
        let state = index
            .state("personal", "INBOX")
            .expect("state")
            .expect("exists");
        assert_eq!(state.uid_validity, 7);
        assert_eq!(state.highest_uid, Some(100));
        assert_eq!(state.indexed_messages, 1);
        let page = index.search(&search(None, None, 10)).expect("search");
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].subject, "Subject");
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

    #[test]
    fn thread_reconstruction_linear_hierarchy_and_provisional_flag() {
        let (_directory, index) = index();

        let mut msg_a = message(1, 1, "Root Topic", true);
        msg_a.message_id = Some("a@example.com".to_owned());

        let mut msg_b = message(1, 2, "Re: Root Topic", true);
        msg_b.message_id = Some("b@example.com".to_owned());
        msg_b.in_reply_to = vec!["a@example.com".to_owned()];

        let mut msg_c = message(1, 3, "Re: Re: Root Topic", true);
        msg_c.message_id = Some("c@example.com".to_owned());
        msg_c.in_reply_to = vec!["a@example.com".to_owned(), "b@example.com".to_owned()];

        let mut sync_batch = batch(1, vec![msg_a, msg_b, msg_c]);
        sync_batch.backfill_complete = true;
        index.apply_sync(&sync_batch, false).expect("sync");

        let query = ThreadQuery {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            uid: Some(2),
            message_id: None,
        };
        let graph = index.thread(&query).expect("thread").expect("found");
        assert_eq!(graph.thread_id, "a@example.com");
        assert_eq!(graph.total_messages, 3);
        assert!(!graph.provisional);
        assert_eq!(graph.root.message_id.as_deref(), Some("a@example.com"));
        assert_eq!(graph.root.children.len(), 1);
        assert_eq!(
            graph.root.children[0].message_id.as_deref(),
            Some("b@example.com")
        );
        assert_eq!(graph.root.children[0].children.len(), 1);
        assert_eq!(
            graph.root.children[0].children[0].message_id.as_deref(),
            Some("c@example.com")
        );
    }

    #[test]
    fn thread_reconstruction_handles_branching_and_missing_parent() {
        let (_directory, index) = index();

        let mut msg_b = message(1, 2, "Re: Root Topic", true);
        msg_b.message_id = Some("b@example.com".to_owned());
        msg_b.in_reply_to = vec!["missing-root@example.com".to_owned()];

        let mut msg_c = message(1, 3, "Re: Root Topic (other branch)", true);
        msg_c.message_id = Some("c@example.com".to_owned());
        msg_c.in_reply_to = vec!["missing-root@example.com".to_owned()];

        let mut sync_batch = batch(1, vec![msg_b, msg_c]);
        sync_batch.backfill_complete = false;
        index.apply_sync(&sync_batch, false).expect("sync");

        let query = ThreadQuery {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            uid: None,
            message_id: Some("b@example.com".to_owned()),
        };
        let graph = index.thread(&query).expect("thread").expect("found");
        assert!(graph.provisional);
        assert_eq!(graph.total_messages, 2);
        assert!(graph.root.missing);
        assert_eq!(
            graph.root.message_id.as_deref(),
            Some("missing-root@example.com")
        );
        assert_eq!(graph.root.children.len(), 2);
    }

    #[test]
    fn thread_reconstruction_breaks_cycles_and_ignores_subject_only_similarity() {
        let (_directory, index) = index();

        let mut msg_x = message(1, 10, "Cycle Topic", true);
        msg_x.message_id = Some("x@example.com".to_owned());
        msg_x.in_reply_to = vec!["y@example.com".to_owned()];

        let mut msg_y = message(1, 11, "Cycle Topic", true);
        msg_y.message_id = Some("y@example.com".to_owned());
        msg_y.in_reply_to = vec!["x@example.com".to_owned()];

        let mut msg_separate = message(1, 12, "Cycle Topic", true);
        msg_separate.message_id = Some("separate@example.com".to_owned());
        msg_separate.in_reply_to = Vec::new();

        let sync_batch = batch(1, vec![msg_x, msg_y, msg_separate]);
        index.apply_sync(&sync_batch, false).expect("sync");

        let query = ThreadQuery {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            uid: Some(10),
            message_id: None,
        };
        let graph = index.thread(&query).expect("thread").expect("found");
        assert_eq!(graph.total_messages, 2);

        let query_sep = ThreadQuery {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            uid: Some(12),
            message_id: None,
        };
        let graph_sep = index.thread(&query_sep).expect("thread").expect("found");
        assert_eq!(graph_sep.total_messages, 1);
        assert_eq!(graph_sep.thread_id, "separate@example.com");
    }
}
