use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use kirje_core::{
    Draft, DraftStatus, MAX_DRAFTS, MAX_OPERATION_LIMIT, MAX_SEND_PLAN_LIMIT, MailError,
    MailErrorCode, OperationEvent, OperationLedger, OperationRecord, OperationStatus, Outbox,
    SendPlan, SendPlanStatus, SendPlanSummary, SendReceipt, SendRequest, digest_json,
};
use rusqlite::{Connection, OptionalExtension as _, Row, Transaction, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

const SCHEMA_VERSION: i64 = 2;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const STALE_APPLY_MINUTES: i64 = 15;

#[derive(Clone, Debug)]
pub struct SqliteOutbox {
    path: PathBuf,
}

impl SqliteOutbox {
    /// Open or initialize a private local send outbox.
    ///
    /// # Errors
    ///
    /// Returns stable path, store, or migration errors.
    pub fn open(path: PathBuf) -> Result<Self, MailError> {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(MailError::invalid_input(
                    "outbox path must be a regular file",
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
        let outbox = Self { path };
        let mut connection = outbox.connection()?;
        migrate(&mut connection)?;
        outbox.secure_files()?;
        Ok(outbox)
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
            .execute_batch("PRAGMA journal_mode = WAL;")
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

impl Outbox for SqliteOutbox {
    fn create(&self, plan: &SendPlan) -> Result<SendPlan, MailError> {
        plan.request.validate()?;
        if plan.status != SendPlanStatus::Planned
            || plan.approved_at.is_some()
            || plan.attempt_count != 0
            || plan.last_error.is_some()
            || plan.receipt.is_some()
        {
            return Err(state_error(
                "only a new planned message can enter the outbox",
            ));
        }
        let (payload_json, payload_sha256) = digest_json(&plan.request)?;
        let operation = OperationRecord {
            id: plan.id.clone(),
            kind: "send".to_owned(),
            account_id: plan.request.account_id.clone(),
            message_id: Some(plan.message_id.clone()),
            payload_json,
            payload_sha256,
            status: OperationStatus::Planned,
            created_at: plan.created_at,
            expires_at: Some(plan.expires_at),
            approved_at: None,
            updated_at: plan.updated_at,
            attempt_count: 0,
            last_error: None,
            receipt_json: None,
        };
        self.create_operation(&operation)?;
        Ok(plan.clone())
    }

    fn get(&self, plan_id: &str, now: DateTime<Utc>) -> Result<Option<SendPlan>, MailError> {
        self.get_operation(plan_id, now)?
            .map(|operation| send_plan_from_operation(&operation))
            .transpose()
    }

    fn list(
        &self,
        account_id: Option<&str>,
        limit: u16,
        now: DateTime<Utc>,
    ) -> Result<Vec<SendPlanSummary>, MailError> {
        if limit == 0 || limit > MAX_OPERATION_LIMIT {
            return Err(MailError::invalid_input(format!(
                "send plan limit must be between 1 and {MAX_SEND_PLAN_LIMIT}"
            )));
        }
        if account_id.is_some_and(str::is_empty) {
            return Err(MailError::invalid_input("account id cannot be empty"));
        }
        self.list_operations(account_id, Some("send"), limit, now)?
            .into_iter()
            .map(|operation| send_plan_from_operation(&operation).map(|plan| plan.summary()))
            .collect()
    }

    fn approve(&self, plan_id: &str, now: DateTime<Utc>) -> Result<SendPlan, MailError> {
        self.approve_operation(plan_id, now)
            .and_then(|operation| send_plan_from_operation(&operation))
    }

    fn claim(&self, plan_id: &str, now: DateTime<Utc>) -> Result<SendPlan, MailError> {
        self.claim_operation(plan_id, now)
            .and_then(|operation| send_plan_from_operation(&operation))
    }

    fn mark_sent(&self, plan_id: &str, receipt: SendReceipt) -> Result<SendPlan, MailError> {
        let receipt_json = serde_json::to_string(&receipt).map_err(|_| store_write_error())?;
        self.succeed_operation(plan_id, receipt_json, receipt.sent_at)
            .and_then(|operation| send_plan_from_operation(&operation))
    }

    fn mark_failed(
        &self,
        plan_id: &str,
        error: MailError,
        now: DateTime<Utc>,
    ) -> Result<SendPlan, MailError> {
        self.fail_operation(plan_id, error, now)
            .and_then(|operation| send_plan_from_operation(&operation))
    }

    fn mark_ambiguous(
        &self,
        plan_id: &str,
        mut error: MailError,
        now: DateTime<Utc>,
    ) -> Result<SendPlan, MailError> {
        error.retryable = false;
        self.ambiguous_operation(plan_id, error, now)
            .and_then(|operation| send_plan_from_operation(&operation))
    }
}

impl OperationLedger for SqliteOutbox {
    fn create_operation(&self, operation: &OperationRecord) -> Result<OperationRecord, MailError> {
        validate_operation_id(&operation.id)?;
        if operation.status != OperationStatus::Planned
            || operation.payload_json.is_empty()
            || operation.payload_sha256 != payload_digest(&operation.payload_json)
        {
            return Err(state_error(
                "only a new planned operation with a valid digest can enter the ledger",
            ));
        }
        let connection = self.connection()?;
        let transaction = connection
            .unchecked_transaction()
            .map_err(|_| store_write_error())?;
        transaction
            .execute(
                "INSERT INTO operations (
                    id, kind, account_id, message_id, payload_json, payload_sha256, status,
                    created_at, expires_at, approved_at, updated_at, attempt_count,
                    last_error_json, receipt_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, 0, NULL, NULL)",
                params![
                    operation.id,
                    operation.kind,
                    operation.account_id,
                    operation.message_id,
                    operation.payload_json,
                    operation.payload_sha256,
                    operation_status_name(operation.status),
                    timestamp(operation.created_at),
                    operation.expires_at.map(timestamp),
                    timestamp(operation.updated_at),
                ],
            )
            .map_err(|_| state_error("operation already exists or is invalid"))?;
        append_event(
            &transaction,
            operation,
            "created",
            Some(operation.status),
            None,
        )?;
        transaction.commit().map_err(|_| store_write_error())?;
        Ok(operation.clone())
    }

    fn get_operation(
        &self,
        operation_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<OperationRecord>, MailError> {
        validate_operation_id(operation_id)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| store_write_error())?;
        reconcile_operations(&transaction, now)?;
        let operation = operation_in_transaction(&transaction, operation_id)?;
        transaction.commit().map_err(|_| store_write_error())?;
        Ok(operation)
    }

    fn list_operations(
        &self,
        account_id: Option<&str>,
        kind: Option<&str>,
        limit: u16,
        now: DateTime<Utc>,
    ) -> Result<Vec<OperationRecord>, MailError> {
        if limit == 0 || limit > MAX_OPERATION_LIMIT {
            return Err(MailError::invalid_input(format!(
                "operation limit must be between 1 and {MAX_OPERATION_LIMIT}"
            )));
        }
        if account_id.is_some_and(str::is_empty) || kind.is_some_and(str::is_empty) {
            return Err(MailError::invalid_input(
                "operation filters cannot be empty",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| store_write_error())?;
        reconcile_operations(&transaction, now)?;
        let mut operations = Vec::new();
        let mut statement = match (account_id, kind) {
            (Some(_), Some(_)) => transaction
                .prepare("SELECT * FROM operations WHERE account_id = ?1 AND kind = ?2 ORDER BY created_at DESC LIMIT ?3")
                .map_err(|_| store_read_error())?,
            (Some(_), None) => transaction
                .prepare("SELECT * FROM operations WHERE account_id = ?1 ORDER BY created_at DESC LIMIT ?2")
                .map_err(|_| store_read_error())?,
            (None, Some(_)) => transaction
                .prepare("SELECT * FROM operations WHERE kind = ?1 ORDER BY created_at DESC LIMIT ?2")
                .map_err(|_| store_read_error())?,
            (None, None) => transaction
                .prepare("SELECT * FROM operations ORDER BY created_at DESC LIMIT ?1")
                .map_err(|_| store_read_error())?,
        };
        let rows = match (account_id, kind) {
            (Some(account_id), Some(kind)) => {
                statement.query_map(params![account_id, kind, limit], operation_from_row)
            }
            (Some(account_id), None) => {
                statement.query_map(params![account_id, limit], operation_from_row)
            }
            (None, Some(kind)) => statement.query_map(params![kind, limit], operation_from_row),
            (None, None) => statement.query_map(params![limit], operation_from_row),
        }
        .map_err(|_| store_read_error())?;
        for row in rows {
            operations.push(row.map_err(|_| store_read_error())??);
        }
        drop(statement);
        transaction.commit().map_err(|_| store_write_error())?;
        Ok(operations)
    }

    fn approve_operation(
        &self,
        operation_id: &str,
        now: DateTime<Utc>,
    ) -> Result<OperationRecord, MailError> {
        operation_transition(
            self,
            operation_id,
            now,
            OperationStatus::Planned,
            OperationStatus::Approved,
            true,
        )
    }

    fn claim_operation(
        &self,
        operation_id: &str,
        now: DateTime<Utc>,
    ) -> Result<OperationRecord, MailError> {
        operation_transition(
            self,
            operation_id,
            now,
            OperationStatus::Approved,
            OperationStatus::Applying,
            false,
        )
    }

    fn succeed_operation(
        &self,
        operation_id: &str,
        receipt_json: String,
        now: DateTime<Utc>,
    ) -> Result<OperationRecord, MailError> {
        finish_operation(
            self,
            operation_id,
            now,
            OperationStatus::Succeeded,
            None,
            Some(&receipt_json),
        )
    }

    fn fail_operation(
        &self,
        operation_id: &str,
        error: MailError,
        now: DateTime<Utc>,
    ) -> Result<OperationRecord, MailError> {
        finish_operation(
            self,
            operation_id,
            now,
            OperationStatus::Failed,
            Some(error),
            None,
        )
    }

    fn ambiguous_operation(
        &self,
        operation_id: &str,
        mut error: MailError,
        now: DateTime<Utc>,
    ) -> Result<OperationRecord, MailError> {
        error.retryable = false;
        finish_operation(
            self,
            operation_id,
            now,
            OperationStatus::Ambiguous,
            Some(error),
            None,
        )
    }

    fn audit(&self, operation_id: &str, limit: u16) -> Result<Vec<OperationEvent>, MailError> {
        validate_operation_id(operation_id)?;
        if limit == 0 || limit > MAX_OPERATION_LIMIT {
            return Err(MailError::invalid_input(format!(
                "audit limit must be between 1 and {MAX_OPERATION_LIMIT}"
            )));
        }
        let connection = self.connection()?;
        let mut statement = connection
            .prepare("SELECT sequence, operation_id, event, status, occurred_at, payload_sha256, detail FROM operation_events WHERE operation_id = ?1 ORDER BY sequence ASC LIMIT ?2")
            .map_err(|_| store_read_error())?;
        let rows = statement
            .query_map(params![operation_id, limit], event_from_row)
            .map_err(|_| store_read_error())?;
        rows.map(|row| row.map_err(|_| store_read_error()).and_then(|event| event))
            .collect()
    }

    fn create_draft(&self, draft: &Draft) -> Result<Draft, MailError> {
        if draft.status != DraftStatus::Draft {
            return Err(state_error("only an active draft can be created"));
        }
        draft.request.validate()?;
        if self.list_drafts(&draft.account_id, MAX_DRAFTS)?.len() >= usize::from(MAX_DRAFTS) {
            return Err(MailError::new(
                MailErrorCode::ResourceLimit,
                format!("an account cannot have more than {MAX_DRAFTS} active drafts"),
                false,
            ));
        }
        let (payload_json, payload_sha256) = digest_json(draft)?;
        let operation = OperationRecord {
            id: draft.id.clone(),
            kind: "draft".to_owned(),
            account_id: draft.account_id.clone(),
            message_id: None,
            payload_json,
            payload_sha256,
            status: OperationStatus::Planned,
            created_at: draft.created_at,
            expires_at: None,
            approved_at: None,
            updated_at: draft.updated_at,
            attempt_count: 0,
            last_error: None,
            receipt_json: None,
        };
        self.create_operation(&operation)?;
        Ok(draft.clone())
    }

    fn get_draft(&self, draft_id: &str) -> Result<Option<Draft>, MailError> {
        self.get_operation(draft_id, Utc::now())?
            .filter(|operation| operation.kind == "draft")
            .map(|operation| {
                serde_json::from_str(&operation.payload_json).map_err(|_| store_read_error())
            })
            .transpose()
    }

    fn list_drafts(&self, account_id: &str, limit: u16) -> Result<Vec<Draft>, MailError> {
        self.list_operations(Some(account_id), Some("draft"), limit, Utc::now())?
            .into_iter()
            .filter_map(|operation| {
                let draft: Result<Draft, _> = serde_json::from_str(&operation.payload_json);
                match draft {
                    Ok(draft) if draft.status == DraftStatus::Draft => Some(Ok(draft)),
                    Ok(_) => None,
                    Err(_) => Some(Err(store_read_error())),
                }
            })
            .collect()
    }

    fn update_draft(&self, draft: &Draft) -> Result<Draft, MailError> {
        if draft.status != DraftStatus::Draft {
            return Err(state_error("only an active draft can be updated"));
        }
        draft.request.validate()?;
        let (payload_json, payload_sha256) = digest_json(draft)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| store_write_error())?;
        let existing =
            operation_in_transaction(&transaction, &draft.id)?.ok_or_else(not_found_error)?;
        if existing.kind != "draft" || existing.status != OperationStatus::Planned {
            return Err(state_error("only an active draft can be updated"));
        }
        transaction
            .execute(
                "UPDATE operations SET account_id = ?1, payload_json = ?2, payload_sha256 = ?3, updated_at = ?4 WHERE id = ?5 AND kind = 'draft' AND status = 'planned'",
                params![draft.account_id, payload_json, payload_sha256, timestamp(draft.updated_at), draft.id],
            )
            .map_err(|_| store_write_error())?;
        let updated =
            operation_in_transaction(&transaction, &draft.id)?.ok_or_else(not_found_error)?;
        append_event(
            &transaction,
            &updated,
            "updated",
            Some(OperationStatus::Planned),
            None,
        )?;
        transaction.commit().map_err(|_| store_write_error())?;
        Ok(draft.clone())
    }

    fn discard_draft(&self, draft_id: &str, now: DateTime<Utc>) -> Result<Draft, MailError> {
        let current = self.get_draft(draft_id)?.ok_or_else(not_found_error)?;
        if current.status != DraftStatus::Draft {
            return Err(state_error("draft is already discarded"));
        }
        let mut discarded = current;
        discarded.status = DraftStatus::Discarded;
        discarded.updated_at = now;
        let (payload_json, payload_sha256) = digest_json(&discarded)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| store_write_error())?;
        transaction
            .execute(
                "UPDATE operations SET payload_json = ?1, payload_sha256 = ?2, updated_at = ?3 WHERE id = ?4 AND kind = 'draft' AND status = 'planned'",
                params![payload_json, payload_sha256, timestamp(now), draft_id],
            )
            .map_err(|_| store_write_error())?;
        let updated =
            operation_in_transaction(&transaction, draft_id)?.ok_or_else(not_found_error)?;
        append_event(
            &transaction,
            &updated,
            "discarded",
            Some(OperationStatus::Planned),
            None,
        )?;
        transaction.commit().map_err(|_| store_write_error())?;
        Ok(discarded)
    }
}

fn operation_transition(
    ledger: &SqliteOutbox,
    operation_id: &str,
    now: DateTime<Utc>,
    from: OperationStatus,
    to: OperationStatus,
    approve: bool,
) -> Result<OperationRecord, MailError> {
    validate_operation_id(operation_id)?;
    let mut connection = ledger.connection()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store_write_error())?;
    reconcile_operations(&transaction, now)?;
    let existing =
        operation_in_transaction(&transaction, operation_id)?.ok_or_else(not_found_error)?;
    if existing.kind == "draft" {
        return Err(state_error(
            "drafts do not participate in approval or apply transitions",
        ));
    }
    if existing.status != from {
        return Err(state_error(format!(
            "operation is {}, expected {}",
            operation_status_name(existing.status),
            operation_status_name(from)
        )));
    }
    let approved_at = approve.then(|| timestamp(now));
    let next_attempt = u32::from(to == OperationStatus::Applying);
    transaction
        .execute(
            "UPDATE operations SET status = ?1, approved_at = COALESCE(?2, approved_at), updated_at = ?3, attempt_count = attempt_count + ?4 WHERE id = ?5 AND status = ?6",
            params![operation_status_name(to), approved_at, timestamp(now), next_attempt, operation_id, operation_status_name(from)],
        )
        .map_err(|_| store_write_error())?;
    let updated =
        operation_in_transaction(&transaction, operation_id)?.ok_or_else(not_found_error)?;
    append_event(&transaction, &updated, "transitioned", Some(to), None)?;
    transaction.commit().map_err(|_| store_write_error())?;
    Ok(updated)
}

fn finish_operation(
    ledger: &SqliteOutbox,
    operation_id: &str,
    now: DateTime<Utc>,
    status: OperationStatus,
    error: Option<MailError>,
    receipt_json: Option<&str>,
) -> Result<OperationRecord, MailError> {
    validate_operation_id(operation_id)?;
    let error_json = error
        .map(|error| serde_json::to_string(&error).map_err(|_| store_write_error()))
        .transpose()?;
    let mut connection = ledger.connection()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store_write_error())?;
    let existing =
        operation_in_transaction(&transaction, operation_id)?.ok_or_else(not_found_error)?;
    if existing.status != OperationStatus::Applying {
        return Err(state_error("only an applying operation can be finalized"));
    }
    transaction
        .execute(
            "UPDATE operations SET status = ?1, updated_at = ?2, last_error_json = ?3, receipt_json = ?4 WHERE id = ?5 AND status = 'applying'",
            params![operation_status_name(status), timestamp(now), error_json, receipt_json, operation_id],
        )
        .map_err(|_| store_write_error())?;
    let updated =
        operation_in_transaction(&transaction, operation_id)?.ok_or_else(not_found_error)?;
    append_event(&transaction, &updated, "finalized", Some(status), None)?;
    transaction.commit().map_err(|_| store_write_error())?;
    Ok(updated)
}

fn operation_in_transaction(
    transaction: &Transaction<'_>,
    operation_id: &str,
) -> Result<Option<OperationRecord>, MailError> {
    transaction
        .query_row(
            "SELECT * FROM operations WHERE id = ?1",
            params![operation_id],
            operation_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())?
        .transpose()
}

fn operation_from_row(row: &Row<'_>) -> rusqlite::Result<Result<OperationRecord, MailError>> {
    let status: String = row.get("status")?;
    let created_at: String = row.get("created_at")?;
    let expires_at: Option<String> = row.get("expires_at")?;
    let approved_at: Option<String> = row.get("approved_at")?;
    let updated_at: String = row.get("updated_at")?;
    let last_error_json: Option<String> = row.get("last_error_json")?;
    Ok((|| {
        let payload_json: String = row.get("payload_json").map_err(|_| store_read_error())?;
        let payload_sha256: String = row.get("payload_sha256").map_err(|_| store_read_error())?;
        if payload_sha256 != payload_digest(&payload_json) {
            return Err(store_read_error());
        }
        Ok(OperationRecord {
            id: row.get("id").map_err(|_| store_read_error())?,
            kind: row.get("kind").map_err(|_| store_read_error())?,
            account_id: row.get("account_id").map_err(|_| store_read_error())?,
            message_id: row.get("message_id").map_err(|_| store_read_error())?,
            payload_json,
            payload_sha256,
            status: parse_operation_status(&status)?,
            created_at: parse_timestamp(&created_at)?,
            expires_at: expires_at.as_deref().map(parse_timestamp).transpose()?,
            approved_at: approved_at.as_deref().map(parse_timestamp).transpose()?,
            updated_at: parse_timestamp(&updated_at)?,
            attempt_count: row.get("attempt_count").map_err(|_| store_read_error())?,
            last_error: last_error_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|_| store_read_error())?,
            receipt_json: row.get("receipt_json").map_err(|_| store_read_error())?,
        })
    })())
}

fn event_from_row(row: &Row<'_>) -> rusqlite::Result<Result<OperationEvent, MailError>> {
    let status: Option<String> = row.get("status")?;
    let occurred_at: String = row.get("occurred_at")?;
    Ok((|| {
        Ok(OperationEvent {
            sequence: row.get("sequence").map_err(|_| store_read_error())?,
            operation_id: row.get("operation_id").map_err(|_| store_read_error())?,
            event: row.get("event").map_err(|_| store_read_error())?,
            status: status.as_deref().map(parse_operation_status).transpose()?,
            occurred_at: parse_timestamp(&occurred_at)?,
            payload_sha256: row.get("payload_sha256").map_err(|_| store_read_error())?,
            detail: row.get("detail").map_err(|_| store_read_error())?,
        })
    })())
}

fn append_event(
    transaction: &Transaction<'_>,
    operation: &OperationRecord,
    event: &str,
    status: Option<OperationStatus>,
    detail: Option<&str>,
) -> Result<(), MailError> {
    transaction
        .execute(
            "INSERT INTO operation_events (operation_id, event, status, occurred_at, payload_sha256, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                operation.id,
                event,
                status.map(operation_status_name),
                timestamp(operation.updated_at),
                operation.payload_sha256,
                detail.map(|value| value.chars().take(512).collect::<String>()),
            ],
        )
        .map_err(|_| store_write_error())?;
    Ok(())
}

fn reconcile_operations(
    transaction: &Transaction<'_>,
    now: DateTime<Utc>,
) -> Result<(), MailError> {
    let now_text = timestamp(now);
    let expired: Vec<String> = {
        let mut statement = transaction
            .prepare("SELECT id FROM operations WHERE status IN ('planned', 'approved') AND expires_at IS NOT NULL AND expires_at <= ?1")
            .map_err(|_| store_read_error())?;
        let rows = statement
            .query_map(params![now_text], |row| row.get::<_, String>(0))
            .map_err(|_| store_read_error())?;
        rows.map(|row| row.map_err(|_| store_read_error()))
            .collect::<Result<_, _>>()?
    };
    for id in expired {
        transaction
            .execute(
                "UPDATE operations SET status = 'expired', updated_at = ?1 WHERE id = ?2 AND status IN ('planned', 'approved')",
                params![timestamp(now), id],
            )
            .map_err(|_| store_write_error())?;
        if let Some(operation) = operation_in_transaction(transaction, &id)? {
            append_event(
                transaction,
                &operation,
                "expired",
                Some(OperationStatus::Expired),
                None,
            )?;
        }
    }

    let stale = timestamp(now - ChronoDuration::minutes(STALE_APPLY_MINUTES));
    let stale_ids: Vec<String> = {
        let mut statement = transaction
            .prepare("SELECT id FROM operations WHERE kind <> 'draft' AND status = 'applying' AND updated_at <= ?1")
            .map_err(|_| store_read_error())?;
        let rows = statement
            .query_map(params![stale], |row| row.get::<_, String>(0))
            .map_err(|_| store_read_error())?;
        rows.map(|row| row.map_err(|_| store_read_error()))
            .collect::<Result<_, _>>()?
    };
    let error = MailError::new(
        MailErrorCode::SendPlanState,
        "previous remote operation ended without a final result",
        false,
    );
    let error_json = serde_json::to_string(&error).map_err(|_| store_write_error())?;
    for id in stale_ids {
        transaction
            .execute(
                "UPDATE operations SET status = 'ambiguous', updated_at = ?1, last_error_json = ?2 WHERE id = ?3 AND status = 'applying'",
                params![timestamp(now), error_json, id],
            )
            .map_err(|_| store_write_error())?;
        if let Some(operation) = operation_in_transaction(transaction, &id)? {
            append_event(
                transaction,
                &operation,
                "reconciled_ambiguous",
                Some(OperationStatus::Ambiguous),
                None,
            )?;
        }
    }
    Ok(())
}

fn validate_operation_id(operation_id: &str) -> Result<(), MailError> {
    uuid::Uuid::parse_str(operation_id)
        .map(|_| ())
        .map_err(|_| MailError::invalid_input("operation id must be a UUID"))
}

fn payload_digest(payload_json: &str) -> String {
    format!("{:x}", Sha256::digest(payload_json.as_bytes()))
}

fn operation_status_name(status: OperationStatus) -> &'static str {
    match status {
        OperationStatus::Planned => "planned",
        OperationStatus::Approved => "approved",
        OperationStatus::Applying => "applying",
        OperationStatus::Succeeded => "succeeded",
        OperationStatus::Failed => "failed",
        OperationStatus::Ambiguous => "ambiguous",
        OperationStatus::Expired => "expired",
    }
}

fn parse_operation_status(status: &str) -> Result<OperationStatus, MailError> {
    match status {
        "planned" => Ok(OperationStatus::Planned),
        "approved" => Ok(OperationStatus::Approved),
        "applying" => Ok(OperationStatus::Applying),
        "succeeded" => Ok(OperationStatus::Succeeded),
        "failed" => Ok(OperationStatus::Failed),
        "ambiguous" => Ok(OperationStatus::Ambiguous),
        "expired" => Ok(OperationStatus::Expired),
        _ => Err(store_read_error()),
    }
}

fn send_plan_from_operation(operation: &OperationRecord) -> Result<SendPlan, MailError> {
    if operation.kind != "send" {
        return Err(state_error("operation is not a send plan"));
    }
    let request: SendRequest =
        serde_json::from_str(&operation.payload_json).map_err(|_| store_read_error())?;
    let status = match operation.status {
        OperationStatus::Planned => SendPlanStatus::Planned,
        OperationStatus::Approved => SendPlanStatus::Approved,
        OperationStatus::Applying => SendPlanStatus::Applying,
        OperationStatus::Succeeded => SendPlanStatus::Sent,
        OperationStatus::Failed => SendPlanStatus::Failed,
        OperationStatus::Ambiguous => SendPlanStatus::Ambiguous,
        OperationStatus::Expired => SendPlanStatus::Expired,
    };
    Ok(SendPlan {
        id: operation.id.clone(),
        content_sha256: operation.payload_sha256.clone(),
        message_id: operation.message_id.clone().ok_or_else(store_read_error)?,
        attachment_summaries: request.attachment_summaries()?,
        request,
        status,
        created_at: operation.created_at,
        expires_at: operation.expires_at.ok_or_else(store_read_error)?,
        approved_at: operation.approved_at,
        updated_at: operation.updated_at,
        attempt_count: operation.attempt_count,
        last_error: operation.last_error.clone(),
        receipt: operation
            .receipt_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| store_read_error())?,
    })
}

fn migrate(connection: &mut Connection) -> Result<(), MailError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| migration_error())?;
    if version > SCHEMA_VERSION {
        return Err(MailError::new(
            MailErrorCode::StoreMigration,
            "outbox schema is newer than this Kirje version",
            false,
        ));
    }
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    let transaction = connection.transaction().map_err(|_| migration_error())?;
    if version == 0 {
        transaction
            .execute_batch(LEGACY_SEND_SCHEMA)
            .map_err(|_| migration_error())?;
    }
    transaction
        .execute_batch(LEDGER_SCHEMA)
        .map_err(|_| migration_error())?;
    if version <= 1 {
        transaction
            .execute_batch(
                "INSERT INTO operations (
                    id, kind, account_id, message_id, payload_json, payload_sha256, status,
                    created_at, expires_at, approved_at, updated_at, attempt_count,
                    last_error_json, receipt_json
                 )
                 SELECT id, 'send', account_id, message_id, request_json, content_sha256,
                    CASE status WHEN 'sent' THEN 'succeeded' ELSE status END,
                    created_at, expires_at, approved_at, updated_at, attempt_count,
                    last_error_json, receipt_json
                 FROM send_plans;
                 INSERT INTO operation_events
                    (operation_id, event, status, occurred_at, payload_sha256, detail)
                 SELECT id, 'migrated',
                    CASE status WHEN 'sent' THEN 'succeeded' ELSE status END,
                    updated_at, content_sha256, 'migrated from legacy send_plans'
                 FROM send_plans;",
            )
            .map_err(|_| migration_error())?;
    }
    transaction
        .execute_batch("PRAGMA user_version = 2;")
        .map_err(|_| migration_error())?;
    transaction.commit().map_err(|_| migration_error())
}

const LEGACY_SEND_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS send_plans (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        request_json TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        message_id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL CHECK(status IN ('planned','approved','applying','sent','failed','ambiguous','expired')),
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        approved_at TEXT,
        updated_at TEXT NOT NULL,
        attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0),
        last_error_json TEXT,
        receipt_json TEXT
    );
    CREATE INDEX IF NOT EXISTS send_plans_account_created
        ON send_plans(account_id, created_at DESC);
";

const LEDGER_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS operations (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        account_id TEXT NOT NULL,
        message_id TEXT,
        payload_json TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('planned','approved','applying','succeeded','failed','ambiguous','expired')),
        created_at TEXT NOT NULL,
        expires_at TEXT,
        approved_at TEXT,
        updated_at TEXT NOT NULL,
        attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0),
        last_error_json TEXT,
        receipt_json TEXT
    );
    CREATE INDEX IF NOT EXISTS operations_account_created
        ON operations(account_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS operations_kind_created
        ON operations(kind, created_at DESC);
    CREATE TABLE IF NOT EXISTS operation_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        operation_id TEXT NOT NULL,
        event TEXT NOT NULL,
        status TEXT,
        occurred_at TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL,
        detail TEXT,
        FOREIGN KEY(operation_id) REFERENCES operations(id)
    );
    CREATE INDEX IF NOT EXISTS operation_events_operation_sequence
        ON operation_events(operation_id, sequence);
";

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, MailError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| store_read_error())
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

fn not_found_error() -> MailError {
    MailError::new(
        MailErrorCode::SendPlanNotFound,
        "send plan was not found",
        false,
    )
}

fn state_error(message: impl Into<String>) -> MailError {
    MailError::new(MailErrorCode::SendPlanState, message, false)
}

fn store_read_error() -> MailError {
    MailError::new(
        MailErrorCode::StoreRead,
        "cannot read the local outbox",
        false,
    )
}

fn store_write_error() -> MailError {
    MailError::new(
        MailErrorCode::StoreWrite,
        "cannot update the local outbox",
        false,
    )
}

fn migration_error() -> MailError {
    MailError::new(
        MailErrorCode::StoreMigration,
        "cannot migrate the local outbox",
        false,
    )
}
