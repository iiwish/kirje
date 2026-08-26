use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use kirje_core::{
    MAX_SEND_PLAN_LIMIT, MailError, MailErrorCode, Outbox, SendPlan, SendPlanStatus,
    SendPlanSummary, SendReceipt,
};
use rusqlite::{Connection, OptionalExtension as _, Row, Transaction, TransactionBehavior, params};

const SCHEMA_VERSION: i64 = 1;
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
        let connection = self.connection()?;
        let request = serde_json::to_string(&plan.request).map_err(|_| store_write_error())?;
        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO send_plans (
                id, account_id, request_json, content_sha256, message_id, status,
                created_at, expires_at, approved_at, updated_at, attempt_count,
                last_error_json, receipt_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, 0, NULL, NULL)",
                params![
                    plan.id,
                    plan.request.account_id,
                    request,
                    plan.content_sha256,
                    plan.message_id,
                    status_name(plan.status),
                    timestamp(plan.created_at),
                    timestamp(plan.expires_at),
                    timestamp(plan.updated_at),
                ],
            )
            .map_err(|_| store_write_error())?;
        if inserted != 1 {
            return Err(state_error("send plan already exists"));
        }
        Ok(plan.clone())
    }

    fn get(&self, plan_id: &str, now: DateTime<Utc>) -> Result<Option<SendPlan>, MailError> {
        validate_plan_id(plan_id)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| store_write_error())?;
        reconcile(&transaction, now)?;
        let plan = plan_in_transaction(&transaction, plan_id)?;
        transaction.commit().map_err(|_| store_write_error())?;
        Ok(plan)
    }

    fn list(
        &self,
        account_id: Option<&str>,
        limit: u16,
        now: DateTime<Utc>,
    ) -> Result<Vec<SendPlanSummary>, MailError> {
        if limit == 0 || limit > MAX_SEND_PLAN_LIMIT {
            return Err(MailError::invalid_input(format!(
                "send plan limit must be between 1 and {MAX_SEND_PLAN_LIMIT}"
            )));
        }
        if account_id.is_some_and(str::is_empty) {
            return Err(MailError::invalid_input("account id cannot be empty"));
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| store_write_error())?;
        reconcile(&transaction, now)?;
        let mut plans = Vec::new();
        if let Some(account_id) = account_id {
            let mut statement = transaction
                .prepare("SELECT * FROM send_plans WHERE account_id = ?1 ORDER BY created_at DESC LIMIT ?2")
                .map_err(|_| store_read_error())?;
            let rows = statement
                .query_map(params![account_id, limit], plan_from_row)
                .map_err(|_| store_read_error())?;
            for row in rows {
                plans.push(row.map_err(|_| store_read_error())??.summary());
            }
        } else {
            let mut statement = transaction
                .prepare("SELECT * FROM send_plans ORDER BY created_at DESC LIMIT ?1")
                .map_err(|_| store_read_error())?;
            let rows = statement
                .query_map(params![limit], plan_from_row)
                .map_err(|_| store_read_error())?;
            for row in rows {
                plans.push(row.map_err(|_| store_read_error())??.summary());
            }
        }
        transaction.commit().map_err(|_| store_write_error())?;
        Ok(plans)
    }

    fn approve(&self, plan_id: &str, now: DateTime<Utc>) -> Result<SendPlan, MailError> {
        transition(
            self,
            plan_id,
            now,
            SendPlanStatus::Planned,
            SendPlanStatus::Approved,
            true,
        )
    }

    fn claim(&self, plan_id: &str, now: DateTime<Utc>) -> Result<SendPlan, MailError> {
        transition(
            self,
            plan_id,
            now,
            SendPlanStatus::Approved,
            SendPlanStatus::Applying,
            false,
        )
    }

    fn mark_sent(&self, plan_id: &str, receipt: SendReceipt) -> Result<SendPlan, MailError> {
        validate_plan_id(plan_id)?;
        let receipt_json = serde_json::to_string(&receipt).map_err(|_| store_write_error())?;
        finish(
            self,
            plan_id,
            receipt.sent_at,
            SendPlanStatus::Sent,
            None,
            Some(&receipt_json),
        )
    }

    fn mark_failed(
        &self,
        plan_id: &str,
        error: MailError,
        now: DateTime<Utc>,
    ) -> Result<SendPlan, MailError> {
        let error = serde_json::to_string(&error).map_err(|_| store_write_error())?;
        finish(
            self,
            plan_id,
            now,
            SendPlanStatus::Failed,
            Some(&error),
            None,
        )
    }

    fn mark_ambiguous(
        &self,
        plan_id: &str,
        mut error: MailError,
        now: DateTime<Utc>,
    ) -> Result<SendPlan, MailError> {
        error.retryable = false;
        let error = serde_json::to_string(&error).map_err(|_| store_write_error())?;
        finish(
            self,
            plan_id,
            now,
            SendPlanStatus::Ambiguous,
            Some(&error),
            None,
        )
    }
}

fn transition(
    outbox: &SqliteOutbox,
    plan_id: &str,
    now: DateTime<Utc>,
    from: SendPlanStatus,
    to: SendPlanStatus,
    approve: bool,
) -> Result<SendPlan, MailError> {
    validate_plan_id(plan_id)?;
    let mut connection = outbox.connection()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store_write_error())?;
    reconcile(&transaction, now)?;
    let Some(existing) = plan_in_transaction(&transaction, plan_id)? else {
        return Err(not_found_error());
    };
    if existing.status != from {
        return Err(state_error(format!(
            "send plan is {}, expected {}",
            status_name(existing.status),
            status_name(from)
        )));
    }
    let approved_at = approve.then(|| timestamp(now));
    let attempts = u32::from(to == SendPlanStatus::Applying);
    transaction
        .execute(
            "UPDATE send_plans SET status = ?1, approved_at = COALESCE(?2, approved_at),
            updated_at = ?3, attempt_count = attempt_count + ?4
         WHERE id = ?5 AND status = ?6",
            params![
                status_name(to),
                approved_at,
                timestamp(now),
                attempts,
                plan_id,
                status_name(from)
            ],
        )
        .map_err(|_| store_write_error())?;
    let plan = plan_in_transaction(&transaction, plan_id)?.ok_or_else(not_found_error)?;
    transaction.commit().map_err(|_| store_write_error())?;
    Ok(plan)
}

fn finish(
    outbox: &SqliteOutbox,
    plan_id: &str,
    now: DateTime<Utc>,
    status: SendPlanStatus,
    error_json: Option<&str>,
    receipt_json: Option<&str>,
) -> Result<SendPlan, MailError> {
    validate_plan_id(plan_id)?;
    let mut connection = outbox.connection()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| store_write_error())?;
    let Some(existing) = plan_in_transaction(&transaction, plan_id)? else {
        return Err(not_found_error());
    };
    if existing.status != SendPlanStatus::Applying {
        return Err(state_error("only an applying send plan can be finalized"));
    }
    transaction
        .execute(
            "UPDATE send_plans SET status = ?1, updated_at = ?2,
            last_error_json = ?3, receipt_json = ?4
         WHERE id = ?5 AND status = 'applying'",
            params![
                status_name(status),
                timestamp(now),
                error_json,
                receipt_json,
                plan_id
            ],
        )
        .map_err(|_| store_write_error())?;
    let plan = plan_in_transaction(&transaction, plan_id)?.ok_or_else(not_found_error)?;
    transaction.commit().map_err(|_| store_write_error())?;
    Ok(plan)
}

fn reconcile(transaction: &Transaction<'_>, now: DateTime<Utc>) -> Result<(), MailError> {
    transaction
        .execute(
            "UPDATE send_plans SET status = 'expired', updated_at = ?1
         WHERE status IN ('planned', 'approved') AND expires_at <= ?1",
            params![timestamp(now)],
        )
        .map_err(|_| store_write_error())?;
    let stale = now - ChronoDuration::minutes(STALE_APPLY_MINUTES);
    let error = serde_json::to_string(&MailError::new(
        MailErrorCode::SendPlanState,
        "previous SMTP attempt ended without a final result",
        false,
    ))
    .map_err(|_| store_write_error())?;
    transaction
        .execute(
            "UPDATE send_plans SET status = 'ambiguous', updated_at = ?1, last_error_json = ?2
         WHERE status = 'applying' AND updated_at <= ?3",
            params![timestamp(now), error, timestamp(stale)],
        )
        .map_err(|_| store_write_error())?;
    Ok(())
}

fn plan_in_transaction(
    transaction: &Transaction<'_>,
    plan_id: &str,
) -> Result<Option<SendPlan>, MailError> {
    transaction
        .query_row(
            "SELECT * FROM send_plans WHERE id = ?1",
            params![plan_id],
            plan_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())?
        .transpose()
}

fn plan_from_row(row: &Row<'_>) -> rusqlite::Result<Result<SendPlan, MailError>> {
    let request_json: String = row.get("request_json")?;
    let status: String = row.get("status")?;
    let created_at: String = row.get("created_at")?;
    let expires_at: String = row.get("expires_at")?;
    let approved_at: Option<String> = row.get("approved_at")?;
    let updated_at: String = row.get("updated_at")?;
    let last_error_json: Option<String> = row.get("last_error_json")?;
    let receipt_json: Option<String> = row.get("receipt_json")?;
    Ok((|| {
        Ok(SendPlan {
            id: row.get("id").map_err(|_| store_read_error())?,
            request: serde_json::from_str(&request_json).map_err(|_| store_read_error())?,
            content_sha256: row.get("content_sha256").map_err(|_| store_read_error())?,
            message_id: row.get("message_id").map_err(|_| store_read_error())?,
            status: parse_status(&status)?,
            created_at: parse_timestamp(&created_at)?,
            expires_at: parse_timestamp(&expires_at)?,
            approved_at: approved_at.as_deref().map(parse_timestamp).transpose()?,
            updated_at: parse_timestamp(&updated_at)?,
            attempt_count: row.get("attempt_count").map_err(|_| store_read_error())?,
            last_error: last_error_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|_| store_read_error())?,
            receipt: receipt_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|_| store_read_error())?,
        })
    })())
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
    transaction.execute_batch(
        "CREATE TABLE send_plans (
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
         CREATE INDEX send_plans_account_created
            ON send_plans(account_id, created_at DESC);
         PRAGMA user_version = 1;",
    ).map_err(|_| migration_error())?;
    transaction.commit().map_err(|_| migration_error())
}

fn validate_plan_id(plan_id: &str) -> Result<(), MailError> {
    uuid::Uuid::parse_str(plan_id)
        .map(|_| ())
        .map_err(|_| MailError::invalid_input("send plan id must be a UUID"))
}

fn status_name(status: SendPlanStatus) -> &'static str {
    match status {
        SendPlanStatus::Planned => "planned",
        SendPlanStatus::Approved => "approved",
        SendPlanStatus::Applying => "applying",
        SendPlanStatus::Sent => "sent",
        SendPlanStatus::Failed => "failed",
        SendPlanStatus::Ambiguous => "ambiguous",
        SendPlanStatus::Expired => "expired",
    }
}

fn parse_status(status: &str) -> Result<SendPlanStatus, MailError> {
    match status {
        "planned" => Ok(SendPlanStatus::Planned),
        "approved" => Ok(SendPlanStatus::Approved),
        "applying" => Ok(SendPlanStatus::Applying),
        "sent" => Ok(SendPlanStatus::Sent),
        "failed" => Ok(SendPlanStatus::Failed),
        "ambiguous" => Ok(SendPlanStatus::Ambiguous),
        "expired" => Ok(SendPlanStatus::Expired),
        _ => Err(store_read_error()),
    }
}

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
