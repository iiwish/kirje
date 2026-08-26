use std::{
    sync::{Arc, Barrier},
    thread,
};

use chrono::{Duration, TimeZone as _, Utc};
use kirje_core::{
    Draft, DraftInput, DraftMode, MailAddress, MailError, MailErrorCode, MailOperationKind,
    MailboxOperationRequest, MessageReference, OperationLedger, OperationStatus, Outbox, SendPlan,
    SendPlanStatus, SendReceipt, SendRequest, digest_json, operation_record,
};
use kirje_store::SqliteOutbox;
use rusqlite::Connection;
use uuid::Uuid;

fn request() -> SendRequest {
    SendRequest {
        account_id: "personal".to_owned(),
        to: vec![MailAddress {
            name: None,
            email: "agent@163.com".to_owned(),
        }],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: "Outbox test".to_owned(),
        text: Some("safe body".to_owned()),
        html: None,
        attachments: Vec::new(),
    }
}

fn mailbox_operation() -> MailboxOperationRequest {
    MailboxOperationRequest {
        account_id: "personal".to_owned(),
        kind: MailOperationKind::SetRead,
        reference: MessageReference {
            account_id: "personal".to_owned(),
            mailbox: "INBOX".to_owned(),
            uid_validity: Some(7),
            uid: 42,
        },
        value: Some(true),
        destination: None,
    }
}

fn fixture() -> (tempfile::TempDir, SqliteOutbox, SendPlan) {
    let directory = tempfile::tempdir().expect("temp dir");
    let outbox = SqliteOutbox::open(directory.path().join("outbox.sqlite3")).expect("outbox");
    let now = Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap();
    let plan = SendPlan::create(request(), now).expect("plan");
    outbox.create(&plan).expect("persist plan");
    (directory, outbox, plan)
}

#[test]
fn persists_immutable_plan_and_lists_bounded_summaries() {
    let (_directory, outbox, plan) = fixture();
    let stored = outbox
        .get(&plan.id, plan.created_at)
        .expect("get")
        .expect("plan");
    assert_eq!(stored, plan);

    let duplicate = outbox.create(&plan).unwrap_err();
    assert_eq!(duplicate.code, MailErrorCode::SendPlanState);

    let summaries = outbox
        .list(Some("personal"), 10, plan.created_at)
        .expect("list");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].content_sha256, plan.content_sha256);
    assert_eq!(summaries[0].recipient_count, 1);
}

#[test]
fn approval_and_claim_are_guarded_transitions() {
    let (_directory, outbox, plan) = fixture();
    let approved_at = plan.created_at + Duration::minutes(1);
    let approved = outbox.approve(&plan.id, approved_at).expect("approve");
    assert_eq!(approved.status, SendPlanStatus::Approved);
    assert_eq!(approved.approved_at, Some(approved_at));

    let applying = outbox
        .claim(&plan.id, approved_at + Duration::minutes(1))
        .expect("claim");
    assert_eq!(applying.status, SendPlanStatus::Applying);
    assert_eq!(applying.attempt_count, 1);

    let second = outbox
        .claim(&plan.id, approved_at + Duration::minutes(2))
        .unwrap_err();
    assert_eq!(second.code, MailErrorCode::SendPlanState);
}

#[test]
fn expired_plan_cannot_be_approved() {
    let (_directory, outbox, plan) = fixture();
    let error = outbox
        .approve(&plan.id, plan.expires_at + Duration::seconds(1))
        .unwrap_err();
    assert_eq!(error.code, MailErrorCode::SendPlanState);
    let stored = outbox
        .get(&plan.id, plan.expires_at + Duration::seconds(1))
        .expect("get")
        .expect("plan");
    assert_eq!(stored.status, SendPlanStatus::Expired);
}

#[test]
fn only_one_concurrent_claim_succeeds() {
    let (_directory, outbox, plan) = fixture();
    let now = plan.created_at + Duration::minutes(1);
    outbox.approve(&plan.id, now).expect("approve");
    let outbox = Arc::new(outbox);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let worker = Arc::clone(&outbox);
        let ready = Arc::clone(&barrier);
        let id = plan.id.clone();
        handles.push(thread::spawn(move || {
            ready.wait();
            worker.claim(&id, now + Duration::seconds(1))
        }));
    }
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
}

#[test]
fn ambiguous_outcome_is_terminal() {
    let (_directory, outbox, plan) = fixture();
    let now = plan.created_at + Duration::minutes(1);
    outbox.approve(&plan.id, now).expect("approve");
    outbox.claim(&plan.id, now).expect("claim");
    let ambiguous = outbox
        .mark_ambiguous(
            &plan.id,
            MailError::new(MailErrorCode::Network, "SMTP result is unknown", false),
            now,
        )
        .expect("mark ambiguous");
    assert_eq!(ambiguous.status, SendPlanStatus::Ambiguous);
    assert!(ambiguous.receipt.is_none());
    assert_eq!(
        outbox.claim(&plan.id, now).unwrap_err().code,
        MailErrorCode::SendPlanState
    );
}

#[test]
fn successful_receipt_finishes_the_plan() {
    let (_directory, outbox, plan) = fixture();
    let now = plan.created_at + Duration::minutes(1);
    outbox.approve(&plan.id, now).expect("approve");
    outbox.claim(&plan.id, now).expect("claim");
    let receipt = SendReceipt {
        accepted: true,
        server_response: Some("250 queued".to_owned()),
        sent_at: now,
    };
    let sent = outbox
        .mark_sent(&plan.id, receipt.clone())
        .expect("mark sent");
    assert_eq!(sent.status, SendPlanStatus::Sent);
    assert_eq!(sent.receipt, Some(receipt));
}

#[test]
fn generic_operation_ledger_is_auditable_and_terminal() {
    let (_directory, outbox, _plan) = fixture();
    let operation_payload = mailbox_operation();
    let (payload_json, payload_sha256) = digest_json(&operation_payload).expect("payload");
    let now = Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap();
    let operation = operation_record(
        Uuid::new_v4().to_string(),
        "set_read",
        "personal".to_owned(),
        payload_json,
        payload_sha256,
        now,
    );
    let created = outbox.create_operation(&operation).expect("create");
    assert_eq!(created.status, OperationStatus::Planned);
    outbox
        .approve_operation(&operation.id, now + Duration::minutes(1))
        .expect("approve");
    outbox
        .claim_operation(&operation.id, now + Duration::minutes(2))
        .expect("claim");
    let finished = outbox
        .succeed_operation(&operation.id, "{\"changed\":true}".to_owned(), now)
        .expect("finish");
    assert_eq!(finished.status, OperationStatus::Succeeded);
    let audit = outbox.audit(&operation.id, 20).expect("audit");
    assert_eq!(audit.len(), 4);
    assert_eq!(audit.last().expect("final event").event, "finalized");
}

#[test]
fn stale_remote_operation_becomes_ambiguous_without_retry() {
    let (_directory, outbox, _plan) = fixture();
    let payload = mailbox_operation();
    let (payload_json, payload_sha256) = digest_json(&payload).expect("payload");
    let started = Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap();
    let operation = operation_record(
        Uuid::new_v4().to_string(),
        "set_read",
        "personal".to_owned(),
        payload_json,
        payload_sha256,
        started,
    );
    outbox.create_operation(&operation).expect("create");
    outbox
        .approve_operation(&operation.id, started)
        .expect("approve");
    outbox
        .claim_operation(&operation.id, started)
        .expect("claim");
    let stale = outbox
        .get_operation(&operation.id, started + Duration::minutes(16))
        .expect("reconcile")
        .expect("operation");
    assert_eq!(stale.status, OperationStatus::Ambiguous);
    assert_eq!(
        outbox
            .claim_operation(&operation.id, started + Duration::minutes(17))
            .unwrap_err()
            .code,
        MailErrorCode::SendPlanState
    );
}

#[test]
fn drafts_share_the_ledger_and_discard_without_erasing_history() {
    let (_directory, outbox, _plan) = fixture();
    let draft = Draft::create(
        DraftInput {
            account_id: "personal".to_owned(),
            mode: DraftMode::New,
            source: None,
            to: vec![MailAddress {
                name: None,
                email: "agent@163.com".to_owned(),
            }],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: Some("Draft".to_owned()),
            text: Some("local".to_owned()),
            html: None,
            attachments: Vec::new(),
        },
        "sender@163.com",
        Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap(),
    )
    .expect("draft");
    outbox.create_draft(&draft).expect("persist draft");
    assert_eq!(outbox.list_drafts("personal", 10).expect("list").len(), 1);
    outbox
        .discard_draft(&draft.id, draft.updated_at + Duration::minutes(1))
        .expect("discard");
    assert_eq!(
        outbox
            .get_draft(&draft.id)
            .expect("read")
            .expect("draft")
            .status,
        kirje_core::DraftStatus::Discarded
    );
    assert_eq!(outbox.audit(&draft.id, 10).expect("audit").len(), 2);
}

#[test]
fn v1_send_plans_migrate_into_the_unified_ledger() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("outbox.sqlite3");
    let plan = SendPlan::create(
        request(),
        Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap(),
    )
    .expect("plan");
    let request_json = serde_json::to_string(&plan.request).expect("request json");
    let connection = Connection::open(&path).expect("sqlite");
    connection
        .execute_batch(
            "CREATE TABLE send_plans (
                id TEXT PRIMARY KEY, account_id TEXT NOT NULL, request_json TEXT NOT NULL,
                content_sha256 TEXT NOT NULL, message_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                approved_at TEXT, updated_at TEXT NOT NULL, attempt_count INTEGER NOT NULL,
                last_error_json TEXT, receipt_json TEXT
            );
            PRAGMA user_version = 1;",
        )
        .expect("legacy schema");
    connection
        .execute(
            "INSERT INTO send_plans VALUES (?1, ?2, ?3, ?4, ?5, 'sent', ?6, ?7, NULL, ?6, 1, NULL, '{\"accepted\":true,\"server_response\":null,\"sent_at\":\"2026-08-26T12:00:00.000000Z\"}')",
            rusqlite::params![
                plan.id,
                plan.request.account_id,
                request_json,
                plan.content_sha256,
                plan.message_id,
                plan.created_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                plan.expires_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            ],
        )
        .expect("legacy row");
    drop(connection);

    let outbox = SqliteOutbox::open(path).expect("migrate");
    let migrated = outbox
        .get(&plan.id, plan.created_at)
        .expect("get")
        .expect("plan");
    assert_eq!(migrated.status, SendPlanStatus::Sent);
    assert_eq!(
        outbox.audit(&plan.id, 10).expect("audit")[0].event,
        "migrated"
    );
}

#[cfg(unix)]
#[test]
fn outbox_files_are_private_and_symbolic_links_are_rejected() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("outbox.sqlite3");
    SqliteOutbox::open(path.clone()).expect("outbox");
    assert_eq!(
        std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let link = directory.path().join("outbox-link.sqlite3");
    symlink(&path, &link).expect("symlink");
    assert_eq!(
        SqliteOutbox::open(link).unwrap_err().code,
        MailErrorCode::InvalidInput
    );
}
