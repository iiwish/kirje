use std::{
    sync::{Arc, Barrier},
    thread,
};

use chrono::{Duration, TimeZone as _, Utc};
use kirje_core::{
    MailAddress, MailError, MailErrorCode, Outbox, SendPlan, SendPlanStatus, SendReceipt,
    SendRequest,
};
use kirje_store::SqliteOutbox;

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
