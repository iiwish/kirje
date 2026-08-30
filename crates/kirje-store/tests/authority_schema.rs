#![cfg(feature = "test-support")]

use std::{
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};

use kirje_core::{MailErrorCode, OwnerPublicKey, Sha256Digest};
use kirje_store::{
    AnchorPresence, AuthorityAnchorState, AuthorityAnchorVersion, AuthorityHome,
    AuthorityOpenContext, AuthorityOpenState, AuthorityStore, BootstrapInput, DeterministicEntropy,
    IsolatedAuthorityHome, JournalLocationDigest,
};
use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const APPLICATION_ID: i64 = 1_263_096_394;
const SCHEMA_VERSION: i64 = 1;
const SCHEMA: &str = include_str!("../src/authority/schema_v1.sql");
const BOOTSTRAP_TRUST_SHA256_HEX: &str =
    "aca92cb83755771f4f7cd97837090f2c3d7cf3df1a382834830df8bb4ac1779e";
const BOOTSTRAP_EVENT_DETAIL_SHA256_HEX: &str =
    "5c37cb3d04458bcfb7a89eb3038e31d2e0f074a81ed07e045794a0aa9519672c";
const CONFIRM_EVENT_DETAIL_SHA256_HEX: &str =
    "6ac5a60f3517c4d914870ae0db4c8aa0160e2b19a9e407a1f6a6d3ef45af8af1";
const TABLES: [&str; 17] = [
    "account_transitions",
    "authority_events",
    "authority_keys",
    "authority_meta",
    "authorization_challenges",
    "authorization_receipts",
    "challenge_effects",
    "credential_cleanup",
    "effect_claims",
    "effect_invocations",
    "effect_observations",
    "grant_uses",
    "nonce_uses",
    "registered_accounts",
    "registered_stores",
    "remote_effects",
    "trust_epochs",
];
const INDEXES: [&str; 15] = [
    "account_transitions_account_state",
    "account_transitions_store_state",
    "authority_events_entity_sequence",
    "authority_keys_one_active_role",
    "authority_keys_one_staged_role",
    "authorization_challenges_context_created_sequence",
    "authorization_challenges_one_pending_context",
    "authorization_challenges_state_epoch_expiry",
    "authorization_receipts_epoch_expiry",
    "effect_claims_invoke_before",
    "registered_accounts_active_display_id",
    "registered_accounts_store_state",
    "trust_epochs_one_active",
    "trust_epochs_one_staged",
    "trust_epochs_one_staged_successor",
];
const TRIGGERS: [&str; 3] = [
    "authority_keys_identity_immutable",
    "trust_epochs_key_roles_insert",
    "trust_epochs_key_roles_update",
];
const COLUMN_INVARIANT_CASES: [(&str, &str, &str, &str); 17] = [
    (
        "account_transitions",
        "kind",
        "prepared_at",
        "before_config_sha256=zeroblob(1)",
    ),
    (
        "authority_events",
        "detail",
        "occurred_at",
        "detail=zeroblob(0)",
    ),
    (
        "authority_keys",
        "role",
        "installed_at",
        "public_key=zeroblob(1)",
    ),
    (
        "authority_meta",
        "bootstrap_state",
        "last_observed_at",
        "journal_id=zeroblob(1)",
    ),
    (
        "authorization_challenges",
        "state",
        "issued_at",
        "manifest=zeroblob(0)",
    ),
    (
        "authorization_receipts",
        "canonical_proof",
        "verified_at",
        "canonical_proof=zeroblob(0)",
    ),
    (
        "challenge_effects",
        "effect_id",
        "ordinal",
        "effect_id=zeroblob(1)",
    ),
    (
        "credential_cleanup",
        "state",
        "created_at",
        "locator_material=zeroblob(0)",
    ),
    (
        "effect_claims",
        "claim_receipt",
        "claimed_at",
        "claim_receipt=zeroblob(0)",
    ),
    (
        "effect_invocations",
        "start_receipt",
        "started_at",
        "start_receipt=zeroblob(0)",
    ),
    (
        "effect_observations",
        "observation",
        "observed_at",
        "observation=zeroblob(0)",
    ),
    (
        "grant_uses",
        "use_receipt",
        "used_at",
        "use_receipt=zeroblob(0)",
    ),
    (
        "nonce_uses",
        "receipt_id",
        "consumed_at",
        "nonce=zeroblob(1)",
    ),
    (
        "registered_accounts",
        "state",
        "updated_at",
        "account_id=zeroblob(1)",
    ),
    (
        "registered_stores",
        "state",
        "updated_at",
        "location_material=zeroblob(0)",
    ),
    (
        "remote_effects",
        "operation_id",
        "created_at",
        "operation_id=zeroblob(1)",
    ),
    (
        "trust_epochs",
        "state",
        "staged_at",
        "bundle_sha256=zeroblob(1)",
    ),
];

fn owner_key() -> OwnerPublicKey {
    OwnerPublicKey::try_from(
        hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").as_slice(),
    )
    .unwrap()
}

fn recovery_key() -> OwnerPublicKey {
    OwnerPublicKey::try_from(
        hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c").as_slice(),
    )
    .unwrap()
}

fn location(byte: u8) -> JournalLocationDigest {
    JournalLocationDigest::from_bytes([byte; 32])
}

fn context(anchor: AnchorPresence, location: JournalLocationDigest) -> AuthorityOpenContext {
    AuthorityOpenContext {
        anchor,
        journal_location_sha256: location,
    }
}

fn input(location: JournalLocationDigest, observed_at_unix_ms: i64) -> BootstrapInput {
    BootstrapInput {
        journal_location_sha256: location,
        owner_public_key: owner_key(),
        recovery_public_key: recovery_key(),
        observed_at_unix_ms,
    }
}

fn isolated(temp: &TempDir) -> IsolatedAuthorityHome {
    IsolatedAuthorityHome::new(temp.path().to_path_buf()).unwrap()
}

fn entropy(seed: u8) -> DeterministicEntropy {
    DeterministicEntropy::new((seed..seed + 48).collect()).unwrap()
}

fn open_isolated(
    home: IsolatedAuthorityHome,
    anchor: AnchorPresence,
    location: JournalLocationDigest,
    entropy: DeterministicEntropy,
) -> AuthorityStore {
    AuthorityStore::open_isolated(context(anchor, location), home, entropy).unwrap()
}

fn prepared_home(
    seed: u8,
    loc: JournalLocationDigest,
    observed_at: i64,
) -> (
    TempDir,
    IsolatedAuthorityHome,
    kirje_store::BootstrapSnapshot,
) {
    let temp = TempDir::new().unwrap();
    let home = isolated(&temp);
    let snapshot = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(seed))
        .prepare_bootstrap(input(loc, observed_at))
        .unwrap();
    (temp, home, snapshot)
}

fn assert_bootstrap_rows(
    home: &IsolatedAuthorityHome,
    state: &str,
    event_count: i64,
    last_observed_at: i64,
) {
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar_text(
            &connection,
            "SELECT bootstrap_state FROM authority_meta WHERE singleton=1"
        ),
        state
    );
    assert_eq!(
        scalar_i64(
            &connection,
            "SELECT last_observed_at FROM authority_meta WHERE singleton=1"
        ),
        last_observed_at
    );
    assert_eq!(
        scalar_i64(&connection, "SELECT COUNT(*) FROM authority_events"),
        event_count
    );
}

fn remove_authority_database(home: &IsolatedAuthorityHome) {
    for suffix in ["", "-wal", "-shm"] {
        let mut path = home.database_path().as_os_str().to_owned();
        path.push(suffix);
        let path = PathBuf::from(path);
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("failed to remove authority database: {error}"),
        }
    }
}

fn assert_stale_prepare_fails_closed(
    store: &AuthorityStore,
    home: &IsolatedAuthorityHome,
    loc: JournalLocationDigest,
    source: &DeterministicEntropy,
    pristine_replacement: bool,
) {
    remove_authority_database(home);
    if pristine_replacement {
        drop(Connection::open(home.database_path()).unwrap());
    }

    let error = mail_error(store.prepare_bootstrap(input(loc, 100_010)));
    assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
    assert_eq!(source.consumed_bytes(), 0);
    if pristine_replacement {
        let connection = Connection::open(home.database_path()).unwrap();
        assert_eq!(user_object_count(&connection), 0);
        assert_eq!(pragma_i64(&connection, "application_id"), 0);
        assert_eq!(pragma_i64(&connection, "user_version"), 0);
    } else {
        assert!(!home.database_path().exists());
    }
}

#[derive(Debug, Eq, PartialEq)]
struct DatabaseFingerprint {
    journal_mode: String,
    application_id: i64,
    user_version: i64,
    schema: Vec<(String, String, Option<String>)>,
    sentinel_rows: Vec<i64>,
}

fn database_fingerprint(home: &IsolatedAuthorityHome) -> DatabaseFingerprint {
    let connection = Connection::open(home.database_path()).unwrap();
    let schema = connection
        .prepare(
            "SELECT type,name,sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let sentinel_rows = if schema
        .iter()
        .any(|(kind, name, _)| kind == "table" && name == "sentinel")
    {
        connection
            .prepare("SELECT value FROM sentinel ORDER BY rowid")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    } else {
        Vec::new()
    };
    DatabaseFingerprint {
        journal_mode: scalar_text(&connection, "PRAGMA journal_mode"),
        application_id: pragma_i64(&connection, "application_id"),
        user_version: pragma_i64(&connection, "user_version"),
        schema,
        sentinel_rows,
    }
}

fn switch_to_delete_journal(home: &IsolatedAuthorityHome) {
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(
        scalar_text(&connection, "PRAGMA journal_mode=DELETE"),
        "delete"
    );
}

fn assert_wal_full(home: &IsolatedAuthorityHome) {
    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(scalar_text(&connection, "PRAGMA journal_mode"), "wal");
    assert_eq!(pragma_i64(&connection, "synchronous"), 2);
}

fn install_preflight_database(
    home: &IsolatedAuthorityHome,
    application_id: i64,
    user_version: i64,
    with_sentinel: bool,
) {
    create_database_parent(home);
    let connection = Connection::open(home.database_path()).unwrap();
    if with_sentinel {
        connection
            .execute_batch("CREATE TABLE sentinel(value INTEGER NOT NULL); INSERT INTO sentinel VALUES (7),(9);")
            .unwrap();
    }
    connection
        .pragma_update(None, "application_id", application_id)
        .unwrap();
    connection
        .pragma_update(None, "user_version", user_version)
        .unwrap();
    assert_eq!(
        scalar_text(&connection, "PRAGMA journal_mode=DELETE"),
        "delete"
    );
}

#[derive(Clone, Copy, Debug)]
enum EventMutation {
    Sequence,
    EntityKind,
    EntityId,
    EventCode,
    Source,
    OccurredAt,
    CanonicalDetail,
    DetailDigest,
    ExtraRow,
}

fn mutate_event(connection: &Connection, event_code: i64, mutation: EventMutation) {
    match mutation {
        EventMutation::Sequence => {
            connection
                .execute(
                    "UPDATE authority_events SET sequence=sequence+10 WHERE event_code=?1",
                    [event_code],
                )
                .unwrap();
        }
        EventMutation::EntityKind => {
            connection
                .execute(
                    "UPDATE authority_events SET entity_kind=2 WHERE event_code=?1",
                    [event_code],
                )
                .unwrap();
        }
        EventMutation::EntityId => {
            connection
                .execute(
                    "UPDATE authority_events SET entity_id=zeroblob(32) WHERE event_code=?1",
                    [event_code],
                )
                .unwrap();
        }
        EventMutation::EventCode => {
            connection
                .execute(
                    "UPDATE authority_events SET event_code=event_code+10 WHERE event_code=?1",
                    [event_code],
                )
                .unwrap();
        }
        EventMutation::Source => {
            connection
                .execute(
                    "UPDATE authority_events SET source=3 WHERE event_code=?1",
                    [event_code],
                )
                .unwrap();
        }
        EventMutation::OccurredAt => {
            connection
                .execute(
                    "UPDATE authority_events SET occurred_at=occurred_at+1 WHERE event_code=?1",
                    [event_code],
                )
                .unwrap();
        }
        EventMutation::CanonicalDetail => {
            let detail = [0xA5_u8];
            let digest: [u8; 32] = Sha256::digest(detail).into();
            connection
                .execute(
                    "UPDATE authority_events SET detail=?1,detail_sha256=?2 WHERE event_code=?3",
                    params![detail, digest, event_code],
                )
                .unwrap();
        }
        EventMutation::DetailDigest => {
            connection
                .execute(
                    "UPDATE authority_events SET detail_sha256=zeroblob(32) WHERE event_code=?1",
                    [event_code],
                )
                .unwrap();
        }
        EventMutation::ExtraRow => {
            connection
                .execute(
                    "INSERT INTO authority_events
                     (entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256)
                     SELECT entity_kind,entity_id,event_code+10,source,occurred_at,detail,detail_sha256
                     FROM authority_events WHERE event_code=?1",
                    [event_code],
                )
                .unwrap();
        }
    }
}

fn simulate_confirm_crash(home: &IsolatedAuthorityHome, realm_id: &[u8; 32]) {
    let mut connection = Connection::open(home.database_path()).unwrap();
    configure(&connection);
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction
        .execute(
            "UPDATE authority_meta SET bootstrap_state='ready',
             anchor_confirmed_at=100000 WHERE singleton=1",
            [],
        )
        .unwrap();
    let detail = [0x92_u8];
    let detail_sha256: [u8; 32] = Sha256::digest(detail).into();
    transaction
        .execute(
            "INSERT INTO authority_events (
                entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256
             ) VALUES (1,?1,2,2,100000,?2,?3)",
            params![realm_id, detail, detail_sha256],
        )
        .unwrap();
    assert_eq!(
        scalar_text(
            &transaction,
            "SELECT bootstrap_state FROM authority_meta WHERE singleton=1"
        ),
        "ready"
    );
    assert_eq!(
        scalar_i64(&transaction, "SELECT COUNT(*) FROM authority_events"),
        2
    );
    transaction.rollback().unwrap();
}

#[test]
fn production_and_isolated_constructors_have_closed_inputs() {
    let _: fn() -> Result<AuthorityHome, kirje_core::MailError> = AuthorityHome::production;
    let _: fn(AuthorityOpenContext) -> Result<AuthorityStore, kirje_core::MailError> =
        AuthorityStore::open_production;

    let temp = TempDir::new().unwrap();
    let home = isolated(&temp);
    assert!(home.root().is_absolute());
    assert!(home.anchor_path().starts_with(home.root()));
    assert!(home.database_path().starts_with(home.root()));
    assert!(home.apply_lock_path().starts_with(home.root()));
    assert_ne!(home.anchor_path(), home.database_path());
    assert_ne!(home.anchor_path(), home.apply_lock_path());
    assert_ne!(home.database_path(), home.apply_lock_path());

    let error = mail_error(IsolatedAuthorityHome::new(
        Path::new("relative").to_path_buf(),
    ));
    assert_eq!(error.code, MailErrorCode::InvalidInput);
}

#[test]
fn canonical_schema_body_has_exact_digest_and_inventory() {
    assert_eq!(
        hex(&Sha256::digest(SCHEMA)),
        "572a73ba5fa83c763188d804ce9767a3c21373410d8b170f6d97b49be0a86454"
    );
    for forbidden in ["PRAGMA", "BEGIN TRANSACTION", "BEGIN IMMEDIATE", "COMMIT"] {
        assert!(!SCHEMA.contains(forbidden));
    }

    let mut connection = Connection::open_in_memory().unwrap();
    configure(&connection);
    let transaction = connection.transaction().unwrap();
    transaction.execute_batch(SCHEMA).unwrap();
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .unwrap();
    transaction.commit().unwrap();

    assert_eq!(objects(&connection, "table"), strings(TABLES));
    assert_eq!(objects(&connection, "index"), strings(INDEXES));
    assert_eq!(objects(&connection, "trigger"), strings(TRIGGERS));
    assert_eq!(pragma_i64(&connection, "application_id"), APPLICATION_ID);
    assert_eq!(pragma_i64(&connection, "user_version"), SCHEMA_VERSION);
    assert_eq!(pragma_i64(&connection, "foreign_keys"), 1);
    assert_eq!(pragma_i64(&connection, "trusted_schema"), 0);
    assert_eq!(pragma_i64(&connection, "synchronous"), 2);
    assert_eq!(pragma_i64(&connection, "busy_timeout"), 5_000);
    assert_eq!(scalar_text(&connection, "PRAGMA integrity_check"), "ok");
    assert_eq!(
        scalar_i64(&connection, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
}

#[test]
fn outer_transaction_rollback_leaves_no_schema_identity_or_rows() {
    let mut connection = Connection::open_in_memory().unwrap();
    configure(&connection);
    {
        let transaction = connection.transaction().unwrap();
        transaction.execute_batch(SCHEMA).unwrap();
        transaction
            .pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        transaction
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .unwrap();
        let root = insert_raw_authority_root(&transaction);
        transaction
            .execute(
                "INSERT INTO authority_meta VALUES (1,'pending_anchor',?1,?2,?3,1,?4,0,0,0,NULL)",
                params![[21_u8; 16], [22_u8; 32], [23_u8; 32], root.bundle_sha256],
            )
            .unwrap();
        let detail = [24_u8];
        let detail_sha256: [u8; 32] = Sha256::digest(detail).into();
        transaction
            .execute(
                "INSERT INTO authority_events (
                    entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256
                 ) VALUES (1,?1,1,1,0,?2,?3)",
                params![[21_u8; 16], detail, detail_sha256],
            )
            .unwrap();
        assert_eq!(user_object_count(&transaction), 35);
        assert_eq!(
            scalar_i64(
                &transaction,
                "SELECT
                    (SELECT COUNT(*) FROM authority_keys) +
                    (SELECT COUNT(*) FROM trust_epochs) +
                    (SELECT COUNT(*) FROM authority_meta) +
                    (SELECT COUNT(*) FROM authority_events)",
            ),
            5
        );
        transaction.rollback().unwrap();
    }
    assert_eq!(user_object_count(&connection), 0);
    assert_eq!(pragma_i64(&connection, "application_id"), 0);
    assert_eq!(pragma_i64(&connection, "user_version"), 0);
}

#[test]
fn challenge_created_event_sequence_is_nullable_transactionally_and_typed_when_linked() {
    let connection = schema_connection();
    let (declared_type, not_null): (String, i64) = connection
        .query_row(
            "SELECT type,\"notnull\" FROM pragma_table_info('authorization_challenges')
             WHERE name='created_event_sequence'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(declared_type, "INTEGER");
    assert_eq!(not_null, 0);
    assert_eq!(
        scalar_text(
            &connection,
            "SELECT sql FROM sqlite_schema
             WHERE type='index' AND name='authorization_challenges_context_created_sequence'",
        ),
        "CREATE INDEX authorization_challenges_context_created_sequence\n\
ON authorization_challenges(context_sha256, created_event_sequence, challenge_id)"
    );

    let root = insert_raw_authority_root(&connection);
    let challenge = RawAuthorization::store_enroll(20, &RawRemoteContext::new(), &root);
    insert_raw_challenge(&connection, &challenge);
    assert_eq!(
        scalar_text(
            &connection,
            "SELECT typeof(created_event_sequence) FROM authorization_challenges",
        ),
        "null"
    );

    connection.execute_batch("SAVEPOINT event_link").unwrap();
    connection
        .execute(
            "UPDATE authorization_challenges SET created_event_sequence=3",
            [],
        )
        .unwrap();
    assert_eq!(
        scalar_i64(
            &connection,
            "SELECT created_event_sequence FROM authorization_challenges",
        ),
        3
    );
    connection
        .execute_batch("ROLLBACK TO event_link; RELEASE event_link")
        .unwrap();
    assert_eq!(
        scalar_text(
            &connection,
            "SELECT typeof(created_event_sequence) FROM authorization_challenges",
        ),
        "null"
    );

    for sql in [
        "UPDATE authorization_challenges SET created_event_sequence=0",
        "UPDATE authorization_challenges SET created_event_sequence=-1",
        "UPDATE authorization_challenges SET created_event_sequence=1.5",
        "UPDATE authorization_challenges SET created_event_sequence='wrong-storage-class'",
    ] {
        assert_sql_mutation_rejected(&connection, sql);
    }
}

#[test]
fn schema_rejects_key_role_epoch_and_partial_unique_violations() {
    let connection = schema_connection();
    let owner = [1_u8; 32];
    let recovery = [2_u8; 32];
    insert_key(&connection, &owner, "owner", 7, &[3_u8; 32], "active");

    assert!(
        connection
            .execute(
                "INSERT INTO authority_keys VALUES (?1,'recovery',8,?2,'active',1,NULL,0,NULL)",
                params![recovery, [3_u8; 32]],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "INSERT INTO authority_keys VALUES (?1,'recovery',7,?2,'active',1,NULL,0,NULL)",
                params![recovery, [4_u8; 32]],
            )
            .is_err()
    );
    insert_key(&connection, &recovery, "recovery", 8, &[4_u8; 32], "active");
    assert!(
        connection
            .execute(
                "INSERT INTO authority_keys VALUES (?1,'owner',7,?2,'active',2,NULL,1,NULL)",
                params![[16_u8; 32], [17_u8; 32]],
            )
            .is_err()
    );

    assert!(connection.execute(
        "INSERT INTO trust_epochs VALUES (1,?1,?2,?3,'active',NULL,NULL,NULL,NULL,NULL,0,0,NULL)",
        params![recovery, owner, [5_u8; 32]],
    ).is_err());
    assert!(connection.execute(
        "INSERT INTO trust_epochs VALUES (1,?1,?2,?3,'staged',NULL,NULL,NULL,NULL,NULL,0,NULL,NULL)",
        params![owner, recovery, [6_u8; 32]],
    ).is_err());
    connection.execute(
        "INSERT INTO trust_epochs VALUES (1,?1,?2,?3,'active',NULL,NULL,NULL,NULL,NULL,0,0,NULL)",
        params![owner, recovery, [7_u8; 32]],
    ).unwrap();
    assert!(connection.execute(
        "INSERT INTO trust_epochs VALUES (3,?1,?2,?3,'staged',1,'owner_rotate',?4,?5,NULL,1,NULL,NULL)",
        params![owner, recovery, [8_u8; 32], [9_u8; 16], [10_u8; 64]],
    ).is_err());
}

#[test]
fn every_table_rejects_an_all_null_row() {
    let connection = schema_connection();
    for table in TABLES {
        let sql = format!("INSERT INTO {table} DEFAULT VALUES");
        assert!(
            connection.execute(&sql, []).is_err(),
            "{table} accepted NULL defaults"
        );
    }
}

#[test]
fn every_table_executes_required_storage_length_and_domain_invariants() {
    let connection = complete_schema_connection();
    assert_required_storage_and_length_invariants(&connection);
    assert_numeric_and_relationship_invariants(&connection);
    assert_closed_enum_invariants(&connection);
    assert_eq!(
        scalar_i64(&connection, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
    assert_eq!(scalar_text(&connection, "PRAGMA integrity_check"), "ok");
    assert_eq!(objects(&connection, "index"), strings(INDEXES));
}

fn assert_required_storage_and_length_invariants(connection: &Connection) {
    assert_eq!(COLUMN_INVARIANT_CASES.len(), TABLES.len());
    for (table, required, integer, length_assignment) in COLUMN_INVARIANT_CASES {
        assert_sql_mutation_rejected(connection, &format!("UPDATE {table} SET {required}=NULL"));
        assert_sql_mutation_rejected(
            connection,
            &format!("UPDATE {table} SET {integer}='wrong-storage-class'"),
        );
        assert_sql_mutation_rejected(
            connection,
            &format!("UPDATE {table} SET {length_assignment}"),
        );
    }
}

fn assert_numeric_and_relationship_invariants(connection: &Connection) {
    for sql in [
        "UPDATE authority_keys SET installed_at=-1",
        "UPDATE trust_epochs SET staged_at=-1",
        "UPDATE authority_meta SET last_observed_at=-1",
        "UPDATE registered_stores SET config_generation=0",
        "UPDATE registered_stores SET updated_at=created_at-1",
        "UPDATE registered_accounts SET account_generation=0",
        "UPDATE registered_accounts SET updated_at=created_at-1",
        "UPDATE authorization_challenges SET action=2",
        "UPDATE authorization_challenges SET action=256",
        "UPDATE authorization_challenges SET expires_at=issued_at",
        "UPDATE challenge_effects SET ordinal=8",
        "UPDATE challenge_effects SET effect_kind=7",
        "UPDATE authorization_receipts SET expires_at=verified_at-1",
        "UPDATE nonce_uses SET consumed_at=-1",
        "UPDATE grant_uses SET action=2",
        "UPDATE grant_uses SET used_at=-1",
        "UPDATE account_transitions SET next_generation=expected_generation+2",
        "UPDATE credential_cleanup SET state='claimed'",
        "UPDATE remote_effects SET ordinal=8",
        "UPDATE remote_effects SET effect_kind=7",
        "UPDATE effect_claims SET invoke_before=claimed_at-1",
        "UPDATE effect_invocations SET started_at=-1",
        "UPDATE effect_observations SET source=2",
        "UPDATE authority_events SET event_code=27",
    ] {
        assert_sql_mutation_rejected(connection, sql);
    }
}

fn assert_closed_enum_invariants(connection: &Connection) {
    for sql in [
        "UPDATE authority_keys SET state='unknown'",
        "UPDATE trust_epochs SET state='unknown'",
        "UPDATE authority_meta SET bootstrap_state='unknown'",
        "UPDATE registered_stores SET state='unknown'",
        "UPDATE registered_accounts SET state='unknown'",
        "UPDATE authorization_challenges SET state='invalidated'",
        "UPDATE account_transitions SET kind='unknown'",
        "UPDATE account_transitions SET state='unknown'",
        "UPDATE credential_cleanup SET locator_kind='unknown'",
        "UPDATE credential_cleanup SET state='unknown'",
    ] {
        assert_sql_mutation_rejected(connection, sql);
    }
}

#[test]
fn every_declared_partial_unique_boundary_rejects_a_competing_row() {
    {
        let connection = schema_connection();
        let root = insert_raw_authority_root(&connection);
        insert_key(&connection, &[0x41; 32], "owner", 7, &[0x42; 32], "staged");
        assert!(
            connection
                .execute(
                    "INSERT INTO authority_keys VALUES
                     (?1,'owner',7,?2,'staged',2,NULL,1,NULL)",
                    params![[0x43_u8; 32], [0x44_u8; 32]],
                )
                .is_err()
        );
        assert_ne!(root.owner_key_id, root.recovery_key_id);
    }

    {
        let connection = complete_schema_connection();
        assert!(
            connection
                .execute(
                    "INSERT INTO trust_epochs VALUES
                     (2,?1,?2,?3,'active',1,'owner_rotate',?4,?5,NULL,1,1,NULL)",
                    params![
                        [11_u8; 32],
                        [12_u8; 32],
                        [0x51_u8; 32],
                        [42_u8; 16],
                        [0x52_u8; 64]
                    ],
                )
                .is_err()
        );
    }

    {
        let connection = complete_schema_connection();
        connection
            .execute(
                "INSERT INTO trust_epochs VALUES
                 (2,?1,?2,?3,'staged',1,'owner_rotate',?4,?5,NULL,1,NULL,NULL)",
                params![
                    [11_u8; 32],
                    [12_u8; 32],
                    [0x53_u8; 32],
                    [42_u8; 16],
                    [0x54_u8; 64]
                ],
            )
            .unwrap();
        assert!(
            connection
                .execute(
                    "INSERT INTO trust_epochs VALUES
                     (3,?1,?2,?3,'staged',2,'owner_rotate',?4,?5,NULL,2,NULL,NULL)",
                    params![
                        [11_u8; 32],
                        [12_u8; 32],
                        [0x55_u8; 32],
                        [42_u8; 16],
                        [0x56_u8; 64]
                    ],
                )
                .is_err()
        );
    }

    {
        let connection = complete_schema_connection();
        insert_pending_challenge(&connection, [0x61; 32], [0x62; 16], [0x63; 32]).unwrap();
        assert!(insert_pending_challenge(&connection, [0x64; 32], [0x65; 16], [0x66; 32]).is_err());
    }

    {
        let connection = complete_schema_connection();
        let root = RawAuthorityRoot {
            owner_key_id: [11; 32],
            recovery_key_id: [12; 32],
            bundle_sha256: [13; 32],
        };
        let mut context = RawRemoteContext::new();
        context.account_id = [0x71; 16];
        context.credential_id = [0x72; 16];
        context.binding_sha256 = [0x73; 32];
        let authorization = RawAuthorization::account_create(120, &context, &root);
        insert_raw_challenge(&connection, &authorization);
        insert_raw_receipt(&connection, &authorization);
        assert!(
            connection
                .execute(
                    "INSERT INTO registered_accounts VALUES
                     (?1,?2,?3,1,?4,?5,'active',?6,NULL,20,20,NULL)",
                    params![
                        context.account_id,
                        context.store_id,
                        [231_u8; 32],
                        context.credential_id,
                        context.binding_sha256,
                        authorization.receipt_id
                    ],
                )
                .is_err()
        );
    }
}

#[test]
fn valid_relationship_chains_pass_and_every_composite_cross_link_fails() {
    let connection = schema_connection();
    let root = insert_raw_authority_root(&connection);
    let context = RawRemoteContext::new();

    let store_authorization = RawAuthorization::store_enroll(20, &context, &root);
    insert_raw_challenge(&connection, &store_authorization);
    insert_raw_receipt(&connection, &store_authorization);
    insert_registered_store(&connection, &context, store_authorization.receipt_id);

    let account_authorization = RawAuthorization::account_create(40, &context, &root);
    insert_raw_challenge(&connection, &account_authorization);
    insert_raw_receipt(&connection, &account_authorization);
    insert_registered_account(&connection, &context, account_authorization.receipt_id);
    insert_grant_use(&connection, &account_authorization);
    insert_account_transition_and_cleanup(&connection, &context, &account_authorization);

    let first = RawAuthorization::remote(60, &context, &root);
    let second = RawAuthorization::remote(90, &context, &root);
    insert_raw_challenge(&connection, &first);
    insert_raw_challenge(&connection, &second);
    insert_challenge_effect(&connection, &first);
    insert_challenge_effect(&connection, &second);

    assert!(insert_receipt_cross_link(&connection, &first, &second).is_err());
    insert_raw_receipt(&connection, &first);
    insert_raw_receipt(&connection, &second);

    assert!(
        connection
            .execute(
                "INSERT INTO nonce_uses VALUES (?1,?2,?3,20)",
                params![first.nonce, second.challenge_id, second.receipt_id],
            )
            .is_err()
    );
    insert_nonce_use(&connection, &first);
    insert_nonce_use(&connection, &second);

    assert!(
        connection
            .execute(
                "INSERT INTO grant_uses VALUES (?1,?2,?3,?4,?5,?6,?7,?8,20)",
                params![
                    first.grant_id,
                    second.receipt_id,
                    first.action,
                    first.target_kind,
                    first.target_id,
                    first.manifest_sha256,
                    [170_u8],
                    [171_u8; 32],
                ],
            )
            .is_err()
    );
    insert_grant_use(&connection, &first);
    insert_grant_use(&connection, &second);

    assert!(insert_remote_effect_cross_link(&connection, &first, &second).is_err());
    insert_remote_effect(&connection, &context, &first);
    insert_remote_effect(&connection, &context, &second);

    assert!(insert_effect_claim_cross_link(&connection, &context, &first, &second).is_err());
    insert_effect_claim(&connection, &context, &first);
    insert_effect_claim(&connection, &context, &second);

    assert!(
        connection
            .execute(
                "INSERT INTO effect_invocations VALUES (?1,?2,?3,?4,?5,?6,20)",
                params![
                    [180_u8; 16],
                    first.effect_id,
                    second.claim_id,
                    [181_u8; 16],
                    [182_u8],
                    [183_u8; 32],
                ],
            )
            .is_err()
    );
    insert_effect_invocation(&connection, &first);
    insert_effect_invocation(&connection, &second);

    assert!(
        connection
            .execute(
                "INSERT INTO effect_observations VALUES (?1,?2,?3,?4,1,?5,?6,1,?7,20)",
                params![
                    [190_u8; 32],
                    first.effect_id,
                    first.claim_id,
                    second.invocation_id,
                    [191_u8],
                    [192_u8; 32],
                    [193_u8],
                ],
            )
            .is_err()
    );
    insert_effect_observation(&connection, &first);
    insert_effect_observation(&connection, &second);

    assert_eq!(
        scalar_i64(&connection, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
    assert_eq!(scalar_text(&connection, "PRAGMA integrity_check"), "ok");
}

#[test]
fn invalid_bootstrap_keys_fail_before_entropy_or_filesystem_effects() {
    let temp = TempDir::new().unwrap();
    let home = isolated(&temp);
    let source = entropy(1);
    let store = open_isolated(
        home.clone(),
        AnchorPresence::Missing,
        location(1),
        source.clone(),
    );
    let key = owner_key();
    let error = mail_error(store.prepare_bootstrap(BootstrapInput {
        journal_location_sha256: location(1),
        owner_public_key: key.clone(),
        recovery_public_key: key,
        observed_at_unix_ms: 1,
    }));
    assert_eq!(error.code, MailErrorCode::AuthorizationMalformed);
    assert!(!error.retryable);
    assert_eq!(source.consumed_bytes(), 0);
    assert!(!home.database_path().exists());
    assert!(!home.apply_lock_path().exists());
}

#[test]
fn bootstrap_is_database_first_stable_and_exactly_retryable() {
    let temp = TempDir::new().unwrap();
    let home = isolated(&temp);
    let source = entropy(7);
    let loc = location(0x44);
    let store = open_isolated(home.clone(), AnchorPresence::Missing, loc, source.clone());
    assert!(matches!(store.state(), AuthorityOpenState::Unconfigured));

    let snapshot = store.prepare_bootstrap(input(loc, 100_000)).unwrap();
    assert_eq!(source.consumed_bytes(), 48);
    assert_eq!(snapshot.minimum_epoch, NonZeroU64::new(1).unwrap());
    assert_eq!(snapshot.anchor.version, AuthorityAnchorVersion::V1);
    assert_eq!(snapshot.anchor.state, AuthorityAnchorState::Normal);
    assert_eq!(snapshot.anchor.journal_id, snapshot.journal_id);
    assert_eq!(snapshot.anchor.realm_id, snapshot.realm_id);
    assert_eq!(
        snapshot.anchor.trust_bundle_sha256,
        snapshot.trust_bundle_sha256
    );
    assert_eq!(snapshot.anchor.journal_location_sha256, loc);
    assert_eq!(snapshot.journal_id.as_bytes()[6] >> 4, 4);
    assert_eq!(snapshot.journal_id.as_bytes()[8] >> 6, 2);
    assert_eq!(snapshot.trust_bundle_sha256, trust_bundle_digest(&snapshot));
    assert_eq!(
        hex(snapshot.journal_location_sha256.as_bytes()),
        "44".repeat(32)
    );
    assert_eq!(
        hex(snapshot.owner_key_id.as_bytes()),
        "79c04b7b63e154185aeae1080202e4ff04f6f138d0548e45c92655e835812876"
    );
    assert_eq!(
        hex(snapshot.recovery_key_id.as_bytes()),
        "8a8221adc799d91d8588e5679c201a82cb61b770574d5ceb5d118407562911df"
    );
    assert_eq!(
        hex(snapshot.trust_bundle_sha256.as_bytes()),
        BOOTSTRAP_TRUST_SHA256_HEX
    );
    let mut trust_mutation = snapshot.clone();
    trust_mutation.minimum_epoch = NonZeroU64::new(2).unwrap();
    assert_ne!(
        trust_bundle_digest(&trust_mutation),
        snapshot.trust_bundle_sha256
    );
    let mut location_mutation = snapshot.clone();
    location_mutation.journal_location_sha256 = location(0x45);
    assert_eq!(
        trust_bundle_digest(&location_mutation),
        snapshot.trust_bundle_sha256
    );
    assert_ne!(
        location_mutation.journal_location_sha256,
        snapshot.journal_location_sha256
    );
    let event_connection = Connection::open(home.database_path()).unwrap();
    let bootstrap_detail = scalar_blob(
        &event_connection,
        "SELECT detail FROM authority_events WHERE event_code=1",
    );
    assert_eq!(
        hex(&Sha256::digest(&bootstrap_detail)),
        BOOTSTRAP_EVENT_DETAIL_SHA256_HEX
    );
    assert_eq!(
        hex(&scalar_blob(
            &event_connection,
            "SELECT detail_sha256 FROM authority_events WHERE event_code=1"
        )),
        BOOTSTRAP_EVENT_DETAIL_SHA256_HEX
    );

    let retry_source = DeterministicEntropy::new(Vec::new()).unwrap();
    let retry = open_isolated(
        home.clone(),
        AnchorPresence::Missing,
        loc,
        retry_source.clone(),
    )
    .prepare_bootstrap(input(loc, 100_001))
    .unwrap();
    assert!(retry == snapshot);
    assert_eq!(retry_source.consumed_bytes(), 0);

    let error = mail_error(
        open_isolated(
            home.clone(),
            AnchorPresence::Missing,
            loc,
            DeterministicEntropy::new(Vec::new()).unwrap(),
        )
        .prepare_bootstrap(input(loc, 70_000)),
    );
    assert_eq!(error.code, MailErrorCode::ClockRollbackDetected);

    let error = mail_error(
        open_isolated(home, AnchorPresence::Missing, loc, entropy(90))
            .prepare_bootstrap(input(location(0x45), 100_001)),
    );
    assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
}

#[test]
fn stale_nonunconfigured_store_never_regenerates_absent_or_pristine_authority() {
    let loc = location(0x46);

    for (seed, pristine_replacement) in [(70_u8, false), (71_u8, true)] {
        let (_temp, home, _snapshot) = prepared_home(seed, loc, 100_000);
        let source = DeterministicEntropy::new(Vec::new()).unwrap();
        let pending = open_isolated(home.clone(), AnchorPresence::Missing, loc, source.clone());
        assert!(matches!(
            pending.state(),
            AuthorityOpenState::BootstrapPending(_)
        ));
        assert_stale_prepare_fails_closed(&pending, &home, loc, &source, pristine_replacement);
    }

    {
        let (_temp, home, snapshot) = prepared_home(72, loc, 100_000);
        let source = DeterministicEntropy::new(Vec::new()).unwrap();
        let confirmation = open_isolated(
            home.clone(),
            AnchorPresence::Present(snapshot.anchor),
            loc,
            source.clone(),
        );
        assert!(matches!(
            confirmation.state(),
            AuthorityOpenState::ConfirmationRequired(_)
        ));
        assert_stale_prepare_fails_closed(&confirmation, &home, loc, &source, false);
    }

    for (seed, pristine_replacement) in [(73_u8, false), (74_u8, true)] {
        let (_temp, home, snapshot) = prepared_home(seed, loc, 100_000);
        open_isolated(
            home.clone(),
            AnchorPresence::Present(snapshot.anchor.clone()),
            loc,
            entropy(80),
        )
        .confirm_anchor(&snapshot.anchor, 100_001)
        .unwrap();
        let source = DeterministicEntropy::new(Vec::new()).unwrap();
        let ready = open_isolated(
            home.clone(),
            AnchorPresence::Present(snapshot.anchor),
            loc,
            source.clone(),
        );
        assert!(matches!(ready.state(), AuthorityOpenState::Ready(_)));
        assert_stale_prepare_fails_closed(&ready, &home, loc, &source, pristine_replacement);
    }
}

#[test]
fn open_uses_one_consistent_read_snapshot_across_concurrent_confirm() {
    let loc = location(0x47);
    let (_temp, home, snapshot) = prepared_home(75, loc, 100_000);
    let confirmation = open_isolated(
        home.clone(),
        AnchorPresence::Present(snapshot.anchor.clone()),
        loc,
        entropy(80),
    );
    let reached = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let paused_home = home
        .clone()
        .with_open_snapshot_pause(Arc::clone(&reached), Arc::clone(&resume));
    let anchor = snapshot.anchor.clone();
    let opener = thread::spawn(move || {
        open_isolated(
            paused_home,
            AnchorPresence::Present(anchor),
            loc,
            entropy(81),
        )
    });

    reached.wait();
    let confirmation_result = confirmation.confirm_anchor(&snapshot.anchor, 100_001);
    resume.wait();
    confirmation_result.unwrap();
    let raced_open = opener.join().unwrap();

    assert!(matches!(
        raced_open.state(),
        AuthorityOpenState::ConfirmationRequired(value) if value == &snapshot
    ));
    let restarted = open_isolated(
        home,
        AnchorPresence::Present(snapshot.anchor),
        loc,
        entropy(82),
    );
    assert!(matches!(restarted.state(), AuthorityOpenState::Ready(_)));
}

#[test]
fn committed_retry_revalidates_identity_inside_its_write_transaction() {
    let loc = location(0x4E);
    let (_temp, home, snapshot) = prepared_home(76, loc, 100_000);
    let reached = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let source = DeterministicEntropy::new(Vec::new()).unwrap();
    let retry = open_isolated(
        home.clone()
            .with_prepare_retry_pause(Arc::clone(&reached), Arc::clone(&resume)),
        AnchorPresence::Missing,
        loc,
        source.clone(),
    );
    assert!(matches!(
        retry.state(),
        AuthorityOpenState::BootstrapPending(value) if value == &snapshot
    ));
    let worker = thread::spawn(move || retry.prepare_bootstrap(input(loc, 100_001)));

    reached.wait();
    let connection = Connection::open(home.database_path()).unwrap();
    connection
        .pragma_update(None, "application_id", 17_i64)
        .unwrap();
    drop(connection);
    resume.wait();

    let error = mail_error(worker.join().unwrap());
    assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
    assert_eq!(source.consumed_bytes(), 0);
    assert_bootstrap_rows(&home, "pending_anchor", 1, 100_000);
}

#[test]
fn valid_authority_open_restores_wal_full_before_consistent_snapshot() {
    let loc = location(0x4F);
    let (_temp, home, snapshot) = prepared_home(77, loc, 100_000);
    switch_to_delete_journal(&home);
    assert_eq!(
        database_fingerprint(&home).journal_mode,
        "delete",
        "fixture must expose the pragma regression"
    );

    let reopened = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(83));

    assert!(matches!(
        reopened.state(),
        AuthorityOpenState::BootstrapPending(value) if value == &snapshot
    ));
    assert_wal_full(&home);
}

#[test]
fn stale_valid_write_paths_restore_wal_full_before_revalidation() {
    let loc = location(0x50);

    {
        let (_temp, home, snapshot) = prepared_home(78, loc, 100_000);
        let confirmation = open_isolated(
            home.clone(),
            AnchorPresence::Present(snapshot.anchor.clone()),
            loc,
            entropy(84),
        );
        switch_to_delete_journal(&home);

        let confirmed = confirmation
            .confirm_anchor(&snapshot.anchor, 100_001)
            .unwrap();

        assert!(confirmed == snapshot);
        assert_wal_full(&home);
        assert_bootstrap_rows(&home, "ready", 2, 100_001);
    }

    {
        let (_temp, home, snapshot) = prepared_home(79, loc, 100_000);
        let source = DeterministicEntropy::new(Vec::new()).unwrap();
        let retry = open_isolated(home.clone(), AnchorPresence::Missing, loc, source.clone());
        switch_to_delete_journal(&home);

        let recovered = retry.prepare_bootstrap(input(loc, 100_001)).unwrap();

        assert!(recovered == snapshot);
        assert_eq!(source.consumed_bytes(), 0);
        assert_wal_full(&home);
        assert_bootstrap_rows(&home, "pending_anchor", 1, 100_001);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn pragma_preflight_does_not_mutate_unrecognized_or_stale_pristine_databases() {
    let loc = location(0x51);

    {
        let temp = TempDir::new().unwrap();
        let home = isolated(&temp);
        let stale = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(85));
        install_preflight_database(&home, 17, 4, true);
        let before = database_fingerprint(&home);

        let opened = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(86));
        assert!(matches!(
            opened.state(),
            AuthorityOpenState::RecoveryRequired
        ));
        assert_eq!(database_fingerprint(&home), before);
        let error = mail_error(stale.prepare_bootstrap(input(loc, 100_000)));
        assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
        assert_eq!(database_fingerprint(&home), before);
    }

    {
        let temp = TempDir::new().unwrap();
        let home = isolated(&temp);
        let stale = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(87));
        install_preflight_database(&home, 0, 0, true);
        let before = database_fingerprint(&home);

        let opened = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(88));
        assert!(matches!(
            opened.state(),
            AuthorityOpenState::RecoveryRequired
        ));
        assert_eq!(database_fingerprint(&home), before);
        let error = mail_error(stale.prepare_bootstrap(input(loc, 100_000)));
        assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
        assert_eq!(database_fingerprint(&home), before);
    }

    {
        let temp = TempDir::new().unwrap();
        let home = isolated(&temp);
        let stale = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(89));
        install_preflight_database(&home, APPLICATION_ID, 2, true);
        let before = database_fingerprint(&home);

        let error = mail_error(AuthorityStore::open_isolated(
            context(AnchorPresence::Missing, loc),
            home.clone(),
            entropy(90),
        ));
        assert_eq!(error.code, MailErrorCode::UnsupportedCapability);
        assert_eq!(database_fingerprint(&home), before);
        let error = mail_error(stale.prepare_bootstrap(input(loc, 100_000)));
        assert_eq!(error.code, MailErrorCode::UnsupportedCapability);
        assert_eq!(database_fingerprint(&home), before);
    }

    {
        let (_temp, home, _snapshot) = prepared_home(91, loc, 100_000);
        let stale_pending = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(92));
        remove_authority_database(&home);
        install_preflight_database(&home, 0, 0, false);
        let before = database_fingerprint(&home);

        let error = mail_error(stale_pending.prepare_bootstrap(input(loc, 100_001)));
        assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
        assert_eq!(database_fingerprint(&home), before);
    }

    {
        let temp = TempDir::new().unwrap();
        let home = isolated(&temp);
        install_preflight_database(&home, 0, 0, false);
        let before = database_fingerprint(&home);
        let first = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(93));
        assert!(matches!(first.state(), AuthorityOpenState::Unconfigured));
        assert_eq!(database_fingerprint(&home), before);

        first.prepare_bootstrap(input(loc, 100_000)).unwrap();
        assert_wal_full(&home);
    }
}

#[test]
fn confirm_requires_exact_confirmation_open_state_and_is_one_shot() {
    let loc = location(0x48);

    {
        let (_temp, home, snapshot) = prepared_home(1, loc, 100_000);
        let pending = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(80));
        assert!(matches!(
            pending.state(),
            AuthorityOpenState::BootstrapPending(_)
        ));
        let error = mail_error(pending.confirm_anchor(&snapshot.anchor, 100_001));
        assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
        assert_bootstrap_rows(&home, "pending_anchor", 1, 100_000);
    }

    {
        let (_temp, home, snapshot) = prepared_home(2, loc, 100_000);
        let mut wrong_anchor = snapshot.anchor.clone();
        wrong_anchor.trust_bundle_sha256 = Sha256Digest::from_bytes([0x81; 32]);
        let recovery = open_isolated(
            home.clone(),
            AnchorPresence::Present(wrong_anchor),
            loc,
            entropy(80),
        );
        assert!(matches!(
            recovery.state(),
            AuthorityOpenState::RecoveryRequired
        ));
        let error = mail_error(recovery.confirm_anchor(&snapshot.anchor, 100_001));
        assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
        assert_bootstrap_rows(&home, "pending_anchor", 1, 100_000);
    }

    {
        let (_temp, home, snapshot) = prepared_home(3, loc, 100_000);
        open_isolated(
            home.clone(),
            AnchorPresence::Present(snapshot.anchor.clone()),
            loc,
            entropy(80),
        )
        .confirm_anchor(&snapshot.anchor, 100_001)
        .unwrap();
        let ready = open_isolated(
            home.clone(),
            AnchorPresence::Present(snapshot.anchor.clone()),
            loc,
            entropy(80),
        );
        assert!(matches!(ready.state(), AuthorityOpenState::Ready(_)));
        let error = mail_error(ready.confirm_anchor(&snapshot.anchor, 100_002));
        assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
        assert_bootstrap_rows(&home, "ready", 2, 100_001);
    }

    {
        let (_temp, home, snapshot) = prepared_home(4, loc, 100_000);
        let confirmation = open_isolated(
            home.clone(),
            AnchorPresence::Present(snapshot.anchor.clone()),
            loc,
            entropy(80),
        );
        confirmation
            .confirm_anchor(&snapshot.anchor, 100_001)
            .unwrap();
        let error = mail_error(confirmation.confirm_anchor(&snapshot.anchor, 100_002));
        assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
        assert_bootstrap_rows(&home, "ready", 2, 100_001);
    }
}

#[test]
fn confirm_rechecks_database_identity_inside_its_write_transaction() {
    let loc = location(0x49);
    for (seed, pragma, value) in [
        (5_u8, "application_id", 17_i64),
        (6_u8, "user_version", 2_i64),
    ] {
        let (_temp, home, snapshot) = prepared_home(seed, loc, 100_000);
        let confirmation = open_isolated(
            home.clone(),
            AnchorPresence::Present(snapshot.anchor.clone()),
            loc,
            entropy(80),
        );
        assert!(matches!(
            confirmation.state(),
            AuthorityOpenState::ConfirmationRequired(_)
        ));
        Connection::open(home.database_path())
            .unwrap()
            .pragma_update(None, pragma, value)
            .unwrap();

        assert!(
            confirmation
                .confirm_anchor(&snapshot.anchor, 100_001)
                .is_err(),
            "stale confirmation accepted changed {pragma}"
        );
        assert_bootstrap_rows(&home, "pending_anchor", 1, 100_000);
    }
}

#[test]
fn confirm_rechecks_event_sequence_high_water_inside_its_transaction() {
    let loc = location(0x4D);
    let (_temp, home, snapshot) = prepared_home(62, loc, 100_000);
    let confirmation = open_isolated(
        home.clone(),
        AnchorPresence::Present(snapshot.anchor.clone()),
        loc,
        entropy(80),
    );
    Connection::open(home.database_path())
        .unwrap()
        .execute(
            "UPDATE sqlite_sequence SET seq=100 WHERE name='authority_events'",
            [],
        )
        .unwrap();

    let error = mail_error(confirmation.confirm_anchor(&snapshot.anchor, 100_001));
    assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
    assert_bootstrap_rows(&home, "pending_anchor", 1, 100_000);
}

#[test]
fn active_epoch_bundle_must_equal_meta_and_recomputed_bundle() {
    let loc = location(0x4A);
    let (_temp, home, _snapshot) = prepared_home(7, loc, 100_000);
    let connection = Connection::open(home.database_path()).unwrap();
    connection
        .execute(
            "UPDATE trust_epochs SET bundle_sha256=?1 WHERE epoch=1",
            [[0xA5_u8; 32]],
        )
        .unwrap();
    assert_eq!(
        scalar_i64(&connection, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
    assert_eq!(scalar_text(&connection, "PRAGMA integrity_check"), "ok");
    drop(connection);

    let store = open_isolated(home, AnchorPresence::Missing, loc, entropy(80));
    assert!(matches!(
        store.state(),
        AuthorityOpenState::RecoveryRequired
    ));
}

#[test]
fn t202a_events_are_exact_canonical_rows_for_pending_and_ready() {
    const MUTATIONS: [EventMutation; 9] = [
        EventMutation::Sequence,
        EventMutation::EntityKind,
        EventMutation::EntityId,
        EventMutation::EventCode,
        EventMutation::Source,
        EventMutation::OccurredAt,
        EventMutation::CanonicalDetail,
        EventMutation::DetailDigest,
        EventMutation::ExtraRow,
    ];

    for (index, mutation) in MUTATIONS.into_iter().enumerate() {
        let loc = location(0x90 + u8::try_from(index).unwrap());
        let (_temp, home, _snapshot) =
            prepared_home(10 + u8::try_from(index).unwrap(), loc, 100_000);
        let connection = Connection::open(home.database_path()).unwrap();
        mutate_event(&connection, 1, mutation);
        drop(connection);
        let store = open_isolated(home, AnchorPresence::Missing, loc, entropy(80));
        assert!(
            matches!(store.state(), AuthorityOpenState::RecoveryRequired),
            "pending accepted {mutation:?} corruption"
        );
    }

    for (index, mutation) in MUTATIONS.into_iter().enumerate() {
        let loc = location(0xA0 + u8::try_from(index).unwrap());
        let (_temp, home, snapshot) =
            prepared_home(30 + u8::try_from(index).unwrap(), loc, 100_000);
        open_isolated(
            home.clone(),
            AnchorPresence::Present(snapshot.anchor.clone()),
            loc,
            entropy(80),
        )
        .confirm_anchor(&snapshot.anchor, 100_001)
        .unwrap();
        let connection = Connection::open(home.database_path()).unwrap();
        mutate_event(&connection, 2, mutation);
        drop(connection);
        let store = open_isolated(
            home,
            AnchorPresence::Present(snapshot.anchor),
            loc,
            entropy(80),
        );
        assert!(
            matches!(store.state(), AuthorityOpenState::RecoveryRequired),
            "ready accepted {mutation:?} corruption"
        );
    }

    let loc = location(0xAF);
    let (_temp, home, snapshot) = prepared_home(50, loc, 100_000);
    Connection::open(home.database_path())
        .unwrap()
        .execute(
            "UPDATE authority_meta SET bootstrap_state='ready',anchor_confirmed_at=100000",
            [],
        )
        .unwrap();
    let store = open_isolated(
        home,
        AnchorPresence::Present(snapshot.anchor),
        loc,
        entropy(80),
    );
    assert!(matches!(
        store.state(),
        AuthorityOpenState::RecoveryRequired
    ));
}

#[test]
fn bootstrap_entropy_failure_rolls_back_every_owned_value_and_restarts_cleanly() {
    let temp = TempDir::new().unwrap();
    let home = isolated(&temp);
    let loc = location(0x4B);
    let short_entropy = DeterministicEntropy::new(vec![0x51; 32]).unwrap();
    let store = open_isolated(
        home.clone(),
        AnchorPresence::Missing,
        loc,
        short_entropy.clone(),
    );
    let error = mail_error(store.prepare_bootstrap(input(loc, 100_000)));
    assert_eq!(error.code, MailErrorCode::Internal);
    assert_eq!(short_entropy.consumed_bytes(), 32);

    let connection = Connection::open(home.database_path()).unwrap();
    assert_eq!(user_object_count(&connection), 0);
    assert_eq!(pragma_i64(&connection, "application_id"), 0);
    assert_eq!(pragma_i64(&connection, "user_version"), 0);
    drop(connection);

    let restarted = open_isolated(home, AnchorPresence::Missing, loc, entropy(60));
    assert!(matches!(
        restarted.state(),
        AuthorityOpenState::Unconfigured
    ));
    restarted.prepare_bootstrap(input(loc, 100_001)).unwrap();
}

#[test]
fn initial_t202a_authority_rows_reject_unaccounted_historical_keys() {
    let loc = location(0x4C);
    let (_temp, home, _snapshot) = prepared_home(61, loc, 100_000);
    Connection::open(home.database_path())
        .unwrap()
        .execute(
            "INSERT INTO authority_keys VALUES
             (?1,'owner',7,?2,'retired',1,1,0,1)",
            params![[0x71_u8; 32], [0x72_u8; 32]],
        )
        .unwrap();

    let store = open_isolated(home, AnchorPresence::Missing, loc, entropy(80));
    assert!(matches!(
        store.state(),
        AuthorityOpenState::RecoveryRequired
    ));
}

#[test]
fn pending_confirm_ready_restart_and_clock_matrix_are_exact() {
    let temp = TempDir::new().unwrap();
    let home = isolated(&temp);
    let loc = location(0x55);
    let snapshot = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(11))
        .prepare_bootstrap(input(loc, 100_000))
        .unwrap();

    let pending = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(80));
    assert!(
        matches!(pending.state(), AuthorityOpenState::BootstrapPending(value) if value == &snapshot)
    );
    let confirmation = open_isolated(
        home.clone(),
        AnchorPresence::Present(snapshot.anchor.clone()),
        loc,
        entropy(80),
    );
    assert!(
        matches!(confirmation.state(), AuthorityOpenState::ConfirmationRequired(value) if value == &snapshot)
    );
    let mut mismatched_anchor = snapshot.anchor.clone();
    mismatched_anchor.trust_bundle_sha256 = Sha256Digest::from_bytes([0x91; 32]);
    let error = mail_error(confirmation.confirm_anchor(&mismatched_anchor, 100_000));
    assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
    let still_pending = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(80));
    assert!(matches!(
        still_pending.state(),
        AuthorityOpenState::BootstrapPending(_)
    ));

    simulate_confirm_crash(&home, snapshot.realm_id.as_bytes());
    let after_confirm_crash =
        open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(80));
    assert!(matches!(
        after_confirm_crash.state(),
        AuthorityOpenState::BootstrapPending(_)
    ));
    let confirmed = confirmation
        .confirm_anchor(&snapshot.anchor, 70_000)
        .unwrap();
    assert!(confirmed == snapshot);
    let event_connection = Connection::open(home.database_path()).unwrap();
    let confirmation_detail = scalar_blob(
        &event_connection,
        "SELECT detail FROM authority_events WHERE event_code=2",
    );
    assert_eq!(
        hex(&Sha256::digest(&confirmation_detail)),
        CONFIRM_EVENT_DETAIL_SHA256_HEX
    );
    assert_eq!(
        hex(&scalar_blob(
            &event_connection,
            "SELECT detail_sha256 FROM authority_events WHERE event_code=2"
        )),
        CONFIRM_EVENT_DETAIL_SHA256_HEX
    );

    let ready = open_isolated(
        home.clone(),
        AnchorPresence::Present(snapshot.anchor.clone()),
        loc,
        entropy(80),
    );
    assert!(matches!(ready.state(), AuthorityOpenState::Ready(value) if value == &snapshot));
    let missing_ready = open_isolated(home.clone(), AnchorPresence::Missing, loc, entropy(80));
    assert!(matches!(
        missing_ready.state(),
        AuthorityOpenState::RecoveryRequired
    ));
    let wrong_location = open_isolated(
        home,
        AnchorPresence::Present(snapshot.anchor.clone()),
        location(0x56),
        entropy(80),
    );
    assert!(matches!(
        wrong_location.state(),
        AuthorityOpenState::RecoveryRequired
    ));

    let rollback_temp = TempDir::new().unwrap();
    let rollback_home = isolated(&rollback_temp);
    let rollback_snapshot = open_isolated(
        rollback_home.clone(),
        AnchorPresence::Missing,
        loc,
        entropy(21),
    )
    .prepare_bootstrap(input(loc, 100_000))
    .unwrap();
    let error = mail_error(
        open_isolated(
            rollback_home,
            AnchorPresence::Present(rollback_snapshot.anchor.clone()),
            loc,
            entropy(80),
        )
        .confirm_anchor(&rollback_snapshot.anchor, 69_999),
    );
    assert_eq!(error.code, MailErrorCode::ClockRollbackDetected);
}

#[test]
#[allow(clippy::too_many_lines)]
fn open_matrix_fails_closed_without_regeneration_or_staged_finalize() {
    let absent = TempDir::new().unwrap();
    let absent_home = isolated(&absent);
    let loc = location(0x66);
    let fabricated_anchor = bootstrap_anchor_for_absent(loc);
    let state = open_isolated(
        absent_home.clone(),
        AnchorPresence::Present(fabricated_anchor),
        loc,
        entropy(30),
    );
    assert!(matches!(
        state.state(),
        AuthorityOpenState::RecoveryRequired
    ));
    assert!(!absent_home.database_path().exists());

    let equal = TempDir::new().unwrap();
    let equal_home = isolated(&equal);
    let mut equal_anchor = bootstrap_anchor_for_absent(loc);
    equal_anchor.recovery_public_key = equal_anchor.owner_public_key.clone();
    let error = mail_error(AuthorityStore::open_isolated(
        context(AnchorPresence::Present(equal_anchor), loc),
        equal_home.clone(),
        entropy(30),
    ));
    assert_eq!(error.code, MailErrorCode::AuthorizationMalformed);
    assert!(!equal_home.database_path().exists());
    let error = mail_error(state.prepare_bootstrap(input(loc, 1)));
    assert_eq!(error.code, MailErrorCode::OwnerRecoveryRequired);
    assert!(!absent_home.database_path().exists());

    let foreign = TempDir::new().unwrap();
    let foreign_home = isolated(&foreign);
    create_database_parent(&foreign_home);
    let connection = Connection::open(foreign_home.database_path()).unwrap();
    connection
        .pragma_update(None, "application_id", 17_i64)
        .unwrap();
    drop(connection);
    let store = open_isolated(foreign_home, AnchorPresence::Missing, loc, entropy(31));
    assert!(matches!(
        store.state(),
        AuthorityOpenState::RecoveryRequired
    ));

    let nonempty = TempDir::new().unwrap();
    let nonempty_home = isolated(&nonempty);
    create_database_parent(&nonempty_home);
    Connection::open(nonempty_home.database_path())
        .unwrap()
        .execute_batch("CREATE TABLE unrelated(value INTEGER);")
        .unwrap();
    let store = open_isolated(nonempty_home, AnchorPresence::Missing, loc, entropy(32));
    assert!(matches!(
        store.state(),
        AuthorityOpenState::RecoveryRequired
    ));

    let altered = TempDir::new().unwrap();
    let altered_home = isolated(&altered);
    open_isolated(
        altered_home.clone(),
        AnchorPresence::Missing,
        loc,
        entropy(34),
    )
    .prepare_bootstrap(input(loc, 1))
    .unwrap();
    Connection::open(altered_home.database_path())
        .unwrap()
        .execute_batch(
            "DROP INDEX authority_events_entity_sequence;
             CREATE INDEX authority_events_entity_sequence ON authority_events(sequence);",
        )
        .unwrap();
    let store = open_isolated(altered_home, AnchorPresence::Missing, loc, entropy(35));
    assert!(matches!(
        store.state(),
        AuthorityOpenState::RecoveryRequired
    ));

    let corrupt = TempDir::new().unwrap();
    let corrupt_home = isolated(&corrupt);
    open_isolated(
        corrupt_home.clone(),
        AnchorPresence::Missing,
        loc,
        entropy(36),
    )
    .prepare_bootstrap(input(loc, 1))
    .unwrap();
    Connection::open(corrupt_home.database_path())
        .unwrap()
        .execute("UPDATE authority_events SET detail_sha256=zeroblob(32)", [])
        .unwrap();
    let store = open_isolated(corrupt_home, AnchorPresence::Missing, loc, entropy(37));
    assert!(matches!(
        store.state(),
        AuthorityOpenState::RecoveryRequired
    ));

    let newer = TempDir::new().unwrap();
    let newer_home = isolated(&newer);
    create_database_parent(&newer_home);
    let connection = Connection::open(newer_home.database_path()).unwrap();
    connection
        .pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    connection
        .pragma_update(None, "user_version", 2_i64)
        .unwrap();
    drop(connection);
    let error = mail_error(AuthorityStore::open_isolated(
        context(AnchorPresence::Missing, loc),
        newer_home,
        entropy(33),
    ));
    assert_eq!(error.code, MailErrorCode::UnsupportedCapability);

    let staged = TempDir::new().unwrap();
    let staged_home = isolated(&staged);
    let snapshot = open_isolated(
        staged_home.clone(),
        AnchorPresence::Missing,
        loc,
        entropy(40),
    )
    .prepare_bootstrap(input(loc, 1))
    .unwrap();
    let connection = Connection::open(staged_home.database_path()).unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints=ON;")
        .unwrap();
    connection
        .execute(
            "UPDATE trust_epochs SET state='staged', activated_at=NULL WHERE epoch=1",
            [],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints=OFF;")
        .unwrap();
    drop(connection);
    let store = open_isolated(
        staged_home,
        AnchorPresence::Present(snapshot.anchor),
        loc,
        entropy(88),
    );
    assert!(matches!(
        store.state(),
        AuthorityOpenState::RecoveryRequired
    ));

    let staged_key = TempDir::new().unwrap();
    let staged_key_home = isolated(&staged_key);
    open_isolated(
        staged_key_home.clone(),
        AnchorPresence::Missing,
        loc,
        entropy(50),
    )
    .prepare_bootstrap(input(loc, 1))
    .unwrap();
    Connection::open(staged_key_home.database_path())
        .unwrap()
        .execute(
            "INSERT INTO authority_keys VALUES (?1,'owner',7,?2,'staged',2,NULL,2,NULL)",
            params![[201_u8; 32], [202_u8; 32]],
        )
        .unwrap();
    let store = open_isolated(staged_key_home, AnchorPresence::Missing, loc, entropy(51));
    assert!(matches!(
        store.state(),
        AuthorityOpenState::RecoveryRequired
    ));
}

#[test]
fn concurrent_bootstrap_has_one_committed_winner_and_stable_identity() {
    let temp = TempDir::new().unwrap();
    let home = isolated(&temp);
    let loc = location(0x77);
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    let sources = [entropy(1), entropy(101)];
    for source in &sources {
        let worker_home = home.clone();
        let worker_barrier = Arc::clone(&barrier);
        let worker_source = source.clone();
        handles.push(thread::spawn(move || {
            let store = open_isolated(worker_home, AnchorPresence::Missing, loc, worker_source);
            worker_barrier.wait();
            store.prepare_bootstrap(input(loc, 10)).unwrap()
        }));
    }
    let first = handles.remove(0).join().unwrap();
    let second = handles.remove(0).join().unwrap();
    assert!(first == second);
    assert_eq!(
        sources
            .iter()
            .map(DeterministicEntropy::consumed_bytes)
            .sum::<usize>(),
        48
    );
}

#[derive(Clone, Copy)]
struct RawAuthorityRoot {
    owner_key_id: [u8; 32],
    recovery_key_id: [u8; 32],
    bundle_sha256: [u8; 32],
}

#[derive(Clone, Copy)]
struct RawRemoteContext {
    store_id: [u8; 16],
    store_location_sha256: [u8; 32],
    config_sha256: [u8; 32],
    account_id: [u8; 16],
    credential_id: [u8; 16],
    binding_sha256: [u8; 32],
    policy_sha256: [u8; 32],
}

impl RawRemoteContext {
    fn new() -> Self {
        Self {
            store_id: [1; 16],
            store_location_sha256: [2; 32],
            config_sha256: [3; 32],
            account_id: [4; 16],
            credential_id: [5; 16],
            binding_sha256: [6; 32],
            policy_sha256: [7; 32],
        }
    }
}

#[derive(Clone, Copy)]
struct RawAuthorization {
    challenge_id: [u8; 32],
    grant_id: [u8; 16],
    receipt_id: [u8; 16],
    nonce: [u8; 32],
    action: i64,
    target_kind: i64,
    target_id: [u8; 16],
    store_id: Option<[u8; 16]>,
    account_id: Option<[u8; 16]>,
    binding_sha256: Option<[u8; 32]>,
    policy_sha256: Option<[u8; 32]>,
    manifest_sha256: [u8; 32],
    owner_key_id: [u8; 32],
    bundle_sha256: [u8; 32],
    effect_id: [u8; 16],
    operation_id: [u8; 16],
    claim_id: [u8; 16],
    invocation_id: [u8; 16],
}

impl RawAuthorization {
    fn store_enroll(seed: u8, context: &RawRemoteContext, root: &RawAuthorityRoot) -> Self {
        Self::new(
            seed,
            256,
            2,
            context.store_id,
            Some(context.store_id),
            None,
            None,
            None,
            root,
        )
    }

    fn account_create(seed: u8, context: &RawRemoteContext, root: &RawAuthorityRoot) -> Self {
        Self::new(
            seed,
            272,
            3,
            context.account_id,
            Some(context.store_id),
            Some(context.account_id),
            Some(context.binding_sha256),
            None,
            root,
        )
    }

    fn remote(seed: u8, context: &RawRemoteContext, root: &RawAuthorityRoot) -> Self {
        Self::new(
            seed,
            1,
            1,
            [seed.wrapping_add(4); 16],
            Some(context.store_id),
            Some(context.account_id),
            Some(context.binding_sha256),
            Some(context.policy_sha256),
            root,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        seed: u8,
        action: i64,
        target_kind: i64,
        target_id: [u8; 16],
        store_id: Option<[u8; 16]>,
        account_id: Option<[u8; 16]>,
        binding_sha256: Option<[u8; 32]>,
        policy_sha256: Option<[u8; 32]>,
        root: &RawAuthorityRoot,
    ) -> Self {
        Self {
            challenge_id: [seed; 32],
            grant_id: [seed.wrapping_add(1); 16],
            receipt_id: [seed.wrapping_add(2); 16],
            nonce: [seed.wrapping_add(3); 32],
            action,
            target_kind,
            target_id,
            store_id,
            account_id,
            binding_sha256,
            policy_sha256,
            manifest_sha256: [seed.wrapping_add(5); 32],
            owner_key_id: root.owner_key_id,
            bundle_sha256: root.bundle_sha256,
            effect_id: [seed.wrapping_add(6); 16],
            operation_id: [seed.wrapping_add(7); 16],
            claim_id: [seed.wrapping_add(8); 16],
            invocation_id: [seed.wrapping_add(9); 16],
        }
    }
}

fn insert_raw_authority_root(connection: &Connection) -> RawAuthorityRoot {
    let owner_key_id = [11; 32];
    let recovery_key_id = [12; 32];
    let bundle_sha256 = [13; 32];
    insert_key(connection, &owner_key_id, "owner", 7, &[14; 32], "active");
    insert_key(
        connection,
        &recovery_key_id,
        "recovery",
        8,
        &[15; 32],
        "active",
    );
    connection.execute(
        "INSERT INTO trust_epochs VALUES (1,?1,?2,?3,'active',NULL,NULL,NULL,NULL,NULL,0,0,NULL)",
        params![owner_key_id, recovery_key_id, bundle_sha256],
    ).unwrap();
    RawAuthorityRoot {
        owner_key_id,
        recovery_key_id,
        bundle_sha256,
    }
}

fn insert_raw_challenge(connection: &Connection, value: &RawAuthorization) {
    connection
        .execute(
            "INSERT INTO authorization_challenges (
                 challenge_id,grant_id,action,target_kind,target_id,store_id,account_id,
                 context_sha256,manifest,manifest_sha256,signing_payload,signing_sha256,
                 key_id,trust_epoch,bundle_sha256,binding_sha256,policy_sha256,nonce,
                 issued_at,expires_at,state,invalidated_at
             ) VALUES (
                 ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?1,?12,1,?13,?14,?15,?16,
                 10,100,'authorized',NULL)",
            params![
                value.challenge_id,
                value.grant_id,
                value.action,
                value.target_kind,
                value.target_id,
                value.store_id.as_ref().map(<[u8; 16]>::as_slice),
                value.account_id.as_ref().map(<[u8; 16]>::as_slice),
                [200_u8; 32],
                [201_u8],
                value.manifest_sha256,
                [202_u8],
                value.owner_key_id,
                value.bundle_sha256,
                value.binding_sha256.as_ref().map(<[u8; 32]>::as_slice),
                value.policy_sha256.as_ref().map(<[u8; 32]>::as_slice),
                value.nonce,
            ],
        )
        .unwrap();
}

fn insert_pending_challenge(
    connection: &Connection,
    challenge_id: [u8; 32],
    grant_id: [u8; 16],
    nonce: [u8; 32],
) -> rusqlite::Result<usize> {
    connection.execute(
        "INSERT INTO authorization_challenges (
             challenge_id,grant_id,action,target_kind,target_id,store_id,account_id,
             context_sha256,manifest,manifest_sha256,signing_payload,signing_sha256,
             key_id,trust_epoch,bundle_sha256,binding_sha256,policy_sha256,nonce,
             issued_at,expires_at,state,invalidated_at
         )
         SELECT ?1,?2,action,target_kind,target_id,store_id,account_id,
                context_sha256,manifest,manifest_sha256,signing_payload,?1,
                key_id,trust_epoch,bundle_sha256,binding_sha256,policy_sha256,?3,
                issued_at,expires_at,'pending',NULL
         FROM authorization_challenges ORDER BY rowid LIMIT 1",
        params![challenge_id, grant_id, nonce],
    )
}

fn insert_raw_receipt(connection: &Connection, value: &RawAuthorization) {
    connection
        .execute(
            "INSERT INTO authorization_receipts VALUES (
         ?1,?2,?3,?4,?5,?6,?7,?8,?2,1,?9,?10,?11,20,100)",
            params![
                value.receipt_id,
                value.challenge_id,
                value.grant_id,
                [value.receipt_id[0].wrapping_add(10); 32],
                value.owner_key_id,
                [210_u8; 64],
                [211_u8],
                value.manifest_sha256,
                value.bundle_sha256,
                [212_u8],
                [value.receipt_id[0].wrapping_add(11); 32],
            ],
        )
        .unwrap();
}

fn insert_receipt_cross_link(
    connection: &Connection,
    first: &RawAuthorization,
    second: &RawAuthorization,
) -> rusqlite::Result<usize> {
    connection.execute(
        "INSERT INTO authorization_receipts VALUES (
         ?1,?2,?3,?4,?5,?6,?7,?8,?2,1,?9,?10,?11,20,100)",
        params![
            [160_u8; 16],
            first.challenge_id,
            second.grant_id,
            [161_u8; 32],
            first.owner_key_id,
            [162_u8; 64],
            [163_u8],
            first.manifest_sha256,
            first.bundle_sha256,
            [164_u8],
            [165_u8; 32],
        ],
    )
}

fn insert_nonce_use(connection: &Connection, value: &RawAuthorization) {
    connection
        .execute(
            "INSERT INTO nonce_uses VALUES (?1,?2,?3,20)",
            params![value.nonce, value.challenge_id, value.receipt_id],
        )
        .unwrap();
}

fn insert_grant_use(connection: &Connection, value: &RawAuthorization) {
    connection
        .execute(
            "INSERT INTO grant_uses VALUES (?1,?2,?3,?4,?5,?6,?7,?8,20)",
            params![
                value.grant_id,
                value.receipt_id,
                value.action,
                value.target_kind,
                value.target_id,
                value.manifest_sha256,
                [220_u8],
                [value.grant_id[0].wrapping_add(12); 32],
            ],
        )
        .unwrap();
}

fn insert_registered_store(
    connection: &Connection,
    context: &RawRemoteContext,
    receipt_id: [u8; 16],
) {
    connection
        .execute(
            "INSERT INTO registered_stores VALUES (?1,?2,?3,1,?4,'active',?5,20,20,NULL)",
            params![
                context.store_id,
                [230_u8],
                context.store_location_sha256,
                context.config_sha256,
                receipt_id,
            ],
        )
        .unwrap();
}

fn insert_registered_account(
    connection: &Connection,
    context: &RawRemoteContext,
    receipt_id: [u8; 16],
) {
    connection
        .execute(
            "INSERT INTO registered_accounts VALUES (?1,?2,?3,1,?4,?5,'active',?6,NULL,20,20,NULL)",
            params![
                context.account_id,
                context.store_id,
                [231_u8; 32],
                context.credential_id,
                context.binding_sha256,
                receipt_id,
            ],
        )
        .unwrap();
}

fn insert_account_transition_and_cleanup(
    connection: &Connection,
    context: &RawRemoteContext,
    authorization: &RawAuthorization,
) {
    let transition_id = [151_u8; 16];
    assert!(
        connection
            .execute(
                "INSERT INTO account_transitions VALUES (
                 ?1,?2,?3,?4,'account_update',?5,?6,1,3,?7,'prepared',20,NULL,NULL,NULL)",
                params![
                    transition_id,
                    authorization.grant_id,
                    context.store_id,
                    context.account_id,
                    [152_u8; 32],
                    [153_u8; 32],
                    [154_u8; 32],
                ],
            )
            .is_err()
    );
    connection
        .execute(
            "INSERT INTO account_transitions VALUES (
         ?1,?2,?3,?4,'account_update',?5,?6,1,2,?7,'prepared',20,NULL,NULL,NULL)",
            params![
                transition_id,
                authorization.grant_id,
                context.store_id,
                context.account_id,
                [152_u8; 32],
                [153_u8; 32],
                [154_u8; 32],
            ],
        )
        .unwrap();
    assert!(connection.execute(
        "INSERT INTO credential_cleanup VALUES (?1,?2,'active_v2',?3,?4,'claimed',NULL,20,NULL)",
        params![[155_u8; 16], transition_id, [156_u8], [157_u8; 32]],
    ).is_err());
    connection.execute(
        "INSERT INTO credential_cleanup VALUES (?1,?2,'active_v2',?3,?4,'provisional',NULL,20,NULL)",
        params![[155_u8; 16], transition_id, [156_u8], [157_u8; 32]],
    ).unwrap();
}

fn insert_challenge_effect(connection: &Connection, value: &RawAuthorization) {
    connection
        .execute(
            "INSERT INTO challenge_effects VALUES (?1,0,?2,1)",
            params![value.challenge_id, value.effect_id],
        )
        .unwrap();
}

fn insert_remote_effect(
    connection: &Connection,
    context: &RawRemoteContext,
    value: &RawAuthorization,
) {
    connection
        .execute(
            "INSERT INTO remote_effects VALUES (
         ?1,?2,?3,?4,0,1,?5,?6,?7,1,?8,1,?9,?10,?11,?12,1,?13,?14,20)",
            params![
                value.effect_id,
                value.challenge_id,
                value.grant_id,
                value.operation_id,
                context.store_id,
                context.store_location_sha256,
                context.account_id,
                context.config_sha256,
                context.credential_id,
                value.manifest_sha256,
                context.binding_sha256,
                context.policy_sha256,
                value.bundle_sha256,
                value.owner_key_id,
            ],
        )
        .unwrap();
}

fn insert_remote_effect_cross_link(
    connection: &Connection,
    first: &RawAuthorization,
    second: &RawAuthorization,
) -> rusqlite::Result<usize> {
    let context = RawRemoteContext::new();
    connection.execute(
        "INSERT INTO remote_effects VALUES (
         ?1,?2,?3,?4,0,1,?5,?6,?7,1,?8,1,?9,?10,?11,?12,1,?13,?14,20)",
        params![
            first.effect_id,
            second.challenge_id,
            first.grant_id,
            first.operation_id,
            context.store_id,
            context.store_location_sha256,
            context.account_id,
            context.config_sha256,
            context.credential_id,
            first.manifest_sha256,
            context.binding_sha256,
            context.policy_sha256,
            first.bundle_sha256,
            first.owner_key_id,
        ],
    )
}

fn insert_effect_claim(
    connection: &Connection,
    context: &RawRemoteContext,
    value: &RawAuthorization,
) {
    connection
        .execute(
            "INSERT INTO effect_claims VALUES (
         ?1,?2,?3,?4,?5,?6,?7,1,?8,1,?9,?10,?11,?12,1,?13,?14,?15,?16,20,100)",
            params![
                value.claim_id,
                value.effect_id,
                value.grant_id,
                value.operation_id,
                context.store_id,
                context.store_location_sha256,
                context.account_id,
                context.config_sha256,
                context.credential_id,
                value.manifest_sha256,
                context.binding_sha256,
                context.policy_sha256,
                value.bundle_sha256,
                value.owner_key_id,
                [240_u8],
                [value.claim_id[0].wrapping_add(13); 32],
            ],
        )
        .unwrap();
}

fn insert_effect_claim_cross_link(
    connection: &Connection,
    context: &RawRemoteContext,
    first: &RawAuthorization,
    second: &RawAuthorization,
) -> rusqlite::Result<usize> {
    connection.execute(
        "INSERT INTO effect_claims VALUES (
         ?1,?2,?3,?4,?5,?6,?7,1,?8,1,?9,?10,?11,?12,1,?13,?14,?15,?16,20,100)",
        params![
            [170_u8; 16],
            first.effect_id,
            second.grant_id,
            second.operation_id,
            context.store_id,
            context.store_location_sha256,
            context.account_id,
            context.config_sha256,
            context.credential_id,
            second.manifest_sha256,
            context.binding_sha256,
            context.policy_sha256,
            second.bundle_sha256,
            second.owner_key_id,
            [171_u8],
            [172_u8; 32],
        ],
    )
}

fn insert_effect_invocation(connection: &Connection, value: &RawAuthorization) {
    connection
        .execute(
            "INSERT INTO effect_invocations VALUES (?1,?2,?3,?4,?5,?6,20)",
            params![
                value.invocation_id,
                value.effect_id,
                value.claim_id,
                [value.invocation_id[0].wrapping_add(14); 16],
                [250_u8],
                [value.invocation_id[0].wrapping_add(15); 32],
            ],
        )
        .unwrap();
}

fn insert_effect_observation(connection: &Connection, value: &RawAuthorization) {
    connection
        .execute(
            "INSERT INTO effect_observations VALUES (?1,?2,?3,?4,1,?5,?6,1,?7,20)",
            params![
                [value.effect_id[0].wrapping_add(16); 32],
                value.effect_id,
                value.claim_id,
                value.invocation_id,
                [251_u8],
                [value.effect_id[0].wrapping_add(17); 32],
                [252_u8],
            ],
        )
        .unwrap();
}

fn bootstrap_anchor_for_absent(loc: JournalLocationDigest) -> kirje_store::AnchorSnapshot {
    let realm = kirje_core::OwnerRealmId::from_bytes([1; 32]);
    let journal_id = "11111111-1111-4111-8111-111111111111".parse().unwrap();
    let owner = owner_key();
    let recovery = recovery_key();
    let owner_id = kirje_core::owner_key_id(kirje_core::OwnerKeyRole::Owner, owner.as_bytes());
    let recovery_id =
        kirje_core::owner_key_id(kirje_core::OwnerKeyRole::Recovery, recovery.as_bytes());
    kirje_store::AnchorSnapshot {
        version: AuthorityAnchorVersion::V1,
        realm_id: realm,
        journal_id,
        journal_location_sha256: loc,
        minimum_epoch: NonZeroU64::new(1).unwrap(),
        owner_key_id: owner_id,
        owner_public_key: owner,
        recovery_key_id: recovery_id,
        recovery_public_key: recovery,
        trust_bundle_sha256: Sha256Digest::from_bytes([2; 32]),
        state: AuthorityAnchorState::Normal,
    }
}

fn trust_bundle_digest(snapshot: &kirje_store::BootstrapSnapshot) -> Sha256Digest {
    let fields: [(&[u8], u16); 7] = [
        (snapshot.realm_id.as_bytes(), 1),
        (snapshot.journal_id.as_bytes(), 2),
        (&snapshot.minimum_epoch.get().to_be_bytes(), 3),
        (snapshot.owner_key_id.as_bytes(), 4),
        (snapshot.owner_public_key.as_bytes(), 5),
        (snapshot.recovery_key_id.as_bytes(), 6),
        (snapshot.recovery_public_key.as_bytes(), 7),
    ];
    let mut bytes = b"KIRJE-TRUST-BUNDLE-V1\0".to_vec();
    bytes.extend_from_slice(&u16::try_from(fields.len()).unwrap().to_be_bytes());
    for (value, tag) in fields {
        bytes.extend_from_slice(&tag.to_be_bytes());
        bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(value);
    }
    Sha256Digest::digest(&bytes)
}

fn complete_schema_connection() -> Connection {
    let connection = schema_connection();
    let root = insert_raw_authority_root(&connection);
    let context = RawRemoteContext::new();
    connection
        .execute(
            "INSERT INTO authority_meta VALUES
             (1,'pending_anchor',?1,?2,?3,1,?4,20,20,20,NULL)",
            params![[31_u8; 16], [32_u8; 32], [33_u8; 32], root.bundle_sha256],
        )
        .unwrap();
    let detail = [34_u8];
    let detail_sha256: [u8; 32] = Sha256::digest(detail).into();
    connection
        .execute(
            "INSERT INTO authority_events
             (entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256)
             VALUES (1,?1,1,2,20,?2,?3)",
            params![[32_u8; 32], detail, detail_sha256],
        )
        .unwrap();

    let store = RawAuthorization::store_enroll(20, &context, &root);
    insert_raw_challenge(&connection, &store);
    insert_raw_receipt(&connection, &store);
    insert_registered_store(&connection, &context, store.receipt_id);

    let account = RawAuthorization::account_create(40, &context, &root);
    insert_raw_challenge(&connection, &account);
    insert_raw_receipt(&connection, &account);
    insert_registered_account(&connection, &context, account.receipt_id);
    insert_grant_use(&connection, &account);
    insert_account_transition_and_cleanup(&connection, &context, &account);

    let remote = RawAuthorization::remote(60, &context, &root);
    insert_raw_challenge(&connection, &remote);
    insert_challenge_effect(&connection, &remote);
    insert_raw_receipt(&connection, &remote);
    insert_nonce_use(&connection, &remote);
    insert_grant_use(&connection, &remote);
    insert_remote_effect(&connection, &context, &remote);
    insert_effect_claim(&connection, &context, &remote);
    insert_effect_invocation(&connection, &remote);
    insert_effect_observation(&connection, &remote);
    connection
}

fn assert_sql_mutation_rejected(connection: &Connection, sql: &str) {
    connection
        .execute_batch("SAVEPOINT invariant_case")
        .unwrap();
    assert!(
        connection.execute(sql, []).is_err(),
        "DDL invariant accepted: {sql}"
    );
    connection
        .execute_batch("ROLLBACK TO invariant_case; RELEASE invariant_case")
        .unwrap();
}

fn schema_connection() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    configure(&connection);
    connection.execute_batch(SCHEMA).unwrap();
    connection
}

fn configure(connection: &Connection) {
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    connection.execute_batch(
        "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
    ).unwrap();
}

fn insert_key(
    connection: &Connection,
    key_id: &[u8; 32],
    role: &str,
    mask: i64,
    public_key: &[u8; 32],
    state: &str,
) {
    connection
        .execute(
            "INSERT INTO authority_keys VALUES (?1,?2,?3,?4,?5,1,NULL,0,NULL)",
            params![key_id, role, mask, public_key, state],
        )
        .unwrap();
}

fn objects(connection: &Connection, kind: &str) -> Vec<String> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema WHERE type=?1 AND name NOT LIKE 'sqlite_%' ORDER BY name",
    ).unwrap();
    statement
        .query_map([kind], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
    values.into_iter().map(str::to_owned).collect()
}

fn user_object_count(connection: &Connection) -> i64 {
    scalar_i64(
        connection,
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
    )
}

fn pragma_i64(connection: &Connection, name: &str) -> i64 {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .unwrap()
}

fn scalar_i64(connection: &Connection, sql: &str) -> i64 {
    connection.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn scalar_text(connection: &Connection, sql: &str) -> String {
    connection.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn scalar_blob(connection: &Connection, sql: &str) -> Vec<u8> {
    connection.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn create_database_parent(home: &IsolatedAuthorityHome) {
    std::fs::create_dir_all(home.database_path().parent().unwrap()).unwrap();
}

fn hex32(value: &str) -> [u8; 32] {
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").unwrap();
        output
    })
}

fn mail_error<T>(result: Result<T, kirje_core::MailError>) -> kirje_core::MailError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("operation unexpectedly succeeded"),
    }
}
