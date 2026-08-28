use std::{
    fs::{File, OpenOptions},
    num::NonZeroU64,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(feature = "test-support")]
use std::sync::{Arc, Barrier, Mutex};

use directories::ProjectDirs;
use kirje_core::{
    JournalId, MailError, MailErrorCode, OwnerKeyRole, OwnerPublicKey, OwnerRealmId, Sha256Digest,
    owner_key_id,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior, params,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const AUTHORITY_SCHEMA_V1: &str = include_str!("authority/schema_v1.sql");
const APPLICATION_ID: i64 = 1_263_096_394;
const SCHEMA_VERSION: i64 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const CLOCK_ROLLBACK_TOLERANCE_MS: i64 = 30_000;
const TRUST_BUNDLE_DOMAIN: &[u8] = b"KIRJE-TRUST-BUNDLE-V1\0";
const EVENT_DETAIL_DOMAIN: &[u8] = b"KIRJE-AUTHORITY-EVENT-DETAIL-V1\0";

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
const INDEXES: [&str; 14] = [
    "account_transitions_account_state",
    "account_transitions_store_state",
    "authority_events_entity_sequence",
    "authority_keys_one_active_role",
    "authority_keys_one_staged_role",
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct JournalLocationDigest(Sha256Digest);

impl JournalLocationDigest {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Sha256Digest::from_bytes(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    #[must_use]
    pub const fn as_digest(self) -> Sha256Digest {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityAnchorVersion {
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityAnchorState {
    Normal,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AnchorSnapshot {
    pub version: AuthorityAnchorVersion,
    pub realm_id: OwnerRealmId,
    pub journal_id: JournalId,
    pub journal_location_sha256: JournalLocationDigest,
    pub minimum_epoch: NonZeroU64,
    pub owner_key_id: Sha256Digest,
    pub owner_public_key: OwnerPublicKey,
    pub recovery_key_id: Sha256Digest,
    pub recovery_public_key: OwnerPublicKey,
    pub trust_bundle_sha256: Sha256Digest,
    pub state: AuthorityAnchorState,
}

#[derive(Clone, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum AnchorPresence {
    Missing,
    Present(AnchorSnapshot),
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorityOpenContext {
    pub anchor: AnchorPresence,
    pub journal_location_sha256: JournalLocationDigest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BootstrapInput {
    pub journal_location_sha256: JournalLocationDigest,
    pub owner_public_key: OwnerPublicKey,
    pub recovery_public_key: OwnerPublicKey,
    pub observed_at_unix_ms: i64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BootstrapSnapshot {
    pub realm_id: OwnerRealmId,
    pub journal_id: JournalId,
    pub minimum_epoch: NonZeroU64,
    pub owner_key_id: Sha256Digest,
    pub owner_public_key: OwnerPublicKey,
    pub recovery_key_id: Sha256Digest,
    pub recovery_public_key: OwnerPublicKey,
    pub trust_bundle_sha256: Sha256Digest,
    pub journal_location_sha256: JournalLocationDigest,
    pub anchor: AnchorSnapshot,
}

#[derive(Clone, Eq, PartialEq)]
pub enum AuthorityOpenState {
    Unconfigured,
    BootstrapPending(BootstrapSnapshot),
    ConfirmationRequired(BootstrapSnapshot),
    Ready(BootstrapSnapshot),
    RecoveryRequired,
}

#[derive(Clone)]
pub struct AuthorityHome {
    anchor: PathBuf,
    database: PathBuf,
    apply_lock: PathBuf,
}

impl AuthorityHome {
    /// Derive the one production authority namespace.
    ///
    /// # Errors
    ///
    /// Returns a stable unsupported error when the platform has no project directories.
    pub fn production() -> Result<Self, MailError> {
        let project = ProjectDirs::from("", "", "kirje").ok_or_else(|| {
            MailError::stable(
                MailErrorCode::SecureFileSemanticsUnsupported,
                "authority home is unavailable on this platform",
            )
        })?;
        Ok(Self {
            anchor: project.config_dir().join("owner-trust.toml"),
            database: project.data_local_dir().join("authority.sqlite3"),
            apply_lock: project.data_local_dir().join("authority.apply.lock"),
        })
    }

    #[must_use]
    pub fn anchor_path(&self) -> &Path {
        &self.anchor
    }

    #[must_use]
    pub fn database_path(&self) -> &Path {
        &self.database
    }

    #[must_use]
    pub fn apply_lock_path(&self) -> &Path {
        &self.apply_lock
    }
}

#[cfg(feature = "test-support")]
#[derive(Clone)]
pub struct IsolatedAuthorityHome {
    root: PathBuf,
    home: AuthorityHome,
    test_hooks: AuthorityTestHooks,
}

#[cfg(feature = "test-support")]
impl IsolatedAuthorityHome {
    /// Create one complete isolated authority home beneath an absolute test root.
    ///
    /// # Errors
    ///
    /// Returns invalid-input for a relative root.
    pub fn new(root: PathBuf) -> Result<Self, MailError> {
        if !root.is_absolute() {
            return Err(MailError::invalid_input(
                "isolated authority root must be absolute",
            ));
        }
        let home = AuthorityHome {
            anchor: root.join("owner-trust.toml"),
            database: root.join("authority.sqlite3"),
            apply_lock: root.join("authority.apply.lock"),
        };
        Ok(Self {
            root,
            home,
            test_hooks: AuthorityTestHooks::default(),
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn anchor_path(&self) -> &Path {
        self.home.anchor_path()
    }

    #[must_use]
    pub fn database_path(&self) -> &Path {
        self.home.database_path()
    }

    #[must_use]
    pub fn apply_lock_path(&self) -> &Path {
        self.home.apply_lock_path()
    }

    #[doc(hidden)]
    #[must_use]
    pub fn with_open_snapshot_pause(mut self, reached: Arc<Barrier>, resume: Arc<Barrier>) -> Self {
        self.test_hooks.open_snapshot = Some(TestPause { reached, resume });
        self
    }

    #[doc(hidden)]
    #[must_use]
    pub fn with_prepare_retry_pause(mut self, reached: Arc<Barrier>, resume: Arc<Barrier>) -> Self {
        self.test_hooks.prepare_retry = Some(TestPause { reached, resume });
        self
    }
}

#[derive(Clone, Default)]
struct AuthorityTestHooks {
    #[cfg(feature = "test-support")]
    open_snapshot: Option<TestPause>,
    #[cfg(feature = "test-support")]
    prepare_retry: Option<TestPause>,
}

#[cfg(feature = "test-support")]
#[derive(Clone)]
struct TestPause {
    reached: Arc<Barrier>,
    resume: Arc<Barrier>,
}

impl AuthorityTestHooks {
    fn after_open_snapshot(&self) {
        #[cfg(feature = "test-support")]
        if let Some(pause) = &self.open_snapshot {
            pause.reached.wait();
            pause.resume.wait();
        }
    }

    fn after_prepare_retry_inspection(&self) {
        #[cfg(feature = "test-support")]
        if let Some(pause) = &self.prepare_retry {
            pause.reached.wait();
            pause.resume.wait();
        }
    }
}

#[cfg(feature = "test-support")]
#[derive(Clone)]
pub struct DeterministicEntropy {
    state: Arc<Mutex<DeterministicEntropyState>>,
}

#[cfg(feature = "test-support")]
struct DeterministicEntropyState {
    bytes: Vec<u8>,
    offset: usize,
}

#[cfg(feature = "test-support")]
impl DeterministicEntropy {
    /// Create an exact deterministic byte stream for isolated tests.
    ///
    /// # Errors
    ///
    /// This constructor currently accepts every bounded in-memory stream.
    pub fn new(bytes: Vec<u8>) -> Result<Self, MailError> {
        Ok(Self {
            state: Arc::new(Mutex::new(DeterministicEntropyState { bytes, offset: 0 })),
        })
    }

    #[must_use]
    pub fn consumed_bytes(&self) -> usize {
        self.state.lock().map_or(0, |state| state.offset)
    }

    fn fill(&self, output: &mut [u8]) -> Result<(), MailError> {
        let mut state = self.state.lock().map_err(|_| entropy_error())?;
        let end = state
            .offset
            .checked_add(output.len())
            .ok_or_else(entropy_error)?;
        let source = state
            .bytes
            .get(state.offset..end)
            .ok_or_else(entropy_error)?;
        output.copy_from_slice(source);
        state.offset = end;
        Ok(())
    }
}

enum EntropySource {
    Os,
    #[cfg(feature = "test-support")]
    Deterministic(DeterministicEntropy),
}

impl EntropySource {
    fn fill(&self, output: &mut [u8]) -> Result<(), MailError> {
        match self {
            Self::Os => getrandom::fill(output).map_err(|_| entropy_error()),
            #[cfg(feature = "test-support")]
            Self::Deterministic(source) => source.fill(output),
        }
    }
}

pub struct AuthorityStore {
    home: AuthorityHome,
    context: AuthorityOpenContext,
    state: AuthorityOpenState,
    entropy: EntropySource,
    test_hooks: AuthorityTestHooks,
}

impl AuthorityStore {
    /// Open the fixed production authority home without permitting path injection.
    ///
    /// # Errors
    ///
    /// Returns a stable store or unsupported-schema error.
    pub fn open_production(context: AuthorityOpenContext) -> Result<Self, MailError> {
        Self::open(
            context,
            AuthorityHome::production()?,
            EntropySource::Os,
            AuthorityTestHooks::default(),
        )
    }

    #[cfg(feature = "test-support")]
    /// Open a complete isolated authority home with deterministic test entropy.
    ///
    /// # Errors
    ///
    /// Returns a stable store or unsupported-schema error.
    pub fn open_isolated(
        context: AuthorityOpenContext,
        home: IsolatedAuthorityHome,
        entropy: DeterministicEntropy,
    ) -> Result<Self, MailError> {
        Self::open(
            context,
            home.home,
            EntropySource::Deterministic(entropy),
            home.test_hooks,
        )
    }

    fn open(
        context: AuthorityOpenContext,
        home: AuthorityHome,
        entropy: EntropySource,
        test_hooks: AuthorityTestHooks,
    ) -> Result<Self, MailError> {
        validate_open_context(&context)?;
        let state = inspect_home(&home, &context, &test_hooks)?;
        Ok(Self {
            home,
            context,
            state,
            entropy,
            test_hooks,
        })
    }

    #[must_use]
    pub const fn state(&self) -> &AuthorityOpenState {
        &self.state
    }

    /// Create or exactly recover the database-first bootstrap snapshot.
    ///
    /// # Errors
    ///
    /// Returns stable malformed, recovery, clock, store, or schema errors.
    #[allow(clippy::needless_pass_by_value)]
    pub fn prepare_bootstrap(&self, input: BootstrapInput) -> Result<BootstrapSnapshot, MailError> {
        validate_bootstrap_input(&input)?;
        if matches!(self.state, AuthorityOpenState::RecoveryRequired) {
            return Err(recovery_error());
        }
        if input.journal_location_sha256 != self.context.journal_location_sha256 {
            return Err(recovery_error());
        }

        let _apply_lock = acquire_apply_lock(&self.home)?;
        let database_exists = authority_database_exists(&self.home.database)?;
        let opened_unconfigured = matches!(self.state, AuthorityOpenState::Unconfigured);
        if !database_exists && !opened_unconfigured {
            return Err(recovery_error());
        }
        if database_exists {
            self.test_hooks.after_prepare_retry_inspection();
        } else {
            ensure_private_parent(&self.home.database)?;
        }
        let mut connection = if database_exists {
            existing_authority_read_connection(&self.home.database)?
        } else {
            authority_connection(&self.home.database)?
        };
        if !database_exists {
            secure_private_file(&self.home.database)?;
        }
        if database_exists {
            match classify_database(&connection)? {
                DatabaseClass::AuthorityV1 => configure_authority_pragmas(&connection)?,
                DatabaseClass::Pristine if opened_unconfigured => {
                    configure_authority_pragmas(&connection)?;
                }
                DatabaseClass::Pristine | DatabaseClass::RecoveryRequired => {
                    return Err(recovery_error());
                }
            }
        }
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| store_write_error())?;
        match classify_database(&transaction)? {
            DatabaseClass::AuthorityV1 => {
                let snapshot =
                    retry_existing_bootstrap(&transaction, &self.context, &self.state, &input)?;
                transaction.commit().map_err(|_| store_write_error())?;
                secure_authority_files(&self.home.database)?;
                return Ok(snapshot);
            }
            DatabaseClass::Pristine if opened_unconfigured => {}
            DatabaseClass::Pristine | DatabaseClass::RecoveryRequired => {
                return Err(recovery_error());
            }
        }
        transaction
            .execute_batch(AUTHORITY_SCHEMA_V1)
            .map_err(|_| store_write_error())?;

        let snapshot = self.bootstrap_snapshot(&input)?;
        insert_bootstrap_rows(&transaction, &snapshot, input.observed_at_unix_ms)?;
        transaction
            .pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(|_| store_write_error())?;
        transaction
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|_| store_write_error())?;
        transaction.commit().map_err(|_| store_write_error())?;
        secure_authority_files(&self.home.database)?;
        Ok(snapshot)
    }

    /// Confirm an exact committed pending anchor.
    ///
    /// # Errors
    ///
    /// Returns stable mismatch, rollback-clock, store, or schema errors.
    pub fn confirm_anchor(
        &self,
        anchor: &AnchorSnapshot,
        observed_at_unix_ms: i64,
    ) -> Result<BootstrapSnapshot, MailError> {
        if observed_at_unix_ms < 0 {
            return Err(MailError::invalid_input(
                "authority observation time must be nonnegative",
            ));
        }
        let opened_snapshot = match (&self.state, &self.context.anchor) {
            (
                AuthorityOpenState::ConfirmationRequired(snapshot),
                AnchorPresence::Present(opened_anchor),
            ) if anchor == opened_anchor && opened_anchor == &snapshot.anchor => snapshot,
            _ => return Err(recovery_error()),
        };
        let _apply_lock = acquire_apply_lock(&self.home)?;
        if !authority_database_exists(&self.home.database)? {
            return Err(recovery_error());
        }
        let mut connection = existing_authority_read_connection(&self.home.database)?;
        if classify_database(&connection)? != DatabaseClass::AuthorityV1 {
            return Err(recovery_error());
        }
        configure_authority_pragmas(&connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| store_write_error())?;
        if classify_database(&transaction)? != DatabaseClass::AuthorityV1 {
            return Err(recovery_error());
        }
        ensure_usable_schema(&transaction)?;
        if staged_count(&transaction)? != 0 {
            return Err(recovery_error());
        }
        let loaded = load_snapshot(&transaction, &AuthorityTestHooks::default())?;
        if loaded.bootstrap_state != "pending_anchor"
            || &loaded.snapshot != opened_snapshot
            || anchor != &loaded.snapshot.anchor
            || anchor.journal_location_sha256 != self.context.journal_location_sha256
        {
            return Err(recovery_error());
        }
        let effective_time = checked_clock(loaded.last_observed_at, observed_at_unix_ms)?;
        let changed = transaction
            .execute(
                "UPDATE authority_meta SET bootstrap_state='ready',
                 last_observed_at=?1, updated_at=?1, anchor_confirmed_at=?1
                 WHERE singleton=1 AND bootstrap_state='pending_anchor'",
                [effective_time],
            )
            .map_err(|_| store_write_error())?;
        if changed != 1 {
            return Err(recovery_error());
        }
        insert_event(
            &transaction,
            loaded.snapshot.realm_id.as_bytes(),
            2,
            0x0101,
            0x0102,
            loaded.snapshot.trust_bundle_sha256,
            effective_time,
        )?;
        transaction.commit().map_err(|_| store_write_error())?;
        secure_authority_files(&self.home.database)?;
        Ok(loaded.snapshot)
    }

    fn bootstrap_snapshot(&self, input: &BootstrapInput) -> Result<BootstrapSnapshot, MailError> {
        let mut realm = [0_u8; 32];
        let mut journal = [0_u8; 16];
        self.entropy.fill(&mut realm)?;
        self.entropy.fill(&mut journal)?;
        journal[6] = (journal[6] & 0x0f) | 0x40;
        journal[8] = (journal[8] & 0x3f) | 0x80;

        let realm_id = OwnerRealmId::from_bytes(realm);
        let journal_id = JournalId::try_from(Uuid::from_bytes(journal))?;
        let minimum_epoch = NonZeroU64::new(1).expect("one is nonzero");
        let owner_id = owner_key_id(OwnerKeyRole::Owner, input.owner_public_key.as_bytes());
        let recovery_id =
            owner_key_id(OwnerKeyRole::Recovery, input.recovery_public_key.as_bytes());
        let trust_bundle_sha256 = trust_bundle_digest(
            realm_id,
            journal_id,
            minimum_epoch,
            owner_id,
            &input.owner_public_key,
            recovery_id,
            &input.recovery_public_key,
        );
        let anchor = AnchorSnapshot {
            version: AuthorityAnchorVersion::V1,
            realm_id,
            journal_id,
            journal_location_sha256: input.journal_location_sha256,
            minimum_epoch,
            owner_key_id: owner_id,
            owner_public_key: input.owner_public_key.clone(),
            recovery_key_id: recovery_id,
            recovery_public_key: input.recovery_public_key.clone(),
            trust_bundle_sha256,
            state: AuthorityAnchorState::Normal,
        };
        Ok(BootstrapSnapshot {
            realm_id,
            journal_id,
            minimum_epoch,
            owner_key_id: owner_id,
            owner_public_key: input.owner_public_key.clone(),
            recovery_key_id: recovery_id,
            recovery_public_key: input.recovery_public_key.clone(),
            trust_bundle_sha256,
            journal_location_sha256: input.journal_location_sha256,
            anchor,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DatabaseClass {
    Pristine,
    AuthorityV1,
    RecoveryRequired,
}

struct LoadedSnapshot {
    snapshot: BootstrapSnapshot,
    bootstrap_state: String,
    last_observed_at: i64,
}

fn inspect_home(
    home: &AuthorityHome,
    context: &AuthorityOpenContext,
    test_hooks: &AuthorityTestHooks,
) -> Result<AuthorityOpenState, MailError> {
    match std::fs::symlink_metadata(&home.database) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Ok(AuthorityOpenState::RecoveryRequired);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(if matches!(context.anchor, AnchorPresence::Missing) {
                AuthorityOpenState::Unconfigured
            } else {
                AuthorityOpenState::RecoveryRequired
            });
        }
        Err(_) => return Err(store_read_error()),
    }
    let mut connection = existing_authority_read_connection(&home.database)?;
    match classify_database(&connection)? {
        DatabaseClass::Pristine => {
            return Ok(if matches!(context.anchor, AnchorPresence::Missing) {
                AuthorityOpenState::Unconfigured
            } else {
                AuthorityOpenState::RecoveryRequired
            });
        }
        DatabaseClass::RecoveryRequired => return Ok(AuthorityOpenState::RecoveryRequired),
        DatabaseClass::AuthorityV1 => configure_authority_pragmas(&connection)?,
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| store_read_error())?;
    let state = inspect_connection(&transaction, context, test_hooks)?;
    transaction.commit().map_err(|_| store_read_error())?;
    Ok(state)
}

fn inspect_connection(
    connection: &Connection,
    context: &AuthorityOpenContext,
    test_hooks: &AuthorityTestHooks,
) -> Result<AuthorityOpenState, MailError> {
    match classify_database(connection)? {
        DatabaseClass::Pristine => Ok(if matches!(context.anchor, AnchorPresence::Missing) {
            AuthorityOpenState::Unconfigured
        } else {
            AuthorityOpenState::RecoveryRequired
        }),
        DatabaseClass::RecoveryRequired => Ok(AuthorityOpenState::RecoveryRequired),
        DatabaseClass::AuthorityV1 => {
            if ensure_usable_schema(connection).is_err() {
                return Ok(AuthorityOpenState::RecoveryRequired);
            }
            if staged_count(connection)? != 0 {
                return Ok(AuthorityOpenState::RecoveryRequired);
            }
            let Ok(loaded) = load_snapshot(connection, test_hooks) else {
                return Ok(AuthorityOpenState::RecoveryRequired);
            };
            if loaded.snapshot.journal_location_sha256 != context.journal_location_sha256 {
                return Ok(AuthorityOpenState::RecoveryRequired);
            }
            match (loaded.bootstrap_state.as_str(), &context.anchor) {
                ("pending_anchor", AnchorPresence::Missing) => {
                    Ok(AuthorityOpenState::BootstrapPending(loaded.snapshot))
                }
                ("pending_anchor", AnchorPresence::Present(anchor))
                    if anchor == &loaded.snapshot.anchor =>
                {
                    Ok(AuthorityOpenState::ConfirmationRequired(loaded.snapshot))
                }
                ("ready", AnchorPresence::Present(anchor)) if anchor == &loaded.snapshot.anchor => {
                    Ok(AuthorityOpenState::Ready(loaded.snapshot))
                }
                _ => Ok(AuthorityOpenState::RecoveryRequired),
            }
        }
    }
}

fn classify_database(connection: &Connection) -> Result<DatabaseClass, MailError> {
    let application_id = pragma_i64(connection, "application_id")?;
    let user_version = pragma_i64(connection, "user_version")?;
    if application_id == 0 {
        return Ok(
            if user_object_count(connection)? == 0 && user_version == 0 {
                DatabaseClass::Pristine
            } else {
                DatabaseClass::RecoveryRequired
            },
        );
    }
    if application_id != APPLICATION_ID {
        return Ok(DatabaseClass::RecoveryRequired);
    }
    if user_version > SCHEMA_VERSION {
        return Err(MailError::stable(
            MailErrorCode::UnsupportedCapability,
            "authority schema version is newer than this binary",
        ));
    }
    if user_version != SCHEMA_VERSION {
        return Ok(DatabaseClass::RecoveryRequired);
    }
    Ok(DatabaseClass::AuthorityV1)
}

fn ensure_usable_schema(connection: &Connection) -> Result<(), MailError> {
    if !schema_inventory_matches(connection)? {
        return Err(recovery_error());
    }
    let foreign_failures: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|_| store_read_error())?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| store_read_error())?;
    if foreign_failures != 0 || integrity != "ok" {
        return Err(recovery_error());
    }
    Ok(())
}

fn schema_inventory_matches(connection: &Connection) -> Result<bool, MailError> {
    if object_names(connection, "table")? != TABLES
        || object_names(connection, "index")? != INDEXES
        || object_names(connection, "trigger")? != TRIGGERS
    {
        return Ok(false);
    }
    let expected = Connection::open_in_memory().map_err(|_| store_read_error())?;
    expected
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")
        .map_err(|_| store_read_error())?;
    expected
        .execute_batch(AUTHORITY_SCHEMA_V1)
        .map_err(|_| store_read_error())?;
    Ok(schema_objects(connection)? == schema_objects(&expected)?)
}

fn object_names(connection: &Connection, kind: &str) -> Result<Vec<String>, MailError> {
    let mut statement = connection
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE type=?1 AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(|_| store_read_error())?;
    statement
        .query_map([kind], |row| row.get(0))
        .map_err(|_| store_read_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| store_read_error())
}

fn schema_objects(connection: &Connection) -> Result<Vec<(String, String, String)>, MailError> {
    let mut statement = connection
        .prepare(
            "SELECT type,name,sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
        )
        .map_err(|_| store_read_error())?;
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|_| store_read_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| store_read_error())
}

#[allow(clippy::too_many_lines)]
fn load_snapshot(
    connection: &Connection,
    test_hooks: &AuthorityTestHooks,
) -> Result<LoadedSnapshot, MailError> {
    let row = connection
        .query_row(
            "SELECT m.bootstrap_state,m.journal_id,m.realm_id,m.journal_location_sha256,
                    m.active_epoch,m.trust_bundle_sha256,m.last_observed_at,
                    m.created_at,m.updated_at,m.anchor_confirmed_at,
                    e.state,e.predecessor_epoch,e.rotation_kind,e.transition_receipt_id,
                    e.new_owner_key_proof,e.new_recovery_key_proof,e.staged_at,
                    e.activated_at,e.retired_at,
                    ok.key_id,ok.role,ok.permission_mask,ok.public_key,ok.state,
                    ok.valid_from_epoch,ok.valid_to_epoch,ok.installed_at,ok.retired_at,
                    rk.key_id,rk.role,rk.permission_mask,rk.public_key,rk.state,
                    rk.valid_from_epoch,rk.valid_to_epoch,rk.installed_at,rk.retired_at
             FROM authority_meta m
             JOIN trust_epochs e ON e.epoch=m.active_epoch
             JOIN authority_keys ok ON ok.key_id=e.owner_key_id
             JOIN authority_keys rk ON rk.key_id=e.recovery_key_id
             WHERE m.singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<Vec<u8>>>(13)?,
                    row.get::<_, Option<Vec<u8>>>(14)?,
                    row.get::<_, Option<Vec<u8>>>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, Option<i64>>(17)?,
                    row.get::<_, Option<i64>>(18)?,
                    row.get::<_, Vec<u8>>(19)?,
                    row.get::<_, String>(20)?,
                    row.get::<_, i64>(21)?,
                    row.get::<_, Vec<u8>>(22)?,
                    row.get::<_, String>(23)?,
                    row.get::<_, i64>(24)?,
                    row.get::<_, Option<i64>>(25)?,
                    row.get::<_, i64>(26)?,
                    row.get::<_, Option<i64>>(27)?,
                    row.get::<_, Vec<u8>>(28)?,
                    row.get::<_, String>(29)?,
                    row.get::<_, i64>(30)?,
                    row.get::<_, Vec<u8>>(31)?,
                    row.get::<_, String>(32)?,
                    row.get::<_, i64>(33)?,
                    row.get::<_, Option<i64>>(34)?,
                    row.get::<_, i64>(35)?,
                    row.get::<_, Option<i64>>(36)?,
                ))
            },
        )
        .optional()
        .map_err(|_| store_read_error())?
        .ok_or_else(recovery_error)?;
    test_hooks.after_open_snapshot();

    let meta_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM authority_meta", [], |value| {
            value.get(0)
        })
        .map_err(|_| store_read_error())?;
    validate_t202a_initial_row_counts(connection)?;
    if meta_count != 1
        || !matches!(row.0.as_str(), "pending_anchor" | "ready")
        || row.4 != 1
        || row.10 != "active"
        || row.11.is_some()
        || row.12.is_some()
        || row.13.is_some()
        || row.14.is_some()
        || row.15.is_some()
        || row.17.is_none()
        || row.18.is_some()
        || row.20 != "owner"
        || row.21 != 7
        || row.23 != "active"
        || row.24 != 1
        || row.25.is_some()
        || row.27.is_some()
        || row.29 != "recovery"
        || row.30 != 8
        || row.32 != "active"
        || row.33 != 1
        || row.34.is_some()
        || row.36.is_some()
        || row.6 < row.7
        || row.7 < 0
        || row.8 != row.6
        || row.16 != row.7
        || row.17 != Some(row.7)
        || row.26 != row.7
        || row.35 != row.7
        || row
            .9
            .is_some_and(|confirmed| confirmed < row.7 || confirmed > row.6)
        || (row.0 == "pending_anchor" && row.9.is_some())
        || (row.0 == "ready" && row.9.is_none())
    {
        return Err(recovery_error());
    }

    let journal_id = JournalId::try_from(Uuid::from_bytes(exact::<16>(&row.1)?))
        .map_err(|_| recovery_error())?;
    let realm_id = OwnerRealmId::from_bytes(exact::<32>(&row.2)?);
    let location = JournalLocationDigest::from_bytes(exact::<32>(&row.3)?);
    let bundle = Sha256Digest::from_bytes(exact::<32>(&row.5)?);
    let epoch_bundle = Sha256Digest::from_bytes(exact::<32>(
        &connection
            .query_row(
                "SELECT bundle_sha256 FROM trust_epochs WHERE epoch=?1",
                [row.4],
                |value| value.get::<_, Vec<u8>>(0),
            )
            .map_err(|_| store_read_error())?,
    )?);
    let owner_id = Sha256Digest::from_bytes(exact::<32>(&row.19)?);
    let owner_public =
        OwnerPublicKey::try_from(exact::<32>(&row.22)?).map_err(|_| recovery_error())?;
    let recovery_id = Sha256Digest::from_bytes(exact::<32>(&row.28)?);
    let recovery_public =
        OwnerPublicKey::try_from(exact::<32>(&row.31)?).map_err(|_| recovery_error())?;
    if owner_public == recovery_public
        || owner_id != owner_key_id(OwnerKeyRole::Owner, owner_public.as_bytes())
        || recovery_id != owner_key_id(OwnerKeyRole::Recovery, recovery_public.as_bytes())
    {
        return Err(recovery_error());
    }
    let epoch = NonZeroU64::new(u64::try_from(row.4).map_err(|_| recovery_error())?)
        .ok_or_else(recovery_error)?;
    let expected_bundle = trust_bundle_digest(
        realm_id,
        journal_id,
        epoch,
        owner_id,
        &owner_public,
        recovery_id,
        &recovery_public,
    );
    if bundle != epoch_bundle || bundle != expected_bundle {
        return Err(recovery_error());
    }
    validate_events(
        connection,
        &row.0,
        realm_id.as_bytes(),
        bundle,
        row.7,
        row.9,
    )?;

    let anchor = AnchorSnapshot {
        version: AuthorityAnchorVersion::V1,
        realm_id,
        journal_id,
        journal_location_sha256: location,
        minimum_epoch: epoch,
        owner_key_id: owner_id,
        owner_public_key: owner_public.clone(),
        recovery_key_id: recovery_id,
        recovery_public_key: recovery_public.clone(),
        trust_bundle_sha256: bundle,
        state: AuthorityAnchorState::Normal,
    };
    Ok(LoadedSnapshot {
        snapshot: BootstrapSnapshot {
            realm_id,
            journal_id,
            minimum_epoch: epoch,
            owner_key_id: owner_id,
            owner_public_key: owner_public,
            recovery_key_id: recovery_id,
            recovery_public_key: recovery_public,
            trust_bundle_sha256: bundle,
            journal_location_sha256: location,
            anchor,
        },
        bootstrap_state: row.0,
        last_observed_at: row.6,
    })
}

fn validate_t202a_initial_row_counts(connection: &Connection) -> Result<(), MailError> {
    let authority_keys: i64 = connection
        .query_row("SELECT COUNT(*) FROM authority_keys", [], |row| row.get(0))
        .map_err(|_| store_read_error())?;
    let trust_epochs: i64 = connection
        .query_row("SELECT COUNT(*) FROM trust_epochs", [], |row| row.get(0))
        .map_err(|_| store_read_error())?;
    let later_rows: i64 = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM registered_stores) +
                (SELECT COUNT(*) FROM registered_accounts) +
                (SELECT COUNT(*) FROM authorization_challenges) +
                (SELECT COUNT(*) FROM challenge_effects) +
                (SELECT COUNT(*) FROM authorization_receipts) +
                (SELECT COUNT(*) FROM nonce_uses) +
                (SELECT COUNT(*) FROM grant_uses) +
                (SELECT COUNT(*) FROM account_transitions) +
                (SELECT COUNT(*) FROM credential_cleanup) +
                (SELECT COUNT(*) FROM remote_effects) +
                (SELECT COUNT(*) FROM effect_claims) +
                (SELECT COUNT(*) FROM effect_invocations) +
                (SELECT COUNT(*) FROM effect_observations)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if authority_keys != 2 || trust_epochs != 1 || later_rows != 0 {
        return Err(recovery_error());
    }
    Ok(())
}

struct StoredAuthorityEvent {
    sequence: i64,
    entity_kind: i64,
    entity_id: Vec<u8>,
    event_code: i64,
    source: i64,
    occurred_at: i64,
    detail: Vec<u8>,
    detail_sha256: Vec<u8>,
}

fn validate_events(
    connection: &Connection,
    bootstrap_state: &str,
    realm_id: &[u8; 32],
    bundle: Sha256Digest,
    created_at: i64,
    anchor_confirmed_at: Option<i64>,
) -> Result<(), MailError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence,entity_kind,entity_id,event_code,source,occurred_at,
                    detail,detail_sha256
             FROM authority_events ORDER BY sequence LIMIT 3",
        )
        .map_err(|_| store_read_error())?;
    let rows = statement
        .query_map([], |row| {
            Ok(StoredAuthorityEvent {
                sequence: row.get(0)?,
                entity_kind: row.get(1)?,
                entity_id: row.get(2)?,
                event_code: row.get(3)?,
                source: row.get(4)?,
                occurred_at: row.get(5)?,
                detail: row.get(6)?,
                detail_sha256: row.get(7)?,
            })
        })
        .map_err(|_| store_read_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| store_read_error())?;
    let expected_count = match bootstrap_state {
        "pending_anchor" => 1,
        "ready" => 2,
        _ => return Err(recovery_error()),
    };
    let sequence_high_water: Option<i64> = connection
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name='authority_events'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| store_read_error())?;
    if rows.len() != expected_count
        || sequence_high_water != Some(i64::try_from(expected_count).map_err(|_| recovery_error())?)
    {
        return Err(recovery_error());
    }
    validate_event_row(&rows[0], 1, realm_id, 1, 0, 0x0101, bundle, created_at)?;
    if expected_count == 2 {
        validate_event_row(
            &rows[1],
            2,
            realm_id,
            2,
            0x0101,
            0x0102,
            bundle,
            anchor_confirmed_at.ok_or_else(recovery_error)?,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_event_row(
    row: &StoredAuthorityEvent,
    sequence: i64,
    realm_id: &[u8; 32],
    event_code: u16,
    prior_state: u16,
    next_state: u16,
    bundle: Sha256Digest,
    occurred_at: i64,
) -> Result<(), MailError> {
    let expected_detail = event_detail(
        realm_id,
        event_code,
        prior_state,
        next_state,
        bundle,
        occurred_at,
    );
    let expected_digest = Sha256::digest(&expected_detail);
    if row.sequence != sequence
        || row.entity_kind != 1
        || row.entity_id.as_slice() != realm_id
        || row.event_code != i64::from(event_code)
        || row.source != 2
        || row.occurred_at != occurred_at
        || row.detail != expected_detail
        || row.detail_sha256.as_slice() != expected_digest.as_slice()
    {
        return Err(recovery_error());
    }
    Ok(())
}

fn insert_bootstrap_rows(
    transaction: &Transaction<'_>,
    snapshot: &BootstrapSnapshot,
    observed_at: i64,
) -> Result<(), MailError> {
    transaction
        .execute(
            "INSERT INTO authority_keys
             (key_id,role,permission_mask,public_key,state,valid_from_epoch,
              valid_to_epoch,installed_at,retired_at)
             VALUES (?1,'owner',7,?2,'active',1,NULL,?3,NULL)",
            params![
                snapshot.owner_key_id.as_bytes(),
                snapshot.owner_public_key.as_bytes(),
                observed_at
            ],
        )
        .map_err(|_| store_write_error())?;
    transaction
        .execute(
            "INSERT INTO authority_keys
             (key_id,role,permission_mask,public_key,state,valid_from_epoch,
              valid_to_epoch,installed_at,retired_at)
             VALUES (?1,'recovery',8,?2,'active',1,NULL,?3,NULL)",
            params![
                snapshot.recovery_key_id.as_bytes(),
                snapshot.recovery_public_key.as_bytes(),
                observed_at
            ],
        )
        .map_err(|_| store_write_error())?;
    transaction
        .execute(
            "INSERT INTO trust_epochs
             (epoch,owner_key_id,recovery_key_id,bundle_sha256,state,predecessor_epoch,
              rotation_kind,transition_receipt_id,new_owner_key_proof,
              new_recovery_key_proof,staged_at,activated_at,retired_at)
             VALUES (1,?1,?2,?3,'active',NULL,NULL,NULL,NULL,NULL,?4,?4,NULL)",
            params![
                snapshot.owner_key_id.as_bytes(),
                snapshot.recovery_key_id.as_bytes(),
                snapshot.trust_bundle_sha256.as_bytes(),
                observed_at
            ],
        )
        .map_err(|_| store_write_error())?;
    transaction
        .execute(
            "INSERT INTO authority_meta
             (singleton,bootstrap_state,journal_id,realm_id,journal_location_sha256,
              active_epoch,trust_bundle_sha256,last_observed_at,created_at,updated_at,
              anchor_confirmed_at)
             VALUES (1,'pending_anchor',?1,?2,?3,1,?4,?5,?5,?5,NULL)",
            params![
                snapshot.journal_id.as_bytes(),
                snapshot.realm_id.as_bytes(),
                snapshot.journal_location_sha256.as_bytes(),
                snapshot.trust_bundle_sha256.as_bytes(),
                observed_at
            ],
        )
        .map_err(|_| store_write_error())?;
    insert_event(
        transaction,
        snapshot.realm_id.as_bytes(),
        1,
        0,
        0x0101,
        snapshot.trust_bundle_sha256,
        observed_at,
    )
}

fn insert_event(
    transaction: &Transaction<'_>,
    realm_id: &[u8; 32],
    event_code: u16,
    prior_state: u16,
    next_state: u16,
    context_digest: Sha256Digest,
    occurred_at: i64,
) -> Result<(), MailError> {
    let detail = event_detail(
        realm_id,
        event_code,
        prior_state,
        next_state,
        context_digest,
        occurred_at,
    );
    let detail_sha256 = Sha256::digest(&detail);
    transaction
        .execute(
            "INSERT INTO authority_events
             (entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256)
             VALUES (1,?1,?2,2,?3,?4,?5)",
            params![
                realm_id,
                i64::from(event_code),
                occurred_at,
                detail,
                detail_sha256.as_slice()
            ],
        )
        .map_err(|_| store_write_error())?;
    Ok(())
}

fn event_detail(
    realm_id: &[u8; 32],
    event_code: u16,
    prior_state: u16,
    next_state: u16,
    context_digest: Sha256Digest,
    occurred_at: i64,
) -> Vec<u8> {
    let event_code_bytes = event_code.to_be_bytes();
    let entity_kind = 1_u16.to_be_bytes();
    let source = [2_u8];
    let no_related_kind = 0_u16.to_be_bytes();
    let prior_state = prior_state.to_be_bytes();
    let next_state = next_state.to_be_bytes();
    let occurred_at_bytes = occurred_at.to_be_bytes();
    let fields: [&[u8]; 11] = [
        &event_code_bytes,
        &entity_kind,
        realm_id,
        &source,
        &no_related_kind,
        &[],
        &prior_state,
        &next_state,
        context_digest.as_bytes(),
        &[],
        &occurred_at_bytes,
    ];
    encode_transcript(EVENT_DETAIL_DOMAIN, &fields)
}

fn trust_bundle_digest(
    realm: OwnerRealmId,
    journal: JournalId,
    epoch: NonZeroU64,
    owner_id: Sha256Digest,
    owner_key: &OwnerPublicKey,
    recovery_id: Sha256Digest,
    recovery_key: &OwnerPublicKey,
) -> Sha256Digest {
    let epoch_bytes = epoch.get().to_be_bytes();
    let fields: [&[u8]; 7] = [
        realm.as_bytes(),
        journal.as_bytes(),
        &epoch_bytes,
        owner_id.as_bytes(),
        owner_key.as_bytes(),
        recovery_id.as_bytes(),
        recovery_key.as_bytes(),
    ];
    Sha256Digest::digest(&encode_transcript(TRUST_BUNDLE_DOMAIN, &fields))
}

fn encode_transcript(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        domain.len() + 2 + fields.iter().map(|field| 6 + field.len()).sum::<usize>(),
    );
    output.extend_from_slice(domain);
    output.extend_from_slice(
        &u16::try_from(fields.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    for (index, field) in fields.iter().enumerate() {
        let tag = u16::try_from(index + 1).unwrap_or(u16::MAX);
        let length = u32::try_from(field.len()).unwrap_or(u32::MAX);
        output.extend_from_slice(&tag.to_be_bytes());
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(field);
    }
    output
}

fn validate_bootstrap_input(input: &BootstrapInput) -> Result<(), MailError> {
    if input.owner_public_key == input.recovery_public_key {
        return Err(MailError::stable(
            MailErrorCode::AuthorizationMalformed,
            "owner and recovery public keys must be distinct",
        ));
    }
    if input.observed_at_unix_ms < 0 {
        return Err(MailError::invalid_input(
            "authority observation time must be nonnegative",
        ));
    }
    Ok(())
}

fn validate_open_context(context: &AuthorityOpenContext) -> Result<(), MailError> {
    if let AnchorPresence::Present(anchor) = &context.anchor
        && anchor.owner_public_key == anchor.recovery_public_key
    {
        return Err(MailError::stable(
            MailErrorCode::AuthorizationMalformed,
            "owner and recovery public keys must be distinct",
        ));
    }
    Ok(())
}

fn retry_existing_bootstrap(
    transaction: &Transaction<'_>,
    context: &AuthorityOpenContext,
    opened_state: &AuthorityOpenState,
    input: &BootstrapInput,
) -> Result<BootstrapSnapshot, MailError> {
    ensure_usable_schema(transaction)?;
    if staged_count(transaction)? != 0 {
        return Err(recovery_error());
    }
    let loaded = load_snapshot(transaction, &AuthorityTestHooks::default())?;
    let context_matches = match (loaded.bootstrap_state.as_str(), &context.anchor) {
        ("pending_anchor", AnchorPresence::Missing) => true,
        ("pending_anchor" | "ready", AnchorPresence::Present(anchor)) => {
            anchor == &loaded.snapshot.anchor
        }
        _ => false,
    };
    let opened_state_matches = match opened_state {
        AuthorityOpenState::Unconfigured => true,
        AuthorityOpenState::BootstrapPending(snapshot) => {
            loaded.bootstrap_state == "pending_anchor" && snapshot == &loaded.snapshot
        }
        AuthorityOpenState::ConfirmationRequired(snapshot) => {
            matches!(loaded.bootstrap_state.as_str(), "pending_anchor" | "ready")
                && snapshot == &loaded.snapshot
        }
        AuthorityOpenState::Ready(snapshot) => {
            loaded.bootstrap_state == "ready" && snapshot == &loaded.snapshot
        }
        AuthorityOpenState::RecoveryRequired => false,
    };
    if !context_matches
        || !opened_state_matches
        || loaded.snapshot.journal_location_sha256 != context.journal_location_sha256
        || loaded.snapshot.owner_public_key != input.owner_public_key
        || loaded.snapshot.recovery_public_key != input.recovery_public_key
        || loaded.snapshot.journal_location_sha256 != input.journal_location_sha256
    {
        return Err(recovery_error());
    }
    observe_existing_bootstrap(
        transaction,
        loaded.last_observed_at,
        input.observed_at_unix_ms,
    )?;
    Ok(loaded.snapshot)
}

fn checked_clock(last: i64, observed: i64) -> Result<i64, MailError> {
    let floor = last.checked_sub(CLOCK_ROLLBACK_TOLERANCE_MS).unwrap_or(0);
    if observed < floor {
        return Err(MailError::stable(
            MailErrorCode::ClockRollbackDetected,
            "authority clock moved beyond the accepted tolerance",
        ));
    }
    Ok(last.max(observed))
}

fn observe_existing_bootstrap(
    transaction: &Transaction<'_>,
    last_observed_at: i64,
    observed_at: i64,
) -> Result<(), MailError> {
    let effective = checked_clock(last_observed_at, observed_at)?;
    let changed = transaction
        .execute(
            "UPDATE authority_meta
             SET last_observed_at=?1, updated_at=MAX(updated_at,?1)
             WHERE singleton=1",
            [effective],
        )
        .map_err(|_| store_write_error())?;
    if changed != 1 {
        return Err(recovery_error());
    }
    Ok(())
}

fn staged_count(connection: &Connection) -> Result<i64, MailError> {
    connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM authority_keys WHERE state='staged')
                  + (SELECT COUNT(*) FROM trust_epochs WHERE state='staged')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())
}

fn authority_connection(path: &Path) -> Result<Connection, MailError> {
    let connection = Connection::open(path).map_err(|_| store_read_error())?;
    configure_connection(&connection)?;
    configure_authority_pragmas(&connection)?;
    Ok(connection)
}

fn existing_authority_read_connection(path: &Path) -> Result<Connection, MailError> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|_| store_read_error())?;
    configure_connection(&connection)?;
    Ok(connection)
}

fn configure_connection(connection: &Connection) -> Result<(), MailError> {
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(|_| store_read_error())?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;",
        )
        .map_err(|_| store_read_error())?;
    Ok(())
}

fn configure_authority_pragmas(connection: &Connection) -> Result<(), MailError> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .map_err(|_| store_write_error())?;
    connection
        .execute_batch("PRAGMA synchronous=FULL;")
        .map_err(|_| store_write_error())?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|_| store_write_error())?;
    if !journal_mode.eq_ignore_ascii_case("wal") || synchronous != 2 {
        return Err(store_write_error());
    }
    Ok(())
}

fn authority_database_exists(path: &Path) -> Result<bool, MailError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(recovery_error()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(store_read_error()),
    }
}

fn acquire_apply_lock(home: &AuthorityHome) -> Result<File, MailError> {
    ensure_private_parent(&home.apply_lock)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&home.apply_lock)
        .map_err(|_| store_write_error())?;
    secure_private_file(&home.apply_lock)?;
    fs4::FileExt::lock(&file).map_err(|_| store_write_error())?;
    Ok(file)
}

fn ensure_private_parent(path: &Path) -> Result<(), MailError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Err(store_write_error());
    };
    let created = !parent.exists();
    std::fs::create_dir_all(parent).map_err(|_| store_write_error())?;
    secure_created_directory(parent, created)
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

#[cfg(unix)]
fn secure_private_file(path: &Path) -> Result<(), MailError> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| store_write_error())
}

#[cfg(not(unix))]
fn secure_private_file(_path: &Path) -> Result<(), MailError> {
    Ok(())
}

fn secure_authority_files(path: &Path) -> Result<(), MailError> {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let candidate = PathBuf::from(name);
        if candidate.exists() {
            secure_private_file(&candidate)?;
        }
    }
    Ok(())
}

fn user_object_count(connection: &Connection) -> Result<i64, MailError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())
}

fn pragma_i64(connection: &Connection, name: &str) -> Result<i64, MailError> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(|_| store_read_error())
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], MailError> {
    bytes.try_into().map_err(|_| recovery_error())
}

fn recovery_error() -> MailError {
    MailError::stable(
        MailErrorCode::OwnerRecoveryRequired,
        "authority state requires owner recovery",
    )
}

fn store_read_error() -> MailError {
    MailError::stable(
        MailErrorCode::StoreRead,
        "authority store could not be read",
    )
}

fn store_write_error() -> MailError {
    MailError::stable(
        MailErrorCode::StoreWrite,
        "authority store could not be updated",
    )
}

fn entropy_error() -> MailError {
    MailError::stable(
        MailErrorCode::Internal,
        "secure authority entropy is unavailable",
    )
}
