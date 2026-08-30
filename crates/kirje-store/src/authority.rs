use std::{
    fs::{File, OpenOptions},
    num::NonZeroU64,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(feature = "test-support")]
use std::sync::{Arc, Barrier, Mutex};

use chrono::{DateTime, SecondsFormat, TimeZone as _, Utc};
use directories::ProjectDirs;
use kirje_core::{
    ActionManifest, AuthorizationGrantId, AuthorizationPayload, AuthorizationProof,
    AuthorizationReceiptId, AuthorizationReceiptProjection, AuthorizationReceiptState, JournalId,
    MailError, MailErrorCode, ManifestPayload, OwnerKeyRole, OwnerPublicKey, OwnerRealmId,
    SensitiveAction, Sha256Digest, StoreEnrollmentState, TargetKind, TrustPermissionMask,
    owner_key_id, verify_authorization_signature,
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
const AUTHORIZATION_CONTEXT_DOMAIN: &[u8] = b"KIRJE-AUTHORIZATION-CONTEXT-V1\0";
const AUTHORIZATION_RECEIPT_DOMAIN: &[u8] = b"KIRJE-AUTHORIZATION-RECEIPT-V1\0";
const AUTHORIZATION_LIFETIME_MS: i64 = 900_000;

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
pub struct CreateChallengeRequest {
    pub manifest: ActionManifest,
    pub observed_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifyProofRequest {
    pub proof: AuthorizationProof,
    pub observed_at_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeReview {
    pub bounded: bool,
    pub authoritative: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationChallengeExport {
    pub contract_version: String,
    pub challenge_id: Sha256Digest,
    pub action: SensitiveAction,
    pub target_kind: TargetKind,
    pub target_id: String,
    pub key_id: Sha256Digest,
    pub trust_epoch: NonZeroU64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub manifest_sha256: Sha256Digest,
    pub signing_payload_sha256: Sha256Digest,
    pub signing_payload_base64url: String,
    pub manifest_base64url: String,
    pub review: ChallengeReview,
}

impl AuthorizationChallengeExport {
    /// Render the one explicit owner-facing signing artifact.
    #[must_use]
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "contract_version": self.contract_version,
            "challenge_id": self.challenge_id,
            "action": self.action,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "key_id": self.key_id,
            "trust_epoch": self.trust_epoch,
            "issued_at": self.issued_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "expires_at": self.expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "manifest_sha256": self.manifest_sha256,
            "signing_payload_sha256": self.signing_payload_sha256,
            "signing_payload_base64url": self.signing_payload_base64url,
            "manifest_base64url": self.manifest_base64url,
            "review": {
                "bounded": self.review.bounded,
                "authoritative": self.review.authoritative,
            },
        })
    }
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

    #[doc(hidden)]
    #[must_use]
    pub fn with_authority_fault(mut self, fault: AuthorityFaultPoint) -> Self {
        self.test_hooks.fault = Some(fault);
        self
    }
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityFaultPoint {
    OldChallengeExpiredState,
    OldChallengeExpiredEvent,
    ChallengeInserted,
    ChallengeClockUpdated,
    ChallengeCreatedEventAppended,
    ChallengeCreatedEvent,
    ChallengeBeforeCommit,
    ChallengeAfterCommit,
    ReceiptInserted,
    NonceInserted,
    AuthorizedStateUpdated,
    ProofClockUpdated,
    AuthorizationEvent,
    ProofBeforeCommit,
    ProofAfterCommit,
    ExpiredStateUpdated,
    ExpiryClockUpdated,
    ExpiryEvent,
    ExpiryBeforeCommit,
    ExpiryAfterCommit,
}

#[derive(Clone, Default)]
struct AuthorityTestHooks {
    #[cfg(feature = "test-support")]
    open_snapshot: Option<TestPause>,
    #[cfg(feature = "test-support")]
    prepare_retry: Option<TestPause>,
    #[cfg(feature = "test-support")]
    fault: Option<AuthorityFaultPoint>,
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

    fn fault(&self, point: TestFaultPoint) -> Result<(), MailError> {
        #[cfg(feature = "test-support")]
        if self.fault == Some(point.into()) {
            return Err(store_write_error());
        }
        let _ = point;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum TestFaultPoint {
    OldChallengeExpiredState,
    OldChallengeExpiredEvent,
    ChallengeInserted,
    ChallengeClockUpdated,
    ChallengeCreatedEventAppended,
    ChallengeCreatedEvent,
    ChallengeBeforeCommit,
    ChallengeAfterCommit,
    ReceiptInserted,
    NonceInserted,
    AuthorizedStateUpdated,
    ProofClockUpdated,
    AuthorizationEvent,
    ProofBeforeCommit,
    ProofAfterCommit,
    ExpiredStateUpdated,
    ExpiryClockUpdated,
    ExpiryEvent,
    ExpiryBeforeCommit,
    ExpiryAfterCommit,
}

#[cfg(feature = "test-support")]
impl From<TestFaultPoint> for AuthorityFaultPoint {
    fn from(value: TestFaultPoint) -> Self {
        match value {
            TestFaultPoint::OldChallengeExpiredState => Self::OldChallengeExpiredState,
            TestFaultPoint::OldChallengeExpiredEvent => Self::OldChallengeExpiredEvent,
            TestFaultPoint::ChallengeInserted => Self::ChallengeInserted,
            TestFaultPoint::ChallengeClockUpdated => Self::ChallengeClockUpdated,
            TestFaultPoint::ChallengeCreatedEventAppended => Self::ChallengeCreatedEventAppended,
            TestFaultPoint::ChallengeCreatedEvent => Self::ChallengeCreatedEvent,
            TestFaultPoint::ChallengeBeforeCommit => Self::ChallengeBeforeCommit,
            TestFaultPoint::ChallengeAfterCommit => Self::ChallengeAfterCommit,
            TestFaultPoint::ReceiptInserted => Self::ReceiptInserted,
            TestFaultPoint::NonceInserted => Self::NonceInserted,
            TestFaultPoint::AuthorizedStateUpdated => Self::AuthorizedStateUpdated,
            TestFaultPoint::ProofClockUpdated => Self::ProofClockUpdated,
            TestFaultPoint::AuthorizationEvent => Self::AuthorizationEvent,
            TestFaultPoint::ProofBeforeCommit => Self::ProofBeforeCommit,
            TestFaultPoint::ProofAfterCommit => Self::ProofAfterCommit,
            TestFaultPoint::ExpiredStateUpdated => Self::ExpiredStateUpdated,
            TestFaultPoint::ExpiryClockUpdated => Self::ExpiryClockUpdated,
            TestFaultPoint::ExpiryEvent => Self::ExpiryEvent,
            TestFaultPoint::ExpiryBeforeCommit => Self::ExpiryBeforeCommit,
            TestFaultPoint::ExpiryAfterCommit => Self::ExpiryAfterCommit,
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

    /// Persist or exactly recover one bounded owner-signing challenge.
    ///
    /// # Errors
    ///
    /// Returns a stable authorization, clock, recovery, store, or schema error.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn create_challenge(
        &self,
        request: CreateChallengeRequest,
    ) -> Result<AuthorizationChallengeExport, MailError> {
        validate_challenge_request(&request)?;
        if !matches!(self.state, AuthorityOpenState::Ready(_)) {
            return Err(recovery_error());
        }
        let reparsed = ActionManifest::parse(request.manifest.canonical_bytes())?;
        if reparsed != request.manifest || reparsed.sha256() != request.manifest.sha256() {
            return Err(recovery_error());
        }
        ensure_t202b_action(request.manifest.action())?;

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
        let loaded = self.validate_ready_transaction(&transaction)?;
        let effective_time = checked_clock(loaded.last_observed_at, request.observed_at_unix_ms)?;
        utc_millis(effective_time)?;
        validate_supported_manifest(&transaction, &loaded.snapshot, &request.manifest)?;

        let signer_key_id = match request.manifest.action().policy().required_role {
            OwnerKeyRole::Owner => loaded.snapshot.owner_key_id,
            OwnerKeyRole::Recovery => loaded.snapshot.recovery_key_id,
        };
        let manifest_snapshot = request.manifest.context();
        let context_sha256 = authorization_context_digest(
            request.manifest.action(),
            request.manifest.context().target.kind(),
            &request.manifest.context().target.canonical_bytes(),
            manifest_snapshot.store_id,
            manifest_snapshot.account_id,
            request.manifest.sha256(),
            manifest_snapshot.account_binding_sha256,
            manifest_snapshot.policy_sha256,
            signer_key_id,
            loaded.snapshot.minimum_epoch,
            loaded.snapshot.trust_bundle_sha256,
        );

        if let Some(existing) = load_pending_challenge(&transaction, context_sha256)? {
            if effective_time <= existing.expires_at {
                observe_clock_pair(&transaction, effective_time)?;
                transaction.commit().map_err(|_| store_write_error())?;
                secure_authority_files(&self.home.database)?;
                return challenge_export_from_stored(&existing);
            }
            let changed = transaction
                .execute(
                    "UPDATE authorization_challenges SET state='expired'
                     WHERE challenge_id=?1 AND state='pending'",
                    [existing.challenge_id.as_bytes()],
                )
                .map_err(|_| store_write_error())?;
            if changed != 1 {
                return Err(recovery_error());
            }
            self.test_hooks
                .fault(TestFaultPoint::OldChallengeExpiredState)?;
            insert_challenge_event(
                &transaction,
                &existing,
                ChallengeEvent::Expired,
                None,
                effective_time,
            )?;
            self.test_hooks
                .fault(TestFaultPoint::OldChallengeExpiredEvent)?;
        }

        validate_requested_expiry(effective_time, request.expires_at_unix_ms)?;

        let mut grant_bytes = [0_u8; 16];
        let mut nonce = [0_u8; 32];
        self.entropy.fill(&mut grant_bytes)?;
        make_uuid_v4(&mut grant_bytes);
        self.entropy.fill(&mut nonce)?;
        let grant_id = AuthorizationGrantId::try_from(Uuid::from_bytes(grant_bytes))?;
        let payload = AuthorizationPayload::new(
            &request.manifest,
            kirje_core::AuthorizationContext {
                owner_realm: loaded.snapshot.realm_id,
                trust_bundle_sha256: loaded.snapshot.trust_bundle_sha256,
                signer_key_id,
                trust_epoch: loaded.snapshot.minimum_epoch,
                grant_id,
                nonce,
                issued_at_unix_ms: effective_time,
                expires_at_unix_ms: request.expires_at_unix_ms,
            },
        )?;
        let snapshot = payload.snapshot();
        let inserted = transaction
            .execute(
                "INSERT INTO authorization_challenges
                 (challenge_id,grant_id,action,target_kind,target_id,store_id,account_id,
                  context_sha256,manifest,manifest_sha256,signing_payload,signing_sha256,
                  key_id,trust_epoch,bundle_sha256,binding_sha256,policy_sha256,nonce,
                  issued_at,expires_at,state,invalidated_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,
                        ?16,?17,?18,?19,?20,'pending',NULL)",
                params![
                    payload.challenge_id().as_bytes(),
                    snapshot.grant_id().as_bytes(),
                    i64::from(snapshot.action().code()),
                    i64::from(snapshot.target_kind().code()),
                    snapshot.target_bytes(),
                    snapshot.store_id().map(|value| value.as_bytes().to_vec()),
                    snapshot.account_id().map(|value| value.as_bytes().to_vec()),
                    context_sha256.as_bytes(),
                    request.manifest.canonical_bytes(),
                    snapshot.manifest_sha256().as_bytes(),
                    snapshot.canonical_bytes(),
                    payload.challenge_id().as_bytes(),
                    snapshot.signer_key_id().as_bytes(),
                    i64::try_from(snapshot.trust_epoch().get()).map_err(|_| recovery_error())?,
                    snapshot.bundle_sha256().as_bytes(),
                    snapshot
                        .binding_sha256()
                        .map(|value| value.as_bytes().to_vec()),
                    snapshot
                        .policy_sha256()
                        .map(|value| value.as_bytes().to_vec()),
                    snapshot.nonce(),
                    snapshot.issued_at_unix_ms(),
                    snapshot.expires_at_unix_ms(),
                ],
            )
            .map_err(|_| store_write_error())?;
        if inserted != 1 {
            return Err(store_write_error());
        }
        self.test_hooks.fault(TestFaultPoint::ChallengeInserted)?;
        observe_clock_pair(&transaction, effective_time)?;
        self.test_hooks
            .fault(TestFaultPoint::ChallengeClockUpdated)?;
        let unlinked = load_unlinked_challenge(&transaction, payload.challenge_id())?;
        let created_event_sequence = insert_challenge_event(
            &transaction,
            &unlinked,
            ChallengeEvent::Created,
            None,
            effective_time,
        )?;
        self.test_hooks
            .fault(TestFaultPoint::ChallengeCreatedEventAppended)?;
        let linked = transaction
            .execute(
                "UPDATE authorization_challenges SET created_event_sequence=?1
                 WHERE challenge_id=?2 AND created_event_sequence IS NULL",
                params![created_event_sequence, payload.challenge_id().as_bytes()],
            )
            .map_err(|_| store_write_error())?;
        if linked != 1 {
            return Err(recovery_error());
        }
        self.test_hooks
            .fault(TestFaultPoint::ChallengeCreatedEvent)?;
        let stored = load_challenge(&transaction, payload.challenge_id())?;
        self.test_hooks
            .fault(TestFaultPoint::ChallengeBeforeCommit)?;
        transaction.commit().map_err(|_| store_write_error())?;
        secure_authority_files(&self.home.database)?;
        self.test_hooks
            .fault(TestFaultPoint::ChallengeAfterCommit)?;
        challenge_export_from_stored(&stored)
    }

    /// Verify one detached proof or exactly recover its immutable receipt.
    ///
    /// # Errors
    ///
    /// Returns a stable malformed, replay, expiry, signature, recovery, clock, or store error.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn verify_proof(
        &self,
        request: VerifyProofRequest,
    ) -> Result<AuthorizationReceiptProjection, MailError> {
        validate_proof_request(&request)?;
        if !matches!(self.state, AuthorityOpenState::Ready(_)) {
            return Err(recovery_error());
        }
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
        let loaded = self.validate_ready_transaction(&transaction)?;
        let challenge = load_challenge(&transaction, request.proof.challenge_id())?;
        let effective_time = checked_clock(loaded.last_observed_at, request.observed_at_unix_ms)?;
        utc_millis(effective_time)?;

        if let Some(receipt) = load_receipt_for_challenge(&transaction, challenge.challenge_id)? {
            if receipt.canonical_proof != request.proof.canonical_bytes() {
                return Err(authorization_replayed_error());
            }
            observe_clock_pair(&transaction, effective_time)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            return receipt_projection(&challenge, &receipt, effective_time);
        }

        match challenge.state.as_str() {
            "expired" => {
                observe_clock_pair(&transaction, effective_time)?;
                transaction.commit().map_err(|_| store_write_error())?;
                secure_authority_files(&self.home.database)?;
                return Err(authorization_expired_error());
            }
            "pending" => {}
            _ => return Err(recovery_error()),
        }
        if effective_time > challenge.expires_at {
            let changed = transaction
                .execute(
                    "UPDATE authorization_challenges SET state='expired'
                     WHERE challenge_id=?1 AND state='pending'",
                    [challenge.challenge_id.as_bytes()],
                )
                .map_err(|_| store_write_error())?;
            if changed != 1 {
                return Err(recovery_error());
            }
            self.test_hooks.fault(TestFaultPoint::ExpiredStateUpdated)?;
            observe_clock_pair(&transaction, effective_time)?;
            self.test_hooks.fault(TestFaultPoint::ExpiryClockUpdated)?;
            insert_challenge_event(
                &transaction,
                &challenge,
                ChallengeEvent::Expired,
                None,
                effective_time,
            )?;
            self.test_hooks.fault(TestFaultPoint::ExpiryEvent)?;
            self.test_hooks.fault(TestFaultPoint::ExpiryBeforeCommit)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            self.test_hooks.fault(TestFaultPoint::ExpiryAfterCommit)?;
            return Err(authorization_expired_error());
        }
        validate_first_proof(&loaded.snapshot, &challenge, &request.proof)?;

        let mut receipt_bytes = [0_u8; 16];
        self.entropy.fill(&mut receipt_bytes)?;
        make_uuid_v4(&mut receipt_bytes);
        let receipt_id = AuthorizationReceiptId::try_from(Uuid::from_bytes(receipt_bytes))?;
        let proof_sha256 = request.proof.proof_sha256();
        let receipt = authorization_receipt(receipt_id, &challenge, proof_sha256, effective_time);
        let receipt_sha256 = Sha256Digest::digest(&receipt);
        transaction
            .execute(
                "INSERT INTO authorization_receipts
                 (receipt_id,challenge_id,grant_id,proof_sha256,key_id,signature,
                  canonical_proof,manifest_sha256,signing_sha256,trust_epoch,bundle_sha256,
                  receipt,receipt_sha256,verified_at,expires_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                params![
                    receipt_id.as_bytes(),
                    challenge.challenge_id.as_bytes(),
                    challenge.grant_id.as_bytes(),
                    proof_sha256.as_bytes(),
                    challenge.key_id.as_bytes(),
                    request.proof.signature_bytes()?.as_slice(),
                    request.proof.canonical_bytes(),
                    challenge.manifest_sha256.as_bytes(),
                    challenge.signing_sha256.as_bytes(),
                    i64::try_from(challenge.trust_epoch.get()).map_err(|_| recovery_error())?,
                    challenge.bundle_sha256.as_bytes(),
                    &receipt,
                    receipt_sha256.as_bytes(),
                    effective_time,
                    challenge.expires_at,
                ],
            )
            .map_err(|_| store_write_error())?;
        self.test_hooks.fault(TestFaultPoint::ReceiptInserted)?;
        transaction
            .execute(
                "INSERT INTO nonce_uses(nonce,challenge_id,receipt_id,consumed_at)
                 VALUES(?1,?2,?3,?4)",
                params![
                    &challenge.nonce,
                    challenge.challenge_id.as_bytes(),
                    receipt_id.as_bytes(),
                    effective_time,
                ],
            )
            .map_err(|_| store_write_error())?;
        self.test_hooks.fault(TestFaultPoint::NonceInserted)?;
        let changed = transaction
            .execute(
                "UPDATE authorization_challenges SET state='authorized'
                 WHERE challenge_id=?1 AND state='pending'",
                [challenge.challenge_id.as_bytes()],
            )
            .map_err(|_| store_write_error())?;
        if changed != 1 {
            return Err(recovery_error());
        }
        self.test_hooks
            .fault(TestFaultPoint::AuthorizedStateUpdated)?;
        observe_clock_pair(&transaction, effective_time)?;
        self.test_hooks.fault(TestFaultPoint::ProofClockUpdated)?;
        let stored_receipt = StoredReceipt {
            receipt_id,
            challenge_id: challenge.challenge_id,
            grant_id: challenge.grant_id,
            proof_sha256,
            key_id: challenge.key_id,
            signature: request.proof.signature_bytes()?,
            canonical_proof: request.proof.canonical_bytes().to_vec(),
            manifest_sha256: challenge.manifest_sha256,
            signing_sha256: challenge.signing_sha256,
            trust_epoch: challenge.trust_epoch,
            bundle_sha256: challenge.bundle_sha256,
            receipt,
            receipt_sha256,
            verified_at: effective_time,
            expires_at: challenge.expires_at,
        };
        insert_challenge_event(
            &transaction,
            &challenge,
            ChallengeEvent::Authorized,
            Some(&stored_receipt),
            effective_time,
        )?;
        self.test_hooks.fault(TestFaultPoint::AuthorizationEvent)?;
        self.test_hooks.fault(TestFaultPoint::ProofBeforeCommit)?;
        transaction.commit().map_err(|_| store_write_error())?;
        secure_authority_files(&self.home.database)?;
        self.test_hooks.fault(TestFaultPoint::ProofAfterCommit)?;
        receipt_projection(&challenge, &stored_receipt, effective_time)
    }

    fn validate_ready_transaction(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<LoadedSnapshot, MailError> {
        if classify_database(transaction)? != DatabaseClass::AuthorityV1 {
            return Err(recovery_error());
        }
        ensure_usable_schema(transaction)?;
        if staged_count(transaction)? != 0 {
            return Err(recovery_error());
        }
        let loaded = load_snapshot(transaction, &AuthorityTestHooks::default())?;
        let AuthorityOpenState::Ready(opened) = &self.state else {
            return Err(recovery_error());
        };
        let AnchorPresence::Present(anchor) = &self.context.anchor else {
            return Err(recovery_error());
        };
        if loaded.bootstrap_state != "ready"
            || &loaded.snapshot != opened
            || anchor != &loaded.snapshot.anchor
            || loaded.snapshot.journal_location_sha256 != self.context.journal_location_sha256
        {
            return Err(recovery_error());
        }
        Ok(loaded)
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

struct StoredChallenge {
    challenge_id: Sha256Digest,
    grant_id: AuthorizationGrantId,
    action: SensitiveAction,
    target_kind_code: u16,
    target_id: Vec<u8>,
    store_id: Option<kirje_core::StoreId>,
    account_id: Option<kirje_core::AccountId>,
    context_sha256: Sha256Digest,
    manifest: Vec<u8>,
    manifest_sha256: Sha256Digest,
    signing_payload: Vec<u8>,
    signing_sha256: Sha256Digest,
    key_id: Sha256Digest,
    trust_epoch: NonZeroU64,
    bundle_sha256: Sha256Digest,
    binding_sha256: Option<Sha256Digest>,
    policy_sha256: Option<Sha256Digest>,
    nonce: [u8; 32],
    issued_at: i64,
    expires_at: i64,
    state: String,
    invalidated_at: Option<i64>,
    created_event_sequence: i64,
}

struct StoredReceipt {
    receipt_id: AuthorizationReceiptId,
    challenge_id: Sha256Digest,
    grant_id: AuthorizationGrantId,
    proof_sha256: Sha256Digest,
    key_id: Sha256Digest,
    signature: [u8; 64],
    canonical_proof: Vec<u8>,
    manifest_sha256: Sha256Digest,
    signing_sha256: Sha256Digest,
    trust_epoch: NonZeroU64,
    bundle_sha256: Sha256Digest,
    receipt: Vec<u8>,
    receipt_sha256: Sha256Digest,
    verified_at: i64,
    expires_at: i64,
}

fn validate_challenge_request(request: &CreateChallengeRequest) -> Result<(), MailError> {
    if request.observed_at_unix_ms < 0 || request.expires_at_unix_ms < 0 {
        return Err(MailError::invalid_input(
            "authority challenge time must be nonnegative",
        ));
    }
    input_utc_millis(request.observed_at_unix_ms)?;
    input_utc_millis(request.expires_at_unix_ms)?;
    Ok(())
}

fn validate_requested_expiry(effective_time: i64, expires_at: i64) -> Result<(), MailError> {
    let lifetime = expires_at
        .checked_sub(effective_time)
        .ok_or_else(|| MailError::invalid_input("authority challenge time overflowed"))?;
    if lifetime <= 0 || lifetime > AUTHORIZATION_LIFETIME_MS {
        return Err(MailError::invalid_input(
            "authority challenge lifetime is outside the contract",
        ));
    }
    Ok(())
}

fn validate_proof_request(request: &VerifyProofRequest) -> Result<(), MailError> {
    if request.observed_at_unix_ms < 0 {
        return Err(MailError::invalid_input(
            "authority observation time must be nonnegative",
        ));
    }
    input_utc_millis(request.observed_at_unix_ms)?;
    if request.proof.canonical_bytes().len() > 4_096
        || AuthorizationProof::parse_canonical(request.proof.canonical_bytes())? != request.proof
    {
        return Err(MailError::stable(
            MailErrorCode::AuthorizationMalformed,
            "authorization proof is malformed",
        ));
    }
    Ok(())
}

fn ensure_t202b_action(action: SensitiveAction) -> Result<(), MailError> {
    match action {
        SensitiveAction::StoreEnroll
        | SensitiveAction::OwnerRotate
        | SensitiveAction::RecoveryRotate
        | SensitiveAction::OwnerRecover => Ok(()),
        SensitiveAction::PolicyUpdate | SensitiveAction::AssuranceUpdate => Err(MailError::stable(
            MailErrorCode::UnsupportedCapability,
            "authorization action is not supported",
        )),
        _ => Err(authorization_context_stale_error()),
    }
}

fn validate_supported_manifest(
    connection: &Connection,
    authority: &BootstrapSnapshot,
    manifest: &ActionManifest,
) -> Result<(), MailError> {
    match manifest.payload() {
        ManifestPayload::StoreEnroll(value) => {
            if value.expected_store_state != StoreEnrollmentState::Unregistered {
                return Err(authorization_context_stale_error());
            }
            let count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM registered_stores WHERE store_id=?1",
                    [value.config_cas.store_id.as_bytes()],
                    |row| row.get(0),
                )
                .map_err(|_| store_read_error())?;
            if count != 0 {
                return Err(authorization_context_stale_error());
            }
        }
        ManifestPayload::OwnerRotate(value) => {
            validate_rotation_manifest(authority, value, OwnerKeyRole::Owner)?;
        }
        ManifestPayload::RecoveryRotate(value) => {
            validate_rotation_manifest(authority, value, OwnerKeyRole::Recovery)?;
        }
        ManifestPayload::OwnerRecover(value) => {
            let next_epoch = authority
                .minimum_epoch
                .get()
                .checked_add(1)
                .and_then(NonZeroU64::new)
                .ok_or_else(authorization_context_stale_error)?;
            let owner = OwnerPublicKey::try_from(value.new_owner_key)
                .map_err(|_| authorization_context_stale_error())?;
            let recovery = OwnerPublicKey::try_from(value.new_recovery_key)
                .map_err(|_| authorization_context_stale_error())?;
            let active_owner = authority.owner_public_key.as_bytes();
            let active_recovery = authority.recovery_public_key.as_bytes();
            let expected_bundle = trust_bundle_digest(
                authority.realm_id,
                authority.journal_id,
                next_epoch,
                value.new_owner_id,
                &owner,
                value.new_recovery_id,
                &recovery,
            );
            if value.journal_id != authority.journal_id
                || value.old_epoch != authority.minimum_epoch
                || value.new_epoch != next_epoch
                || value.old_bundle != authority.trust_bundle_sha256
                || value.invalidation_scope != kirje_core::InvalidationScope::All
                || owner == recovery
                || owner.as_bytes() == active_owner
                || owner.as_bytes() == active_recovery
                || recovery.as_bytes() == active_owner
                || recovery.as_bytes() == active_recovery
                || value.new_owner_id != owner_key_id(OwnerKeyRole::Owner, owner.as_bytes())
                || value.new_recovery_id
                    != owner_key_id(OwnerKeyRole::Recovery, recovery.as_bytes())
                || value.new_bundle != expected_bundle
            {
                return Err(authorization_context_stale_error());
            }
        }
        _ => return Err(authorization_context_stale_error()),
    }
    Ok(())
}

fn validate_rotation_manifest(
    authority: &BootstrapSnapshot,
    value: &kirje_core::TrustRotationManifest,
    expected_role: OwnerKeyRole,
) -> Result<(), MailError> {
    let next_epoch = authority
        .minimum_epoch
        .get()
        .checked_add(1)
        .and_then(NonZeroU64::new)
        .ok_or_else(authorization_context_stale_error)?;
    let proposed = OwnerPublicKey::try_from(value.new_public_key)
        .map_err(|_| authorization_context_stale_error())?;
    let (old_id, old_key, permission, owner, recovery) = match expected_role {
        OwnerKeyRole::Owner => (
            authority.owner_key_id,
            authority.owner_public_key.as_bytes(),
            TrustPermissionMask::Owner,
            proposed.clone(),
            authority.recovery_public_key.clone(),
        ),
        OwnerKeyRole::Recovery => (
            authority.recovery_key_id,
            authority.recovery_public_key.as_bytes(),
            TrustPermissionMask::Recovery,
            authority.owner_public_key.clone(),
            proposed.clone(),
        ),
    };
    let expected_bundle = trust_bundle_digest(
        authority.realm_id,
        authority.journal_id,
        next_epoch,
        owner_key_id(OwnerKeyRole::Owner, owner.as_bytes()),
        &owner,
        owner_key_id(OwnerKeyRole::Recovery, recovery.as_bytes()),
        &recovery,
    );
    if value.role != expected_role
        || value.permissions != permission
        || value.old_key_id != old_id
        || value.old_public_key.as_slice() != old_key
        || value.old_epoch != authority.minimum_epoch
        || value.new_epoch != next_epoch
        || value.old_bundle != authority.trust_bundle_sha256
        || proposed.as_bytes() == authority.owner_public_key.as_bytes()
        || proposed.as_bytes() == authority.recovery_public_key.as_bytes()
        || value.new_key_id != owner_key_id(expected_role, proposed.as_bytes())
        || value.new_bundle != expected_bundle
    {
        return Err(authorization_context_stale_error());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn authorization_context_digest(
    action: SensitiveAction,
    target_kind: TargetKind,
    target_bytes: &[u8],
    store_id: Option<kirje_core::StoreId>,
    account_id: Option<kirje_core::AccountId>,
    manifest_sha256: Sha256Digest,
    binding_sha256: Option<Sha256Digest>,
    policy_sha256: Option<Sha256Digest>,
    key_id: Sha256Digest,
    trust_epoch: NonZeroU64,
    bundle_sha256: Sha256Digest,
) -> Sha256Digest {
    let action = action.code().to_be_bytes();
    let target_kind = target_kind.code().to_be_bytes();
    let store_id = store_id
        .map(|value| value.as_bytes().to_vec())
        .unwrap_or_default();
    let account_id = account_id
        .map(|value| value.as_bytes().to_vec())
        .unwrap_or_default();
    let binding = binding_sha256
        .map(|value| value.as_bytes().to_vec())
        .unwrap_or_default();
    let policy = policy_sha256
        .map(|value| value.as_bytes().to_vec())
        .unwrap_or_default();
    let epoch = trust_epoch.get().to_be_bytes();
    Sha256Digest::digest(&encode_transcript(
        AUTHORIZATION_CONTEXT_DOMAIN,
        &[
            &action,
            &target_kind,
            target_bytes,
            &store_id,
            &account_id,
            manifest_sha256.as_bytes(),
            &binding,
            &policy,
            key_id.as_bytes(),
            &epoch,
            bundle_sha256.as_bytes(),
        ],
    ))
}

fn observe_clock_pair(transaction: &Transaction<'_>, effective: i64) -> Result<(), MailError> {
    let changed = transaction
        .execute(
            "UPDATE authority_meta SET last_observed_at=?1,updated_at=?1 WHERE singleton=1",
            [effective],
        )
        .map_err(|_| store_write_error())?;
    if changed != 1 {
        return Err(recovery_error());
    }
    Ok(())
}

fn make_uuid_v4(bytes: &mut [u8; 16]) {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
}

fn authorization_receipt(
    receipt_id: AuthorizationReceiptId,
    challenge: &StoredChallenge,
    proof_sha256: Sha256Digest,
    verified_at: i64,
) -> Vec<u8> {
    let epoch = challenge.trust_epoch.get().to_be_bytes();
    let verified = verified_at.to_be_bytes();
    let expires = challenge.expires_at.to_be_bytes();
    encode_transcript(
        AUTHORIZATION_RECEIPT_DOMAIN,
        &[
            receipt_id.as_bytes(),
            challenge.challenge_id.as_bytes(),
            challenge.grant_id.as_bytes(),
            proof_sha256.as_bytes(),
            challenge.key_id.as_bytes(),
            challenge.manifest_sha256.as_bytes(),
            challenge.signing_sha256.as_bytes(),
            &epoch,
            challenge.bundle_sha256.as_bytes(),
            &verified,
            &expires,
        ],
    )
}

fn load_pending_challenge(
    connection: &Connection,
    context_sha256: Sha256Digest,
) -> Result<Option<StoredChallenge>, MailError> {
    let challenge = connection
        .query_row(
            "SELECT challenge_id FROM authorization_challenges
             WHERE context_sha256=?1 AND state='pending'",
            [context_sha256.as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|_| store_read_error())?;
    challenge
        .map(|bytes| load_challenge(connection, digest_from_blob(&bytes)?))
        .transpose()
}

#[allow(clippy::too_many_lines)]
fn load_challenge(
    connection: &Connection,
    challenge_id: Sha256Digest,
) -> Result<StoredChallenge, MailError> {
    challenge_preflight(connection, Some(challenge_id))?;
    connection
        .query_row(
            "SELECT challenge_id,grant_id,action,target_kind,target_id,store_id,account_id,
                    context_sha256,manifest,manifest_sha256,signing_payload,signing_sha256,
                    key_id,trust_epoch,bundle_sha256,binding_sha256,policy_sha256,nonce,
                    issued_at,expires_at,state,invalidated_at,created_event_sequence
             FROM authorization_challenges WHERE challenge_id=?1",
            [challenge_id.as_bytes()],
            stored_challenge_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())?
        .ok_or_else(|| {
            MailError::stable(
                MailErrorCode::AuthorizationMalformed,
                "authorization challenge is unknown",
            )
        })
}

fn load_unlinked_challenge(
    connection: &Connection,
    challenge_id: Sha256Digest,
) -> Result<StoredChallenge, MailError> {
    connection
        .query_row(
            "SELECT challenge_id,grant_id,action,target_kind,target_id,store_id,account_id,
                    context_sha256,manifest,manifest_sha256,signing_payload,signing_sha256,
                    key_id,trust_epoch,bundle_sha256,binding_sha256,policy_sha256,nonce,
                    issued_at,expires_at,state,invalidated_at,0
             FROM authorization_challenges
             WHERE challenge_id=?1 AND created_event_sequence IS NULL",
            [challenge_id.as_bytes()],
            stored_challenge_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())?
        .ok_or_else(recovery_error)
}

fn stored_challenge_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredChallenge> {
    let action_code = row.get::<_, i64>(2)?;
    let action_u16 = u16::try_from(action_code).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let action =
        SensitiveAction::from_code(action_u16).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let target_kind_code =
        u16::try_from(row.get::<_, i64>(3)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let trust_epoch = u64::try_from(row.get::<_, i64>(13)?)
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(rusqlite::Error::InvalidQuery)?;
    Ok(StoredChallenge {
        challenge_id: digest_from_blob_sql(row.get::<_, Vec<u8>>(0)?)?,
        grant_id: uuid_from_blob_sql(row.get::<_, Vec<u8>>(1)?)?,
        action,
        target_kind_code,
        target_id: row.get(4)?,
        store_id: optional_uuid_from_blob_sql(row.get(5)?)?,
        account_id: optional_uuid_from_blob_sql(row.get(6)?)?,
        context_sha256: digest_from_blob_sql(row.get(7)?)?,
        manifest: row.get(8)?,
        manifest_sha256: digest_from_blob_sql(row.get(9)?)?,
        signing_payload: row.get(10)?,
        signing_sha256: digest_from_blob_sql(row.get(11)?)?,
        key_id: digest_from_blob_sql(row.get(12)?)?,
        trust_epoch,
        bundle_sha256: digest_from_blob_sql(row.get(14)?)?,
        binding_sha256: optional_digest_from_blob_sql(row.get(15)?)?,
        policy_sha256: optional_digest_from_blob_sql(row.get(16)?)?,
        nonce: row
            .get::<_, Vec<u8>>(17)?
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        issued_at: row.get(18)?,
        expires_at: row.get(19)?,
        state: row.get(20)?,
        invalidated_at: row.get(21)?,
        created_event_sequence: row.get(22)?,
    })
}

fn challenge_preflight(
    connection: &Connection,
    challenge_id: Option<Sha256Digest>,
) -> Result<(), MailError> {
    let malformed: i64 = if let Some(challenge_id) = challenge_id {
        connection.query_row(
            "SELECT COUNT(*) FROM authorization_challenges WHERE challenge_id=?1 AND (
             typeof(challenge_id)<>'blob' OR length(challenge_id)<>32 OR
             typeof(grant_id)<>'blob' OR length(grant_id)<>16 OR
             typeof(action)<>'integer' OR typeof(target_kind)<>'integer' OR
             typeof(target_id)<>'blob' OR length(target_id)>256 OR
             (store_id IS NOT NULL AND (typeof(store_id)<>'blob' OR length(store_id)<>16)) OR
             (account_id IS NOT NULL AND (typeof(account_id)<>'blob' OR length(account_id)<>16)) OR
             typeof(context_sha256)<>'blob' OR length(context_sha256)<>32 OR
             typeof(manifest)<>'blob' OR length(manifest) NOT BETWEEN 1 AND 4194304 OR
             typeof(manifest_sha256)<>'blob' OR length(manifest_sha256)<>32 OR
             typeof(signing_payload)<>'blob' OR length(signing_payload) NOT BETWEEN 1 AND 4194304 OR
             typeof(signing_sha256)<>'blob' OR length(signing_sha256)<>32 OR
             typeof(key_id)<>'blob' OR length(key_id)<>32 OR
             typeof(trust_epoch)<>'integer' OR trust_epoch<=0 OR
             typeof(bundle_sha256)<>'blob' OR length(bundle_sha256)<>32 OR
             (binding_sha256 IS NOT NULL AND
              (typeof(binding_sha256)<>'blob' OR length(binding_sha256)<>32)) OR
             (policy_sha256 IS NOT NULL AND
              (typeof(policy_sha256)<>'blob' OR length(policy_sha256)<>32)) OR
             typeof(nonce)<>'blob' OR length(nonce)<>32 OR
             typeof(issued_at)<>'integer' OR issued_at<0 OR
             typeof(expires_at)<>'integer' OR expires_at<=issued_at OR
             typeof(state)<>'text' OR length(state) NOT BETWEEN 7 AND 11 OR
             state NOT IN ('pending','authorized','expired','invalidated') OR
             typeof(created_event_sequence)<>'integer' OR created_event_sequence<=0 OR
             (state='invalidated' AND
              (typeof(invalidated_at)<>'integer' OR invalidated_at<issued_at)) OR
             (state<>'invalidated' AND invalidated_at IS NOT NULL))",
            [challenge_id.as_bytes()],
            |row| row.get(0),
        )
    } else {
        connection.query_row(
            "SELECT COUNT(*) FROM authorization_challenges WHERE
             typeof(challenge_id)<>'blob' OR length(challenge_id)<>32 OR
             typeof(grant_id)<>'blob' OR length(grant_id)<>16 OR
             typeof(action)<>'integer' OR typeof(target_kind)<>'integer' OR
             typeof(target_id)<>'blob' OR length(target_id)>256 OR
             (store_id IS NOT NULL AND (typeof(store_id)<>'blob' OR length(store_id)<>16)) OR
             (account_id IS NOT NULL AND (typeof(account_id)<>'blob' OR length(account_id)<>16)) OR
             typeof(context_sha256)<>'blob' OR length(context_sha256)<>32 OR
             typeof(manifest)<>'blob' OR length(manifest) NOT BETWEEN 1 AND 4194304 OR
             typeof(manifest_sha256)<>'blob' OR length(manifest_sha256)<>32 OR
             typeof(signing_payload)<>'blob' OR length(signing_payload) NOT BETWEEN 1 AND 4194304 OR
             typeof(signing_sha256)<>'blob' OR length(signing_sha256)<>32 OR
             typeof(key_id)<>'blob' OR length(key_id)<>32 OR
             typeof(trust_epoch)<>'integer' OR trust_epoch<=0 OR
             typeof(bundle_sha256)<>'blob' OR length(bundle_sha256)<>32 OR
             (binding_sha256 IS NOT NULL AND
              (typeof(binding_sha256)<>'blob' OR length(binding_sha256)<>32)) OR
             (policy_sha256 IS NOT NULL AND
              (typeof(policy_sha256)<>'blob' OR length(policy_sha256)<>32)) OR
             typeof(nonce)<>'blob' OR length(nonce)<>32 OR
             typeof(issued_at)<>'integer' OR issued_at<0 OR
             typeof(expires_at)<>'integer' OR expires_at<=issued_at OR
             typeof(state)<>'text' OR length(state) NOT BETWEEN 7 AND 11 OR
             state NOT IN ('pending','authorized','expired','invalidated') OR
             typeof(created_event_sequence)<>'integer' OR created_event_sequence<=0 OR
             (state='invalidated' AND
              (typeof(invalidated_at)<>'integer' OR invalidated_at<issued_at)) OR
             (state<>'invalidated' AND invalidated_at IS NOT NULL)",
            [],
            |row| row.get(0),
        )
    }
    .map_err(|_| store_read_error())?;
    if malformed != 0 {
        return Err(recovery_error());
    }
    Ok(())
}

fn load_receipt_for_challenge(
    connection: &Connection,
    challenge_id: Sha256Digest,
) -> Result<Option<StoredReceipt>, MailError> {
    receipt_preflight(connection, Some(challenge_id))?;
    connection
        .query_row(
            "SELECT receipt_id,challenge_id,grant_id,proof_sha256,key_id,signature,
                    canonical_proof,manifest_sha256,signing_sha256,trust_epoch,bundle_sha256,
                    receipt,receipt_sha256,verified_at,expires_at
             FROM authorization_receipts WHERE challenge_id=?1",
            [challenge_id.as_bytes()],
            stored_receipt_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())
}

fn stored_receipt_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredReceipt> {
    let trust_epoch = u64::try_from(row.get::<_, i64>(9)?)
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(rusqlite::Error::InvalidQuery)?;
    Ok(StoredReceipt {
        receipt_id: uuid_from_blob_sql(row.get(0)?)?,
        challenge_id: digest_from_blob_sql(row.get(1)?)?,
        grant_id: uuid_from_blob_sql(row.get(2)?)?,
        proof_sha256: digest_from_blob_sql(row.get(3)?)?,
        key_id: digest_from_blob_sql(row.get(4)?)?,
        signature: row
            .get::<_, Vec<u8>>(5)?
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        canonical_proof: row.get(6)?,
        manifest_sha256: digest_from_blob_sql(row.get(7)?)?,
        signing_sha256: digest_from_blob_sql(row.get(8)?)?,
        trust_epoch,
        bundle_sha256: digest_from_blob_sql(row.get(10)?)?,
        receipt: row.get(11)?,
        receipt_sha256: digest_from_blob_sql(row.get(12)?)?,
        verified_at: row.get(13)?,
        expires_at: row.get(14)?,
    })
}

fn receipt_preflight(
    connection: &Connection,
    challenge_id: Option<Sha256Digest>,
) -> Result<(), MailError> {
    let malformed_condition = "
        typeof(receipt_id)<>'blob' OR length(receipt_id)<>16 OR
        typeof(challenge_id)<>'blob' OR length(challenge_id)<>32 OR
        typeof(grant_id)<>'blob' OR length(grant_id)<>16 OR
        typeof(proof_sha256)<>'blob' OR length(proof_sha256)<>32 OR
        typeof(key_id)<>'blob' OR length(key_id)<>32 OR
        typeof(signature)<>'blob' OR length(signature)<>64 OR
        typeof(canonical_proof)<>'blob' OR length(canonical_proof) NOT BETWEEN 1 AND 4096 OR
        typeof(manifest_sha256)<>'blob' OR length(manifest_sha256)<>32 OR
        typeof(signing_sha256)<>'blob' OR length(signing_sha256)<>32 OR
        typeof(trust_epoch)<>'integer' OR trust_epoch<=0 OR
        typeof(bundle_sha256)<>'blob' OR length(bundle_sha256)<>32 OR
        typeof(receipt)<>'blob' OR length(receipt) NOT BETWEEN 1 AND 16384 OR
        typeof(receipt_sha256)<>'blob' OR length(receipt_sha256)<>32 OR
        typeof(verified_at)<>'integer' OR verified_at<0 OR
        typeof(expires_at)<>'integer' OR expires_at<verified_at";
    let malformed: i64 = if let Some(challenge_id) = challenge_id {
        connection
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM authorization_receipts
                     WHERE challenge_id=?1 AND ({malformed_condition})"
                ),
                [challenge_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| store_read_error())?
    } else {
        connection
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM authorization_receipts
                     WHERE {malformed_condition}"
                ),
                [],
                |row| row.get(0),
            )
            .map_err(|_| store_read_error())?
    };
    if malformed != 0 {
        return Err(recovery_error());
    }
    Ok(())
}

fn challenge_export_from_stored(
    challenge: &StoredChallenge,
) -> Result<AuthorizationChallengeExport, MailError> {
    let manifest = ActionManifest::parse(&challenge.manifest).map_err(|_| recovery_error())?;
    let payload =
        AuthorizationPayload::parse(&challenge.signing_payload).map_err(|_| recovery_error())?;
    let snapshot = payload.snapshot();
    Ok(AuthorizationChallengeExport {
        contract_version: "kirje.authorization.v1".to_owned(),
        challenge_id: challenge.challenge_id,
        action: challenge.action,
        target_kind: snapshot.target_kind(),
        target_id: snapshot.target_display().as_str().to_owned(),
        key_id: challenge.key_id,
        trust_epoch: challenge.trust_epoch,
        issued_at: utc_millis(challenge.issued_at)?,
        expires_at: utc_millis(challenge.expires_at)?,
        manifest_sha256: manifest.sha256(),
        signing_payload_sha256: challenge.signing_sha256,
        signing_payload_base64url: base64url(&challenge.signing_payload),
        manifest_base64url: base64url(&challenge.manifest),
        review: ChallengeReview {
            bounded: true,
            authoritative: false,
        },
    })
}

fn validate_first_proof(
    authority: &BootstrapSnapshot,
    challenge: &StoredChallenge,
    proof: &AuthorizationProof,
) -> Result<(), MailError> {
    if proof.challenge_id() != challenge.challenge_id
        || proof.key_id() != challenge.key_id
        || proof.signing_payload_sha256() != challenge.signing_sha256
    {
        return Err(MailError::stable(
            MailErrorCode::AuthorizationMalformed,
            "authorization proof does not match the challenge",
        ));
    }
    let expected_key = match challenge.action.policy().required_role {
        OwnerKeyRole::Owner => (
            authority.owner_key_id,
            authority.owner_public_key.as_bytes(),
        ),
        OwnerKeyRole::Recovery => (
            authority.recovery_key_id,
            authority.recovery_public_key.as_bytes(),
        ),
    };
    if challenge.key_id != expected_key.0
        || challenge.trust_epoch != authority.minimum_epoch
        || challenge.bundle_sha256 != authority.trust_bundle_sha256
    {
        return Err(recovery_error());
    }
    verify_authorization_signature(
        expected_key.1,
        &challenge.signing_payload,
        &proof.signature_bytes()?,
    )
}

fn receipt_projection(
    challenge: &StoredChallenge,
    receipt: &StoredReceipt,
    effective_time: i64,
) -> Result<AuthorizationReceiptProjection, MailError> {
    let payload =
        AuthorizationPayload::parse(&challenge.signing_payload).map_err(|_| recovery_error())?;
    let snapshot = payload.snapshot();
    Ok(AuthorizationReceiptProjection {
        contract_version: "kirje.authorization-receipt.v1".to_owned(),
        receipt_id: receipt.receipt_id,
        challenge_id: challenge.challenge_id,
        action: challenge.action,
        target_kind: snapshot.target_kind(),
        target_id: snapshot.target_display().as_str().to_owned(),
        key_fingerprint: challenge.key_id.fingerprint(),
        trust_epoch: challenge.trust_epoch,
        manifest_sha256: challenge.manifest_sha256,
        receipt_sha256: receipt.receipt_sha256,
        verified_at: utc_millis(receipt.verified_at)?,
        expires_at: utc_millis(receipt.expires_at)?,
        state: if effective_time > receipt.expires_at {
            AuthorizationReceiptState::Expired
        } else {
            AuthorizationReceiptState::Unclaimed
        },
    })
}

fn utc_millis(value: i64) -> Result<DateTime<Utc>, MailError> {
    Utc.timestamp_millis_opt(value)
        .single()
        .ok_or_else(recovery_error)
}

fn input_utc_millis(value: i64) -> Result<(), MailError> {
    Utc.timestamp_millis_opt(value)
        .single()
        .map(|_| ())
        .ok_or_else(|| MailError::invalid_input("authority timestamp is outside the contract"))
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(first >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() > 1 {
            output.push(char::from(
                ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))],
            ));
        }
        if chunk.len() > 2 {
            output.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
        }
    }
    output
}

fn digest_from_blob(bytes: &[u8]) -> Result<Sha256Digest, MailError> {
    Ok(Sha256Digest::from_bytes(exact::<32>(bytes)?))
}

fn digest_from_blob_sql(bytes: Vec<u8>) -> rusqlite::Result<Sha256Digest> {
    Ok(Sha256Digest::from_bytes(
        bytes
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    ))
}

fn optional_digest_from_blob_sql(bytes: Option<Vec<u8>>) -> rusqlite::Result<Option<Sha256Digest>> {
    bytes.map(digest_from_blob_sql).transpose()
}

fn uuid_from_blob_sql<T>(bytes: Vec<u8>) -> rusqlite::Result<T>
where
    T: TryFrom<Uuid>,
{
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    T::try_from(Uuid::from_bytes(bytes)).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn optional_uuid_from_blob_sql<T>(bytes: Option<Vec<u8>>) -> rusqlite::Result<Option<T>>
where
    T: TryFrom<Uuid>,
{
    bytes.map(uuid_from_blob_sql).transpose()
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
    preflight_authorization_storage(connection)?;
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

fn preflight_authorization_storage(connection: &Connection) -> Result<(), MailError> {
    challenge_preflight(connection, None)?;
    receipt_preflight(connection, None)?;
    nonce_preflight(connection)?;
    event_preflight(connection)
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
    let snapshot = BootstrapSnapshot {
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
    };
    validate_authorization_history(connection, &row.0, &snapshot, row.6)?;
    validate_events(
        connection,
        &row.0,
        snapshot.realm_id.as_bytes(),
        bundle,
        row.7,
        row.9,
        row.6,
    )?;
    Ok(LoadedSnapshot {
        snapshot,
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
    let forbidden_rows: i64 = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM registered_stores) +
                (SELECT COUNT(*) FROM registered_accounts) +
                (SELECT COUNT(*) FROM challenge_effects) +
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
    if authority_keys != 2 || trust_epochs != 1 || forbidden_rows != 0 {
        return Err(recovery_error());
    }
    Ok(())
}

fn validate_authorization_history(
    connection: &Connection,
    bootstrap_state: &str,
    authority: &BootstrapSnapshot,
    last_observed_at: i64,
) -> Result<(), MailError> {
    let challenge_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM authorization_challenges", [], |row| {
            row.get(0)
        })
        .map_err(|_| store_read_error())?;
    let receipt_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM authorization_receipts", [], |row| {
            row.get(0)
        })
        .map_err(|_| store_read_error())?;
    let nonce_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM nonce_uses", [], |row| row.get(0))
        .map_err(|_| store_read_error())?;
    if bootstrap_state != "ready" {
        if challenge_count != 0 || receipt_count != 0 || nonce_count != 0 {
            return Err(recovery_error());
        }
        return Ok(());
    }
    challenge_preflight(connection, None)?;
    receipt_preflight(connection, None)?;
    nonce_preflight(connection)?;

    let mut statement = connection
        .prepare(
            "SELECT challenge_id,grant_id,action,target_kind,target_id,store_id,account_id,
                    context_sha256,manifest,manifest_sha256,signing_payload,signing_sha256,
                    key_id,trust_epoch,bundle_sha256,binding_sha256,policy_sha256,nonce,
                    issued_at,expires_at,state,invalidated_at,created_event_sequence
             FROM authorization_challenges ORDER BY challenge_id",
        )
        .map_err(|_| store_read_error())?;
    let mut rows = statement.query([]).map_err(|_| store_read_error())?;
    let mut seen = 0_i64;
    let mut authorized = 0_i64;
    while let Some(row) = rows.next().map_err(|_| store_read_error())? {
        let challenge = stored_challenge_from_row(row).map_err(|_| recovery_error())?;
        validate_stored_challenge(connection, authority, &challenge, last_observed_at)?;
        seen = seen.checked_add(1).ok_or_else(recovery_error)?;
        if challenge.state == "authorized" {
            authorized = authorized.checked_add(1).ok_or_else(recovery_error)?;
        }
    }
    if seen != challenge_count || authorized != receipt_count || receipt_count != nonce_count {
        return Err(recovery_error());
    }
    Ok(())
}

fn validate_stored_challenge(
    connection: &Connection,
    authority: &BootstrapSnapshot,
    challenge: &StoredChallenge,
    last_observed_at: i64,
) -> Result<(), MailError> {
    utc_millis(challenge.issued_at)?;
    utc_millis(challenge.expires_at)?;
    if !matches!(
        challenge.state.as_str(),
        "pending" | "authorized" | "expired"
    ) || challenge.invalidated_at.is_some()
        || challenge.issued_at < 0
        || challenge.expires_at <= challenge.issued_at
        || challenge
            .expires_at
            .checked_sub(challenge.issued_at)
            .is_none_or(|lifetime| lifetime > AUTHORIZATION_LIFETIME_MS)
        || challenge.issued_at > last_observed_at
    {
        return Err(recovery_error());
    }
    ensure_t202b_action(challenge.action).map_err(|_| recovery_error())?;
    let manifest = ActionManifest::parse(&challenge.manifest).map_err(|_| recovery_error())?;
    let payload =
        AuthorizationPayload::parse(&challenge.signing_payload).map_err(|_| recovery_error())?;
    let snapshot = payload.snapshot();
    if manifest.canonical_bytes() != challenge.manifest
        || manifest.sha256() != challenge.manifest_sha256
        || manifest.action() != challenge.action
        || payload.canonical_bytes() != challenge.signing_payload
        || payload.challenge_id() != challenge.challenge_id
        || challenge.signing_sha256 != challenge.challenge_id
        || snapshot.owner_realm() != authority.realm_id
        || snapshot.action() != challenge.action
        || snapshot.target_kind().code() != challenge.target_kind_code
        || snapshot.target_bytes() != challenge.target_id
        || snapshot.store_id() != challenge.store_id
        || snapshot.account_id() != challenge.account_id
        || snapshot.manifest_sha256() != challenge.manifest_sha256
        || snapshot.binding_sha256() != challenge.binding_sha256
        || snapshot.policy_sha256() != challenge.policy_sha256
        || snapshot.bundle_sha256() != challenge.bundle_sha256
        || snapshot.signer_key_id() != challenge.key_id
        || snapshot.trust_epoch() != challenge.trust_epoch
        || snapshot.grant_id() != challenge.grant_id
        || snapshot.nonce() != &challenge.nonce
        || snapshot.issued_at_unix_ms() != challenge.issued_at
        || snapshot.expires_at_unix_ms() != challenge.expires_at
        || snapshot.effect().is_some()
    {
        return Err(recovery_error());
    }
    let expected_signer = match challenge.action.policy().required_role {
        OwnerKeyRole::Owner => authority.owner_key_id,
        OwnerKeyRole::Recovery => authority.recovery_key_id,
    };
    let expected_context = authorization_context_digest(
        challenge.action,
        snapshot.target_kind(),
        snapshot.target_bytes(),
        snapshot.store_id(),
        snapshot.account_id(),
        snapshot.manifest_sha256(),
        snapshot.binding_sha256(),
        snapshot.policy_sha256(),
        expected_signer,
        authority.minimum_epoch,
        authority.trust_bundle_sha256,
    );
    if challenge.key_id != expected_signer
        || challenge.trust_epoch != authority.minimum_epoch
        || challenge.bundle_sha256 != authority.trust_bundle_sha256
        || challenge.context_sha256 != expected_context
    {
        return Err(recovery_error());
    }
    validate_supported_manifest(connection, authority, &manifest).map_err(|_| recovery_error())?;
    let receipt = load_receipt_for_challenge(connection, challenge.challenge_id)?;
    let nonce = load_nonce_use(connection, challenge.challenge_id)?;
    match challenge.state.as_str() {
        "authorized" => {
            let receipt = receipt.ok_or_else(recovery_error)?;
            let nonce = nonce.ok_or_else(recovery_error)?;
            validate_stored_receipt(authority, challenge, &receipt, &nonce)?;
        }
        "pending" | "expired" if receipt.is_none() && nonce.is_none() => {}
        _ => return Err(recovery_error()),
    }
    Ok(())
}

fn validate_stored_receipt(
    authority: &BootstrapSnapshot,
    challenge: &StoredChallenge,
    receipt: &StoredReceipt,
    nonce: &StoredNonceUse,
) -> Result<(), MailError> {
    utc_millis(receipt.verified_at)?;
    utc_millis(receipt.expires_at)?;
    let proof = AuthorizationProof::parse_canonical(&receipt.canonical_proof)
        .map_err(|_| recovery_error())?;
    let expected_receipt = authorization_receipt(
        receipt.receipt_id,
        challenge,
        receipt.proof_sha256,
        receipt.verified_at,
    );
    let public_key = match challenge.action.policy().required_role {
        OwnerKeyRole::Owner => authority.owner_public_key.as_bytes(),
        OwnerKeyRole::Recovery => authority.recovery_public_key.as_bytes(),
    };
    if receipt.challenge_id != challenge.challenge_id
        || receipt.grant_id != challenge.grant_id
        || receipt.proof_sha256 != proof.proof_sha256()
        || receipt.key_id != challenge.key_id
        || receipt.signature != proof.signature_bytes().map_err(|_| recovery_error())?
        || proof.challenge_id() != challenge.challenge_id
        || proof.key_id() != challenge.key_id
        || proof.signing_payload_sha256() != challenge.signing_sha256
        || receipt.manifest_sha256 != challenge.manifest_sha256
        || receipt.signing_sha256 != challenge.signing_sha256
        || receipt.trust_epoch != challenge.trust_epoch
        || receipt.bundle_sha256 != challenge.bundle_sha256
        || receipt.receipt != expected_receipt
        || receipt.receipt_sha256 != Sha256Digest::digest(&expected_receipt)
        || receipt.verified_at < challenge.issued_at
        || receipt.verified_at > challenge.expires_at
        || receipt.expires_at != challenge.expires_at
        || nonce.nonce != challenge.nonce
        || nonce.challenge_id != challenge.challenge_id
        || nonce.receipt_id != receipt.receipt_id
        || nonce.consumed_at != receipt.verified_at
    {
        return Err(recovery_error());
    }
    verify_authorization_signature(public_key, &challenge.signing_payload, &receipt.signature)
        .map_err(|_| recovery_error())
}

struct StoredNonceUse {
    nonce: [u8; 32],
    challenge_id: Sha256Digest,
    receipt_id: AuthorizationReceiptId,
    consumed_at: i64,
}

fn nonce_preflight(connection: &Connection) -> Result<(), MailError> {
    let malformed: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM nonce_uses WHERE
             typeof(nonce)<>'blob' OR length(nonce)<>32 OR
             typeof(challenge_id)<>'blob' OR length(challenge_id)<>32 OR
             typeof(receipt_id)<>'blob' OR length(receipt_id)<>16 OR
             typeof(consumed_at)<>'integer' OR consumed_at<0",
            [],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if malformed != 0 {
        return Err(recovery_error());
    }
    Ok(())
}

fn load_nonce_use(
    connection: &Connection,
    challenge_id: Sha256Digest,
) -> Result<Option<StoredNonceUse>, MailError> {
    connection
        .query_row(
            "SELECT nonce,challenge_id,receipt_id,consumed_at
             FROM nonce_uses WHERE challenge_id=?1",
            [challenge_id.as_bytes()],
            |row| {
                Ok(StoredNonceUse {
                    nonce: row
                        .get::<_, Vec<u8>>(0)?
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    challenge_id: digest_from_blob_sql(row.get(1)?)?,
                    receipt_id: uuid_from_blob_sql(row.get(2)?)?,
                    consumed_at: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|_| store_read_error())
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
    last_observed_at: i64,
) -> Result<(), MailError> {
    event_preflight(connection)?;
    let mut statement = connection
        .prepare(
            "SELECT sequence,entity_kind,entity_id,event_code,source,occurred_at,
                    detail,detail_sha256
             FROM authority_events ORDER BY sequence",
        )
        .map_err(|_| store_read_error())?;
    let mut rows = statement.query([]).map_err(|_| store_read_error())?;
    let expected_prefix = match bootstrap_state {
        "pending_anchor" => 1_i64,
        "ready" => 2_i64,
        _ => return Err(recovery_error()),
    };
    let mut expected_sequence = 1_i64;
    while let Some(row) = rows.next().map_err(|_| store_read_error())? {
        let row = stored_authority_event_from_row(row).map_err(|_| store_read_error())?;
        if row.sequence != expected_sequence {
            return Err(recovery_error());
        }
        match row.sequence {
            1 => validate_event_row(&row, 1, realm_id, 1, 0, 0x0101, bundle, created_at)?,
            2 if expected_prefix == 2 => validate_event_row(
                &row,
                2,
                realm_id,
                2,
                0x0101,
                0x0102,
                bundle,
                anchor_confirmed_at.ok_or_else(recovery_error)?,
            )?,
            sequence if sequence > expected_prefix => {
                validate_challenge_event(connection, &row, last_observed_at)?;
            }
            _ => return Err(recovery_error()),
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(recovery_error)?;
    }
    let count = expected_sequence - 1;
    let sequence_high_water: Option<i64> = connection
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name='authority_events'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| store_read_error())?;
    if count < expected_prefix || sequence_high_water != Some(count) {
        return Err(recovery_error());
    }
    if expected_prefix == 1 && count != 1 {
        return Err(recovery_error());
    }
    validate_challenge_lifecycles(connection)?;
    Ok(())
}

fn event_preflight(connection: &Connection) -> Result<(), MailError> {
    let malformed: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM authority_events WHERE
             typeof(sequence)<>'integer' OR sequence<=0 OR
             typeof(entity_kind)<>'integer' OR entity_kind NOT BETWEEN 1 AND 13 OR
             typeof(entity_id)<>'blob' OR length(entity_id) NOT BETWEEN 1 AND 32 OR
             typeof(event_code)<>'integer' OR event_code NOT BETWEEN 1 AND 26 OR
             typeof(source)<>'integer' OR source NOT BETWEEN 1 AND 6 OR
             typeof(occurred_at)<>'integer' OR occurred_at<0 OR
             typeof(detail)<>'blob' OR length(detail) NOT BETWEEN 1 AND 65536 OR
             typeof(detail_sha256)<>'blob' OR length(detail_sha256)<>32",
            [],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if malformed != 0 {
        return Err(recovery_error());
    }
    Ok(())
}

fn stored_authority_event_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredAuthorityEvent> {
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
}

fn validate_challenge_event(
    connection: &Connection,
    row: &StoredAuthorityEvent,
    last_observed_at: i64,
) -> Result<(), MailError> {
    if row.entity_kind != 8 || row.entity_id.len() != 32 {
        return Err(recovery_error());
    }
    let challenge_id = digest_from_blob(&row.entity_id)?;
    let challenge = match load_challenge(connection, challenge_id) {
        Ok(challenge) => challenge,
        Err(error) if error.code == MailErrorCode::AuthorizationMalformed => {
            return Err(recovery_error());
        }
        Err(error) => return Err(error),
    };
    let (event, source, occurred_at) = match row.event_code {
        3 => (ChallengeEvent::Created, 1_i64, challenge.issued_at),
        4 => {
            let receipt = load_receipt_for_challenge(connection, challenge.challenge_id)?
                .ok_or_else(recovery_error)?;
            (ChallengeEvent::Authorized, 3, receipt.verified_at)
        }
        5 if row.occurred_at > challenge.expires_at && row.occurred_at <= last_observed_at => {
            (ChallengeEvent::Expired, 1, row.occurred_at)
        }
        _ => return Err(recovery_error()),
    };
    let receipt = if matches!(event, ChallengeEvent::Authorized) {
        load_receipt_for_challenge(connection, challenge.challenge_id)?
    } else {
        None
    };
    let (related_kind, related_id, prior_state, next_state, context, receipt_id) = match event {
        ChallengeEvent::Created => (
            10_u16,
            challenge.grant_id.as_bytes().as_slice(),
            0_u16,
            0x0801_u16,
            challenge.context_sha256,
            None,
        ),
        ChallengeEvent::Authorized => {
            let receipt = receipt.as_ref().ok_or_else(recovery_error)?;
            (
                9,
                receipt.receipt_id.as_bytes().as_slice(),
                0x0801,
                0x0802,
                receipt.receipt_sha256,
                Some(receipt.receipt_id),
            )
        }
        ChallengeEvent::Expired => (
            0,
            &[] as &[u8],
            0x0801,
            0x0803,
            challenge.context_sha256,
            None,
        ),
    };
    let expected_detail = authority_event_detail(
        u16::try_from(row.event_code).map_err(|_| recovery_error())?,
        8,
        challenge.challenge_id.as_bytes(),
        u8::try_from(source).map_err(|_| recovery_error())?,
        related_kind,
        related_id,
        prior_state,
        next_state,
        context,
        receipt_id,
        occurred_at,
    );
    if row.source != source
        || row.occurred_at != occurred_at
        || (matches!(event, ChallengeEvent::Created)
            && row.sequence != challenge.created_event_sequence)
        || row.detail != expected_detail
        || row.detail_sha256.as_slice() != Sha256::digest(&expected_detail).as_slice()
    {
        return Err(recovery_error());
    }
    Ok(())
}

struct PreviousChallengeLifecycle {
    context_sha256: Sha256Digest,
    state: String,
    terminal_event_sequence: Option<i64>,
}

fn validate_challenge_lifecycles(connection: &Connection) -> Result<(), MailError> {
    let mut statement = connection
        .prepare(
            "SELECT context_sha256,created_event_sequence,challenge_id,state
             FROM authorization_challenges
                  INDEXED BY authorization_challenges_context_created_sequence
             ORDER BY context_sha256,created_event_sequence,challenge_id",
        )
        .map_err(|_| store_read_error())?;
    let mut rows = statement.query([]).map_err(|_| store_read_error())?;
    let mut previous: Option<PreviousChallengeLifecycle> = None;
    while let Some(row) = rows.next().map_err(|_| store_read_error())? {
        let context_bytes = row.get::<_, Vec<u8>>(0).map_err(|_| recovery_error())?;
        let context_sha256 = digest_from_blob(&context_bytes)?;
        let created_event_sequence = row.get::<_, i64>(1).map_err(|_| recovery_error())?;
        let challenge_bytes = row.get::<_, Vec<u8>>(2).map_err(|_| recovery_error())?;
        let challenge_id = digest_from_blob(&challenge_bytes)?;
        let state = row.get::<_, String>(3).map_err(|_| recovery_error())?;
        let terminal_event_sequence = validate_challenge_event_graph(
            connection,
            challenge_id,
            created_event_sequence,
            &state,
        )?;

        if let Some(prior) = &previous
            && prior.context_sha256 == context_sha256
            && (!matches!(prior.state.as_str(), "authorized" | "expired")
                || prior
                    .terminal_event_sequence
                    .is_none_or(|sequence| sequence >= created_event_sequence))
        {
            return Err(recovery_error());
        }
        previous = Some(PreviousChallengeLifecycle {
            context_sha256,
            state,
            terminal_event_sequence,
        });
    }
    Ok(())
}

fn validate_challenge_event_graph(
    connection: &Connection,
    challenge_id: Sha256Digest,
    created_event_sequence: i64,
    state: &str,
) -> Result<Option<i64>, MailError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence,event_code FROM authority_events
                  INDEXED BY authority_events_entity_sequence
             WHERE entity_kind=8 AND entity_id=?1 AND event_code IN (3,4,5)
             ORDER BY sequence LIMIT 4",
        )
        .map_err(|_| store_read_error())?;
    let mut rows = statement
        .query([challenge_id.as_bytes()])
        .map_err(|_| store_read_error())?;
    let mut created = None;
    let mut authorized = None;
    let mut expired = None;
    while let Some(row) = rows.next().map_err(|_| store_read_error())? {
        let sequence = row.get::<_, i64>(0).map_err(|_| recovery_error())?;
        let event_code = row.get::<_, i64>(1).map_err(|_| recovery_error())?;
        let slot = match event_code {
            3 => &mut created,
            4 => &mut authorized,
            5 => &mut expired,
            _ => return Err(recovery_error()),
        };
        if slot.replace(sequence).is_some() {
            return Err(recovery_error());
        }
    }
    if created != Some(created_event_sequence) {
        return Err(recovery_error());
    }
    let terminal = match state {
        "pending" if authorized.is_none() && expired.is_none() => None,
        "authorized" if authorized.is_some() && expired.is_none() => authorized,
        "expired" if authorized.is_none() && expired.is_some() => expired,
        _ => return Err(recovery_error()),
    };
    if terminal.is_some_and(|sequence| sequence <= created_event_sequence) {
        return Err(recovery_error());
    }
    Ok(terminal)
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

#[derive(Clone, Copy)]
enum ChallengeEvent {
    Created,
    Authorized,
    Expired,
}

fn insert_challenge_event(
    transaction: &Transaction<'_>,
    challenge: &StoredChallenge,
    event: ChallengeEvent,
    receipt: Option<&StoredReceipt>,
    occurred_at: i64,
) -> Result<i64, MailError> {
    let (
        event_code,
        source,
        related_kind,
        related_id,
        prior_state,
        next_state,
        context,
        receipt_id,
    ) = match event {
        ChallengeEvent::Created => (
            3_u16,
            1_u8,
            10_u16,
            challenge.grant_id.as_bytes().as_slice(),
            0_u16,
            0x0801_u16,
            challenge.context_sha256,
            None,
        ),
        ChallengeEvent::Authorized => {
            let receipt = receipt.ok_or_else(recovery_error)?;
            (
                4,
                3,
                9,
                receipt.receipt_id.as_bytes().as_slice(),
                0x0801,
                0x0802,
                receipt.receipt_sha256,
                Some(receipt.receipt_id),
            )
        }
        ChallengeEvent::Expired => (
            5,
            1,
            0,
            &[] as &[u8],
            0x0801,
            0x0803,
            challenge.context_sha256,
            None,
        ),
    };
    let detail = authority_event_detail(
        event_code,
        8,
        challenge.challenge_id.as_bytes(),
        source,
        related_kind,
        related_id,
        prior_state,
        next_state,
        context,
        receipt_id,
        occurred_at,
    );
    let detail_sha256 = Sha256::digest(&detail);
    let inserted = transaction
        .execute(
            "INSERT INTO authority_events
             (entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256)
             VALUES(8,?1,?2,?3,?4,?5,?6)",
            params![
                challenge.challenge_id.as_bytes(),
                i64::from(event_code),
                i64::from(source),
                occurred_at,
                detail,
                detail_sha256.as_slice(),
            ],
        )
        .map_err(|_| store_write_error())?;
    if inserted != 1 {
        return Err(store_write_error());
    }
    let sequence = transaction.last_insert_rowid();
    if sequence <= 0 {
        return Err(recovery_error());
    }
    Ok(sequence)
}

#[allow(clippy::too_many_arguments)]
fn authority_event_detail(
    event_code: u16,
    entity_kind: u16,
    entity_id: &[u8],
    source: u8,
    related_kind: u16,
    related_id: &[u8],
    prior_state: u16,
    next_state: u16,
    context_digest: Sha256Digest,
    receipt_id: Option<AuthorizationReceiptId>,
    occurred_at: i64,
) -> Vec<u8> {
    let event_code = event_code.to_be_bytes();
    let entity_kind = entity_kind.to_be_bytes();
    let source = [source];
    let related_kind = related_kind.to_be_bytes();
    let prior_state = prior_state.to_be_bytes();
    let next_state = next_state.to_be_bytes();
    let receipt = receipt_id
        .map(|value| value.as_bytes().to_vec())
        .unwrap_or_default();
    let occurred_at = occurred_at.to_be_bytes();
    encode_transcript(
        EVENT_DETAIL_DOMAIN,
        &[
            &event_code,
            &entity_kind,
            entity_id,
            &source,
            &related_kind,
            related_id,
            &prior_state,
            &next_state,
            context_digest.as_bytes(),
            &receipt,
            &occurred_at,
        ],
    )
}

fn event_detail(
    realm_id: &[u8; 32],
    event_code: u16,
    prior_state: u16,
    next_state: u16,
    context_digest: Sha256Digest,
    occurred_at: i64,
) -> Vec<u8> {
    authority_event_detail(
        event_code,
        1,
        realm_id,
        2,
        0,
        &[],
        prior_state,
        next_state,
        context_digest,
        None,
        occurred_at,
    )
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

fn authorization_context_stale_error() -> MailError {
    MailError::stable(
        MailErrorCode::AuthorizationContextStale,
        "authorization context is stale",
    )
}

fn authorization_expired_error() -> MailError {
    MailError::stable(
        MailErrorCode::AuthorizationExpired,
        "authorization challenge has expired",
    )
}

fn authorization_replayed_error() -> MailError {
    MailError::stable(
        MailErrorCode::AuthorizationReplayed,
        "authorization proof conflicts with an immutable receipt",
    )
}
