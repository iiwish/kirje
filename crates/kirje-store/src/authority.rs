use std::{
    fs::{File, OpenOptions},
    num::NonZeroU64,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(feature = "test-support")]
use std::cell::Cell;
#[cfg(feature = "test-support")]
use std::sync::{
    Arc, Barrier, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use chrono::{DateTime, SecondsFormat, TimeZone as _, Utc};
use directories::ProjectDirs;
use kirje_core::{
    AccountId, AccountMutationManifest, ActionManifest, AuthorizationGrantId, AuthorizationPayload,
    AuthorizationProof, AuthorizationReceiptId, AuthorizationReceiptProjection,
    AuthorizationReceiptState, CleanupId, CleanupState, CredentialId, JournalId, LocatorKind,
    MailError, MailErrorCode, ManifestPayload, OwnerKeyRole, OwnerPublicKey, OwnerRealmId,
    PlatformLocationMaterial, SensitiveAction, Sha256Digest, StoreEnrollmentState, StoreId,
    TargetKind, TransitionId, TrustPermissionMask, owner_key_id, verify_authorization_signature,
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
const GRANT_USE_DOMAIN: &[u8] = b"KIRJE-GRANT-USE-V1\0";
const STORE_ENROLLMENT_INTENT_DOMAIN: &[u8] = b"KIRJE-STORE-ENROLLMENT-INTENT-V1\0";
const ACCOUNT_DISPLAY_ID_DOMAIN: &[u8] = b"KIRJE-ACCOUNT-DISPLAY-ID-V1\0";
const ACCOUNT_TRANSITION_DOMAIN: &[u8] = b"KIRJE-ACCOUNT-TRANSITION-V1\0";
const ACCOUNT_TRANSITION_INTENT_DOMAIN: &[u8] = b"KIRJE-ACCOUNT-TRANSITION-INTENT-V1\0";
const ACCOUNT_TRANSITION_RECOVERY_DOMAIN: &[u8] = b"KIRJE-ACCOUNT-TRANSITION-RECOVERY-V1\0";
const CREDENTIAL_LOCATOR_V2_DOMAIN: &[u8] = b"KIRJE-CREDENTIAL-LOCATOR-V2\0";
const DELETE_ONLY_LOCATOR_DOMAIN: &[u8] = b"KIRJE-DELETE-ONLY-LOCATOR-V1\0";
const CREDENTIAL_CLEANUP_TOMBSTONE_DOMAIN: &[u8] = b"KIRJE-CREDENTIAL-CLEANUP-TOMBSTONE-V1\0";
const ACTIVE_V2_LOCATOR_SERVICE: &[u8] = b"dev.kirje.mail.credentials.v2";
const LEGACY_V1_LOCATOR_SERVICE: &[u8] = b"dev.kirje.mail";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
const AUTHORIZATION_LIFETIME_MS: i64 = 900_000;

const TABLES: [&str; 20] = [
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
    "registered_account_versions",
    "registered_accounts",
    "registered_credentials",
    "registered_store_versions",
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

#[derive(Clone, Eq, PartialEq)]
pub struct GrantUseRequest {
    grant_id: AuthorizationGrantId,
    receipt_id: AuthorizationReceiptId,
    action: SensitiveAction,
    target_kind: TargetKind,
    target_bytes: Vec<u8>,
    manifest_sha256: Sha256Digest,
}

impl GrantUseRequest {
    /// Bind one bounded immutable grant-use identity.
    ///
    /// # Errors
    ///
    /// Returns invalid-input when action, target kind, or target bytes disagree.
    pub fn new(
        grant_id: AuthorizationGrantId,
        receipt_id: AuthorizationReceiptId,
        action: SensitiveAction,
        target_kind: TargetKind,
        target_bytes: Vec<u8>,
        manifest_sha256: Sha256Digest,
    ) -> Result<Self, MailError> {
        if action.policy().target_kind != target_kind
            || !valid_target_shape(target_kind, &target_bytes)
        {
            return Err(MailError::invalid_input(
                "grant target is outside the authorization contract",
            ));
        }
        Ok(Self {
            grant_id,
            receipt_id,
            action,
            target_kind,
            target_bytes,
            manifest_sha256,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EnrollStoreRequest {
    grant_use: GrantUseRequest,
    store_id: StoreId,
    location_material: PlatformLocationMaterial,
    location_bytes: Vec<u8>,
    location_sha256: Sha256Digest,
    config_generation: NonZeroU64,
    config_sha256: Sha256Digest,
    observed_at_unix_ms: i64,
}

impl EnrollStoreRequest {
    /// Bind one exact private platform location and initial config identity.
    ///
    /// # Errors
    ///
    /// Returns stable input/resource errors before any database access.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        grant_use: GrantUseRequest,
        store_id: StoreId,
        location_material: PlatformLocationMaterial,
        location_sha256: Sha256Digest,
        config_generation: NonZeroU64,
        config_sha256: Sha256Digest,
        observed_at_unix_ms: i64,
    ) -> Result<Self, MailError> {
        if observed_at_unix_ms < 0 {
            return Err(MailError::invalid_input(
                "authority observation time must be nonnegative",
            ));
        }
        input_utc_millis(observed_at_unix_ms)?;
        if config_generation.get() > u64::try_from(i64::MAX).unwrap_or(u64::MAX) {
            return Err(MailError::invalid_input(
                "config generation is outside the store range",
            ));
        }
        let location_bytes = location_material.canonical_bytes()?;
        if location_bytes.is_empty()
            || location_bytes.len() > 4_096
            || Sha256Digest::digest(&location_bytes) != location_sha256
        {
            return Err(MailError::invalid_input(
                "config location material does not match its digest",
            ));
        }
        Ok(Self {
            grant_use,
            store_id,
            location_material,
            location_bytes,
            location_sha256,
            config_generation,
            config_sha256,
            observed_at_unix_ms,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum EnrolledStoreState {
    Active,
}

#[derive(Clone, Eq, PartialEq)]
pub struct EnrolledStoreProjection {
    pub store_id: StoreId,
    pub state: EnrolledStoreState,
    pub config_generation: NonZeroU64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AccountTransitionKind {
    AccountCreate,
    AccountUpdate,
    AccountRemove,
    CredentialSet,
    CredentialDelete,
}

impl AccountTransitionKind {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::AccountCreate => 1,
            Self::AccountUpdate => 2,
            Self::AccountRemove => 3,
            Self::CredentialSet => 4,
            Self::CredentialDelete => 5,
        }
    }

    const fn database_name(self) -> &'static str {
        match self {
            Self::AccountCreate => "account_create",
            Self::AccountUpdate => "account_update",
            Self::AccountRemove => "account_remove",
            Self::CredentialSet => "credential_set",
            Self::CredentialDelete => "credential_delete",
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AccountTransitionState {
    Prepared,
    ConfigCommitted,
    Finalized,
    Aborted,
    RecoveryRequired,
}

impl AccountTransitionState {
    const fn event_state(self) -> u16 {
        match self {
            Self::Prepared => 0x0601,
            Self::ConfigCommitted => 0x0602,
            Self::Finalized => 0x0603,
            Self::Aborted => 0x0604,
            Self::RecoveryRequired => 0x0605,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RegisteredAccountState {
    Proposed,
    Active,
    Blocked,
    Removed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RegisteredStoreTransitionState {
    Active,
    Blocked,
    RecoveryRequired,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialCleanupReservation {
    cleanup_id: CleanupId,
    locator_kind: LocatorKind,
    locator_material: Vec<u8>,
    locator_sha256: Sha256Digest,
}

impl CredentialCleanupReservation {
    /// Seal bounded delete-only locator material for an account transition.
    ///
    /// The material is intentionally not printable, serializable, or exposed by
    /// any accessor. Authority compares its digest with the signed manifest.
    ///
    /// # Errors
    ///
    /// Returns invalid-input when material is not the canonical closed locator form.
    pub fn new(
        cleanup_id: CleanupId,
        locator_kind: LocatorKind,
        locator_material: Vec<u8>,
    ) -> Result<Self, MailError> {
        let (encoded_kind, service, username) = parse_delete_only_locator(&locator_material)
            .ok_or_else(|| {
                MailError::invalid_input("cleanup locator material is outside the contract")
            })?;
        if encoded_kind != locator_kind
            || !delete_only_locator_shape_is_valid(encoded_kind, service, username)
        {
            return Err(MailError::invalid_input(
                "cleanup locator material is outside the contract",
            ));
        }
        let locator_sha256 = Sha256Digest::digest(&locator_material);
        Ok(Self {
            cleanup_id,
            locator_kind,
            locator_material,
            locator_sha256,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PrepareAccountTransitionRequest {
    grant_use: GrantUseRequest,
    transition_id: TransitionId,
    store_id: StoreId,
    account_id: AccountId,
    kind: AccountTransitionKind,
    before_config_sha256: Sha256Digest,
    after_config_sha256: Sha256Digest,
    expected_generation: NonZeroU64,
    next_generation: NonZeroU64,
    display_id_sha256: Sha256Digest,
    account_generation: NonZeroU64,
    credential_id: CredentialId,
    binding_sha256: Sha256Digest,
    cleanup_reservations: Vec<CredentialCleanupReservation>,
    observed_at_unix_ms: i64,
}

impl PrepareAccountTransitionRequest {
    /// Bind an exact account transition reservation to one authorized grant.
    ///
    /// # Errors
    ///
    /// Returns invalid-input when generations, time, or create identity are invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        grant_use: GrantUseRequest,
        transition_id: TransitionId,
        store_id: StoreId,
        account_id: AccountId,
        kind: AccountTransitionKind,
        before_config_sha256: Sha256Digest,
        after_config_sha256: Sha256Digest,
        expected_generation: NonZeroU64,
        next_generation: NonZeroU64,
        display_id_sha256: Sha256Digest,
        account_generation: NonZeroU64,
        credential_id: CredentialId,
        binding_sha256: Sha256Digest,
        observed_at_unix_ms: i64,
    ) -> Result<Self, MailError> {
        input_utc_millis(observed_at_unix_ms)?;
        let max = u64::try_from(i64::MAX).unwrap_or(u64::MAX);
        if expected_generation.get() > max
            || next_generation.get() > max
            || expected_generation.get().checked_add(1) != Some(next_generation.get())
            || before_config_sha256 == after_config_sha256
            || (kind == AccountTransitionKind::AccountCreate && account_generation.get() != 1)
        {
            return Err(MailError::invalid_input(
                "account transition request is outside the contract",
            ));
        }
        Ok(Self {
            grant_use,
            transition_id,
            store_id,
            account_id,
            kind,
            before_config_sha256,
            after_config_sha256,
            expected_generation,
            next_generation,
            display_id_sha256,
            account_generation,
            credential_id,
            binding_sha256,
            cleanup_reservations: Vec::new(),
            observed_at_unix_ms,
        })
    }

    /// Attach the private cleanup reservations sealed by an update manifest.
    ///
    /// # Errors
    ///
    /// Returns invalid-input for an unsupported transition kind, an empty or
    /// oversized list, or duplicate cleanup identities or locator digests.
    pub fn with_cleanup_reservations(
        mut self,
        cleanup_reservations: Vec<CredentialCleanupReservation>,
    ) -> Result<Self, MailError> {
        if !matches!(
            self.kind,
            AccountTransitionKind::AccountUpdate | AccountTransitionKind::AccountRemove
        ) || cleanup_reservations.is_empty()
            || cleanup_reservations.len() > 100
            || cleanup_reservations
                .iter()
                .enumerate()
                .any(|(index, item)| {
                    cleanup_reservations[..index].iter().any(|prior| {
                        prior.cleanup_id == item.cleanup_id
                            || prior.locator_sha256 == item.locator_sha256
                    })
                })
        {
            return Err(MailError::invalid_input(
                "cleanup reservations are outside the transition contract",
            ));
        }
        self.cleanup_reservations = cleanup_reservations;
        Ok(self)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AccountTransitionObservationRequest {
    transition_id: TransitionId,
    source_state: AccountTransitionState,
    actual_config_generation: NonZeroU64,
    actual_config_sha256: Sha256Digest,
    observed_at_unix_ms: i64,
}

impl AccountTransitionObservationRequest {
    /// Bind one exact local config observation to a declared transition phase.
    ///
    /// # Errors
    ///
    /// Returns invalid-input for a nonrepresentable time or generation.
    pub fn new(
        transition_id: TransitionId,
        source_state: AccountTransitionState,
        actual_config_generation: NonZeroU64,
        actual_config_sha256: Sha256Digest,
        observed_at_unix_ms: i64,
    ) -> Result<Self, MailError> {
        input_utc_millis(observed_at_unix_ms)?;
        if actual_config_generation.get() > u64::try_from(i64::MAX).unwrap_or(u64::MAX) {
            return Err(MailError::invalid_input(
                "account transition generation is outside the store range",
            ));
        }
        Ok(Self {
            transition_id,
            source_state,
            actual_config_generation,
            actual_config_sha256,
            observed_at_unix_ms,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AccountTransitionProjection {
    pub transition_id: TransitionId,
    pub account_id: AccountId,
    pub transition_state: AccountTransitionState,
    pub account_state: RegisteredAccountState,
    pub store_state: RegisteredStoreTransitionState,
    pub config_generation: NonZeroU64,
    pub account_generation: NonZeroU64,
    pub prepared_at: DateTime<Utc>,
}

/// Input for atomically consuming one cleanup authorization grant.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialCleanupClaimRequest {
    grant_use: GrantUseRequest,
    cleanup_id: CleanupId,
    observed_at_unix_ms: i64,
}

impl CredentialCleanupClaimRequest {
    /// Bind one exact cleanup target to its immutable authorization grant.
    ///
    /// # Errors
    ///
    /// Rejects non-cleanup grants, mismatched targets, and invalid timestamps.
    pub fn new(
        grant_use: GrantUseRequest,
        cleanup_id: CleanupId,
        observed_at_unix_ms: i64,
    ) -> Result<Self, MailError> {
        if grant_use.action != SensitiveAction::CredentialCleanup
            || grant_use.target_kind != TargetKind::Cleanup
            || grant_use.target_bytes.as_slice() != cleanup_id.as_bytes()
            || observed_at_unix_ms < 0
        {
            return Err(credential_cleanup_invalid_error());
        }
        input_utc_millis(observed_at_unix_ms)?;
        Ok(Self {
            grant_use,
            cleanup_id,
            observed_at_unix_ms,
        })
    }
}

/// Durable public state for a credential-cleanup lifecycle.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialCleanupProjection {
    pub cleanup_id: CleanupId,
    pub state: CleanupState,
    pub claimed_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Result of claiming or exactly recovering one cleanup grant.
pub struct CredentialCleanupClaimOutcome {
    pub projection: CredentialCleanupProjection,
    pub permit: Option<CleanupDeletePermit>,
}

/// Opaque single-owner permission to invoke the delete-only credential boundary.
pub struct CleanupDeletePermit {
    cleanup_id: CleanupId,
    grant_id: AuthorizationGrantId,
    receipt_id: AuthorizationReceiptId,
    use_sha256: Sha256Digest,
    locator_material: Vec<u8>,
    database_path: PathBuf,
    _apply_lock: File,
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

    /// Install a deterministic delete-only backend result for isolated tests.
    #[must_use]
    pub fn with_credential_delete_probe(mut self, calls: Arc<AtomicUsize>, fail: bool) -> Self {
        self.test_hooks.credential_delete = Some(CredentialDeleteTestHook { calls, fail });
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
    GrantUseInserted,
    GrantUsedEvent,
    RegisteredStoreInserted,
    RegisteredStoreVersionInserted,
    StoreEnrolledEvent,
    EnrollmentClockUpdated,
    EnrollmentBeforeCommit,
    EnrollmentAfterCommit,
    EnrollmentExpiredState,
    EnrollmentExpiryClockUpdated,
    EnrollmentExpiryEvent,
    EnrollmentExpiryAfterCommit,
    EnrollmentChallengeRead,
    AccountStoreBlocked,
    AccountForeignKeysDeferred,
    RegisteredAccountInserted,
    AccountTransitionInserted,
    RegisteredCredentialInserted,
    AccountCleanupInserted,
    AccountForeignKeyChecked,
    AccountStoreBlockedEvent,
    AccountTransitionPreparedEvent,
    AccountPrepareClockUpdated,
    AccountPrepareBeforeCommit,
    AccountPrepareAfterCommit,
    AccountStoreVersionInserted,
    AccountVersionInserted,
    AccountTransitionCommitted,
    AccountStoreCommitted,
    AccountConfigCommittedEvent,
    AccountConfigClockUpdated,
    AccountConfigBeforeCommit,
    AccountConfigAfterCommit,
    AccountFinalizeAccountUpdated,
    AccountFinalizeTransitionUpdated,
    AccountFinalizeStoreUpdated,
    AccountFinalizeCleanupUpdated,
    AccountFinalizeTransitionEvent,
    AccountFinalizeStoreEvent,
    AccountFinalizeClockUpdated,
    AccountFinalizeBeforeCommit,
    AccountFinalizeAfterCommit,
    AccountAbortAccountUpdated,
    AccountAbortTransitionUpdated,
    AccountAbortStoreUpdated,
    AccountAbortTransitionEvent,
    AccountAbortStoreEvent,
    AccountAbortClockUpdated,
    AccountAbortBeforeCommit,
    AccountAbortAfterCommit,
    AccountRecoveryAccountUpdated,
    AccountRecoveryTransitionUpdated,
    AccountRecoveryStoreUpdated,
    AccountRecoveryStoreEvent,
    AccountRecoveryTransitionEvent,
    AccountRecoveryClockUpdated,
    AccountRecoveryBeforeCommit,
    AccountRecoveryAfterCommit,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Default)]
pub struct AuthorityValidationQueryCounts {
    pub challenge_preflight: u64,
    pub receipt_preflight: u64,
    pub nonce_preflight: u64,
    pub grant_preflight: u64,
    pub store_preflight: u64,
    pub event_preflight: u64,
    pub registry_parent_preflight: u64,
    pub registry_stream: u64,
    pub bounded_keyed: u64,
}

#[cfg(feature = "test-support")]
std::thread_local! {
    static AUTHORITY_VALIDATION_QUERY_COUNTS: Cell<AuthorityValidationQueryCounts> =
        const { Cell::new(AuthorityValidationQueryCounts {
            challenge_preflight: 0,
            receipt_preflight: 0,
            nonce_preflight: 0,
            grant_preflight: 0,
            store_preflight: 0,
            event_preflight: 0,
            registry_parent_preflight: 0,
            registry_stream: 0,
            bounded_keyed: 0,
        }) };
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn reset_authority_validation_query_counts() {
    AUTHORITY_VALIDATION_QUERY_COUNTS.set(AuthorityValidationQueryCounts::default());
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
#[must_use]
pub fn take_authority_validation_query_counts() -> AuthorityValidationQueryCounts {
    AUTHORITY_VALIDATION_QUERY_COUNTS.replace(AuthorityValidationQueryCounts::default())
}

#[derive(Clone, Copy)]
enum ValidationQueryKind {
    ChallengePreflight,
    ReceiptPreflight,
    NoncePreflight,
    GrantPreflight,
    StorePreflight,
    EventPreflight,
    RegistryParentPreflight,
    RegistryStream,
    BoundedKeyed,
}

fn record_validation_query(kind: ValidationQueryKind) {
    #[cfg(feature = "test-support")]
    AUTHORITY_VALIDATION_QUERY_COUNTS.with(|cell| {
        let mut counts = cell.get();
        match kind {
            ValidationQueryKind::ChallengePreflight => counts.challenge_preflight += 1,
            ValidationQueryKind::ReceiptPreflight => counts.receipt_preflight += 1,
            ValidationQueryKind::NoncePreflight => counts.nonce_preflight += 1,
            ValidationQueryKind::GrantPreflight => counts.grant_preflight += 1,
            ValidationQueryKind::StorePreflight => counts.store_preflight += 1,
            ValidationQueryKind::EventPreflight => counts.event_preflight += 1,
            ValidationQueryKind::RegistryParentPreflight => {
                counts.registry_parent_preflight += 1;
            }
            ValidationQueryKind::RegistryStream => counts.registry_stream += 1,
            ValidationQueryKind::BoundedKeyed => counts.bounded_keyed += 1,
        }
        cell.set(counts);
    });
    #[cfg(not(feature = "test-support"))]
    let _ = kind;
}

#[derive(Clone, Default)]
struct AuthorityTestHooks {
    #[cfg(feature = "test-support")]
    open_snapshot: Option<TestPause>,
    #[cfg(feature = "test-support")]
    prepare_retry: Option<TestPause>,
    #[cfg(feature = "test-support")]
    fault: Option<AuthorityFaultPoint>,
    #[cfg(feature = "test-support")]
    credential_delete: Option<CredentialDeleteTestHook>,
}

#[cfg(feature = "test-support")]
#[derive(Clone)]
struct CredentialDeleteTestHook {
    calls: Arc<AtomicUsize>,
    fail: bool,
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

    fn read_fault(&self, point: TestFaultPoint) -> Result<(), MailError> {
        #[cfg(feature = "test-support")]
        if self.fault == Some(point.into()) {
            return Err(store_read_error());
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
    GrantUseInserted,
    GrantUsedEvent,
    RegisteredStoreInserted,
    RegisteredStoreVersionInserted,
    StoreEnrolledEvent,
    EnrollmentClockUpdated,
    EnrollmentBeforeCommit,
    EnrollmentAfterCommit,
    EnrollmentExpiredState,
    EnrollmentExpiryClockUpdated,
    EnrollmentExpiryEvent,
    EnrollmentExpiryAfterCommit,
    EnrollmentChallengeRead,
    AccountStoreBlocked,
    AccountForeignKeysDeferred,
    RegisteredAccountInserted,
    AccountTransitionInserted,
    RegisteredCredentialInserted,
    AccountCleanupInserted,
    AccountForeignKeyChecked,
    AccountStoreBlockedEvent,
    AccountTransitionPreparedEvent,
    AccountPrepareClockUpdated,
    AccountPrepareBeforeCommit,
    AccountPrepareAfterCommit,
    AccountStoreVersionInserted,
    AccountVersionInserted,
    AccountTransitionCommitted,
    AccountStoreCommitted,
    AccountConfigCommittedEvent,
    AccountConfigClockUpdated,
    AccountConfigBeforeCommit,
    AccountConfigAfterCommit,
    AccountFinalizeAccountUpdated,
    AccountFinalizeTransitionUpdated,
    AccountFinalizeStoreUpdated,
    AccountFinalizeCleanupUpdated,
    AccountFinalizeTransitionEvent,
    AccountFinalizeStoreEvent,
    AccountFinalizeClockUpdated,
    AccountFinalizeBeforeCommit,
    AccountFinalizeAfterCommit,
    AccountAbortAccountUpdated,
    AccountAbortTransitionUpdated,
    AccountAbortStoreUpdated,
    AccountAbortTransitionEvent,
    AccountAbortStoreEvent,
    AccountAbortClockUpdated,
    AccountAbortBeforeCommit,
    AccountAbortAfterCommit,
    AccountRecoveryAccountUpdated,
    AccountRecoveryTransitionUpdated,
    AccountRecoveryStoreUpdated,
    AccountRecoveryStoreEvent,
    AccountRecoveryTransitionEvent,
    AccountRecoveryClockUpdated,
    AccountRecoveryBeforeCommit,
    AccountRecoveryAfterCommit,
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
            TestFaultPoint::GrantUseInserted => Self::GrantUseInserted,
            TestFaultPoint::GrantUsedEvent => Self::GrantUsedEvent,
            TestFaultPoint::RegisteredStoreInserted => Self::RegisteredStoreInserted,
            TestFaultPoint::RegisteredStoreVersionInserted => Self::RegisteredStoreVersionInserted,
            TestFaultPoint::StoreEnrolledEvent => Self::StoreEnrolledEvent,
            TestFaultPoint::EnrollmentClockUpdated => Self::EnrollmentClockUpdated,
            TestFaultPoint::EnrollmentBeforeCommit => Self::EnrollmentBeforeCommit,
            TestFaultPoint::EnrollmentAfterCommit => Self::EnrollmentAfterCommit,
            TestFaultPoint::EnrollmentExpiredState => Self::EnrollmentExpiredState,
            TestFaultPoint::EnrollmentExpiryClockUpdated => Self::EnrollmentExpiryClockUpdated,
            TestFaultPoint::EnrollmentExpiryEvent => Self::EnrollmentExpiryEvent,
            TestFaultPoint::EnrollmentExpiryAfterCommit => Self::EnrollmentExpiryAfterCommit,
            TestFaultPoint::EnrollmentChallengeRead => Self::EnrollmentChallengeRead,
            TestFaultPoint::AccountStoreBlocked => Self::AccountStoreBlocked,
            TestFaultPoint::AccountForeignKeysDeferred => Self::AccountForeignKeysDeferred,
            TestFaultPoint::RegisteredAccountInserted => Self::RegisteredAccountInserted,
            TestFaultPoint::AccountTransitionInserted => Self::AccountTransitionInserted,
            TestFaultPoint::RegisteredCredentialInserted => Self::RegisteredCredentialInserted,
            TestFaultPoint::AccountCleanupInserted => Self::AccountCleanupInserted,
            TestFaultPoint::AccountForeignKeyChecked => Self::AccountForeignKeyChecked,
            TestFaultPoint::AccountStoreBlockedEvent => Self::AccountStoreBlockedEvent,
            TestFaultPoint::AccountTransitionPreparedEvent => Self::AccountTransitionPreparedEvent,
            TestFaultPoint::AccountPrepareClockUpdated => Self::AccountPrepareClockUpdated,
            TestFaultPoint::AccountPrepareBeforeCommit => Self::AccountPrepareBeforeCommit,
            TestFaultPoint::AccountPrepareAfterCommit => Self::AccountPrepareAfterCommit,
            TestFaultPoint::AccountStoreVersionInserted => Self::AccountStoreVersionInserted,
            TestFaultPoint::AccountVersionInserted => Self::AccountVersionInserted,
            TestFaultPoint::AccountTransitionCommitted => Self::AccountTransitionCommitted,
            TestFaultPoint::AccountStoreCommitted => Self::AccountStoreCommitted,
            TestFaultPoint::AccountConfigCommittedEvent => Self::AccountConfigCommittedEvent,
            TestFaultPoint::AccountConfigClockUpdated => Self::AccountConfigClockUpdated,
            TestFaultPoint::AccountConfigBeforeCommit => Self::AccountConfigBeforeCommit,
            TestFaultPoint::AccountConfigAfterCommit => Self::AccountConfigAfterCommit,
            TestFaultPoint::AccountFinalizeAccountUpdated => Self::AccountFinalizeAccountUpdated,
            TestFaultPoint::AccountFinalizeTransitionUpdated => {
                Self::AccountFinalizeTransitionUpdated
            }
            TestFaultPoint::AccountFinalizeStoreUpdated => Self::AccountFinalizeStoreUpdated,
            TestFaultPoint::AccountFinalizeCleanupUpdated => Self::AccountFinalizeCleanupUpdated,
            TestFaultPoint::AccountFinalizeTransitionEvent => Self::AccountFinalizeTransitionEvent,
            TestFaultPoint::AccountFinalizeStoreEvent => Self::AccountFinalizeStoreEvent,
            TestFaultPoint::AccountFinalizeClockUpdated => Self::AccountFinalizeClockUpdated,
            TestFaultPoint::AccountFinalizeBeforeCommit => Self::AccountFinalizeBeforeCommit,
            TestFaultPoint::AccountFinalizeAfterCommit => Self::AccountFinalizeAfterCommit,
            TestFaultPoint::AccountAbortAccountUpdated => Self::AccountAbortAccountUpdated,
            TestFaultPoint::AccountAbortTransitionUpdated => Self::AccountAbortTransitionUpdated,
            TestFaultPoint::AccountAbortStoreUpdated => Self::AccountAbortStoreUpdated,
            TestFaultPoint::AccountAbortTransitionEvent => Self::AccountAbortTransitionEvent,
            TestFaultPoint::AccountAbortStoreEvent => Self::AccountAbortStoreEvent,
            TestFaultPoint::AccountAbortClockUpdated => Self::AccountAbortClockUpdated,
            TestFaultPoint::AccountAbortBeforeCommit => Self::AccountAbortBeforeCommit,
            TestFaultPoint::AccountAbortAfterCommit => Self::AccountAbortAfterCommit,
            TestFaultPoint::AccountRecoveryAccountUpdated => Self::AccountRecoveryAccountUpdated,
            TestFaultPoint::AccountRecoveryTransitionUpdated => {
                Self::AccountRecoveryTransitionUpdated
            }
            TestFaultPoint::AccountRecoveryStoreUpdated => Self::AccountRecoveryStoreUpdated,
            TestFaultPoint::AccountRecoveryStoreEvent => Self::AccountRecoveryStoreEvent,
            TestFaultPoint::AccountRecoveryTransitionEvent => Self::AccountRecoveryTransitionEvent,
            TestFaultPoint::AccountRecoveryClockUpdated => Self::AccountRecoveryClockUpdated,
            TestFaultPoint::AccountRecoveryBeforeCommit => Self::AccountRecoveryBeforeCommit,
            TestFaultPoint::AccountRecoveryAfterCommit => Self::AccountRecoveryAfterCommit,
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
        ensure_supported_challenge_action(request.manifest.action())?;

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
        validate_intrinsic_manifest(&loaded.snapshot, &request.manifest)?;

        let signer_key_id = match request.manifest.action().policy().required_role {
            OwnerKeyRole::Owner => loaded.snapshot.owner_key_id,
            OwnerKeyRole::Recovery => loaded.snapshot.recovery_key_id,
        };
        let manifest_snapshot = request.manifest.context();
        let cleanup_action = request.manifest.action() == SensitiveAction::CredentialCleanup;
        if cleanup_action {
            validate_credential_cleanup_public_pair(&transaction, &request.manifest)?;
            validate_fresh_manifest_context(&transaction, &loaded.snapshot, &request.manifest)?;
        }

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

        if !cleanup_action {
            validate_fresh_manifest_context(&transaction, &loaded.snapshot, &request.manifest)?;
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
            let projection =
                receipt_projection(&transaction, &challenge, &receipt, effective_time)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            return Ok(projection);
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
        let projection =
            receipt_projection(&transaction, &challenge, &stored_receipt, effective_time)?;
        transaction.commit().map_err(|_| store_write_error())?;
        secure_authority_files(&self.home.database)?;
        self.test_hooks.fault(TestFaultPoint::ProofAfterCommit)?;
        Ok(projection)
    }

    /// Consume one immutable store-enrollment receipt and register its exact store.
    ///
    /// # Errors
    ///
    /// Returns stable replay, expiry, context, identity, recovery, clock, or store errors.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn enroll_store(
        &self,
        request: EnrollStoreRequest,
    ) -> Result<EnrolledStoreProjection, MailError> {
        validate_enroll_store_request(&request)?;
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

        if let Some(grant) = load_grant_use(&transaction, request.grant_use.grant_id)? {
            if !grant.matches_request(&request.grant_use) {
                return Err(grant_already_used_error());
            }
            let receipt = load_receipt_by_id(&transaction, request.grant_use.receipt_id)?
                .ok_or_else(recovery_error)?;
            let challenge = load_challenge(&transaction, receipt.challenge_id)?;
            let enrollment = validate_enrollment_identity(&request, &challenge, &receipt)?;
            let store = load_registered_store_by_receipt(&transaction, receipt.receipt_id)?
                .ok_or_else(recovery_error)?;
            if !store.matches_request(&request, &enrollment) {
                return Err(authorization_context_stale_error());
            }
            let version = load_store_version_by_receipt(&transaction, receipt.receipt_id)?
                .ok_or_else(recovery_error)?;
            validate_initial_store_version(&version, &store, &enrollment, &receipt)?;
            let effective_time =
                checked_clock(loaded.last_observed_at, request.observed_at_unix_ms)?;
            utc_millis(effective_time)?;
            observe_clock_pair(&transaction, effective_time)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            return enrolled_store_projection(&version);
        }

        let receipt = load_receipt_by_id(&transaction, request.grant_use.receipt_id)?
            .ok_or_else(authorization_context_stale_error)?;
        let challenge = classify_enrollment_challenge_result(
            self.test_hooks
                .read_fault(TestFaultPoint::EnrollmentChallengeRead)
                .and_then(|()| load_challenge(&transaction, receipt.challenge_id)),
        )?;
        let _enrollment = validate_enrollment_identity(&request, &challenge, &receipt)?;
        let intent_sha256 = enrollment_intent_digest(&request);
        let effective_time = checked_clock(loaded.last_observed_at, request.observed_at_unix_ms)?;
        utc_millis(effective_time)?;

        if challenge.state == "expired" {
            validate_exact_enrollment_expiry(&transaction, &challenge, &receipt, intent_sha256)?;
            observe_clock_pair(&transaction, effective_time)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            return Err(authorization_expired_error());
        }
        if challenge.state != "authorized" {
            return Err(authorization_context_stale_error());
        }
        if effective_time > receipt.expires_at {
            let changed = transaction
                .execute(
                    "UPDATE authorization_challenges SET state='expired'
                     WHERE challenge_id=?1 AND state='authorized'",
                    [challenge.challenge_id.as_bytes()],
                )
                .map_err(|_| store_write_error())?;
            if changed != 1 {
                return Err(recovery_error());
            }
            self.test_hooks
                .fault(TestFaultPoint::EnrollmentExpiredState)?;
            observe_clock_pair(&transaction, effective_time)?;
            self.test_hooks
                .fault(TestFaultPoint::EnrollmentExpiryClockUpdated)?;
            insert_enrollment_expiry_event(
                &transaction,
                &challenge,
                &receipt,
                intent_sha256,
                effective_time,
            )?;
            self.test_hooks
                .fault(TestFaultPoint::EnrollmentExpiryEvent)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            self.test_hooks
                .fault(TestFaultPoint::EnrollmentExpiryAfterCommit)?;
            return Err(authorization_expired_error());
        }

        if store_identity_count(&transaction, request.store_id, request.location_sha256)? != 0 {
            return Err(config_store_identity_conflict_error());
        }
        let use_receipt = grant_use_transcript(&request.grant_use, effective_time);
        let use_sha256 = Sha256Digest::digest(&use_receipt);
        let inserted = transaction
            .execute(
                "INSERT INTO grant_uses
                 (grant_id,receipt_id,action,target_kind,target_id,manifest_sha256,
                  use_receipt,use_sha256,used_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    request.grant_use.grant_id.as_bytes(),
                    request.grant_use.receipt_id.as_bytes(),
                    i64::from(request.grant_use.action.code()),
                    i64::from(request.grant_use.target_kind.code()),
                    &request.grant_use.target_bytes,
                    request.grant_use.manifest_sha256.as_bytes(),
                    &use_receipt,
                    use_sha256.as_bytes(),
                    effective_time,
                ],
            )
            .map_err(|_| store_write_error())?;
        if inserted != 1 {
            return Err(store_write_error());
        }
        self.test_hooks.fault(TestFaultPoint::GrantUseInserted)?;
        insert_grant_used_event(
            &transaction,
            request.grant_use.grant_id,
            receipt.receipt_id,
            use_sha256,
            effective_time,
        )?;
        self.test_hooks.fault(TestFaultPoint::GrantUsedEvent)?;
        let inserted = transaction
            .execute(
                "INSERT INTO registered_stores
                 (store_id,location_material,location_sha256,config_generation,config_sha256,
                  state,enrolled_receipt_id,created_at,updated_at,removed_at)
                 VALUES(?1,?2,?3,?4,?5,'active',?6,?7,?7,NULL)",
                params![
                    request.store_id.as_bytes(),
                    &request.location_bytes,
                    request.location_sha256.as_bytes(),
                    i64::try_from(request.config_generation.get())
                        .map_err(|_| authorization_context_stale_error())?,
                    request.config_sha256.as_bytes(),
                    receipt.receipt_id.as_bytes(),
                    effective_time,
                ],
            )
            .map_err(|_| store_write_error())?;
        if inserted != 1 {
            return Err(store_write_error());
        }
        self.test_hooks
            .fault(TestFaultPoint::RegisteredStoreInserted)?;
        let inserted = transaction
            .execute(
                "INSERT INTO registered_store_versions
                 (store_id,location_sha256,config_generation,config_sha256,
                  enrolled_receipt_id,committed_transition_id,created_at)
                 VALUES(?1,?2,?3,?4,?5,NULL,?6)",
                params![
                    request.store_id.as_bytes(),
                    request.location_sha256.as_bytes(),
                    i64::try_from(request.config_generation.get())
                        .map_err(|_| authorization_context_stale_error())?,
                    request.config_sha256.as_bytes(),
                    receipt.receipt_id.as_bytes(),
                    effective_time,
                ],
            )
            .map_err(|_| store_write_error())?;
        if inserted != 1 {
            return Err(store_write_error());
        }
        self.test_hooks
            .fault(TestFaultPoint::RegisteredStoreVersionInserted)?;
        insert_store_enrolled_event(
            &transaction,
            request.store_id,
            request.grant_use.grant_id,
            receipt.receipt_id,
            use_sha256,
            effective_time,
        )?;
        self.test_hooks.fault(TestFaultPoint::StoreEnrolledEvent)?;
        observe_clock_pair(&transaction, effective_time)?;
        self.test_hooks
            .fault(TestFaultPoint::EnrollmentClockUpdated)?;
        self.test_hooks
            .fault(TestFaultPoint::EnrollmentBeforeCommit)?;
        transaction.commit().map_err(|_| store_write_error())?;
        secure_authority_files(&self.home.database)?;
        self.test_hooks
            .fault(TestFaultPoint::EnrollmentAfterCommit)?;
        enrolled_store_projection(&StoredRegisteredStoreVersion {
            store_id: request.store_id,
            location_sha256: request.location_sha256,
            config_generation: request.config_generation,
            config_sha256: request.config_sha256,
            enrolled_receipt_id: Some(receipt.receipt_id),
            committed_transition_id: None,
            created_at: effective_time,
        })
    }

    /// Reserve one supported authorized account or credential transition.
    ///
    /// # Errors
    ///
    /// Returns a stable transition, authorization, clock, recovery, or store error.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn prepare_account_transition(
        &self,
        request: PrepareAccountTransitionRequest,
    ) -> Result<AccountTransitionProjection, MailError> {
        if !matches!(
            request.kind,
            AccountTransitionKind::AccountCreate
                | AccountTransitionKind::AccountUpdate
                | AccountTransitionKind::AccountRemove
                | AccountTransitionKind::CredentialSet
                | AccountTransitionKind::CredentialDelete
        ) {
            return Err(authorization_context_stale_error());
        }
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
        let effective_time = checked_clock(loaded.last_observed_at, request.observed_at_unix_ms)?;
        utc_millis(effective_time)?;

        if let Some(grant) = load_grant_use(&transaction, request.grant_use.grant_id)? {
            if !grant.matches_request(&request.grant_use) {
                return Err(grant_already_used_error());
            }
            let transition = load_account_transition_by_grant(&transaction, grant.grant_id)?
                .ok_or_else(recovery_error)?;
            validate_prepare_retry_identity(&transaction, &request, &transition)?;
            let projection = transition_projection(&transaction, &transition)?;
            observe_clock_pair(&transaction, effective_time)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            return Ok(projection);
        }

        let receipt = load_receipt_by_id(&transaction, request.grant_use.receipt_id)?
            .ok_or_else(authorization_context_stale_error)?;
        let challenge = load_challenge(&transaction, receipt.challenge_id).map_err(|error| {
            match error.code {
                MailErrorCode::AuthorizationMalformed => authorization_context_stale_error(),
                _ => error,
            }
        })?;
        validate_account_prepare_identity(&request, &challenge, &receipt)?;
        validate_cleanup_reservation_origins(&loaded.snapshot, &request, &challenge)?;
        let intent_sha256 = account_prepare_intent(&request);
        if challenge.state == "expired" {
            validate_exact_enrollment_expiry(&transaction, &challenge, &receipt, intent_sha256)?;
            observe_clock_pair(&transaction, effective_time)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            return Err(authorization_expired_error());
        }
        if challenge.state != "authorized" {
            return Err(authorization_context_stale_error());
        }
        if effective_time > receipt.expires_at {
            let changed = transaction
                .execute(
                    "UPDATE authorization_challenges SET state='expired'
                     WHERE challenge_id=?1 AND state='authorized'",
                    [challenge.challenge_id.as_bytes()],
                )
                .map_err(|_| store_write_error())?;
            if changed != 1 {
                return Err(recovery_error());
            }
            self.test_hooks
                .fault(TestFaultPoint::EnrollmentExpiredState)?;
            observe_clock_pair(&transaction, effective_time)?;
            self.test_hooks
                .fault(TestFaultPoint::EnrollmentExpiryClockUpdated)?;
            insert_enrollment_expiry_event(
                &transaction,
                &challenge,
                &receipt,
                intent_sha256,
                effective_time,
            )?;
            self.test_hooks
                .fault(TestFaultPoint::EnrollmentExpiryEvent)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            self.test_hooks
                .fault(TestFaultPoint::EnrollmentExpiryAfterCommit)?;
            return Err(authorization_expired_error());
        }

        validate_prepare_occupancy(&transaction, &request, &challenge)?;
        let transition_sha256 = account_transition_digest(&request, effective_time);
        let collision: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM account_transitions WHERE transition_sha256=?1",
                [transition_sha256.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| store_read_error())?;
        if collision != 0 {
            return Err(account_identity_conflict_error());
        }

        let use_receipt = grant_use_transcript(&request.grant_use, effective_time);
        let use_sha256 = Sha256Digest::digest(&use_receipt);
        insert_grant_use(
            &transaction,
            &request.grant_use,
            &use_receipt,
            use_sha256,
            effective_time,
        )?;
        self.test_hooks.fault(TestFaultPoint::GrantUseInserted)?;
        insert_grant_used_event(
            &transaction,
            request.grant_use.grant_id,
            receipt.receipt_id,
            use_sha256,
            effective_time,
        )?;
        self.test_hooks.fault(TestFaultPoint::GrantUsedEvent)?;
        let changed = transaction
            .execute(
                "UPDATE registered_stores SET state='blocked',updated_at=?1
                 WHERE store_id=?2 AND state='active' AND config_generation=?3
                   AND config_sha256=?4 AND location_sha256=?5",
                params![
                    effective_time,
                    request.store_id.as_bytes(),
                    i64::try_from(request.expected_generation.get())
                        .map_err(|_| authorization_context_stale_error())?,
                    request.before_config_sha256.as_bytes(),
                    account_manifest_location_sha256(&challenge)?.as_bytes(),
                ],
            )
            .map_err(|_| store_write_error())?;
        if changed != 1 {
            return Err(account_update_conflict_error());
        }
        self.test_hooks.fault(TestFaultPoint::AccountStoreBlocked)?;
        transaction
            .execute_batch("PRAGMA defer_foreign_keys=ON")
            .map_err(|_| store_write_error())?;
        if pragma_i64(&transaction, "defer_foreign_keys")? != 1 {
            return Err(recovery_error());
        }
        self.test_hooks
            .fault(TestFaultPoint::AccountForeignKeysDeferred)?;
        let account_changed = match request.kind {
            AccountTransitionKind::AccountCreate => transaction.execute(
                "INSERT INTO registered_accounts
                 (account_id,store_id,display_id_sha256,account_generation,credential_id,
                  binding_sha256,state,authorized_receipt_id,active_transition_id,
                  created_at,updated_at,removed_at)
                 VALUES(?1,?2,?3,?4,?5,?6,'proposed',?7,?8,?9,?9,NULL)",
                params![
                    request.account_id.as_bytes(),
                    request.store_id.as_bytes(),
                    request.display_id_sha256.as_bytes(),
                    i64::try_from(request.account_generation.get())
                        .map_err(|_| authorization_context_stale_error())?,
                    request.credential_id.as_bytes(),
                    request.binding_sha256.as_bytes(),
                    receipt.receipt_id.as_bytes(),
                    request.transition_id.as_bytes(),
                    effective_time,
                ],
            ),
            AccountTransitionKind::AccountUpdate
            | AccountTransitionKind::AccountRemove
            | AccountTransitionKind::CredentialSet
            | AccountTransitionKind::CredentialDelete => {
                let mutation = account_mutation_manifest(&challenge, request.kind)?;
                let before = mutation
                    .before
                    .as_ref()
                    .ok_or_else(authorization_context_stale_error)?;
                transaction.execute(
                    "UPDATE registered_accounts SET account_generation=?1,credential_id=?2,
                     binding_sha256=?3,state='blocked',authorized_receipt_id=?4,
                     active_transition_id=?5,updated_at=?6
                     WHERE account_id=?7 AND store_id=?8 AND display_id_sha256=?9
                       AND account_generation=?10 AND credential_id=?11 AND binding_sha256=?12
                       AND state='active' AND active_transition_id IS NULL AND removed_at IS NULL",
                    params![
                        i64::try_from(request.account_generation.get())
                            .map_err(|_| authorization_context_stale_error())?,
                        request.credential_id.as_bytes(),
                        request.binding_sha256.as_bytes(),
                        receipt.receipt_id.as_bytes(),
                        request.transition_id.as_bytes(),
                        effective_time,
                        request.account_id.as_bytes(),
                        request.store_id.as_bytes(),
                        request.display_id_sha256.as_bytes(),
                        i64::try_from(before.generation.get())
                            .map_err(|_| authorization_context_stale_error())?,
                        before.credential_id.as_bytes(),
                        before.binding_sha256.as_bytes(),
                    ],
                )
            }
        }
        .map_err(|_| store_write_error())?;
        if account_changed != 1 {
            return Err(store_write_error());
        }
        self.test_hooks
            .fault(TestFaultPoint::RegisteredAccountInserted)?;
        let inserted = transaction
            .execute(
                "INSERT INTO account_transitions
                 (transition_id,grant_id,store_id,account_id,kind,before_config_sha256,
                  after_config_sha256,expected_generation,next_generation,transition_sha256,
                  state,prepared_at,config_committed_at,finalized_at,resolved_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'prepared',?11,NULL,NULL,NULL)",
                params![
                    request.transition_id.as_bytes(),
                    request.grant_use.grant_id.as_bytes(),
                    request.store_id.as_bytes(),
                    request.account_id.as_bytes(),
                    request.kind.database_name(),
                    request.before_config_sha256.as_bytes(),
                    request.after_config_sha256.as_bytes(),
                    i64::try_from(request.expected_generation.get())
                        .map_err(|_| authorization_context_stale_error())?,
                    i64::try_from(request.next_generation.get())
                        .map_err(|_| authorization_context_stale_error())?,
                    transition_sha256.as_bytes(),
                    effective_time,
                ],
            )
            .map_err(|_| store_write_error())?;
        if inserted != 1 {
            return Err(store_write_error());
        }
        self.test_hooks
            .fault(TestFaultPoint::AccountTransitionInserted)?;
        if matches!(
            request.kind,
            AccountTransitionKind::AccountCreate | AccountTransitionKind::AccountUpdate
        ) {
            let inserted = transaction
                .execute(
                    "INSERT INTO registered_credentials
                     (credential_id,account_id,store_id,created_transition_id,created_at)
                     VALUES(?1,?2,?3,?4,?5)",
                    params![
                        request.credential_id.as_bytes(),
                        request.account_id.as_bytes(),
                        request.store_id.as_bytes(),
                        request.transition_id.as_bytes(),
                        effective_time,
                    ],
                )
                .map_err(|_| store_write_error())?;
            if inserted != 1 {
                return Err(store_write_error());
            }
            self.test_hooks
                .fault(TestFaultPoint::RegisteredCredentialInserted)?;
        }
        for cleanup in &request.cleanup_reservations {
            let inserted = transaction
                .execute(
                    "INSERT INTO credential_cleanup
                     (cleanup_id,transition_id,locator_kind,locator_material,locator_sha256,
                      state,claim_grant_id,created_at,deleted_at)
                     VALUES(?1,?2,?3,?4,?5,'provisional',NULL,?6,NULL)",
                    params![
                        cleanup.cleanup_id.as_bytes(),
                        request.transition_id.as_bytes(),
                        locator_kind_name(cleanup.locator_kind),
                        &cleanup.locator_material,
                        cleanup.locator_sha256.as_bytes(),
                        effective_time,
                    ],
                )
                .map_err(|_| store_write_error())?;
            if inserted != 1 {
                return Err(store_write_error());
            }
        }
        self.test_hooks
            .fault(TestFaultPoint::AccountCleanupInserted)?;
        if foreign_key_violation_count(&transaction)? != 0 {
            return Err(recovery_error());
        }
        self.test_hooks
            .fault(TestFaultPoint::AccountForeignKeyChecked)?;
        insert_account_transition_event(
            &transaction,
            request.store_id.as_bytes(),
            4,
            9,
            4,
            6,
            request.transition_id.as_bytes(),
            0x0401,
            0x0402,
            transition_sha256,
            receipt.receipt_id,
            effective_time,
        )?;
        self.test_hooks
            .fault(TestFaultPoint::AccountStoreBlockedEvent)?;
        insert_account_transition_event(
            &transaction,
            request.transition_id.as_bytes(),
            6,
            10,
            4,
            5,
            request.account_id.as_bytes(),
            0,
            AccountTransitionState::Prepared.event_state(),
            transition_sha256,
            receipt.receipt_id,
            effective_time,
        )?;
        self.test_hooks
            .fault(TestFaultPoint::AccountTransitionPreparedEvent)?;
        observe_clock_pair(&transaction, effective_time)?;
        self.test_hooks
            .fault(TestFaultPoint::AccountPrepareClockUpdated)?;
        self.test_hooks
            .fault(TestFaultPoint::AccountPrepareBeforeCommit)?;
        transaction.commit().map_err(|_| store_write_error())?;
        secure_authority_files(&self.home.database)?;
        self.test_hooks
            .fault(TestFaultPoint::AccountPrepareAfterCommit)?;
        Ok(AccountTransitionProjection {
            transition_id: request.transition_id,
            account_id: request.account_id,
            transition_state: AccountTransitionState::Prepared,
            account_state: if request.kind == AccountTransitionKind::AccountCreate {
                RegisteredAccountState::Proposed
            } else {
                RegisteredAccountState::Blocked
            },
            store_state: RegisteredStoreTransitionState::Blocked,
            config_generation: request.expected_generation,
            account_generation: request.account_generation,
            prepared_at: utc_millis(effective_time)?,
        })
    }

    /// Record an exact config-commit observation.
    ///
    /// # Errors
    ///
    /// Returns a stable transition, clock, recovery, or store error.
    #[allow(clippy::needless_pass_by_value)]
    pub fn mark_config_committed(
        &self,
        request: AccountTransitionObservationRequest,
    ) -> Result<AccountTransitionProjection, MailError> {
        self.apply_account_observation(&request, AccountObservationOperation::ConfigCommitted)
    }

    /// Finalize one config-committed account transition.
    ///
    /// # Errors
    ///
    /// Returns a stable transition, clock, recovery, or store error.
    #[allow(clippy::needless_pass_by_value)]
    pub fn finalize_account_transition(
        &self,
        request: AccountTransitionObservationRequest,
    ) -> Result<AccountTransitionProjection, MailError> {
        self.apply_account_observation(&request, AccountObservationOperation::Finalize)
    }

    /// Abort one prepared account transition with known no config effect.
    ///
    /// # Errors
    ///
    /// Returns a stable transition, clock, recovery, or store error.
    #[allow(clippy::needless_pass_by_value)]
    pub fn abort_transition(
        &self,
        request: AccountTransitionObservationRequest,
    ) -> Result<AccountTransitionProjection, MailError> {
        self.apply_account_observation(&request, AccountObservationOperation::Abort)
    }

    /// Persist one exact unsafe config observation as terminal recovery-required state.
    ///
    /// # Errors
    ///
    /// Returns a stable transition, clock, recovery, or store error.
    #[allow(clippy::needless_pass_by_value)]
    pub fn mark_transition_recovery_required(
        &self,
        request: AccountTransitionObservationRequest,
    ) -> Result<AccountTransitionProjection, MailError> {
        self.apply_account_observation(&request, AccountObservationOperation::Recovery)
    }

    /// Consume one authorized cleanup grant and return the sole delete permit.
    ///
    /// Exact recovery of a committed claim returns a fresh opaque permit. Exact
    /// recovery after deletion returns the terminal projection without a permit.
    ///
    /// # Errors
    ///
    /// Returns stable replay, expiry, cleanup, recovery, clock, or store errors.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn claim_credential_cleanup(
        &self,
        request: CredentialCleanupClaimRequest,
    ) -> Result<CredentialCleanupClaimOutcome, MailError> {
        if !matches!(self.state, AuthorityOpenState::Ready(_)) {
            return Err(recovery_error());
        }
        let apply_lock = acquire_apply_lock(&self.home)?;
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

        if let Some(grant) = load_grant_use(&transaction, request.grant_use.grant_id)? {
            if !grant.matches_request(&request.grant_use) {
                return Err(grant_already_used_error());
            }
            let receipt =
                load_receipt_by_id(&transaction, grant.receipt_id)?.ok_or_else(recovery_error)?;
            let challenge = load_challenge(&transaction, receipt.challenge_id)?;
            let manifest = validate_cleanup_claim_identity(&request, &challenge, &receipt)?;
            let cleanup = load_credential_cleanup(&transaction, request.cleanup_id)?
                .ok_or_else(recovery_error)?;
            if cleanup.claim_grant_id != Some(grant.grant_id)
                || !matches!(cleanup.state, CleanupState::Claimed | CleanupState::Deleted)
            {
                return Err(recovery_error());
            }
            validate_credential_cleanup_context(&transaction, &loaded.snapshot, &manifest, false)?;
            let effective_time =
                checked_clock(loaded.last_observed_at, request.observed_at_unix_ms)?;
            utc_millis(effective_time)?;
            observe_clock_pair(&transaction, effective_time)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            let projection = cleanup_projection(&cleanup, Some(grant.used_at))?;
            let permit = if cleanup.state == CleanupState::Claimed {
                Some(cleanup_delete_permit(
                    &self.home, &cleanup, &grant, apply_lock,
                )?)
            } else {
                None
            };
            return Ok(CredentialCleanupClaimOutcome { projection, permit });
        }

        let receipt = load_receipt_by_id(&transaction, request.grant_use.receipt_id)?
            .ok_or_else(authorization_context_stale_error)?;
        let challenge = load_challenge(&transaction, receipt.challenge_id).map_err(|error| {
            if error.code == MailErrorCode::AuthorizationMalformed {
                authorization_context_stale_error()
            } else {
                error
            }
        })?;
        let manifest = validate_cleanup_claim_identity(&request, &challenge, &receipt)?;
        let effective_time = checked_clock(loaded.last_observed_at, request.observed_at_unix_ms)?;
        utc_millis(effective_time)?;
        if challenge.state == "expired" {
            return Err(authorization_expired_error());
        }
        if challenge.state != "authorized" {
            return Err(authorization_context_stale_error());
        }
        if effective_time > receipt.expires_at {
            let changed = transaction
                .execute(
                    "UPDATE authorization_challenges SET state='expired'
                     WHERE challenge_id=?1 AND state='authorized'",
                    [challenge.challenge_id.as_bytes()],
                )
                .map_err(|_| store_write_error())?;
            if changed != 1 {
                return Err(recovery_error());
            }
            observe_clock_pair(&transaction, effective_time)?;
            insert_enrollment_expiry_event(
                &transaction,
                &challenge,
                &receipt,
                challenge.manifest_sha256,
                effective_time,
            )?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            return Err(authorization_expired_error());
        }

        validate_credential_cleanup_public_pair(&transaction, &manifest)?;
        validate_credential_cleanup_context(&transaction, &loaded.snapshot, &manifest, true)?;
        let cleanup = load_credential_cleanup(&transaction, request.cleanup_id)?
            .ok_or_else(credential_cleanup_invalid_error)?;
        let use_receipt = grant_use_transcript(&request.grant_use, effective_time);
        let use_sha256 = Sha256Digest::digest(&use_receipt);
        insert_grant_use(
            &transaction,
            &request.grant_use,
            &use_receipt,
            use_sha256,
            effective_time,
        )?;
        insert_grant_used_event(
            &transaction,
            request.grant_use.grant_id,
            receipt.receipt_id,
            use_sha256,
            effective_time,
        )?;
        let changed = transaction
            .execute(
                "UPDATE credential_cleanup SET state='claimed',claim_grant_id=?1
                 WHERE cleanup_id=?2 AND state='ready' AND claim_grant_id IS NULL
                   AND deleted_at IS NULL",
                params![
                    request.grant_use.grant_id.as_bytes(),
                    request.cleanup_id.as_bytes(),
                ],
            )
            .map_err(|_| store_write_error())?;
        if changed != 1 {
            return Err(credential_cleanup_invalid_error());
        }
        insert_cleanup_event(
            &transaction,
            request.cleanup_id,
            16,
            request.grant_use.grant_id,
            receipt.receipt_id,
            0x0702,
            0x0703,
            use_sha256,
            effective_time,
        )?;
        observe_clock_pair(&transaction, effective_time)?;
        transaction.commit().map_err(|_| store_write_error())?;
        secure_authority_files(&self.home.database)?;
        let claimed = StoredCredentialCleanup {
            state: CleanupState::Claimed,
            claim_grant_id: Some(request.grant_use.grant_id),
            ..cleanup
        };
        let grant = StoredGrantUse {
            grant_id: request.grant_use.grant_id,
            receipt_id: request.grant_use.receipt_id,
            action: request.grant_use.action,
            target_kind: request.grant_use.target_kind,
            target_id: request.grant_use.target_bytes,
            manifest_sha256: request.grant_use.manifest_sha256,
            use_receipt,
            use_sha256,
            used_at: effective_time,
        };
        let projection = cleanup_projection(&claimed, Some(effective_time))?;
        let permit = cleanup_delete_permit(&self.home, &claimed, &grant, apply_lock)?;
        Ok(CredentialCleanupClaimOutcome {
            projection,
            permit: Some(permit),
        })
    }

    #[allow(clippy::too_many_lines)]
    fn apply_account_observation(
        &self,
        request: &AccountTransitionObservationRequest,
        operation: AccountObservationOperation,
    ) -> Result<AccountTransitionProjection, MailError> {
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
        let effective_time = checked_clock(loaded.last_observed_at, request.observed_at_unix_ms)?;
        utc_millis(effective_time)?;
        let transition = load_account_transition(&transaction, request.transition_id)?
            .ok_or_else(account_update_conflict_error)?;
        if !matches!(
            transition.kind,
            AccountTransitionKind::AccountCreate
                | AccountTransitionKind::AccountUpdate
                | AccountTransitionKind::AccountRemove
                | AccountTransitionKind::CredentialSet
                | AccountTransitionKind::CredentialDelete
        ) {
            return Err(account_update_conflict_error());
        }
        let pair = classify_observed_pair(&transition, request);

        if transition.state == AccountTransitionState::RecoveryRequired {
            let store = load_registered_store_by_id(&transaction, transition.store_id)?
                .ok_or_else(recovery_error)?;
            let prior = if transition.config_committed_at.is_some() {
                AccountTransitionState::ConfigCommitted
            } else {
                AccountTransitionState::Prepared
            };
            let exact_recovery_observation = match prior {
                AccountTransitionState::Prepared => pair == ObservedConfigPair::Third,
                AccountTransitionState::ConfigCommitted => pair != ObservedConfigPair::After,
                _ => false,
            };
            let exact_config_commit_retry = operation
                == AccountObservationOperation::ConfigCommitted
                && prior == AccountTransitionState::ConfigCommitted
                && request.source_state == AccountTransitionState::Prepared
                && pair == ObservedConfigPair::After;
            if (!exact_recovery_observation && !exact_config_commit_retry)
                || (exact_recovery_observation
                    && (request.actual_config_generation != store.config_generation
                        || request.actual_config_sha256 != store.config_sha256))
            {
                return Err(account_update_conflict_error());
            }
            let projection = transition_projection(&transaction, &transition)?;
            observe_clock_pair(&transaction, effective_time)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            return Ok(projection);
        }

        let completed = match operation {
            AccountObservationOperation::ConfigCommitted => matches!(
                transition.state,
                AccountTransitionState::ConfigCommitted
                    | AccountTransitionState::Finalized
                    | AccountTransitionState::RecoveryRequired
            ),
            AccountObservationOperation::Finalize => {
                transition.state == AccountTransitionState::Finalized
            }
            AccountObservationOperation::Abort => {
                transition.state == AccountTransitionState::Aborted
            }
            AccountObservationOperation::Recovery => {
                transition.state == AccountTransitionState::RecoveryRequired
            }
        };
        if completed {
            let exact = match operation {
                AccountObservationOperation::ConfigCommitted => {
                    request.source_state == AccountTransitionState::Prepared
                        && pair == ObservedConfigPair::After
                }
                AccountObservationOperation::Finalize => {
                    request.source_state == AccountTransitionState::ConfigCommitted
                        && pair == ObservedConfigPair::After
                }
                AccountObservationOperation::Abort => {
                    request.source_state == AccountTransitionState::Prepared
                        && pair == ObservedConfigPair::Before
                }
                AccountObservationOperation::Recovery => false,
            };
            if !exact {
                return Err(account_update_conflict_error());
            }
            let projection = transition_projection(&transaction, &transition)?;
            observe_clock_pair(&transaction, effective_time)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            return Ok(projection);
        }

        let unsafe_pair = (transition.state == AccountTransitionState::Prepared
            && pair == ObservedConfigPair::Third)
            || (transition.state == AccountTransitionState::ConfigCommitted
                && pair != ObservedConfigPair::After);
        if unsafe_pair {
            let projection = commit_account_recovery(
                &transaction,
                &transition,
                request,
                effective_time,
                &self.test_hooks,
            )?;
            self.test_hooks
                .fault(TestFaultPoint::AccountRecoveryBeforeCommit)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            self.test_hooks
                .fault(TestFaultPoint::AccountRecoveryAfterCommit)?;
            return Ok(projection);
        }

        match operation {
            AccountObservationOperation::ConfigCommitted
                if request.source_state == AccountTransitionState::Prepared
                    && transition.state == AccountTransitionState::Prepared
                    && pair == ObservedConfigPair::Before =>
            {
                let projection = transition_projection(&transaction, &transition)?;
                observe_clock_pair(&transaction, effective_time)?;
                transaction.commit().map_err(|_| store_write_error())?;
                secure_authority_files(&self.home.database)?;
                Ok(projection)
            }
            AccountObservationOperation::ConfigCommitted
                if request.source_state == AccountTransitionState::Prepared
                    && transition.state == AccountTransitionState::Prepared
                    && pair == ObservedConfigPair::After =>
            {
                let account = load_registered_account(&transaction, transition.account_id)?
                    .ok_or_else(recovery_error)?;
                insert_transition_versions(
                    &transaction,
                    &transition,
                    &account,
                    effective_time,
                    &self.test_hooks,
                )?;
                let changed = transaction
                    .execute(
                        "UPDATE account_transitions SET state='config_committed',
                         config_committed_at=?1 WHERE transition_id=?2 AND state='prepared'",
                        params![effective_time, transition.transition_id.as_bytes()],
                    )
                    .map_err(|_| store_write_error())?;
                if changed != 1 {
                    return Err(recovery_error());
                }
                self.test_hooks
                    .fault(TestFaultPoint::AccountTransitionCommitted)?;
                let changed = transaction
                    .execute(
                        "UPDATE registered_stores SET config_generation=?1,config_sha256=?2,
                         updated_at=?3 WHERE store_id=?4 AND state='blocked'
                         AND config_generation=?5 AND config_sha256=?6",
                        params![
                            i64::try_from(transition.next_generation.get())
                                .map_err(|_| recovery_error())?,
                            transition.after_config_sha256.as_bytes(),
                            effective_time,
                            transition.store_id.as_bytes(),
                            i64::try_from(transition.expected_generation.get())
                                .map_err(|_| recovery_error())?,
                            transition.before_config_sha256.as_bytes(),
                        ],
                    )
                    .map_err(|_| store_write_error())?;
                if changed != 1 {
                    return Err(recovery_error());
                }
                self.test_hooks
                    .fault(TestFaultPoint::AccountStoreCommitted)?;
                insert_transition_phase_event(
                    &transaction,
                    &transition,
                    11,
                    4,
                    AccountTransitionState::Prepared,
                    AccountTransitionState::ConfigCommitted,
                    transition.transition_sha256,
                    effective_time,
                )?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountConfigCommittedEvent)?;
                observe_clock_pair(&transaction, effective_time)?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountConfigClockUpdated)?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountConfigBeforeCommit)?;
                let projection = projection_for_transition_state(
                    &transaction,
                    &transition,
                    AccountTransitionState::ConfigCommitted,
                    if transition.kind == AccountTransitionKind::AccountCreate {
                        RegisteredAccountState::Proposed
                    } else {
                        RegisteredAccountState::Blocked
                    },
                    RegisteredStoreTransitionState::Blocked,
                    transition.next_generation,
                )?;
                transaction.commit().map_err(|_| store_write_error())?;
                secure_authority_files(&self.home.database)?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountConfigAfterCommit)?;
                Ok(projection)
            }
            AccountObservationOperation::Finalize
                if request.source_state == AccountTransitionState::ConfigCommitted
                    && transition.state == AccountTransitionState::ConfigCommitted
                    && pair == ObservedConfigPair::After =>
            {
                update_finalize_rows(&transaction, &transition, effective_time, &self.test_hooks)?;
                let receipt_id = transition_receipt_id(&transaction, &transition)?;
                insert_transition_phase_event(
                    &transaction,
                    &transition,
                    12,
                    4,
                    AccountTransitionState::ConfigCommitted,
                    AccountTransitionState::Finalized,
                    transition.transition_sha256,
                    effective_time,
                )?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountFinalizeTransitionEvent)?;
                insert_account_transition_event(
                    &transaction,
                    transition.store_id.as_bytes(),
                    4,
                    9,
                    4,
                    6,
                    transition.transition_id.as_bytes(),
                    0x0402,
                    0x0401,
                    transition.transition_sha256,
                    receipt_id,
                    effective_time,
                )?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountFinalizeStoreEvent)?;
                insert_cleanup_ready_events(&transaction, &transition, receipt_id, effective_time)?;
                observe_clock_pair(&transaction, effective_time)?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountFinalizeClockUpdated)?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountFinalizeBeforeCommit)?;
                let projection = projection_for_transition_state(
                    &transaction,
                    &transition,
                    AccountTransitionState::Finalized,
                    if transition.kind == AccountTransitionKind::AccountRemove {
                        RegisteredAccountState::Removed
                    } else {
                        RegisteredAccountState::Active
                    },
                    RegisteredStoreTransitionState::Active,
                    transition.next_generation,
                )?;
                transaction.commit().map_err(|_| store_write_error())?;
                secure_authority_files(&self.home.database)?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountFinalizeAfterCommit)?;
                Ok(projection)
            }
            AccountObservationOperation::Abort
                if request.source_state == AccountTransitionState::Prepared
                    && transition.state == AccountTransitionState::Prepared
                    && pair == ObservedConfigPair::Before =>
            {
                update_abort_rows(&transaction, &transition, effective_time, &self.test_hooks)?;
                let receipt_id = transition_receipt_id(&transaction, &transition)?;
                insert_transition_phase_event(
                    &transaction,
                    &transition,
                    13,
                    6,
                    AccountTransitionState::Prepared,
                    AccountTransitionState::Aborted,
                    transition.transition_sha256,
                    effective_time,
                )?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountAbortTransitionEvent)?;
                insert_account_transition_event(
                    &transaction,
                    transition.store_id.as_bytes(),
                    4,
                    9,
                    6,
                    6,
                    transition.transition_id.as_bytes(),
                    0x0402,
                    0x0401,
                    transition.transition_sha256,
                    receipt_id,
                    effective_time,
                )?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountAbortStoreEvent)?;
                observe_clock_pair(&transaction, effective_time)?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountAbortClockUpdated)?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountAbortBeforeCommit)?;
                let projection = projection_for_transition_state(
                    &transaction,
                    &transition,
                    AccountTransitionState::Aborted,
                    if transition.kind == AccountTransitionKind::AccountCreate {
                        RegisteredAccountState::Removed
                    } else {
                        RegisteredAccountState::Active
                    },
                    RegisteredStoreTransitionState::Active,
                    transition.expected_generation,
                )?;
                transaction.commit().map_err(|_| store_write_error())?;
                secure_authority_files(&self.home.database)?;
                self.test_hooks
                    .fault(TestFaultPoint::AccountAbortAfterCommit)?;
                Ok(projection)
            }
            AccountObservationOperation::Recovery
                if matches!(
                    request.source_state,
                    AccountTransitionState::Prepared | AccountTransitionState::ConfigCommitted
                ) =>
            {
                Err(account_update_conflict_error())
            }
            _ => Err(account_update_conflict_error()),
        }
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

mod credential_cleanup_delete_adapter {
    use super::*;

    impl AuthorityStore {
        /// Consume the opaque cleanup permit, invoke one idempotent credential
        /// deletion, and durably record the terminal cleanup state.
        ///
        /// # Errors
        ///
        /// Backend failures leave the durable cleanup in `claimed` state so an
        /// exact grant recovery can retry safely.
        #[allow(clippy::too_many_lines)]
        pub fn apply_credential_cleanup_delete(
            &self,
            permit: CleanupDeletePermit,
            observed_at_unix_ms: i64,
        ) -> Result<CredentialCleanupProjection, MailError> {
            let CleanupDeletePermit {
                cleanup_id,
                grant_id,
                receipt_id,
                use_sha256,
                locator_material,
                database_path,
                _apply_lock,
            } = permit;
            if database_path != self.home.database
                || !matches!(self.state, AuthorityOpenState::Ready(_))
                || observed_at_unix_ms < 0
            {
                return Err(recovery_error());
            }
            input_utc_millis(observed_at_unix_ms)?;
            let mut connection = existing_authority_read_connection(&self.home.database)?;
            if classify_database(&connection)? != DatabaseClass::AuthorityV1 {
                return Err(recovery_error());
            }
            configure_authority_pragmas(&connection)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| store_write_error())?;
            let loaded = self.validate_ready_transaction(&transaction)?;
            let effective_time = checked_clock(loaded.last_observed_at, observed_at_unix_ms)?;
            utc_millis(effective_time)?;
            let cleanup =
                load_credential_cleanup(&transaction, cleanup_id)?.ok_or_else(recovery_error)?;
            let grant = load_grant_use(&transaction, grant_id)?.ok_or_else(recovery_error)?;
            if cleanup.state != CleanupState::Claimed
                || cleanup.claim_grant_id != Some(grant_id)
                || cleanup.locator_material != locator_material
                || cleanup.locator_sha256 != Sha256Digest::digest(&locator_material)
                || cleanup.deleted_at.is_some()
                || grant.receipt_id != receipt_id
                || grant.use_sha256 != use_sha256
                || grant.action != SensitiveAction::CredentialCleanup
                || grant.target_kind != TargetKind::Cleanup
                || grant.target_id.as_slice() != cleanup_id.as_bytes()
            {
                return Err(recovery_error());
            }
            let (kind, service, username) =
                parse_delete_only_locator(&locator_material).ok_or_else(recovery_error)?;
            if kind != cleanup.locator_kind
                || !delete_only_locator_shape_is_valid(kind, service, username)
            {
                return Err(recovery_error());
            }
            let service = std::str::from_utf8(service).map_err(|_| recovery_error())?;
            let username = std::str::from_utf8(username).map_err(|_| recovery_error())?;
            let locator = kirje_credential::DeleteOnlyLocator::new(service, username)
                .map_err(|_| credential_delete_error())?;
            #[cfg(feature = "test-support")]
            let simulated = self.test_hooks.credential_delete.as_ref().map(|hook| {
                hook.calls.fetch_add(1, Ordering::SeqCst);
                if hook.fail {
                    Err(credential_delete_error())
                } else {
                    Ok(())
                }
            });
            #[cfg(not(feature = "test-support"))]
            let simulated: Option<Result<(), MailError>> = None;
            if let Some(result) = simulated {
                result?;
                drop(locator);
            } else {
                kirje_credential::delete_only(locator).map_err(|_| credential_delete_error())?;
            }

            let changed = transaction
                .execute(
                    "UPDATE credential_cleanup SET state='deleted',deleted_at=?1
                     WHERE cleanup_id=?2 AND state='claimed' AND claim_grant_id=?3
                       AND deleted_at IS NULL",
                    params![effective_time, cleanup_id.as_bytes(), grant_id.as_bytes()],
                )
                .map_err(|_| store_write_error())?;
            if changed != 1 {
                return Err(recovery_error());
            }
            insert_cleanup_event(
                &transaction,
                cleanup_id,
                17,
                grant_id,
                receipt_id,
                0x0703,
                0x0704,
                use_sha256,
                effective_time,
            )?;
            observe_clock_pair(&transaction, effective_time)?;
            transaction.commit().map_err(|_| store_write_error())?;
            secure_authority_files(&self.home.database)?;
            let deleted = StoredCredentialCleanup {
                state: CleanupState::Deleted,
                deleted_at: Some(effective_time),
                ..cleanup
            };
            cleanup_projection(&deleted, Some(grant.used_at))
        }
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

struct StoredGrantUse {
    grant_id: AuthorizationGrantId,
    receipt_id: AuthorizationReceiptId,
    action: SensitiveAction,
    target_kind: TargetKind,
    target_id: Vec<u8>,
    manifest_sha256: Sha256Digest,
    use_receipt: Vec<u8>,
    use_sha256: Sha256Digest,
    used_at: i64,
}

struct StoredCredentialCleanup {
    cleanup_id: CleanupId,
    transition_id: TransitionId,
    locator_kind: LocatorKind,
    locator_material: Vec<u8>,
    locator_sha256: Sha256Digest,
    state: CleanupState,
    claim_grant_id: Option<AuthorizationGrantId>,
    created_at: i64,
    deleted_at: Option<i64>,
}

impl StoredGrantUse {
    fn matches_request(&self, request: &GrantUseRequest) -> bool {
        self.grant_id == request.grant_id
            && self.receipt_id == request.receipt_id
            && self.action == request.action
            && self.target_kind == request.target_kind
            && self.target_id == request.target_bytes
            && self.manifest_sha256 == request.manifest_sha256
    }
}

struct StoredRegisteredStore {
    store_id: StoreId,
    location_material: Vec<u8>,
    location_sha256: Sha256Digest,
    config_generation: NonZeroU64,
    config_sha256: Sha256Digest,
    state: String,
    enrolled_receipt_id: AuthorizationReceiptId,
    created_at: i64,
    updated_at: i64,
    removed_at: Option<i64>,
}

struct StoredRegisteredStoreVersion {
    store_id: StoreId,
    location_sha256: Sha256Digest,
    config_generation: NonZeroU64,
    config_sha256: Sha256Digest,
    enrolled_receipt_id: Option<AuthorizationReceiptId>,
    committed_transition_id: Option<Vec<u8>>,
    created_at: i64,
}

struct StoredAccountTransition {
    transition_id: TransitionId,
    grant_id: AuthorizationGrantId,
    store_id: StoreId,
    account_id: AccountId,
    kind: AccountTransitionKind,
    before_config_sha256: Sha256Digest,
    after_config_sha256: Sha256Digest,
    expected_generation: NonZeroU64,
    next_generation: NonZeroU64,
    transition_sha256: Sha256Digest,
    state: AccountTransitionState,
    prepared_at: i64,
    config_committed_at: Option<i64>,
    finalized_at: Option<i64>,
    resolved_at: Option<i64>,
}

struct StoredRegisteredAccount {
    account_id: AccountId,
    store_id: StoreId,
    display_id_sha256: Sha256Digest,
    account_generation: NonZeroU64,
    credential_id: CredentialId,
    binding_sha256: Sha256Digest,
    state: RegisteredAccountState,
    authorized_receipt_id: AuthorizationReceiptId,
    active_transition_id: Option<TransitionId>,
    created_at: i64,
    updated_at: i64,
    removed_at: Option<i64>,
}

fn transition_kind_from_name(value: &str) -> Result<AccountTransitionKind, MailError> {
    match value {
        "account_create" => Ok(AccountTransitionKind::AccountCreate),
        "account_update" => Ok(AccountTransitionKind::AccountUpdate),
        "account_remove" => Ok(AccountTransitionKind::AccountRemove),
        "credential_set" => Ok(AccountTransitionKind::CredentialSet),
        "credential_delete" => Ok(AccountTransitionKind::CredentialDelete),
        _ => Err(recovery_error()),
    }
}

fn transition_state_from_name(value: &str) -> Result<AccountTransitionState, MailError> {
    match value {
        "prepared" => Ok(AccountTransitionState::Prepared),
        "config_committed" => Ok(AccountTransitionState::ConfigCommitted),
        "finalized" => Ok(AccountTransitionState::Finalized),
        "aborted" => Ok(AccountTransitionState::Aborted),
        "recovery_required" => Ok(AccountTransitionState::RecoveryRequired),
        _ => Err(recovery_error()),
    }
}

fn transition_state_name(value: AccountTransitionState) -> &'static str {
    match value {
        AccountTransitionState::Prepared => "prepared",
        AccountTransitionState::ConfigCommitted => "config_committed",
        AccountTransitionState::Finalized => "finalized",
        AccountTransitionState::Aborted => "aborted",
        AccountTransitionState::RecoveryRequired => "recovery_required",
    }
}

fn account_state_from_name(value: &str) -> Result<RegisteredAccountState, MailError> {
    match value {
        "proposed" => Ok(RegisteredAccountState::Proposed),
        "active" => Ok(RegisteredAccountState::Active),
        "blocked" => Ok(RegisteredAccountState::Blocked),
        "removed" => Ok(RegisteredAccountState::Removed),
        _ => Err(recovery_error()),
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AccountObservationOperation {
    ConfigCommitted,
    Finalize,
    Abort,
    Recovery,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ObservedConfigPair {
    Before,
    After,
    Third,
}

fn classify_observed_pair(
    transition: &StoredAccountTransition,
    request: &AccountTransitionObservationRequest,
) -> ObservedConfigPair {
    if request.actual_config_generation == transition.expected_generation
        && request.actual_config_sha256 == transition.before_config_sha256
    {
        ObservedConfigPair::Before
    } else if request.actual_config_generation == transition.next_generation
        && request.actual_config_sha256 == transition.after_config_sha256
    {
        ObservedConfigPair::After
    } else {
        ObservedConfigPair::Third
    }
}

fn validate_account_prepare_identity(
    request: &PrepareAccountTransitionRequest,
    challenge: &StoredChallenge,
    receipt: &StoredReceipt,
) -> Result<(), MailError> {
    let manifest = ActionManifest::parse(&challenge.manifest)
        .map_err(|_| authorization_context_stale_error())?;
    let (value, action, target_kind) = match (request.kind, manifest.payload()) {
        (AccountTransitionKind::AccountCreate, ManifestPayload::AccountCreate(value)) => {
            (value, SensitiveAction::AccountCreate, TargetKind::Account)
        }
        (AccountTransitionKind::AccountUpdate, ManifestPayload::AccountUpdate(value)) => {
            (value, SensitiveAction::AccountUpdate, TargetKind::Account)
        }
        (AccountTransitionKind::AccountRemove, ManifestPayload::AccountRemove(value)) => {
            (value, SensitiveAction::AccountRemove, TargetKind::Account)
        }
        (AccountTransitionKind::CredentialSet, ManifestPayload::CredentialSet(value)) => (
            &value.account,
            SensitiveAction::CredentialSet,
            TargetKind::Credential,
        ),
        (AccountTransitionKind::CredentialDelete, ManifestPayload::CredentialDelete(value)) => (
            &value.account,
            SensitiveAction::CredentialDelete,
            TargetKind::Credential,
        ),
        _ => return Err(authorization_context_stale_error()),
    };
    let account_snapshot = match request.kind {
        AccountTransitionKind::AccountCreate
        | AccountTransitionKind::AccountUpdate
        | AccountTransitionKind::CredentialSet
        | AccountTransitionKind::CredentialDelete => value
            .after
            .as_ref()
            .ok_or_else(authorization_context_stale_error)?,
        AccountTransitionKind::AccountRemove => value
            .before
            .as_ref()
            .ok_or_else(authorization_context_stale_error)?,
    };
    let target_bytes: &[u8] = match (request.kind, target_kind) {
        (AccountTransitionKind::CredentialDelete, TargetKind::Credential) => value
            .before
            .as_ref()
            .ok_or_else(authorization_context_stale_error)?
            .credential_id
            .as_bytes(),
        (_, TargetKind::Account) => account_snapshot.account_id.as_bytes(),
        (_, TargetKind::Credential) => account_snapshot.credential_id.as_bytes(),
        _ => return Err(authorization_context_stale_error()),
    };
    if request.grant_use.grant_id != challenge.grant_id
        || request.grant_use.receipt_id != receipt.receipt_id
        || receipt.challenge_id != challenge.challenge_id
        || receipt.grant_id != challenge.grant_id
        || request.grant_use.action != action
        || request.grant_use.action != challenge.action
        || request.grant_use.target_kind != target_kind
        || request.grant_use.target_kind.code() != challenge.target_kind_code
        || request.grant_use.target_bytes.as_slice() != target_bytes
        || challenge.target_id.as_slice() != target_bytes
        || request.grant_use.manifest_sha256 != challenge.manifest_sha256
        || request.transition_id != value.transition_id
        || request.store_id != value.config_cas.store_id
        || request.account_id != account_snapshot.account_id
        || request.before_config_sha256 != value.config_cas.exact_content_sha256
        || request.after_config_sha256 != value.after_config_sha256
        || request.expected_generation != value.config_cas.generation
        || request.next_generation != value.next_config_generation
        || request.display_id_sha256 != display_id_digest(&account_snapshot.display_id)
        || request.account_generation != account_snapshot.generation
        || request.credential_id != account_snapshot.credential_id
        || request.binding_sha256 != account_snapshot.binding_sha256
        || !cleanup_reservations_match(&request.cleanup_reservations, &value.cleanup)
    {
        return Err(authorization_context_stale_error());
    }
    Ok(())
}

fn account_manifest_location_sha256(
    challenge: &StoredChallenge,
) -> Result<Sha256Digest, MailError> {
    let manifest = ActionManifest::parse(&challenge.manifest)
        .map_err(|_| authorization_context_stale_error())?;
    let value = match manifest.payload() {
        ManifestPayload::AccountCreate(value)
        | ManifestPayload::AccountUpdate(value)
        | ManifestPayload::AccountRemove(value) => value,
        ManifestPayload::CredentialSet(value) | ManifestPayload::CredentialDelete(value) => {
            &value.account
        }
        _ => return Err(authorization_context_stale_error()),
    };
    Ok(value.config_cas.location_sha256)
}

fn cleanup_reservations_match(
    reservations: &[CredentialCleanupReservation],
    descriptors: &[kirje_core::CleanupDescriptor],
) -> bool {
    reservations.len() == descriptors.len()
        && reservations
            .iter()
            .zip(descriptors)
            .all(|(reservation, descriptor)| {
                descriptor.expected_state == CleanupState::Provisional
                    && reservation.cleanup_id == descriptor.cleanup_id
                    && reservation.locator_kind == descriptor.locator_kind
                    && reservation.locator_sha256 == descriptor.locator_sha256
            })
}

fn locator_kind_code(kind: LocatorKind) -> u8 {
    match kind {
        LocatorKind::ActiveV2 => 1,
        LocatorKind::LegacyV1 => 2,
    }
}

fn parse_delete_only_locator(material: &[u8]) -> Option<(LocatorKind, &[u8], &[u8])> {
    if !private_material_length_is_bounded(material.len())
        || !material.starts_with(DELETE_ONLY_LOCATOR_DOMAIN)
    {
        return None;
    }
    let mut cursor = DELETE_ONLY_LOCATOR_DOMAIN.len();
    let count = locator_read_u16(material, &mut cursor)?;
    if count != 3 {
        return None;
    }
    let mut fields = [&[][..]; 3];
    for (index, field) in fields.iter_mut().enumerate() {
        let tag = locator_read_u16(material, &mut cursor)?;
        if tag != u16::try_from(index + 1).ok()? {
            return None;
        }
        let length = usize::try_from(locator_read_u32(material, &mut cursor)?).ok()?;
        let end = cursor.checked_add(length)?;
        *field = material.get(cursor..end)?;
        cursor = end;
    }
    if cursor != material.len() || fields[0].len() != 1 {
        return None;
    }
    let kind = match fields[0][0] {
        1 => LocatorKind::ActiveV2,
        2 => LocatorKind::LegacyV1,
        _ => return None,
    };
    Some((kind, fields[1], fields[2]))
}

const fn private_material_length_is_bounded(length: usize) -> bool {
    length >= 1 && length <= 4_096
}

fn locator_read_u16(bytes: &[u8], cursor: &mut usize) -> Option<u16> {
    let end = cursor.checked_add(2)?;
    let value = u16::from_be_bytes(bytes.get(*cursor..end)?.try_into().ok()?);
    *cursor = end;
    Some(value)
}

fn locator_read_u32(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    let end = cursor.checked_add(4)?;
    let value = u32::from_be_bytes(bytes.get(*cursor..end)?.try_into().ok()?);
    *cursor = end;
    Some(value)
}

fn delete_only_locator_shape_is_valid(kind: LocatorKind, service: &[u8], username: &[u8]) -> bool {
    let Ok(service_text) = std::str::from_utf8(service) else {
        return false;
    };
    let Ok(username_text) = std::str::from_utf8(username) else {
        return false;
    };
    if service.is_empty()
        || service.len() > 128
        || service_text.chars().count() > 128
        || username.is_empty()
        || username.len() > 1_024
        || username_text.chars().count() > 1_024
        || service.contains(&0)
        || username.contains(&0)
    {
        return false;
    }
    match kind {
        LocatorKind::ActiveV2 => {
            service == ACTIVE_V2_LOCATOR_SERVICE
                && username.len() == 67
                && username.starts_with(b"v2:")
                && username[3..]
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        }
        LocatorKind::LegacyV1 => {
            service == LEGACY_V1_LOCATOR_SERVICE
                && username.len() <= 64
                && username
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        }
    }
}

fn active_v2_username(
    realm_id: OwnerRealmId,
    store_id: StoreId,
    account_id: AccountId,
    credential_id: CredentialId,
    binding_sha256: Sha256Digest,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(CREDENTIAL_LOCATOR_V2_DOMAIN);
    hasher.update(realm_id.as_bytes());
    hasher.update(store_id.as_bytes());
    hasher.update(account_id.as_bytes());
    hasher.update(credential_id.as_bytes());
    hasher.update(binding_sha256.as_bytes());
    let digest = hasher.finalize();
    let mut username = Vec::with_capacity(67);
    username.extend_from_slice(b"v2:");
    for byte in digest {
        username.push(LOWER_HEX[usize::from(byte >> 4)]);
        username.push(LOWER_HEX[usize::from(byte & 0x0f)]);
    }
    username
}

fn expected_delete_only_locator(
    realm_id: OwnerRealmId,
    store_id: StoreId,
    before: &kirje_core::AccountSnapshot,
    kind: LocatorKind,
) -> Vec<u8> {
    let kind_bytes = [locator_kind_code(kind)];
    let (service, username) = match kind {
        LocatorKind::ActiveV2 => (
            ACTIVE_V2_LOCATOR_SERVICE,
            active_v2_username(
                realm_id,
                store_id,
                before.account_id,
                before.credential_id,
                before.binding_sha256,
            ),
        ),
        LocatorKind::LegacyV1 => (
            LEGACY_V1_LOCATOR_SERVICE,
            before.display_id.as_bytes().to_vec(),
        ),
    };
    encode_transcript(
        DELETE_ONLY_LOCATOR_DOMAIN,
        &[&kind_bytes, service, &username],
    )
}

fn validate_cleanup_reservation_origins(
    authority: &BootstrapSnapshot,
    request: &PrepareAccountTransitionRequest,
    challenge: &StoredChallenge,
) -> Result<(), MailError> {
    if request.cleanup_reservations.is_empty() {
        return Ok(());
    }
    let mutation = account_mutation_manifest(challenge, request.kind)?;
    let before = mutation
        .before
        .as_ref()
        .ok_or_else(authorization_context_stale_error)?;
    for reservation in &request.cleanup_reservations {
        let expected = expected_delete_only_locator(
            authority.realm_id,
            mutation.config_cas.store_id,
            before,
            reservation.locator_kind,
        );
        if reservation.locator_material != expected
            || reservation.locator_sha256 != Sha256Digest::digest(&expected)
        {
            return Err(authorization_context_stale_error());
        }
    }
    Ok(())
}

const fn locator_kind_name(kind: LocatorKind) -> &'static str {
    match kind {
        LocatorKind::ActiveV2 => "active_v2",
        LocatorKind::LegacyV1 => "legacy_v1",
    }
}

fn locator_kind_from_name(value: &str) -> Option<LocatorKind> {
    match value {
        "active_v2" => Some(LocatorKind::ActiveV2),
        "legacy_v1" => Some(LocatorKind::LegacyV1),
        _ => None,
    }
}

fn cleanup_state_from_name(value: &str) -> Option<CleanupState> {
    match value {
        "provisional" => Some(CleanupState::Provisional),
        "ready" => Some(CleanupState::Ready),
        "claimed" => Some(CleanupState::Claimed),
        "deleted" => Some(CleanupState::Deleted),
        _ => None,
    }
}

fn account_mutation_manifest(
    challenge: &StoredChallenge,
    kind: AccountTransitionKind,
) -> Result<AccountMutationManifest, MailError> {
    let manifest = ActionManifest::parse(&challenge.manifest)
        .map_err(|_| authorization_context_stale_error())?;
    match (kind, manifest.payload()) {
        (AccountTransitionKind::AccountCreate, ManifestPayload::AccountCreate(value))
        | (AccountTransitionKind::AccountUpdate, ManifestPayload::AccountUpdate(value))
        | (AccountTransitionKind::AccountRemove, ManifestPayload::AccountRemove(value)) => {
            Ok(value.clone())
        }
        (AccountTransitionKind::CredentialSet, ManifestPayload::CredentialSet(value))
        | (AccountTransitionKind::CredentialDelete, ManifestPayload::CredentialDelete(value)) => {
            Ok(value.account.clone())
        }
        _ => Err(authorization_context_stale_error()),
    }
}

#[allow(clippy::too_many_lines)]
fn validate_prepare_occupancy(
    connection: &Connection,
    request: &PrepareAccountTransitionRequest,
    challenge: &StoredChallenge,
) -> Result<(), MailError> {
    let store = load_registered_store_by_id(connection, request.store_id)?
        .ok_or_else(authorization_context_stale_error)?;
    match store.state.as_str() {
        "recovery_required" => return Err(recovery_error()),
        "active" => {}
        _ => return Err(account_update_conflict_error()),
    }
    if store.config_generation != request.expected_generation
        || store.config_sha256 != request.before_config_sha256
    {
        return Err(authorization_context_stale_error());
    }
    let active_transition: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM account_transitions
             WHERE store_id=?1 AND state IN ('prepared','config_committed')",
            [request.store_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if active_transition != 0 {
        return Err(account_update_conflict_error());
    }
    match request.kind {
        AccountTransitionKind::AccountCreate => {
            let identities: i64 = connection
                .query_row(
                    "SELECT
                        (SELECT COUNT(*) FROM registered_accounts WHERE account_id=?1) +
                        (SELECT COUNT(*) FROM registered_credentials WHERE credential_id=?2) +
                        (SELECT COUNT(*) FROM account_transitions WHERE transition_id=?3)",
                    params![
                        request.account_id.as_bytes(),
                        request.credential_id.as_bytes(),
                        request.transition_id.as_bytes(),
                    ],
                    |row| row.get(0),
                )
                .map_err(|_| store_read_error())?;
            if identities != 0 {
                return Err(account_identity_conflict_error());
            }
            let display: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM registered_accounts
                     WHERE store_id=?1 AND display_id_sha256=?2
                       AND state IN ('proposed','active','blocked')",
                    params![
                        request.store_id.as_bytes(),
                        request.display_id_sha256.as_bytes()
                    ],
                    |row| row.get(0),
                )
                .map_err(|_| store_read_error())?;
            if display != 0 {
                return Err(account_already_exists_error());
            }
        }
        AccountTransitionKind::AccountUpdate
        | AccountTransitionKind::AccountRemove
        | AccountTransitionKind::CredentialSet
        | AccountTransitionKind::CredentialDelete => {
            let mutation = account_mutation_manifest(challenge, request.kind)?;
            let before = mutation
                .before
                .as_ref()
                .ok_or_else(authorization_context_stale_error)?;
            let account = load_registered_account(connection, request.account_id)?
                .ok_or_else(authorization_context_stale_error)?;
            if account.state != RegisteredAccountState::Active
                || account.store_id != request.store_id
                || account.display_id_sha256 != display_id_digest(&before.display_id)
                || account.account_generation != before.generation
                || account.credential_id != before.credential_id
                || account.binding_sha256 != before.binding_sha256
                || account.active_transition_id.is_some()
                || account.removed_at.is_some()
            {
                return Err(authorization_context_stale_error());
            }
            let identities: i64 = if request.kind == AccountTransitionKind::AccountUpdate {
                connection
                    .query_row(
                        "SELECT
                            (SELECT COUNT(*) FROM registered_credentials WHERE credential_id=?1) +
                            (SELECT COUNT(*) FROM account_transitions WHERE transition_id=?2)",
                        params![
                            request.credential_id.as_bytes(),
                            request.transition_id.as_bytes(),
                        ],
                        |row| row.get(0),
                    )
                    .map_err(|_| store_read_error())?
            } else {
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM account_transitions WHERE transition_id=?1",
                        [request.transition_id.as_bytes()],
                        |row| row.get(0),
                    )
                    .map_err(|_| store_read_error())?
            };
            if identities != 0 {
                return Err(account_identity_conflict_error());
            }
            for cleanup in &request.cleanup_reservations {
                let occupied: i64 = connection
                    .query_row(
                        "SELECT COUNT(*) FROM credential_cleanup
                         WHERE cleanup_id=?1 OR locator_sha256=?2",
                        params![
                            cleanup.cleanup_id.as_bytes(),
                            cleanup.locator_sha256.as_bytes(),
                        ],
                        |row| row.get(0),
                    )
                    .map_err(|_| store_read_error())?;
                if occupied != 0 {
                    return Err(account_identity_conflict_error());
                }
            }
        }
    }
    Ok(())
}

fn validate_prepare_retry_identity(
    connection: &Connection,
    request: &PrepareAccountTransitionRequest,
    transition: &StoredAccountTransition,
) -> Result<(), MailError> {
    let grant = load_grant_use(connection, transition.grant_id)?.ok_or_else(recovery_error)?;
    let receipt = load_receipt_by_id(connection, grant.receipt_id)?.ok_or_else(recovery_error)?;
    let challenge = load_challenge(connection, receipt.challenge_id)?;
    validate_account_prepare_identity(request, &challenge, &receipt)
        .map_err(|_| grant_already_used_error())?;
    if transition.transition_id != request.transition_id
        || transition.grant_id != request.grant_use.grant_id
        || transition.store_id != request.store_id
        || transition.account_id != request.account_id
        || transition.kind != request.kind
        || transition.before_config_sha256 != request.before_config_sha256
        || transition.after_config_sha256 != request.after_config_sha256
        || transition.expected_generation != request.expected_generation
        || transition.next_generation != request.next_generation
        || transition.transition_sha256
            != account_transition_digest(request, transition.prepared_at)
    {
        return Err(grant_already_used_error());
    }
    let cleanup_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM credential_cleanup WHERE transition_id=?1",
            [transition.transition_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if usize::try_from(cleanup_count).ok() != Some(request.cleanup_reservations.len()) {
        return Err(grant_already_used_error());
    }
    for cleanup in &request.cleanup_reservations {
        let stored: Option<(String, Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT locator_kind,locator_material,locator_sha256
                 FROM credential_cleanup WHERE cleanup_id=?1 AND transition_id=?2",
                params![
                    cleanup.cleanup_id.as_bytes(),
                    transition.transition_id.as_bytes(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| store_read_error())?;
        let Some((kind, material, digest)) = stored else {
            return Err(grant_already_used_error());
        };
        if kind != locator_kind_name(cleanup.locator_kind)
            || material != cleanup.locator_material
            || digest.as_slice() != cleanup.locator_sha256.as_bytes()
        {
            return Err(grant_already_used_error());
        }
    }
    Ok(())
}

fn insert_grant_use(
    transaction: &Transaction<'_>,
    request: &GrantUseRequest,
    receipt: &[u8],
    receipt_sha256: Sha256Digest,
    used_at: i64,
) -> Result<(), MailError> {
    let inserted = transaction
        .execute(
            "INSERT INTO grant_uses
             (grant_id,receipt_id,action,target_kind,target_id,manifest_sha256,
              use_receipt,use_sha256,used_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                request.grant_id.as_bytes(),
                request.receipt_id.as_bytes(),
                i64::from(request.action.code()),
                i64::from(request.target_kind.code()),
                &request.target_bytes,
                request.manifest_sha256.as_bytes(),
                receipt,
                receipt_sha256.as_bytes(),
                used_at,
            ],
        )
        .map_err(|_| store_write_error())?;
    if inserted != 1 {
        return Err(store_write_error());
    }
    Ok(())
}

fn foreign_key_violation_count(connection: &Connection) -> Result<i64, MailError> {
    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| store_read_error())?;
    let mut rows = statement.query([]).map_err(|_| store_read_error())?;
    let mut count = 0_i64;
    while rows.next().map_err(|_| store_read_error())?.is_some() {
        count = count.checked_add(1).ok_or_else(recovery_error)?;
    }
    Ok(count)
}

#[allow(clippy::too_many_arguments)]
fn insert_account_transition_event(
    transaction: &Transaction<'_>,
    entity_id: &[u8],
    entity_kind: u16,
    event_code: u16,
    source: u8,
    related_kind: u16,
    related_id: &[u8],
    prior_state: u16,
    next_state: u16,
    context: Sha256Digest,
    receipt_id: AuthorizationReceiptId,
    occurred_at: i64,
) -> Result<(), MailError> {
    insert_typed_event(
        transaction,
        entity_kind,
        entity_id,
        event_code,
        source,
        related_kind,
        related_id,
        prior_state,
        next_state,
        context,
        Some(receipt_id),
        occurred_at,
    )
}

fn transition_receipt_id(
    connection: &Connection,
    transition: &StoredAccountTransition,
) -> Result<AuthorizationReceiptId, MailError> {
    let grant = load_grant_use(connection, transition.grant_id)?.ok_or_else(recovery_error)?;
    Ok(grant.receipt_id)
}

#[allow(clippy::too_many_arguments)]
fn insert_transition_phase_event(
    transaction: &Transaction<'_>,
    transition: &StoredAccountTransition,
    event_code: u16,
    source: u8,
    prior: AccountTransitionState,
    next: AccountTransitionState,
    context: Sha256Digest,
    occurred_at: i64,
) -> Result<(), MailError> {
    let receipt_id = transition_receipt_id(transaction, transition)?;
    insert_account_transition_event(
        transaction,
        transition.transition_id.as_bytes(),
        6,
        event_code,
        source,
        5,
        transition.account_id.as_bytes(),
        prior.event_state(),
        next.event_state(),
        context,
        receipt_id,
        occurred_at,
    )
}

fn insert_cleanup_ready_events(
    transaction: &Transaction<'_>,
    transition: &StoredAccountTransition,
    receipt_id: AuthorizationReceiptId,
    occurred_at: i64,
) -> Result<(), MailError> {
    let mut statement = transaction
        .prepare(
            "SELECT cleanup_id FROM credential_cleanup
             WHERE transition_id=?1 AND state='ready' ORDER BY cleanup_id",
        )
        .map_err(|_| store_read_error())?;
    let mut rows = statement
        .query([transition.transition_id.as_bytes()])
        .map_err(|_| store_read_error())?;
    while let Some(row) = rows.next().map_err(|_| store_read_error())? {
        let cleanup_id: Vec<u8> = row.get(0).map_err(|_| store_read_error())?;
        insert_account_transition_event(
            transaction,
            &cleanup_id,
            7,
            15,
            6,
            6,
            transition.transition_id.as_bytes(),
            0x0701,
            0x0702,
            transition.transition_sha256,
            receipt_id,
            occurred_at,
        )?;
    }
    Ok(())
}

fn projection_for_state(
    transition: &StoredAccountTransition,
    transition_state: AccountTransitionState,
    account_state: RegisteredAccountState,
    store_state: RegisteredStoreTransitionState,
    config_generation: NonZeroU64,
    account_generation: NonZeroU64,
) -> Result<AccountTransitionProjection, MailError> {
    Ok(AccountTransitionProjection {
        transition_id: transition.transition_id,
        account_id: transition.account_id,
        transition_state,
        account_state,
        store_state,
        config_generation,
        account_generation,
        prepared_at: utc_millis(transition.prepared_at)?,
    })
}

fn projection_for_transition_state(
    connection: &Connection,
    transition: &StoredAccountTransition,
    transition_state: AccountTransitionState,
    account_state: RegisteredAccountState,
    store_state: RegisteredStoreTransitionState,
    config_generation: NonZeroU64,
) -> Result<AccountTransitionProjection, MailError> {
    projection_for_state(
        transition,
        transition_state,
        account_state,
        store_state,
        config_generation,
        transition_projection_account_generation(connection, transition, transition_state)?,
    )
}

fn transition_projection_account_generation(
    connection: &Connection,
    transition: &StoredAccountTransition,
    transition_state: AccountTransitionState,
) -> Result<NonZeroU64, MailError> {
    if transition.kind == AccountTransitionKind::AccountRemove
        || (matches!(
            transition.kind,
            AccountTransitionKind::AccountUpdate
                | AccountTransitionKind::CredentialSet
                | AccountTransitionKind::CredentialDelete
        ) && transition_state == AccountTransitionState::Aborted)
    {
        let grant = load_grant_use(connection, transition.grant_id)?.ok_or_else(recovery_error)?;
        let receipt =
            load_receipt_by_id(connection, grant.receipt_id)?.ok_or_else(recovery_error)?;
        let challenge = load_challenge(connection, receipt.challenge_id)?;
        let manifest = ActionManifest::parse(&challenge.manifest).map_err(|_| recovery_error())?;
        let mutation = match (transition.kind, manifest.payload()) {
            (AccountTransitionKind::AccountUpdate, ManifestPayload::AccountUpdate(mutation))
            | (AccountTransitionKind::AccountRemove, ManifestPayload::AccountRemove(mutation)) => {
                mutation
            }
            (AccountTransitionKind::CredentialSet, ManifestPayload::CredentialSet(mutation)) => {
                &mutation.account
            }
            (
                AccountTransitionKind::CredentialDelete,
                ManifestPayload::CredentialDelete(mutation),
            ) => &mutation.account,
            _ => return Err(recovery_error()),
        };
        return Ok(mutation
            .before
            .as_ref()
            .ok_or_else(recovery_error)?
            .generation);
    }
    transition_account_generation(connection, transition)
}

fn transition_account_generation(
    connection: &Connection,
    transition: &StoredAccountTransition,
) -> Result<NonZeroU64, MailError> {
    let grant = load_grant_use(connection, transition.grant_id)?.ok_or_else(recovery_error)?;
    let receipt = load_receipt_by_id(connection, grant.receipt_id)?.ok_or_else(recovery_error)?;
    let challenge = load_challenge(connection, receipt.challenge_id)?;
    let manifest = ActionManifest::parse(&challenge.manifest).map_err(|_| recovery_error())?;
    let mutation = match (transition.kind, manifest.payload()) {
        (AccountTransitionKind::AccountCreate, ManifestPayload::AccountCreate(mutation))
        | (AccountTransitionKind::AccountUpdate, ManifestPayload::AccountUpdate(mutation)) => {
            mutation
        }
        (AccountTransitionKind::CredentialSet, ManifestPayload::CredentialSet(mutation))
        | (AccountTransitionKind::CredentialDelete, ManifestPayload::CredentialDelete(mutation)) => {
            &mutation.account
        }
        _ => return Err(recovery_error()),
    };
    Ok(mutation
        .after
        .as_ref()
        .ok_or_else(recovery_error)?
        .generation)
}

#[allow(clippy::too_many_lines)]
fn transition_projection(
    connection: &Connection,
    transition: &StoredAccountTransition,
) -> Result<AccountTransitionProjection, MailError> {
    let account =
        load_registered_account(connection, transition.account_id)?.ok_or_else(recovery_error)?;
    let account_generation =
        transition_projection_account_generation(connection, transition, transition.state)?;
    if account.account_id != transition.account_id || account.store_id != transition.store_id {
        return Err(recovery_error());
    }
    match transition.state {
        AccountTransitionState::Prepared => {
            let store = load_registered_store_by_id(connection, transition.store_id)?
                .ok_or_else(recovery_error)?;
            let expected_account_state = if transition.kind == AccountTransitionKind::AccountCreate
            {
                RegisteredAccountState::Proposed
            } else {
                RegisteredAccountState::Blocked
            };
            if account.state != expected_account_state
                || account.active_transition_id != Some(transition.transition_id)
                || account.account_generation != account_generation
                || store.state != "blocked"
                || store.config_generation != transition.expected_generation
                || store.config_sha256 != transition.before_config_sha256
            {
                return Err(recovery_error());
            }
            projection_for_state(
                transition,
                transition.state,
                expected_account_state,
                RegisteredStoreTransitionState::Blocked,
                transition.expected_generation,
                account_generation,
            )
        }
        AccountTransitionState::ConfigCommitted => {
            let store = load_registered_store_by_id(connection, transition.store_id)?
                .ok_or_else(recovery_error)?;
            let expected_account_state = if transition.kind == AccountTransitionKind::AccountCreate
            {
                RegisteredAccountState::Proposed
            } else {
                RegisteredAccountState::Blocked
            };
            if account.state != expected_account_state
                || account.active_transition_id != Some(transition.transition_id)
                || account.account_generation != account_generation
                || store.state != "blocked"
                || store.config_generation != transition.next_generation
                || store.config_sha256 != transition.after_config_sha256
            {
                return Err(recovery_error());
            }
            projection_for_state(
                transition,
                transition.state,
                expected_account_state,
                RegisteredStoreTransitionState::Blocked,
                transition.next_generation,
                account_generation,
            )
        }
        AccountTransitionState::Finalized => projection_for_state(
            transition,
            transition.state,
            if transition.kind == AccountTransitionKind::AccountRemove {
                RegisteredAccountState::Removed
            } else {
                RegisteredAccountState::Active
            },
            RegisteredStoreTransitionState::Active,
            transition.next_generation,
            account_generation,
        ),
        AccountTransitionState::Aborted => projection_for_state(
            transition,
            transition.state,
            if transition.kind == AccountTransitionKind::AccountCreate {
                RegisteredAccountState::Removed
            } else {
                RegisteredAccountState::Active
            },
            RegisteredStoreTransitionState::Active,
            transition.expected_generation,
            account_generation,
        ),
        AccountTransitionState::RecoveryRequired => {
            let store = load_registered_store_by_id(connection, transition.store_id)?
                .ok_or_else(recovery_error)?;
            if account.state != RegisteredAccountState::Blocked
                || account.active_transition_id != Some(transition.transition_id)
                || store.state != "recovery_required"
            {
                return Err(recovery_error());
            }
            projection_for_state(
                transition,
                transition.state,
                RegisteredAccountState::Blocked,
                RegisteredStoreTransitionState::RecoveryRequired,
                store.config_generation,
                account_generation,
            )
        }
    }
}

fn insert_transition_versions(
    transaction: &Transaction<'_>,
    transition: &StoredAccountTransition,
    account: &StoredRegisteredAccount,
    created_at: i64,
    test_hooks: &AuthorityTestHooks,
) -> Result<(), MailError> {
    let store = load_registered_store_by_id(transaction, transition.store_id)?
        .ok_or_else(recovery_error)?;
    let inserted = transaction
        .execute(
            "INSERT INTO registered_store_versions
             (store_id,location_sha256,config_generation,config_sha256,
              enrolled_receipt_id,committed_transition_id,created_at)
             VALUES(?1,?2,?3,?4,NULL,?5,?6)",
            params![
                transition.store_id.as_bytes(),
                store.location_sha256.as_bytes(),
                i64::try_from(transition.next_generation.get()).map_err(|_| recovery_error())?,
                transition.after_config_sha256.as_bytes(),
                transition.transition_id.as_bytes(),
                created_at,
            ],
        )
        .map_err(|_| store_write_error())?;
    if inserted != 1 {
        return Err(store_write_error());
    }
    test_hooks.fault(TestFaultPoint::AccountStoreVersionInserted)?;
    if transition.kind == AccountTransitionKind::AccountRemove {
        return Ok(());
    }
    let inserted = transaction
        .execute(
            "INSERT INTO registered_account_versions
             (account_id,store_id,account_generation,credential_id,binding_sha256,
              committed_transition_id,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                account.account_id.as_bytes(),
                account.store_id.as_bytes(),
                i64::try_from(account.account_generation.get()).map_err(|_| recovery_error())?,
                account.credential_id.as_bytes(),
                account.binding_sha256.as_bytes(),
                transition.transition_id.as_bytes(),
                created_at,
            ],
        )
        .map_err(|_| store_write_error())?;
    if inserted != 1 {
        return Err(store_write_error());
    }
    test_hooks.fault(TestFaultPoint::AccountVersionInserted)?;
    Ok(())
}

fn update_finalize_rows(
    transaction: &Transaction<'_>,
    transition: &StoredAccountTransition,
    at: i64,
    test_hooks: &AuthorityTestHooks,
) -> Result<(), MailError> {
    let account_prior = if transition.kind == AccountTransitionKind::AccountCreate {
        "proposed"
    } else {
        "blocked"
    };
    let account = if transition.kind == AccountTransitionKind::AccountRemove {
        transaction.execute(
            "UPDATE registered_accounts SET state='removed',active_transition_id=NULL,
             updated_at=?1,removed_at=?1 WHERE account_id=?2 AND state=?3
             AND active_transition_id=?4",
            params![
                at,
                transition.account_id.as_bytes(),
                account_prior,
                transition.transition_id.as_bytes()
            ],
        )
    } else {
        transaction.execute(
            "UPDATE registered_accounts SET state='active',active_transition_id=NULL,
             updated_at=?1,removed_at=NULL WHERE account_id=?2 AND state=?3
             AND active_transition_id=?4",
            params![
                at,
                transition.account_id.as_bytes(),
                account_prior,
                transition.transition_id.as_bytes()
            ],
        )
    }
    .map_err(|_| store_write_error())?;
    if account != 1 {
        return Err(recovery_error());
    }
    test_hooks.fault(TestFaultPoint::AccountFinalizeAccountUpdated)?;
    let transition_changed = transaction
        .execute(
            "UPDATE account_transitions SET state='finalized',finalized_at=?1
             WHERE transition_id=?2 AND state='config_committed'",
            params![at, transition.transition_id.as_bytes()],
        )
        .map_err(|_| store_write_error())?;
    if transition_changed != 1 {
        return Err(recovery_error());
    }
    test_hooks.fault(TestFaultPoint::AccountFinalizeTransitionUpdated)?;
    let store = transaction
        .execute(
            "UPDATE registered_stores SET state='active',updated_at=?1
             WHERE store_id=?2 AND state='blocked' AND config_generation=?3
             AND config_sha256=?4",
            params![
                at,
                transition.store_id.as_bytes(),
                i64::try_from(transition.next_generation.get()).map_err(|_| recovery_error())?,
                transition.after_config_sha256.as_bytes(),
            ],
        )
        .map_err(|_| store_write_error())?;
    if store != 1 {
        return Err(recovery_error());
    }
    test_hooks.fault(TestFaultPoint::AccountFinalizeStoreUpdated)?;
    transaction
        .execute(
            "UPDATE credential_cleanup SET state='ready'
             WHERE transition_id=?1 AND state='provisional'",
            [transition.transition_id.as_bytes()],
        )
        .map_err(|_| store_write_error())?;
    test_hooks.fault(TestFaultPoint::AccountFinalizeCleanupUpdated)?;
    Ok(())
}

fn update_abort_rows(
    transaction: &Transaction<'_>,
    transition: &StoredAccountTransition,
    at: i64,
    test_hooks: &AuthorityTestHooks,
) -> Result<(), MailError> {
    let account = if transition.kind == AccountTransitionKind::AccountCreate {
        transaction.execute(
            "UPDATE registered_accounts SET state='removed',active_transition_id=NULL,
             updated_at=?1,removed_at=?1 WHERE account_id=?2 AND state='proposed'
             AND active_transition_id=?3",
            params![
                at,
                transition.account_id.as_bytes(),
                transition.transition_id.as_bytes()
            ],
        )
    } else {
        if !matches!(
            transition.kind,
            AccountTransitionKind::AccountUpdate
                | AccountTransitionKind::AccountRemove
                | AccountTransitionKind::CredentialSet
                | AccountTransitionKind::CredentialDelete
        ) {
            return Err(recovery_error());
        }
        let generation = transition_projection_account_generation(
            transaction,
            transition,
            AccountTransitionState::Aborted,
        )?;
        let previous: (Vec<u8>, Vec<u8>, Vec<u8>) = transaction
            .query_row(
                "SELECT credential_id,binding_sha256,committed_transition_id
                 FROM registered_account_versions
                 WHERE account_id=?1 AND account_generation=?2",
                params![
                    transition.account_id.as_bytes(),
                    i64::try_from(generation.get()).map_err(|_| recovery_error())?,
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| recovery_error())?;
        let previous_transition_id: TransitionId =
            uuid_from_blob_sql(previous.2).map_err(|_| recovery_error())?;
        let previous_transition = load_account_transition(transaction, previous_transition_id)?
            .ok_or_else(recovery_error)?;
        let previous_receipt = transition_receipt_id(transaction, &previous_transition)?;
        transaction.execute(
            "UPDATE registered_accounts SET account_generation=?1,credential_id=?2,
             binding_sha256=?3,state='active',authorized_receipt_id=?4,
             active_transition_id=NULL,updated_at=?5,removed_at=NULL
             WHERE account_id=?6 AND state='blocked' AND active_transition_id=?7",
            params![
                i64::try_from(generation.get()).map_err(|_| recovery_error())?,
                previous.0,
                previous.1,
                previous_receipt.as_bytes(),
                at,
                transition.account_id.as_bytes(),
                transition.transition_id.as_bytes(),
            ],
        )
    }
    .map_err(|_| store_write_error())?;
    if account != 1 {
        return Err(recovery_error());
    }
    test_hooks.fault(TestFaultPoint::AccountAbortAccountUpdated)?;
    let transition_changed = transaction
        .execute(
            "UPDATE account_transitions SET state='aborted',resolved_at=?1
             WHERE transition_id=?2 AND state='prepared'",
            params![at, transition.transition_id.as_bytes()],
        )
        .map_err(|_| store_write_error())?;
    if transition_changed != 1 {
        return Err(recovery_error());
    }
    test_hooks.fault(TestFaultPoint::AccountAbortTransitionUpdated)?;
    let store = transaction
        .execute(
            "UPDATE registered_stores SET state='active',updated_at=?1
             WHERE store_id=?2 AND state='blocked' AND config_generation=?3
             AND config_sha256=?4",
            params![
                at,
                transition.store_id.as_bytes(),
                i64::try_from(transition.expected_generation.get()).map_err(|_| recovery_error())?,
                transition.before_config_sha256.as_bytes(),
            ],
        )
        .map_err(|_| store_write_error())?;
    if store != 1 {
        return Err(recovery_error());
    }
    test_hooks.fault(TestFaultPoint::AccountAbortStoreUpdated)?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn commit_account_recovery(
    transaction: &Transaction<'_>,
    transition: &StoredAccountTransition,
    request: &AccountTransitionObservationRequest,
    at: i64,
    test_hooks: &AuthorityTestHooks,
) -> Result<AccountTransitionProjection, MailError> {
    if !matches!(
        transition.state,
        AccountTransitionState::Prepared | AccountTransitionState::ConfigCommitted
    ) {
        return Err(account_update_conflict_error());
    }
    let recovery = account_recovery_digest(
        transition,
        transition.state,
        request.actual_config_generation,
        request.actual_config_sha256,
    );
    let account_prior = if transition.kind == AccountTransitionKind::AccountCreate {
        "proposed"
    } else {
        "blocked"
    };
    let account = transaction
        .execute(
            "UPDATE registered_accounts SET state='blocked',updated_at=?1
             WHERE account_id=?2 AND active_transition_id=?3 AND state=?4",
            params![
                at,
                transition.account_id.as_bytes(),
                transition.transition_id.as_bytes(),
                account_prior,
            ],
        )
        .map_err(|_| store_write_error())?;
    if account != 1 {
        return Err(recovery_error());
    }
    test_hooks.fault(TestFaultPoint::AccountRecoveryAccountUpdated)?;
    let changed = transaction
        .execute(
            "UPDATE account_transitions SET state='recovery_required',resolved_at=?1
             WHERE transition_id=?2 AND state=?3",
            params![
                at,
                transition.transition_id.as_bytes(),
                transition_state_name(transition.state),
            ],
        )
        .map_err(|_| store_write_error())?;
    if changed != 1 {
        return Err(recovery_error());
    }
    test_hooks.fault(TestFaultPoint::AccountRecoveryTransitionUpdated)?;
    let store = transaction
        .execute(
            "UPDATE registered_stores SET state='recovery_required',config_generation=?1,
             config_sha256=?2,updated_at=?3 WHERE store_id=?4 AND state='blocked'",
            params![
                i64::try_from(request.actual_config_generation.get())
                    .map_err(|_| recovery_error())?,
                request.actual_config_sha256.as_bytes(),
                at,
                transition.store_id.as_bytes(),
            ],
        )
        .map_err(|_| store_write_error())?;
    if store != 1 {
        return Err(recovery_error());
    }
    test_hooks.fault(TestFaultPoint::AccountRecoveryStoreUpdated)?;
    let receipt_id = transition_receipt_id(transaction, transition)?;
    insert_account_transition_event(
        transaction,
        transition.store_id.as_bytes(),
        4,
        9,
        5,
        6,
        transition.transition_id.as_bytes(),
        0x0402,
        0x0404,
        recovery,
        receipt_id,
        at,
    )?;
    test_hooks.fault(TestFaultPoint::AccountRecoveryStoreEvent)?;
    insert_transition_phase_event(
        transaction,
        transition,
        14,
        5,
        transition.state,
        AccountTransitionState::RecoveryRequired,
        recovery,
        at,
    )?;
    test_hooks.fault(TestFaultPoint::AccountRecoveryTransitionEvent)?;
    observe_clock_pair(transaction, at)?;
    test_hooks.fault(TestFaultPoint::AccountRecoveryClockUpdated)?;
    projection_for_transition_state(
        transaction,
        transition,
        AccountTransitionState::RecoveryRequired,
        RegisteredAccountState::Blocked,
        RegisteredStoreTransitionState::RecoveryRequired,
        request.actual_config_generation,
    )
}

impl StoredRegisteredStore {
    fn matches_request(
        &self,
        request: &EnrollStoreRequest,
        enrollment: &StoreEnrollmentContext,
    ) -> bool {
        self.store_id == request.store_id
            && self.location_material == request.location_bytes
            && self.location_sha256 == request.location_sha256
            && self.enrolled_receipt_id == request.grant_use.receipt_id
            && self.store_id == enrollment.store_id
            && self.location_sha256 == enrollment.location_sha256
    }
}

fn validate_initial_store_version(
    version: &StoredRegisteredStoreVersion,
    store: &StoredRegisteredStore,
    enrollment: &StoreEnrollmentContext,
    receipt: &StoredReceipt,
) -> Result<(), MailError> {
    utc_millis(version.created_at)?;
    if version.store_id != store.store_id
        || version.store_id != enrollment.store_id
        || version.location_sha256 != store.location_sha256
        || version.location_sha256 != enrollment.location_sha256
        || version.config_generation != enrollment.config_generation
        || version.config_sha256 != enrollment.config_sha256
        || version.enrolled_receipt_id != Some(receipt.receipt_id)
        || version.committed_transition_id.is_some()
        || version.created_at != store.created_at
    {
        return Err(recovery_error());
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct StoreEnrollmentContext {
    store_id: StoreId,
    location_sha256: Sha256Digest,
    config_generation: NonZeroU64,
    config_sha256: Sha256Digest,
}

fn valid_target_shape(kind: TargetKind, bytes: &[u8]) -> bool {
    match kind {
        TargetKind::Operation
        | TargetKind::Store
        | TargetKind::Account
        | TargetKind::Credential
        | TargetKind::Cleanup
        | TargetKind::RemoteEffect => bytes.len() == 16,
        TargetKind::TrustEpoch => bytes.len() == 8 && bytes != [0_u8; 8],
        TargetKind::Policy | TargetKind::Assurance => bytes.is_empty(),
    }
}

fn validate_enroll_store_request(request: &EnrollStoreRequest) -> Result<(), MailError> {
    input_utc_millis(request.observed_at_unix_ms)?;
    let canonical = request.location_material.canonical_bytes()?;
    if canonical != request.location_bytes
        || canonical.len() > 4_096
        || Sha256Digest::digest(&canonical) != request.location_sha256
        || request.config_generation.get() > u64::try_from(i64::MAX).unwrap_or(u64::MAX)
    {
        return Err(MailError::invalid_input(
            "store enrollment request is outside the contract",
        ));
    }
    Ok(())
}

fn validate_challenge_request(request: &CreateChallengeRequest) -> Result<(), MailError> {
    if request.observed_at_unix_ms < 0 || request.expires_at_unix_ms < 0 {
        return Err(MailError::invalid_input(
            "authority challenge time must be nonnegative",
        ));
    }
    input_utc_millis(request.observed_at_unix_ms)?;
    input_utc_millis(request.expires_at_unix_ms)?;
    if let ManifestPayload::CredentialCleanup(cleanup) = request.manifest.payload()
        && cleanup.transition_id.is_none()
    {
        return Err(MailError::stable(
            MailErrorCode::AuthorizationMalformed,
            "credential cleanup authorization is malformed",
        ));
    }
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

fn ensure_supported_challenge_action(action: SensitiveAction) -> Result<(), MailError> {
    match action {
        SensitiveAction::StoreEnroll
        | SensitiveAction::AccountCreate
        | SensitiveAction::AccountUpdate
        | SensitiveAction::AccountRemove
        | SensitiveAction::CredentialSet
        | SensitiveAction::CredentialDelete
        | SensitiveAction::CredentialCleanup
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

fn validate_fresh_manifest_context(
    connection: &Connection,
    authority: &BootstrapSnapshot,
    manifest: &ActionManifest,
) -> Result<(), MailError> {
    match manifest.payload() {
        ManifestPayload::StoreEnroll(value) => {
            let count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM registered_stores
                     WHERE store_id=?1 OR location_sha256=?2",
                    params![
                        value.config_cas.store_id.as_bytes(),
                        value.config_cas.location_sha256.as_bytes()
                    ],
                    |row| row.get(0),
                )
                .map_err(|_| store_read_error())?;
            if count != 0 {
                return Err(config_store_identity_conflict_error());
            }
        }
        ManifestPayload::AccountCreate(value) => {
            validate_fresh_account_create_context(connection, value)?;
        }
        ManifestPayload::AccountUpdate(value) | ManifestPayload::AccountRemove(value) => {
            validate_fresh_account_mutation_context(connection, value)?;
        }
        ManifestPayload::CredentialSet(value) | ManifestPayload::CredentialDelete(value) => {
            validate_fresh_account_mutation_context(connection, &value.account)?;
        }
        ManifestPayload::CredentialCleanup(_) => {
            validate_credential_cleanup_context(connection, authority, manifest, true)?;
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::type_complexity)]
fn validate_credential_cleanup_context(
    connection: &Connection,
    authority: &BootstrapSnapshot,
    manifest: &ActionManifest,
    require_ready_eligibility: bool,
) -> Result<(), MailError> {
    let ManifestPayload::CredentialCleanup(cleanup_manifest) = manifest.payload() else {
        return Err(credential_cleanup_invalid_error());
    };
    let transition_id = cleanup_manifest
        .transition_id
        .ok_or_else(credential_cleanup_invalid_error)?;
    if cleanup_manifest.expected_state != CleanupState::Ready {
        return Err(credential_cleanup_invalid_error());
    }

    let row: Option<(
        Option<Vec<u8>>,
        String,
        Vec<u8>,
        Vec<u8>,
        String,
        Option<Vec<u8>>,
        i64,
        Option<i64>,
    )> = connection
        .query_row(
            "SELECT transition_id,locator_kind,locator_material,locator_sha256,state,
                    claim_grant_id,created_at,deleted_at
             FROM credential_cleanup WHERE cleanup_id=?1",
            [cleanup_manifest.cleanup_id.as_bytes()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| store_read_error())?;
    let Some((
        stored_transition,
        stored_kind,
        locator_material,
        locator_digest,
        cleanup_state,
        claim_grant_id,
        created_at,
        deleted_at,
    )) = row
    else {
        return Err(credential_cleanup_invalid_error());
    };
    let stored_transition: TransitionId = stored_transition
        .ok_or_else(recovery_error)
        .and_then(|bytes| uuid_from_blob_sql(bytes).map_err(|_| recovery_error()))?;
    if stored_transition != transition_id {
        return Err(credential_cleanup_invalid_error());
    }

    let transition = load_account_transition(connection, transition_id)?
        .ok_or_else(credential_cleanup_invalid_error)?;
    if transition.state != AccountTransitionState::Finalized
        || !matches!(
            transition.kind,
            AccountTransitionKind::AccountUpdate | AccountTransitionKind::AccountRemove
        )
        || transition.prepared_at != created_at
    {
        return Err(credential_cleanup_invalid_error());
    }
    let origin_grant =
        load_grant_use(connection, transition.grant_id)?.ok_or_else(recovery_error)?;
    let origin_receipt =
        load_receipt_by_id(connection, origin_grant.receipt_id)?.ok_or_else(recovery_error)?;
    let origin_challenge =
        load_challenge(connection, origin_receipt.challenge_id).map_err(|_| recovery_error())?;
    let origin_manifest =
        ActionManifest::parse(&origin_challenge.manifest).map_err(|_| recovery_error())?;
    let ((AccountTransitionKind::AccountUpdate, ManifestPayload::AccountUpdate(mutation))
    | (AccountTransitionKind::AccountRemove, ManifestPayload::AccountRemove(mutation))) =
        (transition.kind, origin_manifest.payload())
    else {
        return Err(recovery_error());
    };
    let before = mutation.before.as_ref().ok_or_else(recovery_error)?;
    if mutation.transition_id != transition.transition_id
        || mutation.config_cas.store_id != transition.store_id
        || before.account_id != transition.account_id
        || manifest.context().store_id != Some(transition.store_id)
        || manifest.context().account_id != Some(transition.account_id)
        || manifest.context().account_binding_sha256 != Some(before.binding_sha256)
    {
        return Err(credential_cleanup_invalid_error());
    }

    let mut matching_descriptor = None;
    for descriptor in &mutation.cleanup {
        if descriptor.cleanup_id == cleanup_manifest.cleanup_id
            && matching_descriptor.replace(descriptor).is_some()
        {
            return Err(credential_cleanup_invalid_error());
        }
    }
    let descriptor = matching_descriptor.ok_or_else(credential_cleanup_invalid_error)?;
    if descriptor.expected_state != CleanupState::Provisional
        || descriptor.locator_kind != cleanup_manifest.locator_kind
        || descriptor.locator_sha256 != cleanup_manifest.locator_sha256
        || stored_kind != locator_kind_name(descriptor.locator_kind)
        || locator_digest.as_slice() != descriptor.locator_sha256.as_bytes()
    {
        return Err(credential_cleanup_invalid_error());
    }
    let expected_locator = expected_delete_only_locator(
        authority.realm_id,
        transition.store_id,
        before,
        descriptor.locator_kind,
    );
    if locator_material != expected_locator
        || Sha256Digest::digest(&locator_material) != descriptor.locator_sha256
    {
        return Err(credential_cleanup_invalid_error());
    }

    let historical_version_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM registered_account_versions
             WHERE account_id=?1 AND store_id=?2 AND account_generation=?3
               AND credential_id=?4 AND binding_sha256=?5",
            params![
                before.account_id.as_bytes(),
                transition.store_id.as_bytes(),
                i64::try_from(before.generation.get()).map_err(|_| recovery_error())?,
                before.credential_id.as_bytes(),
                before.binding_sha256.as_bytes(),
            ],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if historical_version_count != 1 {
        return Err(recovery_error());
    }

    let generation = before.generation.get().to_be_bytes();
    let kind = [locator_kind_code(descriptor.locator_kind)];
    let created = created_at.to_be_bytes();
    let expected_state = [1_u8];
    let tombstone = encode_transcript(
        CREDENTIAL_CLEANUP_TOMBSTONE_DOMAIN,
        &[
            authority.realm_id.as_bytes(),
            cleanup_manifest.cleanup_id.as_bytes(),
            transition.transition_id.as_bytes(),
            transition.transition_sha256.as_bytes(),
            origin_challenge.manifest_sha256.as_bytes(),
            transition.store_id.as_bytes(),
            transition.account_id.as_bytes(),
            &generation,
            before.credential_id.as_bytes(),
            before.binding_sha256.as_bytes(),
            &kind,
            descriptor.locator_sha256.as_bytes(),
            &created,
            &expected_state,
        ],
    );
    if cleanup_manifest.tombstone_sha256 != Sha256Digest::digest(&tombstone) {
        return Err(credential_cleanup_invalid_error());
    }

    if require_ready_eligibility
        && (cleanup_state != "ready" || claim_grant_id.is_some() || deleted_at.is_some())
    {
        return Err(credential_cleanup_invalid_error());
    }
    Ok(())
}

fn validate_credential_cleanup_public_pair(
    connection: &Connection,
    manifest: &ActionManifest,
) -> Result<(), MailError> {
    let store_id = manifest
        .context()
        .store_id
        .ok_or_else(credential_cleanup_invalid_error)?;
    let account_id = manifest
        .context()
        .account_id
        .ok_or_else(credential_cleanup_invalid_error)?;
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    let (store_state, account_store, account_state): (
        Option<String>,
        Option<Vec<u8>>,
        Option<String>,
    ) = connection
        .query_row(
            "SELECT
                (SELECT state FROM registered_stores WHERE store_id=?1),
                (SELECT store_id FROM registered_accounts WHERE account_id=?2),
                (SELECT state FROM registered_accounts WHERE account_id=?2)",
            params![store_id.as_bytes(), account_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| store_read_error())?;
    let (Some(store_state), Some(account_store), Some(account_state)) =
        (store_state, account_store, account_state)
    else {
        return Err(credential_cleanup_invalid_error());
    };
    if account_store.as_slice() != store_id.as_bytes() {
        return Err(credential_cleanup_invalid_error());
    }
    match store_state.as_str() {
        "recovery_required" => return Err(recovery_error()),
        "blocked" => return Err(account_update_conflict_error()),
        "active" => {}
        _ => return Err(credential_cleanup_invalid_error()),
    }
    match account_state.as_str() {
        "active" | "removed" => Ok(()),
        "blocked" | "proposed" => Err(account_update_conflict_error()),
        _ => Err(credential_cleanup_invalid_error()),
    }
}

fn validate_cleanup_claim_identity(
    request: &CredentialCleanupClaimRequest,
    challenge: &StoredChallenge,
    receipt: &StoredReceipt,
) -> Result<ActionManifest, MailError> {
    let manifest = ActionManifest::parse(&challenge.manifest)
        .map_err(|_| authorization_context_stale_error())?;
    let ManifestPayload::CredentialCleanup(cleanup) = manifest.payload() else {
        return Err(authorization_context_stale_error());
    };
    if request.grant_use.grant_id != challenge.grant_id
        || request.grant_use.receipt_id != receipt.receipt_id
        || receipt.challenge_id != challenge.challenge_id
        || receipt.grant_id != challenge.grant_id
        || request.grant_use.action != SensitiveAction::CredentialCleanup
        || request.grant_use.action != challenge.action
        || request.grant_use.target_kind != TargetKind::Cleanup
        || request.grant_use.target_kind.code() != challenge.target_kind_code
        || request.grant_use.target_bytes != challenge.target_id
        || request.grant_use.target_bytes.as_slice() != request.cleanup_id.as_bytes()
        || request.grant_use.manifest_sha256 != challenge.manifest_sha256
        || request.grant_use.manifest_sha256 != receipt.manifest_sha256
        || cleanup.cleanup_id != request.cleanup_id
    {
        return Err(authorization_context_stale_error());
    }
    Ok(manifest)
}

fn cleanup_projection(
    cleanup: &StoredCredentialCleanup,
    claimed_at: Option<i64>,
) -> Result<CredentialCleanupProjection, MailError> {
    Ok(CredentialCleanupProjection {
        cleanup_id: cleanup.cleanup_id,
        state: cleanup.state,
        claimed_at: claimed_at.map(utc_millis).transpose()?,
        deleted_at: cleanup.deleted_at.map(utc_millis).transpose()?,
    })
}

fn cleanup_delete_permit(
    home: &AuthorityHome,
    cleanup: &StoredCredentialCleanup,
    grant: &StoredGrantUse,
    apply_lock: File,
) -> Result<CleanupDeletePermit, MailError> {
    utc_millis(cleanup.created_at)?;
    let (kind, service, username) =
        parse_delete_only_locator(&cleanup.locator_material).ok_or_else(recovery_error)?;
    if cleanup.state != CleanupState::Claimed
        || cleanup.claim_grant_id != Some(grant.grant_id)
        || cleanup.locator_kind != kind
        || cleanup.locator_sha256 != Sha256Digest::digest(&cleanup.locator_material)
        || cleanup.deleted_at.is_some()
        || !delete_only_locator_shape_is_valid(kind, service, username)
    {
        return Err(recovery_error());
    }
    Ok(CleanupDeletePermit {
        cleanup_id: cleanup.cleanup_id,
        grant_id: grant.grant_id,
        receipt_id: grant.receipt_id,
        use_sha256: grant.use_sha256,
        locator_material: cleanup.locator_material.clone(),
        database_path: home.database.clone(),
        _apply_lock: apply_lock,
    })
}

fn validate_fresh_account_mutation_context(
    connection: &Connection,
    value: &kirje_core::AccountMutationManifest,
) -> Result<(), MailError> {
    let before = value
        .before
        .as_ref()
        .ok_or_else(authorization_context_stale_error)?;
    let store = load_registered_store_by_id(connection, value.config_cas.store_id)?
        .ok_or_else(authorization_context_stale_error)?;
    if store.location_sha256 != value.config_cas.location_sha256 {
        return Err(config_store_identity_conflict_error());
    }
    match store.state.as_str() {
        "recovery_required" => return Err(recovery_error()),
        "blocked" => return Err(account_update_conflict_error()),
        "active" => {}
        _ => return Err(authorization_context_stale_error()),
    }
    if store.config_generation != value.config_cas.generation
        || store.config_sha256 != value.config_cas.exact_content_sha256
    {
        return Err(authorization_context_stale_error());
    }
    let active: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM account_transitions
             WHERE store_id=?1 AND state IN ('prepared','config_committed')",
            [value.config_cas.store_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if active != 0 {
        return Err(account_update_conflict_error());
    }
    let account = load_registered_account(connection, before.account_id)?
        .ok_or_else(authorization_context_stale_error)?;
    match account.state {
        RegisteredAccountState::Active if account.active_transition_id.is_none() => {}
        RegisteredAccountState::Proposed | RegisteredAccountState::Blocked => {
            return Err(account_update_conflict_error());
        }
        RegisteredAccountState::Removed | RegisteredAccountState::Active => {
            return Err(authorization_context_stale_error());
        }
    }
    if account.store_id != value.config_cas.store_id
        || account.account_id != before.account_id
        || account.display_id_sha256 != display_id_digest(&before.display_id)
        || account.account_generation != before.generation
        || account.credential_id != before.credential_id
        || account.binding_sha256 != before.binding_sha256
    {
        return Err(authorization_context_stale_error());
    }
    let mut collisions: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM account_transitions WHERE transition_id=?1",
            [value.transition_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if let Some(after) = &value.after
        && after.credential_id != before.credential_id
    {
        collisions = collisions
            .checked_add(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM registered_credentials WHERE credential_id=?1",
                        [after.credential_id.as_bytes()],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(|_| store_read_error())?,
            )
            .ok_or_else(recovery_error)?;
    }
    for cleanup in &value.cleanup {
        collisions = collisions
            .checked_add(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM credential_cleanup
                         WHERE cleanup_id=?1 OR locator_sha256=?2",
                        params![
                            cleanup.cleanup_id.as_bytes(),
                            cleanup.locator_sha256.as_bytes()
                        ],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(|_| store_read_error())?,
            )
            .ok_or_else(recovery_error)?;
    }
    if collisions != 0 {
        return Err(account_identity_conflict_error());
    }
    Ok(())
}

fn validate_fresh_account_create_context(
    connection: &Connection,
    value: &kirje_core::AccountMutationManifest,
) -> Result<(), MailError> {
    let after = value
        .after
        .as_ref()
        .ok_or_else(authorization_context_stale_error)?;
    let store = load_registered_store_by_id(connection, value.config_cas.store_id)?
        .ok_or_else(authorization_context_stale_error)?;
    if store.location_sha256 != value.config_cas.location_sha256 {
        return Err(config_store_identity_conflict_error());
    }
    match store.state.as_str() {
        "recovery_required" => return Err(recovery_error()),
        "blocked" => return Err(account_update_conflict_error()),
        "active" => {}
        _ => return Err(authorization_context_stale_error()),
    }
    if store.config_generation != value.config_cas.generation
        || store.config_sha256 != value.config_cas.exact_content_sha256
    {
        return Err(authorization_context_stale_error());
    }
    let active: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM account_transitions
             WHERE store_id=?1 AND state IN ('prepared','config_committed')",
            [value.config_cas.store_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if active != 0 {
        return Err(account_update_conflict_error());
    }
    let identities: i64 = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM registered_accounts WHERE account_id=?1) +
                (SELECT COUNT(*) FROM registered_credentials WHERE credential_id=?2) +
                (SELECT COUNT(*) FROM account_transitions WHERE transition_id=?3)",
            params![
                after.account_id.as_bytes(),
                after.credential_id.as_bytes(),
                value.transition_id.as_bytes(),
            ],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if identities != 0 {
        return Err(account_identity_conflict_error());
    }
    let display = display_id_digest(&after.display_id);
    let occupied: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM registered_accounts
             WHERE store_id=?1 AND display_id_sha256=?2
               AND state IN ('proposed','active','blocked')",
            params![value.config_cas.store_id.as_bytes(), display.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if occupied != 0 {
        return Err(account_already_exists_error());
    }
    Ok(())
}

fn validate_intrinsic_manifest(
    authority: &BootstrapSnapshot,
    manifest: &ActionManifest,
) -> Result<(), MailError> {
    match manifest.payload() {
        ManifestPayload::StoreEnroll(value) => {
            if value.expected_store_state != StoreEnrollmentState::Unregistered {
                return Err(authorization_context_stale_error());
            }
        }
        ManifestPayload::AccountCreate(value) => {
            let Some(after) = &value.after else {
                return Err(authorization_context_stale_error());
            };
            if value.before.is_some()
                || !value.cleanup.is_empty()
                || !after.cleanup_ids.is_empty()
                || after.state_reason
                    != Some(kirje_core::AccountStateReason::CredentialReentryRequired)
                || value.config_cas.exact_content_sha256 == value.after_config_sha256
                || value.next_config_generation.get()
                    != value
                        .config_cas
                        .generation
                        .get()
                        .checked_add(1)
                        .ok_or_else(authorization_context_stale_error)?
            {
                return Err(authorization_context_stale_error());
            }
        }
        ManifestPayload::AccountUpdate(value) => validate_account_update_intrinsic(value)?,
        ManifestPayload::AccountRemove(value) => validate_account_remove_intrinsic(value)?,
        ManifestPayload::CredentialSet(value) | ManifestPayload::CredentialDelete(value) => {
            validate_credential_mutation_intrinsic(value)?;
        }
        ManifestPayload::CredentialCleanup(_) => {}
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

fn validate_account_update_intrinsic(
    value: &kirje_core::AccountMutationManifest,
) -> Result<(), MailError> {
    let (Some(before), Some(after)) = (&value.before, &value.after) else {
        return Err(authorization_context_stale_error());
    };
    let mut expected_cleanup_ids = before.cleanup_ids.clone();
    expected_cleanup_ids.extend(value.cleanup.iter().map(|item| item.cleanup_id));
    if value.config_cas.exact_content_sha256 == value.after_config_sha256
        || !provisional_cleanup_is_unique(&value.cleanup)
        || expected_cleanup_ids != after.cleanup_ids
        || after.state_reason != Some(kirje_core::AccountStateReason::CredentialReentryRequired)
    {
        return Err(authorization_context_stale_error());
    }
    Ok(())
}

fn validate_account_remove_intrinsic(
    value: &kirje_core::AccountMutationManifest,
) -> Result<(), MailError> {
    if value.config_cas.exact_content_sha256 == value.after_config_sha256
        || !provisional_cleanup_is_unique(&value.cleanup)
    {
        return Err(authorization_context_stale_error());
    }
    Ok(())
}

fn validate_credential_mutation_intrinsic(
    value: &kirje_core::CredentialMutationManifest,
) -> Result<(), MailError> {
    let Some(after) = &value.account.after else {
        return Err(authorization_context_stale_error());
    };
    if value.account.config_cas.exact_content_sha256 == value.account.after_config_sha256
        || !value.account.cleanup.is_empty()
        || after.state_reason.is_some()
    {
        return Err(authorization_context_stale_error());
    }
    Ok(())
}

fn provisional_cleanup_is_unique(items: &[kirje_core::CleanupDescriptor]) -> bool {
    !items.is_empty()
        && items.len() <= 100
        && items.iter().enumerate().all(|(index, item)| {
            item.expected_state == kirje_core::CleanupState::Provisional
                && items[..index].iter().all(|prior| {
                    prior.cleanup_id != item.cleanup_id
                        && prior.locator_sha256 != item.locator_sha256
                })
        })
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

fn display_id_digest(display_id: &str) -> Sha256Digest {
    Sha256Digest::digest(&encode_transcript(
        ACCOUNT_DISPLAY_ID_DOMAIN,
        &[display_id.as_bytes()],
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

fn grant_use_transcript(request: &GrantUseRequest, used_at: i64) -> Vec<u8> {
    let action = request.action.code().to_be_bytes();
    let target_kind = request.target_kind.code().to_be_bytes();
    let used_at = used_at.to_be_bytes();
    encode_transcript(
        GRANT_USE_DOMAIN,
        &[
            request.grant_id.as_bytes(),
            request.receipt_id.as_bytes(),
            &action,
            &target_kind,
            &request.target_bytes,
            request.manifest_sha256.as_bytes(),
            &used_at,
        ],
    )
}

fn enrollment_intent_digest(request: &EnrollStoreRequest) -> Sha256Digest {
    let action = request.grant_use.action.code().to_be_bytes();
    let target_kind = request.grant_use.target_kind.code().to_be_bytes();
    let generation = request.config_generation.get().to_be_bytes();
    Sha256Digest::digest(&encode_transcript(
        STORE_ENROLLMENT_INTENT_DOMAIN,
        &[
            request.grant_use.grant_id.as_bytes(),
            request.grant_use.receipt_id.as_bytes(),
            &action,
            &target_kind,
            &request.grant_use.target_bytes,
            request.grant_use.manifest_sha256.as_bytes(),
            request.store_id.as_bytes(),
            request.location_sha256.as_bytes(),
            &generation,
            request.config_sha256.as_bytes(),
        ],
    ))
}

fn enrollment_intent_from_rows(
    challenge: &StoredChallenge,
    receipt: &StoredReceipt,
    enrollment: StoreEnrollmentContext,
) -> Sha256Digest {
    let action = challenge.action.code().to_be_bytes();
    let target_kind = challenge.target_kind_code.to_be_bytes();
    let generation = enrollment.config_generation.get().to_be_bytes();
    Sha256Digest::digest(&encode_transcript(
        STORE_ENROLLMENT_INTENT_DOMAIN,
        &[
            challenge.grant_id.as_bytes(),
            receipt.receipt_id.as_bytes(),
            &action,
            &target_kind,
            &challenge.target_id,
            challenge.manifest_sha256.as_bytes(),
            enrollment.store_id.as_bytes(),
            enrollment.location_sha256.as_bytes(),
            &generation,
            enrollment.config_sha256.as_bytes(),
        ],
    ))
}

fn account_transition_digest(
    request: &PrepareAccountTransitionRequest,
    prepared_at: i64,
) -> Sha256Digest {
    let kind = [request.kind.code()];
    let expected = request.expected_generation.get().to_be_bytes();
    let next = request.next_generation.get().to_be_bytes();
    let prepared = prepared_at.to_be_bytes();
    Sha256Digest::digest(&encode_transcript(
        ACCOUNT_TRANSITION_DOMAIN,
        &[
            request.transition_id.as_bytes(),
            request.grant_use.grant_id.as_bytes(),
            request.store_id.as_bytes(),
            request.account_id.as_bytes(),
            &kind,
            request.before_config_sha256.as_bytes(),
            request.after_config_sha256.as_bytes(),
            &expected,
            &next,
            &prepared,
        ],
    ))
}

fn account_prepare_intent(request: &PrepareAccountTransitionRequest) -> Sha256Digest {
    let action = request.grant_use.action.code().to_be_bytes();
    let target_kind = request.grant_use.target_kind.code().to_be_bytes();
    let kind = [request.kind.code()];
    let expected = request.expected_generation.get().to_be_bytes();
    let next = request.next_generation.get().to_be_bytes();
    let account_generation = request.account_generation.get().to_be_bytes();
    Sha256Digest::digest(&encode_transcript(
        ACCOUNT_TRANSITION_INTENT_DOMAIN,
        &[
            request.grant_use.grant_id.as_bytes(),
            request.grant_use.receipt_id.as_bytes(),
            &action,
            &target_kind,
            &request.grant_use.target_bytes,
            request.grant_use.manifest_sha256.as_bytes(),
            request.transition_id.as_bytes(),
            request.store_id.as_bytes(),
            request.account_id.as_bytes(),
            &kind,
            request.before_config_sha256.as_bytes(),
            request.after_config_sha256.as_bytes(),
            &expected,
            &next,
            request.display_id_sha256.as_bytes(),
            &account_generation,
            request.credential_id.as_bytes(),
            request.binding_sha256.as_bytes(),
        ],
    ))
}

fn account_prepare_intent_from_rows(
    challenge: &StoredChallenge,
    receipt: &StoredReceipt,
    value: &kirje_core::AccountMutationManifest,
) -> Result<Sha256Digest, MailError> {
    let account = match challenge.action {
        SensitiveAction::AccountCreate
        | SensitiveAction::AccountUpdate
        | SensitiveAction::CredentialSet
        | SensitiveAction::CredentialDelete => value.after.as_ref().ok_or_else(recovery_error)?,
        SensitiveAction::AccountRemove => value.before.as_ref().ok_or_else(recovery_error)?,
        _ => return Err(recovery_error()),
    };
    let action = challenge.action.code().to_be_bytes();
    let target_kind = challenge.target_kind_code.to_be_bytes();
    let kind = [match challenge.action {
        SensitiveAction::AccountCreate => AccountTransitionKind::AccountCreate.code(),
        SensitiveAction::AccountUpdate => AccountTransitionKind::AccountUpdate.code(),
        SensitiveAction::AccountRemove => AccountTransitionKind::AccountRemove.code(),
        SensitiveAction::CredentialSet => AccountTransitionKind::CredentialSet.code(),
        SensitiveAction::CredentialDelete => AccountTransitionKind::CredentialDelete.code(),
        _ => return Err(recovery_error()),
    }];
    let expected = value.config_cas.generation.get().to_be_bytes();
    let next = value.next_config_generation.get().to_be_bytes();
    let account_generation = account.generation.get().to_be_bytes();
    Ok(Sha256Digest::digest(&encode_transcript(
        ACCOUNT_TRANSITION_INTENT_DOMAIN,
        &[
            challenge.grant_id.as_bytes(),
            receipt.receipt_id.as_bytes(),
            &action,
            &target_kind,
            &challenge.target_id,
            challenge.manifest_sha256.as_bytes(),
            value.transition_id.as_bytes(),
            value.config_cas.store_id.as_bytes(),
            account.account_id.as_bytes(),
            &kind,
            value.config_cas.exact_content_sha256.as_bytes(),
            value.after_config_sha256.as_bytes(),
            &expected,
            &next,
            display_id_digest(&account.display_id).as_bytes(),
            &account_generation,
            account.credential_id.as_bytes(),
            account.binding_sha256.as_bytes(),
        ],
    )))
}

fn account_recovery_digest(
    transition: &StoredAccountTransition,
    prior_state: AccountTransitionState,
    actual_generation: NonZeroU64,
    actual_config_sha256: Sha256Digest,
) -> Sha256Digest {
    let state = prior_state.event_state().to_be_bytes();
    let generation = actual_generation.get().to_be_bytes();
    Sha256Digest::digest(&encode_transcript(
        ACCOUNT_TRANSITION_RECOVERY_DOMAIN,
        &[
            transition.transition_sha256.as_bytes(),
            &state,
            &generation,
            actual_config_sha256.as_bytes(),
        ],
    ))
}

fn store_enrollment_context(
    manifest: &ActionManifest,
) -> Result<StoreEnrollmentContext, MailError> {
    let ManifestPayload::StoreEnroll(value) = manifest.payload() else {
        return Err(authorization_context_stale_error());
    };
    if value.expected_store_state != StoreEnrollmentState::Unregistered {
        return Err(authorization_context_stale_error());
    }
    Ok(StoreEnrollmentContext {
        store_id: value.config_cas.store_id,
        location_sha256: value.config_cas.location_sha256,
        config_generation: value.config_cas.generation,
        config_sha256: value.config_cas.exact_content_sha256,
    })
}

fn validate_enrollment_identity(
    request: &EnrollStoreRequest,
    challenge: &StoredChallenge,
    receipt: &StoredReceipt,
) -> Result<StoreEnrollmentContext, MailError> {
    let manifest = ActionManifest::parse(&challenge.manifest)
        .map_err(|_| authorization_context_stale_error())?;
    let enrollment = store_enrollment_context(&manifest)?;
    if request.grant_use.grant_id != challenge.grant_id
        || request.grant_use.receipt_id != receipt.receipt_id
        || receipt.challenge_id != challenge.challenge_id
        || receipt.grant_id != challenge.grant_id
        || request.grant_use.action != SensitiveAction::StoreEnroll
        || request.grant_use.action != challenge.action
        || request.grant_use.target_kind.code() != challenge.target_kind_code
        || request.grant_use.target_bytes != challenge.target_id
        || request.grant_use.manifest_sha256 != challenge.manifest_sha256
        || request.store_id != enrollment.store_id
        || request.location_sha256 != enrollment.location_sha256
        || request.config_generation != enrollment.config_generation
        || request.config_sha256 != enrollment.config_sha256
        || request.location_bytes != request.location_material.canonical_bytes()?
    {
        return Err(authorization_context_stale_error());
    }
    Ok(enrollment)
}

fn classify_enrollment_challenge_result(
    result: Result<StoredChallenge, MailError>,
) -> Result<StoredChallenge, MailError> {
    match result {
        Ok(challenge) => Ok(challenge),
        Err(error) if error.code == MailErrorCode::AuthorizationMalformed => {
            Err(authorization_context_stale_error())
        }
        Err(error) => Err(error),
    }
}

fn grant_preflight(connection: &Connection) -> Result<(), MailError> {
    record_validation_query(ValidationQueryKind::GrantPreflight);
    let malformed: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM grant_uses WHERE
             typeof(grant_id)<>'blob' OR length(grant_id)<>16 OR
             typeof(receipt_id)<>'blob' OR length(receipt_id)<>16 OR
             typeof(action)<>'integer' OR
             typeof(target_kind)<>'integer' OR
             typeof(target_id)<>'blob' OR length(target_id)>256 OR
             typeof(manifest_sha256)<>'blob' OR length(manifest_sha256)<>32 OR
             typeof(use_receipt)<>'blob' OR length(use_receipt) NOT BETWEEN 1 AND 16384 OR
             typeof(use_sha256)<>'blob' OR length(use_sha256)<>32 OR
             typeof(used_at)<>'integer' OR used_at<0",
            [],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if malformed != 0 {
        return Err(recovery_error());
    }
    Ok(())
}

fn store_preflight(connection: &Connection) -> Result<(), MailError> {
    record_validation_query(ValidationQueryKind::StorePreflight);
    let malformed: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM registered_stores WHERE
             typeof(store_id)<>'blob' OR length(store_id)<>16 OR
             typeof(location_material)<>'blob' OR length(location_material) NOT BETWEEN 1 AND 4096 OR
             typeof(location_sha256)<>'blob' OR length(location_sha256)<>32 OR
             typeof(config_generation)<>'integer' OR config_generation<=0 OR
             typeof(config_sha256)<>'blob' OR length(config_sha256)<>32 OR
             typeof(state)<>'text' OR state NOT IN ('active','blocked','removed','recovery_required') OR
             typeof(enrolled_receipt_id)<>'blob' OR length(enrolled_receipt_id)<>16 OR
             typeof(created_at)<>'integer' OR created_at<0 OR
             typeof(updated_at)<>'integer' OR updated_at<created_at OR
             (removed_at IS NOT NULL AND (typeof(removed_at)<>'integer' OR removed_at<created_at))",
            [],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if malformed != 0 {
        return Err(recovery_error());
    }
    Ok(())
}

fn registry_parent_preflight(connection: &Connection) -> Result<(), MailError> {
    record_validation_query(ValidationQueryKind::RegistryParentPreflight);
    let malformed: i64 = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM registered_accounts WHERE
                    typeof(account_id)<>'blob' OR length(account_id)<>16 OR
                    typeof(store_id)<>'blob' OR length(store_id)<>16 OR
                    typeof(display_id_sha256)<>'blob' OR length(display_id_sha256)<>32 OR
                    typeof(account_generation)<>'integer' OR account_generation<=0 OR
                    typeof(credential_id)<>'blob' OR length(credential_id)<>16 OR
                    typeof(binding_sha256)<>'blob' OR length(binding_sha256)<>32 OR
                    typeof(state)<>'text' OR state NOT IN ('proposed','active','blocked','removed') OR
                    typeof(authorized_receipt_id)<>'blob' OR length(authorized_receipt_id)<>16 OR
                    (active_transition_id IS NOT NULL AND
                     (typeof(active_transition_id)<>'blob' OR length(active_transition_id)<>16)) OR
                    typeof(created_at)<>'integer' OR created_at<0 OR
                    typeof(updated_at)<>'integer' OR updated_at<created_at OR
                    (removed_at IS NOT NULL AND
                     (typeof(removed_at)<>'integer' OR removed_at<created_at))) +
                (SELECT COUNT(*) FROM account_transitions WHERE
                    typeof(transition_id)<>'blob' OR length(transition_id)<>16 OR
                    typeof(grant_id)<>'blob' OR length(grant_id)<>16 OR
                    typeof(store_id)<>'blob' OR length(store_id)<>16 OR
                    typeof(account_id)<>'blob' OR length(account_id)<>16 OR
                    typeof(kind)<>'text' OR kind NOT IN
                      ('account_create','account_update','account_remove','credential_set','credential_delete') OR
                    typeof(before_config_sha256)<>'blob' OR length(before_config_sha256)<>32 OR
                    typeof(after_config_sha256)<>'blob' OR length(after_config_sha256)<>32 OR
                    typeof(expected_generation)<>'integer' OR expected_generation<=0 OR
                    typeof(next_generation)<>'integer' OR next_generation<=0 OR
                    typeof(transition_sha256)<>'blob' OR length(transition_sha256)<>32 OR
                    typeof(state)<>'text' OR state NOT IN
                      ('prepared','config_committed','finalized','aborted','recovery_required') OR
                    typeof(prepared_at)<>'integer' OR prepared_at<0 OR
                    (config_committed_at IS NOT NULL AND typeof(config_committed_at)<>'integer') OR
                    (finalized_at IS NOT NULL AND typeof(finalized_at)<>'integer') OR
                    (resolved_at IS NOT NULL AND typeof(resolved_at)<>'integer')) +
                (SELECT COUNT(*) FROM registered_credentials WHERE
                    typeof(credential_id)<>'blob' OR length(credential_id)<>16 OR
                    typeof(account_id)<>'blob' OR length(account_id)<>16 OR
                    typeof(store_id)<>'blob' OR length(store_id)<>16 OR
                    typeof(created_transition_id)<>'blob' OR length(created_transition_id)<>16 OR
                    typeof(created_at)<>'integer' OR created_at<0) +
                (SELECT COUNT(*) FROM registered_store_versions WHERE
                    typeof(store_id)<>'blob' OR length(store_id)<>16 OR
                    typeof(location_sha256)<>'blob' OR length(location_sha256)<>32 OR
                    typeof(config_generation)<>'integer' OR config_generation<=0 OR
                    typeof(config_sha256)<>'blob' OR length(config_sha256)<>32 OR
                    (enrolled_receipt_id IS NOT NULL AND
                     (typeof(enrolled_receipt_id)<>'blob' OR length(enrolled_receipt_id)<>16)) OR
                    (committed_transition_id IS NOT NULL AND
                     (typeof(committed_transition_id)<>'blob' OR length(committed_transition_id)<>16)) OR
                    ((enrolled_receipt_id IS NULL)=(committed_transition_id IS NULL)) OR
                    typeof(created_at)<>'integer' OR created_at<0) +
                (SELECT COUNT(*) FROM registered_account_versions WHERE
                    typeof(account_id)<>'blob' OR length(account_id)<>16 OR
                    typeof(store_id)<>'blob' OR length(store_id)<>16 OR
                    typeof(account_generation)<>'integer' OR account_generation<=0 OR
                    typeof(credential_id)<>'blob' OR length(credential_id)<>16 OR
                    typeof(binding_sha256)<>'blob' OR length(binding_sha256)<>32 OR
                    typeof(committed_transition_id)<>'blob' OR
                    length(committed_transition_id)<>16 OR
                    typeof(created_at)<>'integer' OR created_at<0) +
                (SELECT COUNT(*) FROM credential_cleanup WHERE
                    typeof(cleanup_id)<>'blob' OR length(cleanup_id)<>16 OR
                    (transition_id IS NOT NULL AND
                     (typeof(transition_id)<>'blob' OR length(transition_id)<>16)) OR
                    typeof(locator_kind)<>'text' OR
                    locator_kind NOT IN ('active_v2','legacy_v1') OR
                    typeof(locator_material)<>'blob' OR
                    length(locator_material) NOT BETWEEN 1 AND 4096 OR
                    typeof(locator_sha256)<>'blob' OR length(locator_sha256)<>32 OR
                    typeof(state)<>'text' OR
                    state NOT IN ('provisional','ready','claimed','deleted') OR
                    (claim_grant_id IS NOT NULL AND
                     (typeof(claim_grant_id)<>'blob' OR length(claim_grant_id)<>16)) OR
                    typeof(created_at)<>'integer' OR created_at<0 OR
                    (deleted_at IS NOT NULL AND
                     (typeof(deleted_at)<>'integer' OR deleted_at<created_at)))",
            [],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if malformed != 0 {
        return Err(recovery_error());
    }
    Ok(())
}

fn load_grant_use(
    connection: &Connection,
    grant_id: AuthorizationGrantId,
) -> Result<Option<StoredGrantUse>, MailError> {
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    connection
        .query_row(
            "SELECT grant_id,receipt_id,action,target_kind,target_id,manifest_sha256,
                    use_receipt,use_sha256,used_at
             FROM grant_uses WHERE grant_id=?1",
            [grant_id.as_bytes()],
            stored_grant_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())
}

fn stored_grant_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredGrantUse> {
    let action = SensitiveAction::from_code(
        u16::try_from(row.get::<_, i64>(2)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let target_kind = target_kind_from_code(
        u16::try_from(row.get::<_, i64>(3)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(StoredGrantUse {
        grant_id: uuid_from_blob_sql(row.get(0)?)?,
        receipt_id: uuid_from_blob_sql(row.get(1)?)?,
        action,
        target_kind,
        target_id: row.get(4)?,
        manifest_sha256: digest_from_blob_sql(row.get(5)?)?,
        use_receipt: row.get(6)?,
        use_sha256: digest_from_blob_sql(row.get(7)?)?,
        used_at: row.get(8)?,
    })
}

fn target_kind_from_code(code: u16) -> Result<TargetKind, MailError> {
    SensitiveAction::ALL
        .into_iter()
        .map(|action| action.policy().target_kind)
        .find(|kind| kind.code() == code)
        .ok_or_else(|| MailError::invalid_input("authorization target kind is unknown"))
}

fn load_receipt_by_id(
    connection: &Connection,
    receipt_id: AuthorizationReceiptId,
) -> Result<Option<StoredReceipt>, MailError> {
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    connection
        .query_row(
            "SELECT receipt_id,challenge_id,grant_id,proof_sha256,key_id,signature,
                    canonical_proof,manifest_sha256,signing_sha256,trust_epoch,bundle_sha256,
                    receipt,receipt_sha256,verified_at,expires_at
             FROM authorization_receipts WHERE receipt_id=?1",
            [receipt_id.as_bytes()],
            stored_receipt_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())
}

fn load_credential_cleanup(
    connection: &Connection,
    cleanup_id: CleanupId,
) -> Result<Option<StoredCredentialCleanup>, MailError> {
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    connection
        .query_row(
            "SELECT cleanup_id,transition_id,locator_kind,locator_material,locator_sha256,
                    state,claim_grant_id,created_at,deleted_at
             FROM credential_cleanup WHERE cleanup_id=?1",
            [cleanup_id.as_bytes()],
            |row| {
                let transition = row
                    .get::<_, Option<Vec<u8>>>(1)?
                    .ok_or(rusqlite::Error::InvalidQuery)
                    .and_then(uuid_from_blob_sql)?;
                let claim_grant_id = row
                    .get::<_, Option<Vec<u8>>>(6)?
                    .map(uuid_from_blob_sql)
                    .transpose()?;
                Ok(StoredCredentialCleanup {
                    cleanup_id: uuid_from_blob_sql(row.get(0)?)?,
                    transition_id: transition,
                    locator_kind: locator_kind_from_name(&row.get::<_, String>(2)?)
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                    locator_material: row.get(3)?,
                    locator_sha256: digest_from_blob_sql(row.get(4)?)?,
                    state: cleanup_state_from_name(&row.get::<_, String>(5)?)
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                    claim_grant_id,
                    created_at: row.get(7)?,
                    deleted_at: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(|_| store_read_error())
}

fn load_registered_store_by_receipt(
    connection: &Connection,
    receipt_id: AuthorizationReceiptId,
) -> Result<Option<StoredRegisteredStore>, MailError> {
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    connection
        .query_row(
            "SELECT store_id,location_material,location_sha256,config_generation,
                    config_sha256,state,enrolled_receipt_id,created_at,updated_at,removed_at
             FROM registered_stores WHERE enrolled_receipt_id=?1",
            [receipt_id.as_bytes()],
            stored_registered_store_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())
}

fn load_registered_store_by_id(
    connection: &Connection,
    store_id: StoreId,
) -> Result<Option<StoredRegisteredStore>, MailError> {
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    connection
        .query_row(
            "SELECT store_id,location_material,location_sha256,config_generation,
                    config_sha256,state,enrolled_receipt_id,created_at,updated_at,removed_at
             FROM registered_stores WHERE store_id=?1",
            [store_id.as_bytes()],
            stored_registered_store_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())
}

fn load_store_version_by_receipt(
    connection: &Connection,
    receipt_id: AuthorizationReceiptId,
) -> Result<Option<StoredRegisteredStoreVersion>, MailError> {
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    connection
        .query_row(
            "SELECT store_id,location_sha256,config_generation,config_sha256,
                    enrolled_receipt_id,committed_transition_id,created_at
             FROM registered_store_versions WHERE enrolled_receipt_id=?1",
            [receipt_id.as_bytes()],
            stored_store_version_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())
}

fn load_account_transition(
    connection: &Connection,
    transition_id: TransitionId,
) -> Result<Option<StoredAccountTransition>, MailError> {
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    connection
        .query_row(
            "SELECT transition_id,grant_id,store_id,account_id,kind,
                    before_config_sha256,after_config_sha256,expected_generation,
                    next_generation,transition_sha256,state,prepared_at,
                    config_committed_at,finalized_at,resolved_at
             FROM account_transitions WHERE transition_id=?1",
            [transition_id.as_bytes()],
            stored_account_transition_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())
}

fn load_account_transition_by_grant(
    connection: &Connection,
    grant_id: AuthorizationGrantId,
) -> Result<Option<StoredAccountTransition>, MailError> {
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    connection
        .query_row(
            "SELECT transition_id,grant_id,store_id,account_id,kind,
                    before_config_sha256,after_config_sha256,expected_generation,
                    next_generation,transition_sha256,state,prepared_at,
                    config_committed_at,finalized_at,resolved_at
             FROM account_transitions WHERE grant_id=?1",
            [grant_id.as_bytes()],
            stored_account_transition_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())
}

fn stored_account_transition_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredAccountTransition> {
    let expected_generation = positive_generation_sql(row.get(7)?)?;
    let next_generation = positive_generation_sql(row.get(8)?)?;
    let kind_name: String = row.get(4)?;
    let state_name: String = row.get(10)?;
    Ok(StoredAccountTransition {
        transition_id: uuid_from_blob_sql(row.get(0)?)?,
        grant_id: uuid_from_blob_sql(row.get(1)?)?,
        store_id: uuid_from_blob_sql(row.get(2)?)?,
        account_id: uuid_from_blob_sql(row.get(3)?)?,
        kind: transition_kind_from_name(&kind_name).map_err(|_| rusqlite::Error::InvalidQuery)?,
        before_config_sha256: digest_from_blob_sql(row.get(5)?)?,
        after_config_sha256: digest_from_blob_sql(row.get(6)?)?,
        expected_generation,
        next_generation,
        transition_sha256: digest_from_blob_sql(row.get(9)?)?,
        state: transition_state_from_name(&state_name)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        prepared_at: row.get(11)?,
        config_committed_at: row.get(12)?,
        finalized_at: row.get(13)?,
        resolved_at: row.get(14)?,
    })
}

fn load_registered_account(
    connection: &Connection,
    account_id: AccountId,
) -> Result<Option<StoredRegisteredAccount>, MailError> {
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    connection
        .query_row(
            "SELECT account_id,store_id,display_id_sha256,account_generation,
                    credential_id,binding_sha256,state,authorized_receipt_id,
                    active_transition_id,created_at,updated_at,removed_at
             FROM registered_accounts WHERE account_id=?1",
            [account_id.as_bytes()],
            |row| {
                let state: String = row.get(6)?;
                Ok(StoredRegisteredAccount {
                    account_id: uuid_from_blob_sql(row.get(0)?)?,
                    store_id: uuid_from_blob_sql(row.get(1)?)?,
                    display_id_sha256: digest_from_blob_sql(row.get(2)?)?,
                    account_generation: positive_generation_sql(row.get(3)?)?,
                    credential_id: uuid_from_blob_sql(row.get(4)?)?,
                    binding_sha256: digest_from_blob_sql(row.get(5)?)?,
                    state: account_state_from_name(&state)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    authorized_receipt_id: uuid_from_blob_sql(row.get(7)?)?,
                    active_transition_id: row
                        .get::<_, Option<Vec<u8>>>(8)?
                        .map(uuid_from_blob_sql)
                        .transpose()?,
                    created_at: row.get(9)?,
                    updated_at: row.get(10)?,
                    removed_at: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(|_| store_read_error())
}

fn positive_generation_sql(value: i64) -> rusqlite::Result<NonZeroU64> {
    u64::try_from(value)
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn stored_registered_store_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredRegisteredStore> {
    let generation = u64::try_from(row.get::<_, i64>(3)?)
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(rusqlite::Error::InvalidQuery)?;
    Ok(StoredRegisteredStore {
        store_id: uuid_from_blob_sql(row.get(0)?)?,
        location_material: row.get(1)?,
        location_sha256: digest_from_blob_sql(row.get(2)?)?,
        config_generation: generation,
        config_sha256: digest_from_blob_sql(row.get(4)?)?,
        state: row.get(5)?,
        enrolled_receipt_id: uuid_from_blob_sql(row.get(6)?)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
        removed_at: row.get(9)?,
    })
}

fn stored_store_version_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredRegisteredStoreVersion> {
    let generation = u64::try_from(row.get::<_, i64>(2)?)
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(rusqlite::Error::InvalidQuery)?;
    let enrolled_receipt_id = row
        .get::<_, Option<Vec<u8>>>(4)?
        .map(uuid_from_blob_sql)
        .transpose()?;
    Ok(StoredRegisteredStoreVersion {
        store_id: uuid_from_blob_sql(row.get(0)?)?,
        location_sha256: digest_from_blob_sql(row.get(1)?)?,
        config_generation: generation,
        config_sha256: digest_from_blob_sql(row.get(3)?)?,
        enrolled_receipt_id,
        committed_transition_id: row.get(5)?,
        created_at: row.get(6)?,
    })
}

fn store_identity_count(
    connection: &Connection,
    store_id: StoreId,
    location_sha256: Sha256Digest,
) -> Result<i64, MailError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM registered_stores
             WHERE store_id=?1 OR location_sha256=?2",
            params![store_id.as_bytes(), location_sha256.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())
}

fn enrolled_store_projection(
    version: &StoredRegisteredStoreVersion,
) -> Result<EnrolledStoreProjection, MailError> {
    if version.enrolled_receipt_id.is_none() || version.committed_transition_id.is_some() {
        return Err(recovery_error());
    }
    Ok(EnrolledStoreProjection {
        store_id: version.store_id,
        state: EnrolledStoreState::Active,
        config_generation: version.config_generation,
        created_at: utc_millis(version.created_at)?,
        updated_at: utc_millis(version.created_at)?,
    })
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
    record_validation_query(ValidationQueryKind::BoundedKeyed);
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
    record_validation_query(ValidationQueryKind::ChallengePreflight);
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
    record_validation_query(ValidationQueryKind::BoundedKeyed);
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
    record_validation_query(ValidationQueryKind::ReceiptPreflight);
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
    connection: &Connection,
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
        state: if connection
            .query_row(
                "SELECT COUNT(*) FROM grant_uses WHERE receipt_id=?1",
                [receipt.receipt_id.as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| store_read_error())?
            == 1
        {
            AuthorizationReceiptState::Used
        } else if challenge.state == "expired" || effective_time > receipt.expires_at {
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
    grant_preflight(connection)?;
    store_preflight(connection)?;
    registry_parent_preflight(connection)?;
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
                (SELECT COUNT(*) FROM challenge_effects) +
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
        let registry_count: i64 = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM grant_uses)
                      + (SELECT COUNT(*) FROM registered_stores)
                      + (SELECT COUNT(*) FROM registered_store_versions)
                      + (SELECT COUNT(*) FROM registered_credentials)
                      + (SELECT COUNT(*) FROM registered_account_versions)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| store_read_error())?;
        if challenge_count != 0 || receipt_count != 0 || nonce_count != 0 || registry_count != 0 {
            return Err(recovery_error());
        }
        return Ok(());
    }
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
    while let Some(row) = rows.next().map_err(|_| store_read_error())? {
        let challenge = stored_challenge_from_row(row).map_err(|_| recovery_error())?;
        validate_stored_challenge(connection, authority, &challenge, last_observed_at)?;
        seen = seen.checked_add(1).ok_or_else(recovery_error)?;
    }
    if seen != challenge_count || receipt_count != nonce_count {
        return Err(recovery_error());
    }
    validate_registry_history(connection)
}

#[allow(clippy::too_many_lines)]
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
    ensure_supported_challenge_action(challenge.action).map_err(|_| recovery_error())?;
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
    validate_intrinsic_manifest(authority, &manifest).map_err(|_| recovery_error())?;
    if challenge.action == SensitiveAction::CredentialCleanup {
        validate_credential_cleanup_context(connection, authority, &manifest, false)
            .map_err(|_| recovery_error())?;
    }
    let receipt = load_receipt_for_challenge(connection, challenge.challenge_id)?;
    let nonce = load_nonce_use(connection, challenge.challenge_id)?;
    match challenge.state.as_str() {
        "authorized" => {
            let receipt = receipt.ok_or_else(recovery_error)?;
            let nonce = nonce.ok_or_else(recovery_error)?;
            validate_stored_receipt(authority, challenge, &receipt, &nonce)?;
        }
        "expired" if receipt.is_some() && nonce.is_some() => {
            let receipt = receipt.ok_or_else(recovery_error)?;
            let nonce = nonce.ok_or_else(recovery_error)?;
            validate_stored_receipt(authority, challenge, &receipt, &nonce)?;
            let grants: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM grant_uses WHERE receipt_id=?1",
                    [receipt.receipt_id.as_bytes()],
                    |row| row.get(0),
                )
                .map_err(|_| store_read_error())?;
            if grants != 0 {
                return Err(recovery_error());
            }
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

#[allow(clippy::too_many_lines)]
fn validate_registry_history(connection: &Connection) -> Result<(), MailError> {
    record_validation_query(ValidationQueryKind::RegistryStream);
    let (
        grant_count,
        store_count,
        version_count,
        credential_count,
        account_version_count,
        account_count,
        transition_count,
        committed_count,
        account_version_transition_count,
        credential_transition_count,
        create_count,
        unattached_cleanup_count,
        claimed_cleanup_count,
    ) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM grant_uses),
                (SELECT COUNT(*) FROM registered_stores),
                (SELECT COUNT(*) FROM registered_store_versions),
                (SELECT COUNT(*) FROM registered_credentials),
                (SELECT COUNT(*) FROM registered_account_versions),
                (SELECT COUNT(*) FROM registered_accounts),
                (SELECT COUNT(*) FROM account_transitions),
                (SELECT COUNT(*) FROM account_transitions
                 WHERE state IN ('config_committed','finalized')
                    OR (state='recovery_required' AND config_committed_at IS NOT NULL)),
                (SELECT COUNT(*) FROM account_transitions
                 WHERE kind<>'account_remove' AND
                   (state IN ('config_committed','finalized')
                    OR (state='recovery_required' AND config_committed_at IS NOT NULL))),
                (SELECT COUNT(*) FROM account_transitions
                 WHERE kind IN ('account_create','account_update')),
                (SELECT COUNT(*) FROM account_transitions WHERE kind='account_create'),
                (SELECT COUNT(*) FROM credential_cleanup WHERE transition_id IS NULL),
                (SELECT COUNT(*) FROM credential_cleanup
                 WHERE state IN ('claimed','deleted'))",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            },
        )
        .map_err(|_| store_read_error())?;
    if grant_count != store_count + transition_count + claimed_cleanup_count
        || credential_count != credential_transition_count
        || account_count != create_count
        || version_count != store_count + committed_count
        || account_version_count != account_version_transition_count
        || unattached_cleanup_count != 0
    {
        return Err(recovery_error());
    }

    record_validation_query(ValidationQueryKind::RegistryStream);
    let mut statement = connection
        .prepare(
            "SELECT grant_id,receipt_id,action,target_kind,target_id,manifest_sha256,
                    use_receipt,use_sha256,used_at
             FROM grant_uses ORDER BY grant_id",
        )
        .map_err(|_| store_read_error())?;
    let mut rows = statement.query([]).map_err(|_| store_read_error())?;
    let mut seen = 0_i64;
    while let Some(row) = rows.next().map_err(|_| store_read_error())? {
        let grant = stored_grant_from_row(row).map_err(|_| recovery_error())?;
        validate_stored_grant(connection, &grant)?;
        seen = seen.checked_add(1).ok_or_else(recovery_error)?;
    }
    if seen != grant_count {
        return Err(recovery_error());
    }

    record_validation_query(ValidationQueryKind::RegistryStream);
    let mut statement = connection
        .prepare(
            "SELECT store_id,location_material,location_sha256,config_generation,
                    config_sha256,state,enrolled_receipt_id,created_at,updated_at,removed_at
             FROM registered_stores ORDER BY store_id",
        )
        .map_err(|_| store_read_error())?;
    let mut rows = statement.query([]).map_err(|_| store_read_error())?;
    let mut seen = 0_i64;
    while let Some(row) = rows.next().map_err(|_| store_read_error())? {
        let store = stored_registered_store_from_row(row).map_err(|_| recovery_error())?;
        validate_stored_store(connection, &store)?;
        seen = seen.checked_add(1).ok_or_else(recovery_error)?;
    }
    if seen != store_count {
        return Err(recovery_error());
    }

    record_validation_query(ValidationQueryKind::RegistryStream);
    let mut statement = connection
        .prepare(
            "SELECT store_id,location_sha256,config_generation,config_sha256,
                    enrolled_receipt_id,committed_transition_id,created_at
             FROM registered_store_versions ORDER BY store_id,config_generation",
        )
        .map_err(|_| store_read_error())?;
    let mut rows = statement.query([]).map_err(|_| store_read_error())?;
    let mut seen = 0_i64;
    while let Some(row) = rows.next().map_err(|_| store_read_error())? {
        let version = stored_store_version_from_row(row).map_err(|_| recovery_error())?;
        validate_stored_store_version(connection, &version)?;
        seen = seen.checked_add(1).ok_or_else(recovery_error)?;
    }
    if seen != version_count {
        return Err(recovery_error());
    }

    record_validation_query(ValidationQueryKind::RegistryStream);
    let mut statement = connection
        .prepare(
            "SELECT transition_id,grant_id,store_id,account_id,kind,
                    before_config_sha256,after_config_sha256,expected_generation,
                    next_generation,transition_sha256,state,prepared_at,
                    config_committed_at,finalized_at,resolved_at
             FROM account_transitions ORDER BY transition_id",
        )
        .map_err(|_| store_read_error())?;
    let mut rows = statement.query([]).map_err(|_| store_read_error())?;
    let mut seen = 0_i64;
    while let Some(row) = rows.next().map_err(|_| store_read_error())? {
        let transition = stored_account_transition_from_row(row).map_err(|_| recovery_error())?;
        validate_stored_account_transition(connection, &transition)?;
        seen = seen.checked_add(1).ok_or_else(recovery_error)?;
    }
    if seen != transition_count {
        return Err(recovery_error());
    }
    Ok(())
}

fn validate_stored_grant(connection: &Connection, grant: &StoredGrantUse) -> Result<(), MailError> {
    utc_millis(grant.used_at)?;
    if !matches!(
        (grant.action, grant.target_kind),
        (SensitiveAction::StoreEnroll, TargetKind::Store)
            | (
                SensitiveAction::AccountCreate
                    | SensitiveAction::AccountUpdate
                    | SensitiveAction::AccountRemove,
                TargetKind::Account
            )
            | (
                SensitiveAction::CredentialSet | SensitiveAction::CredentialDelete,
                TargetKind::Credential
            )
            | (SensitiveAction::CredentialCleanup, TargetKind::Cleanup)
    ) || !valid_target_shape(grant.target_kind, &grant.target_id)
        || grant.use_receipt != grant_use_transcript_from_row(grant)
        || grant.use_sha256 != Sha256Digest::digest(&grant.use_receipt)
    {
        return Err(recovery_error());
    }
    let receipt = load_receipt_by_id(connection, grant.receipt_id)?.ok_or_else(recovery_error)?;
    let challenge = load_challenge(connection, receipt.challenge_id)?;
    if challenge.state != "authorized"
        || grant.grant_id != challenge.grant_id
        || grant.receipt_id != receipt.receipt_id
        || grant.action != challenge.action
        || grant.target_kind.code() != challenge.target_kind_code
        || grant.target_id != challenge.target_id
        || grant.manifest_sha256 != challenge.manifest_sha256
        || receipt.verified_at > grant.used_at
        || grant.used_at > receipt.expires_at
    {
        return Err(recovery_error());
    }
    if matches!(
        grant.action,
        SensitiveAction::AccountCreate
            | SensitiveAction::AccountUpdate
            | SensitiveAction::AccountRemove
            | SensitiveAction::CredentialSet
            | SensitiveAction::CredentialDelete
    ) {
        let transition = load_account_transition_by_grant(connection, grant.grant_id)?
            .ok_or_else(recovery_error)?;
        return validate_stored_account_transition(connection, &transition);
    }
    if grant.action == SensitiveAction::CredentialCleanup {
        let cleanup_id: CleanupId =
            uuid_from_blob_sql(grant.target_id.clone()).map_err(|_| recovery_error())?;
        let cleanup =
            load_credential_cleanup(connection, cleanup_id)?.ok_or_else(recovery_error)?;
        let manifest = ActionManifest::parse(&challenge.manifest).map_err(|_| recovery_error())?;
        let ManifestPayload::CredentialCleanup(value) = manifest.payload() else {
            return Err(recovery_error());
        };
        if cleanup.cleanup_id != value.cleanup_id
            || cleanup.transition_id != value.transition_id.ok_or_else(recovery_error)?
            || cleanup.locator_kind != value.locator_kind
            || cleanup.locator_sha256 != value.locator_sha256
            || cleanup.claim_grant_id != Some(grant.grant_id)
            || !matches!(cleanup.state, CleanupState::Claimed | CleanupState::Deleted)
        {
            return Err(recovery_error());
        }
        return Ok(());
    }
    let manifest = ActionManifest::parse(&challenge.manifest).map_err(|_| recovery_error())?;
    let enrollment = store_enrollment_context(&manifest).map_err(|_| recovery_error())?;
    let store = load_registered_store_by_receipt(connection, receipt.receipt_id)?
        .ok_or_else(recovery_error)?;
    let version = load_store_version_by_receipt(connection, receipt.receipt_id)?
        .ok_or_else(recovery_error)?;
    if store.store_id != enrollment.store_id
        || store.location_sha256 != enrollment.location_sha256
        || store.enrolled_receipt_id != receipt.receipt_id
        || store.created_at != grant.used_at
    {
        return Err(recovery_error());
    }
    validate_initial_store_version(&version, &store, &enrollment, &receipt)?;
    validate_registry_events(connection, grant, &store)
}

fn validate_stored_store(
    connection: &Connection,
    store: &StoredRegisteredStore,
) -> Result<(), MailError> {
    utc_millis(store.created_at)?;
    utc_millis(store.updated_at)?;
    if !matches!(
        store.state.as_str(),
        "active" | "blocked" | "recovery_required"
    ) || store.removed_at.is_some()
        || store.updated_at < store.created_at
        || Sha256Digest::digest(&store.location_material) != store.location_sha256
    {
        return Err(recovery_error());
    }
    let receipt =
        load_receipt_by_id(connection, store.enrolled_receipt_id)?.ok_or_else(recovery_error)?;
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    let grant_id: Option<Vec<u8>> = connection
        .query_row(
            "SELECT grant_id FROM grant_uses WHERE receipt_id=?1",
            [receipt.receipt_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| store_read_error())?;
    let grant_id = grant_id.ok_or_else(recovery_error)?;
    let grant_id = uuid_from_blob_sql(grant_id).map_err(|_| recovery_error())?;
    let grant = load_grant_use(connection, grant_id)?.ok_or_else(recovery_error)?;
    if grant.used_at != store.created_at {
        return Err(recovery_error());
    }
    let version = load_store_version_by_receipt(connection, receipt.receipt_id)?
        .ok_or_else(recovery_error)?;
    let challenge = load_challenge(connection, receipt.challenge_id)?;
    let manifest = ActionManifest::parse(&challenge.manifest).map_err(|_| recovery_error())?;
    let enrollment = store_enrollment_context(&manifest).map_err(|_| recovery_error())?;
    validate_initial_store_version(&version, store, &enrollment, &receipt)?;
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    let transitions: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM account_transitions WHERE store_id=?1",
            [store.store_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if transitions == 0
        && (store.state != "active"
            || store.config_generation != enrollment.config_generation
            || store.config_sha256 != enrollment.config_sha256
            || store.updated_at != store.created_at)
    {
        return Err(recovery_error());
    }
    account_store_event_is_exact(connection, store, &version)
}

fn validate_stored_store_version(
    connection: &Connection,
    version: &StoredRegisteredStoreVersion,
) -> Result<(), MailError> {
    if let Some(transition_bytes) = &version.committed_transition_id {
        if version.enrolled_receipt_id.is_some() {
            return Err(recovery_error());
        }
        let transition_id: TransitionId =
            uuid_from_blob_sql(transition_bytes.clone()).map_err(|_| recovery_error())?;
        let transition =
            load_account_transition(connection, transition_id)?.ok_or_else(recovery_error)?;
        if version.store_id != transition.store_id
            || version.config_generation != transition.next_generation
            || version.config_sha256 != transition.after_config_sha256
            || version.created_at != transition.config_committed_at.ok_or_else(recovery_error)?
        {
            return Err(recovery_error());
        }
        return Ok(());
    }
    let receipt_id = version.enrolled_receipt_id.ok_or_else(recovery_error)?;
    let receipt = load_receipt_by_id(connection, receipt_id)?.ok_or_else(recovery_error)?;
    let challenge = load_challenge(connection, receipt.challenge_id)?;
    let manifest = ActionManifest::parse(&challenge.manifest).map_err(|_| recovery_error())?;
    let enrollment = store_enrollment_context(&manifest).map_err(|_| recovery_error())?;
    let store =
        load_registered_store_by_id(connection, version.store_id)?.ok_or_else(recovery_error)?;
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    let grant_id: Vec<u8> = connection
        .query_row(
            "SELECT grant_id FROM grant_uses WHERE receipt_id=?1",
            [receipt_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    let grant_id = uuid_from_blob_sql(grant_id).map_err(|_| recovery_error())?;
    let grant = load_grant_use(connection, grant_id)?.ok_or_else(recovery_error)?;
    if grant.receipt_id != receipt_id || grant.used_at != version.created_at {
        return Err(recovery_error());
    }
    validate_initial_store_version(version, &store, &enrollment, &receipt)
}

fn grant_use_transcript_from_row(grant: &StoredGrantUse) -> Vec<u8> {
    let action = grant.action.code().to_be_bytes();
    let target_kind = grant.target_kind.code().to_be_bytes();
    let used_at = grant.used_at.to_be_bytes();
    encode_transcript(
        GRANT_USE_DOMAIN,
        &[
            grant.grant_id.as_bytes(),
            grant.receipt_id.as_bytes(),
            &action,
            &target_kind,
            &grant.target_id,
            grant.manifest_sha256.as_bytes(),
            &used_at,
        ],
    )
}

fn transition_digest_from_row(transition: &StoredAccountTransition) -> Sha256Digest {
    let kind = [transition.kind.code()];
    let expected = transition.expected_generation.get().to_be_bytes();
    let next = transition.next_generation.get().to_be_bytes();
    let prepared = transition.prepared_at.to_be_bytes();
    Sha256Digest::digest(&encode_transcript(
        ACCOUNT_TRANSITION_DOMAIN,
        &[
            transition.transition_id.as_bytes(),
            transition.grant_id.as_bytes(),
            transition.store_id.as_bytes(),
            transition.account_id.as_bytes(),
            &kind,
            transition.before_config_sha256.as_bytes(),
            transition.after_config_sha256.as_bytes(),
            &expected,
            &next,
            &prepared,
        ],
    ))
}

#[allow(clippy::too_many_lines, clippy::type_complexity)]
fn validate_stored_account_transition(
    connection: &Connection,
    transition: &StoredAccountTransition,
) -> Result<(), MailError> {
    utc_millis(transition.prepared_at)?;
    if !matches!(
        transition.kind,
        AccountTransitionKind::AccountCreate
            | AccountTransitionKind::AccountUpdate
            | AccountTransitionKind::AccountRemove
            | AccountTransitionKind::CredentialSet
            | AccountTransitionKind::CredentialDelete
    ) || transition.expected_generation.get().checked_add(1)
        != Some(transition.next_generation.get())
        || transition.before_config_sha256 == transition.after_config_sha256
        || transition.transition_sha256 != transition_digest_from_row(transition)
    {
        return Err(recovery_error());
    }
    let timestamp_shape = match transition.state {
        AccountTransitionState::Prepared => {
            transition.config_committed_at.is_none()
                && transition.finalized_at.is_none()
                && transition.resolved_at.is_none()
        }
        AccountTransitionState::ConfigCommitted => {
            transition.config_committed_at.is_some()
                && transition.finalized_at.is_none()
                && transition.resolved_at.is_none()
        }
        AccountTransitionState::Finalized => {
            transition.config_committed_at.is_some()
                && transition.finalized_at.is_some()
                && transition.resolved_at.is_none()
        }
        AccountTransitionState::Aborted => {
            transition.config_committed_at.is_none()
                && transition.finalized_at.is_none()
                && transition.resolved_at.is_some()
        }
        AccountTransitionState::RecoveryRequired => {
            transition.finalized_at.is_none() && transition.resolved_at.is_some()
        }
    };
    if !timestamp_shape {
        return Err(recovery_error());
    }
    let grant = load_grant_use(connection, transition.grant_id)?.ok_or_else(recovery_error)?;
    let receipt = load_receipt_by_id(connection, grant.receipt_id)?.ok_or_else(recovery_error)?;
    let challenge = load_challenge(connection, receipt.challenge_id)?;
    let manifest = ActionManifest::parse(&challenge.manifest).map_err(|_| recovery_error())?;
    let (value, expected_action, expected_target_kind) = match (transition.kind, manifest.payload())
    {
        (AccountTransitionKind::AccountCreate, ManifestPayload::AccountCreate(value)) => {
            (value, SensitiveAction::AccountCreate, TargetKind::Account)
        }
        (AccountTransitionKind::AccountUpdate, ManifestPayload::AccountUpdate(value)) => {
            (value, SensitiveAction::AccountUpdate, TargetKind::Account)
        }
        (AccountTransitionKind::AccountRemove, ManifestPayload::AccountRemove(value)) => {
            (value, SensitiveAction::AccountRemove, TargetKind::Account)
        }
        (AccountTransitionKind::CredentialSet, ManifestPayload::CredentialSet(value)) => (
            &value.account,
            SensitiveAction::CredentialSet,
            TargetKind::Credential,
        ),
        (AccountTransitionKind::CredentialDelete, ManifestPayload::CredentialDelete(value)) => (
            &value.account,
            SensitiveAction::CredentialDelete,
            TargetKind::Credential,
        ),
        _ => return Err(recovery_error()),
    };
    let account_snapshot = match transition.kind {
        AccountTransitionKind::AccountCreate
        | AccountTransitionKind::AccountUpdate
        | AccountTransitionKind::CredentialSet
        | AccountTransitionKind::CredentialDelete => {
            value.after.as_ref().ok_or_else(recovery_error)?
        }
        AccountTransitionKind::AccountRemove => value.before.as_ref().ok_or_else(recovery_error)?,
    };
    let expected_target_id: &[u8] = match (transition.kind, expected_target_kind) {
        (AccountTransitionKind::CredentialDelete, TargetKind::Credential) => value
            .before
            .as_ref()
            .ok_or_else(recovery_error)?
            .credential_id
            .as_bytes(),
        (_, TargetKind::Account) => transition.account_id.as_bytes(),
        (_, TargetKind::Credential) => account_snapshot.credential_id.as_bytes(),
        _ => return Err(recovery_error()),
    };
    let account =
        load_registered_account(connection, transition.account_id)?.ok_or_else(recovery_error)?;
    if grant.action != expected_action
        || grant.target_kind != expected_target_kind
        || grant.target_id.as_slice() != expected_target_id
        || value.transition_id != transition.transition_id
        || value.config_cas.store_id != transition.store_id
        || account_snapshot.account_id != transition.account_id
        || display_id_digest(&account_snapshot.display_id) != account.display_id_sha256
        || value.config_cas.generation != transition.expected_generation
        || value.config_cas.exact_content_sha256 != transition.before_config_sha256
        || value.next_config_generation != transition.next_generation
        || value.after_config_sha256 != transition.after_config_sha256
    {
        return Err(recovery_error());
    }
    let successors: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM account_transitions
             WHERE account_id=?1 AND transition_id<>?2 AND expected_generation>=?3",
            params![
                transition.account_id.as_bytes(),
                transition.transition_id.as_bytes(),
                i64::try_from(transition.next_generation.get()).map_err(|_| recovery_error())?,
            ],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if successors != 0
        && !matches!(
            transition.state,
            AccountTransitionState::Finalized | AccountTransitionState::Aborted
        )
    {
        return Err(recovery_error());
    }
    if transition.kind == AccountTransitionKind::AccountCreate
        && account.created_at != transition.prepared_at
    {
        return Err(recovery_error());
    }
    if successors == 0 {
        validate_current_account_for_transition(
            connection,
            &account,
            transition,
            value,
            receipt.receipt_id,
        )?;
    }
    if transition.kind != AccountTransitionKind::AccountRemove {
        record_validation_query(ValidationQueryKind::BoundedKeyed);
        let credential: Option<(Vec<u8>, Vec<u8>, Vec<u8>, i64)> = connection
            .query_row(
                "SELECT account_id,store_id,created_transition_id,created_at
                 FROM registered_credentials WHERE credential_id=?1",
                [account_snapshot.credential_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| store_read_error())?;
        let (credential_account, credential_store, credential_transition, credential_created) =
            credential.ok_or_else(recovery_error)?;
        if credential_account.as_slice() != transition.account_id.as_bytes()
            || credential_store.as_slice() != transition.store_id.as_bytes()
            || (matches!(
                transition.kind,
                AccountTransitionKind::AccountCreate | AccountTransitionKind::AccountUpdate
            ) && (credential_transition.as_slice() != transition.transition_id.as_bytes()
                || credential_created != transition.prepared_at))
        {
            return Err(recovery_error());
        }
    }
    let committed = transition.config_committed_at.is_some();
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    let store_versions: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM registered_store_versions
             WHERE committed_transition_id=?1",
            [transition.transition_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    let account_versions: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM registered_account_versions
             WHERE committed_transition_id=?1",
            [transition.transition_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    let expected_account_versions =
        i64::from(committed && transition.kind != AccountTransitionKind::AccountRemove);
    if store_versions != i64::from(committed) || account_versions != expected_account_versions {
        return Err(recovery_error());
    }
    if transition.kind != AccountTransitionKind::AccountRemove
        && let Some(committed_at) = transition.config_committed_at
    {
        record_validation_query(ValidationQueryKind::BoundedKeyed);
        let version: Option<(Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>, i64)> = connection
            .query_row(
                "SELECT account_id,store_id,account_generation,credential_id,
                        binding_sha256,created_at FROM registered_account_versions
                 WHERE committed_transition_id=?1",
                [transition.transition_id.as_bytes()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| store_read_error())?;
        let (version_account, version_store, generation, version_credential, binding, created_at) =
            version.ok_or_else(recovery_error)?;
        if version_account.as_slice() != transition.account_id.as_bytes()
            || version_store.as_slice() != transition.store_id.as_bytes()
            || generation
                != i64::try_from(account_snapshot.generation.get()).map_err(|_| recovery_error())?
            || version_credential.as_slice() != account_snapshot.credential_id.as_bytes()
            || binding.as_slice() != account_snapshot.binding_sha256.as_bytes()
            || created_at != committed_at
        {
            return Err(recovery_error());
        }
    }
    if matches!(
        transition.kind,
        AccountTransitionKind::AccountUpdate
            | AccountTransitionKind::AccountRemove
            | AccountTransitionKind::CredentialSet
            | AccountTransitionKind::CredentialDelete
    ) {
        validate_account_mutation_parent(connection, transition, value)?;
    }
    validate_transition_cleanup(connection, transition, value)?;
    transition_projection(connection, transition)?;
    validate_transition_events(connection, transition, receipt.receipt_id)
}

#[allow(clippy::too_many_lines)]
fn validate_current_account_for_transition(
    connection: &Connection,
    account: &StoredRegisteredAccount,
    transition: &StoredAccountTransition,
    mutation: &AccountMutationManifest,
    receipt_id: AuthorizationReceiptId,
) -> Result<(), MailError> {
    let restored_predecessor = matches!(
        transition.kind,
        AccountTransitionKind::AccountUpdate
            | AccountTransitionKind::AccountRemove
            | AccountTransitionKind::CredentialSet
            | AccountTransitionKind::CredentialDelete
    ) && transition.state == AccountTransitionState::Aborted;
    let current = match transition.kind {
        AccountTransitionKind::AccountUpdate
        | AccountTransitionKind::CredentialSet
        | AccountTransitionKind::CredentialDelete
            if restored_predecessor =>
        {
            mutation.before.as_ref().ok_or_else(recovery_error)?
        }
        AccountTransitionKind::AccountCreate
        | AccountTransitionKind::AccountUpdate
        | AccountTransitionKind::CredentialSet
        | AccountTransitionKind::CredentialDelete => {
            mutation.after.as_ref().ok_or_else(recovery_error)?
        }
        AccountTransitionKind::AccountRemove => {
            mutation.before.as_ref().ok_or_else(recovery_error)?
        }
    };
    let expected_receipt = if restored_predecessor {
        let parent: Vec<u8> = connection
            .query_row(
                "SELECT committed_transition_id FROM registered_account_versions
                 WHERE account_id=?1 AND account_generation=?2",
                params![
                    transition.account_id.as_bytes(),
                    i64::try_from(current.generation.get()).map_err(|_| recovery_error())?,
                ],
                |row| row.get(0),
            )
            .map_err(|_| store_read_error())?;
        let parent_id: TransitionId = uuid_from_blob_sql(parent).map_err(|_| recovery_error())?;
        let parent = load_account_transition(connection, parent_id)?.ok_or_else(recovery_error)?;
        transition_receipt_id(connection, &parent)?
    } else {
        receipt_id
    };
    if account.account_generation != current.generation
        || account.credential_id != current.credential_id
        || account.binding_sha256 != current.binding_sha256
        || account.authorized_receipt_id != expected_receipt
    {
        return Err(recovery_error());
    }
    let valid_state = match (transition.kind, transition.state) {
        (
            AccountTransitionKind::AccountCreate,
            AccountTransitionState::Prepared | AccountTransitionState::ConfigCommitted,
        ) => {
            account.state == RegisteredAccountState::Proposed
                && account.active_transition_id == Some(transition.transition_id)
                && account.updated_at == transition.prepared_at
                && account.removed_at.is_none()
        }
        (
            AccountTransitionKind::AccountUpdate
            | AccountTransitionKind::AccountRemove
            | AccountTransitionKind::CredentialSet
            | AccountTransitionKind::CredentialDelete,
            AccountTransitionState::Prepared | AccountTransitionState::ConfigCommitted,
        ) => {
            account.state == RegisteredAccountState::Blocked
                && account.active_transition_id == Some(transition.transition_id)
                && account.updated_at == transition.prepared_at
                && account.removed_at.is_none()
        }
        (
            AccountTransitionKind::AccountCreate
            | AccountTransitionKind::AccountUpdate
            | AccountTransitionKind::CredentialSet
            | AccountTransitionKind::CredentialDelete,
            AccountTransitionState::Finalized,
        ) => {
            account.state == RegisteredAccountState::Active
                && account.active_transition_id.is_none()
                && account.updated_at == transition.finalized_at.ok_or_else(recovery_error)?
                && account.removed_at.is_none()
        }
        (AccountTransitionKind::AccountRemove, AccountTransitionState::Finalized) => {
            let finalized = transition.finalized_at.ok_or_else(recovery_error)?;
            account.state == RegisteredAccountState::Removed
                && account.active_transition_id.is_none()
                && account.updated_at == finalized
                && account.removed_at == Some(finalized)
        }
        (AccountTransitionKind::AccountCreate, AccountTransitionState::Aborted) => {
            let resolved = transition.resolved_at.ok_or_else(recovery_error)?;
            account.state == RegisteredAccountState::Removed
                && account.active_transition_id.is_none()
                && account.updated_at == resolved
                && account.removed_at == Some(resolved)
        }
        (
            AccountTransitionKind::AccountUpdate
            | AccountTransitionKind::AccountRemove
            | AccountTransitionKind::CredentialSet
            | AccountTransitionKind::CredentialDelete,
            AccountTransitionState::Aborted,
        ) => {
            account.state == RegisteredAccountState::Active
                && account.active_transition_id.is_none()
                && account.updated_at == transition.resolved_at.ok_or_else(recovery_error)?
                && account.removed_at.is_none()
        }
        (_, AccountTransitionState::RecoveryRequired) => {
            account.state == RegisteredAccountState::Blocked
                && account.active_transition_id == Some(transition.transition_id)
                && account.updated_at == transition.resolved_at.ok_or_else(recovery_error)?
                && account.removed_at.is_none()
        }
    };
    if !valid_state {
        return Err(recovery_error());
    }
    Ok(())
}

fn validate_account_mutation_parent(
    connection: &Connection,
    transition: &StoredAccountTransition,
    mutation: &AccountMutationManifest,
) -> Result<(), MailError> {
    let before = mutation.before.as_ref().ok_or_else(recovery_error)?;
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    let parent: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT credential_id,binding_sha256,committed_transition_id
             FROM registered_account_versions
             WHERE account_id=?1 AND store_id=?2 AND account_generation=?3",
            params![
                transition.account_id.as_bytes(),
                transition.store_id.as_bytes(),
                i64::try_from(before.generation.get()).map_err(|_| recovery_error())?,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| store_read_error())?;
    let (credential, binding, parent_transition) = parent.ok_or_else(recovery_error)?;
    if credential.as_slice() != before.credential_id.as_bytes()
        || binding.as_slice() != before.binding_sha256.as_bytes()
    {
        return Err(recovery_error());
    }
    let parent_transition_id: TransitionId =
        uuid_from_blob_sql(parent_transition).map_err(|_| recovery_error())?;
    let parent_transition =
        load_account_transition(connection, parent_transition_id)?.ok_or_else(recovery_error)?;
    if parent_transition.state != AccountTransitionState::Finalized
        || parent_transition.account_id != transition.account_id
    {
        return Err(recovery_error());
    }
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    let store_version: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM registered_store_versions
             WHERE store_id=?1 AND config_generation=?2 AND config_sha256=?3",
            params![
                transition.store_id.as_bytes(),
                i64::try_from(transition.expected_generation.get()).map_err(|_| recovery_error())?,
                transition.before_config_sha256.as_bytes(),
            ],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if store_version != 1 {
        return Err(recovery_error());
    }
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::type_complexity)]
fn validate_transition_cleanup(
    connection: &Connection,
    transition: &StoredAccountTransition,
    mutation: &AccountMutationManifest,
) -> Result<(), MailError> {
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM credential_cleanup WHERE transition_id=?1",
            [transition.transition_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| store_read_error())?;
    if usize::try_from(count).ok() != Some(mutation.cleanup.len()) {
        return Err(recovery_error());
    }
    let realm_id = if mutation.cleanup.is_empty() {
        None
    } else {
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT realm_id FROM authority_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| store_read_error())?;
        Some(OwnerRealmId::from_bytes(exact::<32>(&bytes)?))
    };
    let before = mutation.before.as_ref();
    for descriptor in &mutation.cleanup {
        record_validation_query(ValidationQueryKind::BoundedKeyed);
        let row: Option<(
            String,
            Vec<u8>,
            Vec<u8>,
            String,
            Option<Vec<u8>>,
            Option<i64>,
            i64,
        )> = connection
            .query_row(
                "SELECT locator_kind,locator_material,locator_sha256,state,
                            claim_grant_id,deleted_at,created_at
                     FROM credential_cleanup WHERE cleanup_id=?1 AND transition_id=?2",
                params![
                    descriptor.cleanup_id.as_bytes(),
                    transition.transition_id.as_bytes(),
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| store_read_error())?;
        let (kind, material, digest, state, claim, deleted, created_at) =
            row.ok_or_else(recovery_error)?;
        let expected_locator = expected_delete_only_locator(
            realm_id.ok_or_else(recovery_error)?,
            transition.store_id,
            before.ok_or_else(recovery_error)?,
            descriptor.locator_kind,
        );
        let lifecycle_valid = match (transition.state, state.as_str()) {
            (AccountTransitionState::Finalized, "ready")
            | (
                AccountTransitionState::Prepared
                | AccountTransitionState::ConfigCommitted
                | AccountTransitionState::Aborted
                | AccountTransitionState::RecoveryRequired,
                "provisional",
            ) => claim.is_none() && deleted.is_none(),
            (AccountTransitionState::Finalized, "claimed") => claim.is_some() && deleted.is_none(),
            (AccountTransitionState::Finalized, "deleted") => claim.is_some() && deleted.is_some(),
            _ => false,
        };
        if descriptor.expected_state != CleanupState::Provisional
            || kind != locator_kind_name(descriptor.locator_kind)
            || digest.as_slice() != descriptor.locator_sha256.as_bytes()
            || material != expected_locator
            || Sha256Digest::digest(&material) != descriptor.locator_sha256
            || !lifecycle_valid
            || created_at != transition.prepared_at
        {
            return Err(recovery_error());
        }
        let claim_grant = claim
            .map(uuid_from_blob_sql)
            .transpose()
            .map_err(|_| recovery_error())?;
        let claim_time = if let Some(grant_id) = claim_grant {
            let grant = load_grant_use(connection, grant_id)?.ok_or_else(recovery_error)?;
            if grant.action != SensitiveAction::CredentialCleanup
                || grant.target_kind != TargetKind::Cleanup
                || grant.target_id.as_slice() != descriptor.cleanup_id.as_bytes()
                || grant.used_at < transition.finalized_at.ok_or_else(recovery_error)?
                || deleted.is_some_and(|deleted_at| deleted_at < grant.used_at)
            {
                return Err(recovery_error());
            }
            Some(grant.used_at)
        } else {
            None
        };
        record_validation_query(ValidationQueryKind::BoundedKeyed);
        let ready_events: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM authority_events
                 WHERE entity_kind=7 AND entity_id=?1 AND event_code=15",
                [descriptor.cleanup_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| store_read_error())?;
        let expected_events = i64::from(transition.state == AccountTransitionState::Finalized);
        if ready_events != expected_events {
            return Err(recovery_error());
        }
        for (event_code, expected) in [
            (16, i64::from(claim_time.is_some())),
            (17, i64::from(deleted.is_some())),
        ] {
            record_validation_query(ValidationQueryKind::BoundedKeyed);
            let actual: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM authority_events
                     WHERE entity_kind=7 AND entity_id=?1 AND event_code=?2",
                    params![descriptor.cleanup_id.as_bytes(), i64::from(event_code)],
                    |row| row.get(0),
                )
                .map_err(|_| store_read_error())?;
            if actual != expected {
                return Err(recovery_error());
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_transition_events(
    connection: &Connection,
    transition: &StoredAccountTransition,
    receipt_id: AuthorizationReceiptId,
) -> Result<(), MailError> {
    let grant = load_grant_use(connection, transition.grant_id)?.ok_or_else(recovery_error)?;
    let grant_event = load_single_entity_event(connection, 10, transition.grant_id.as_bytes(), 7)?;
    let prepare_store_detail = authority_event_detail(
        9,
        4,
        transition.store_id.as_bytes(),
        4,
        6,
        transition.transition_id.as_bytes(),
        0x0401,
        0x0402,
        transition.transition_sha256,
        Some(receipt_id),
        transition.prepared_at,
    );
    let prepared =
        load_single_entity_event(connection, 6, transition.transition_id.as_bytes(), 10)?;
    let prepare_store_event = load_event_by_sequence(
        connection,
        prepared
            .sequence
            .checked_sub(1)
            .ok_or_else(recovery_error)?,
    )?;
    let prepared_detail = authority_event_detail(
        10,
        6,
        transition.transition_id.as_bytes(),
        4,
        5,
        transition.account_id.as_bytes(),
        0,
        AccountTransitionState::Prepared.event_state(),
        transition.transition_sha256,
        Some(receipt_id),
        transition.prepared_at,
    );
    if grant_event.sequence.checked_add(1) != Some(prepare_store_event.sequence)
        || prepare_store_event.sequence.checked_add(1) != Some(prepared.sequence)
        || grant.used_at != transition.prepared_at
        || prepare_store_event.entity_kind != 4
        || prepare_store_event.entity_id.as_slice() != transition.store_id.as_bytes()
        || prepare_store_event.event_code != 9
        || prepare_store_event.source != 4
        || prepare_store_event.occurred_at != transition.prepared_at
        || prepare_store_event.detail != prepare_store_detail
        || prepare_store_event.detail_sha256.as_slice()
            != Sha256::digest(&prepare_store_detail).as_slice()
        || prepared.detail != prepared_detail
        || prepared.detail_sha256.as_slice() != Sha256::digest(&prepared_detail).as_slice()
    {
        return Err(recovery_error());
    }

    let mut previous = prepared.sequence;
    if let Some(at) = transition.config_committed_at {
        let event =
            load_single_entity_event(connection, 6, transition.transition_id.as_bytes(), 11)?;
        let detail = authority_event_detail(
            11,
            6,
            transition.transition_id.as_bytes(),
            4,
            5,
            transition.account_id.as_bytes(),
            AccountTransitionState::Prepared.event_state(),
            AccountTransitionState::ConfigCommitted.event_state(),
            transition.transition_sha256,
            Some(receipt_id),
            at,
        );
        if event.detail != detail
            || event.detail_sha256.as_slice() != Sha256::digest(&detail).as_slice()
            || event.sequence <= previous
        {
            return Err(recovery_error());
        }
        previous = event.sequence;
    }
    match transition.state {
        AccountTransitionState::Prepared | AccountTransitionState::ConfigCommitted => {}
        AccountTransitionState::Finalized => {
            let at = transition.finalized_at.ok_or_else(recovery_error)?;
            let event =
                load_single_entity_event(connection, 6, transition.transition_id.as_bytes(), 12)?;
            let detail = authority_event_detail(
                12,
                6,
                transition.transition_id.as_bytes(),
                4,
                5,
                transition.account_id.as_bytes(),
                AccountTransitionState::ConfigCommitted.event_state(),
                AccountTransitionState::Finalized.event_state(),
                transition.transition_sha256,
                Some(receipt_id),
                at,
            );
            let store_detail = authority_event_detail(
                9,
                4,
                transition.store_id.as_bytes(),
                4,
                6,
                transition.transition_id.as_bytes(),
                0x0402,
                0x0401,
                transition.transition_sha256,
                Some(receipt_id),
                at,
            );
            let store_event = load_event_by_sequence(
                connection,
                event.sequence.checked_add(1).ok_or_else(recovery_error)?,
            )?;
            if event.sequence <= previous
                || event.sequence.checked_add(1) != Some(store_event.sequence)
                || event.detail != detail
                || store_event.entity_kind != 4
                || store_event.entity_id.as_slice() != transition.store_id.as_bytes()
                || store_event.event_code != 9
                || store_event.source != 4
                || store_event.occurred_at != at
                || store_event.detail != store_detail
                || store_event.detail_sha256.as_slice() != Sha256::digest(&store_detail).as_slice()
            {
                return Err(recovery_error());
            }
        }
        AccountTransitionState::Aborted => {
            let at = transition.resolved_at.ok_or_else(recovery_error)?;
            validate_terminal_transition_pair(
                connection,
                transition,
                receipt_id,
                previous,
                13,
                6,
                AccountTransitionState::Prepared,
                AccountTransitionState::Aborted,
                0x0401,
                transition.transition_sha256,
                at,
            )?;
        }
        AccountTransitionState::RecoveryRequired => {
            let at = transition.resolved_at.ok_or_else(recovery_error)?;
            let store = load_registered_store_by_id(connection, transition.store_id)?
                .ok_or_else(recovery_error)?;
            let prior = if transition.config_committed_at.is_some() {
                AccountTransitionState::ConfigCommitted
            } else {
                AccountTransitionState::Prepared
            };
            let recovery = account_recovery_digest(
                transition,
                prior,
                store.config_generation,
                store.config_sha256,
            );
            validate_terminal_transition_pair(
                connection,
                transition,
                receipt_id,
                previous,
                14,
                5,
                prior,
                AccountTransitionState::RecoveryRequired,
                0x0404,
                recovery,
                at,
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_terminal_transition_pair(
    connection: &Connection,
    transition: &StoredAccountTransition,
    receipt_id: AuthorizationReceiptId,
    previous: i64,
    event_code: u16,
    source: u8,
    prior: AccountTransitionState,
    next: AccountTransitionState,
    store_next: u16,
    context: Sha256Digest,
    at: i64,
) -> Result<(), MailError> {
    let event = load_single_entity_event(
        connection,
        6,
        transition.transition_id.as_bytes(),
        i64::from(event_code),
    )?;
    let detail = authority_event_detail(
        event_code,
        6,
        transition.transition_id.as_bytes(),
        source,
        5,
        transition.account_id.as_bytes(),
        prior.event_state(),
        next.event_state(),
        context,
        Some(receipt_id),
        at,
    );
    let store_detail = authority_event_detail(
        9,
        4,
        transition.store_id.as_bytes(),
        source,
        6,
        transition.transition_id.as_bytes(),
        0x0402,
        store_next,
        context,
        Some(receipt_id),
        at,
    );
    let store_sequence = if event_code == 14 {
        event.sequence.checked_sub(1).ok_or_else(recovery_error)?
    } else {
        event.sequence.checked_add(1).ok_or_else(recovery_error)?
    };
    let store_event = load_event_by_sequence(connection, store_sequence)?;
    let ordered = if event_code == 13 {
        event.sequence == previous.checked_add(1).ok_or_else(recovery_error)?
            && store_event.sequence == event.sequence.checked_add(1).ok_or_else(recovery_error)?
    } else {
        store_event.sequence > previous
            && event.sequence
                == store_event
                    .sequence
                    .checked_add(1)
                    .ok_or_else(recovery_error)?
    };
    if !ordered
        || event.detail != detail
        || event.detail_sha256.as_slice() != Sha256::digest(&detail).as_slice()
        || store_event.entity_kind != 4
        || store_event.entity_id.as_slice() != transition.store_id.as_bytes()
        || store_event.event_code != 9
        || store_event.source != i64::from(source)
        || store_event.occurred_at != at
        || store_event.detail != store_detail
        || store_event.detail_sha256.as_slice() != Sha256::digest(&store_detail).as_slice()
    {
        return Err(recovery_error());
    }
    Ok(())
}

fn load_event_by_sequence(
    connection: &Connection,
    sequence: i64,
) -> Result<StoredAuthorityEvent, MailError> {
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    connection
        .query_row(
            "SELECT sequence,entity_kind,entity_id,event_code,source,occurred_at,
                    detail,detail_sha256 FROM authority_events
             WHERE sequence=?1",
            [sequence],
            stored_authority_event_from_row,
        )
        .optional()
        .map_err(|_| store_read_error())?
        .ok_or_else(recovery_error)
}

fn validate_registry_events(
    connection: &Connection,
    grant: &StoredGrantUse,
    store: &StoredRegisteredStore,
) -> Result<(), MailError> {
    let grant_event = load_single_entity_event(connection, 10, grant.grant_id.as_bytes(), 7)?;
    let store_event = load_single_entity_event(connection, 4, store.store_id.as_bytes(), 8)?;
    let expected_grant = authority_event_detail(
        7,
        10,
        grant.grant_id.as_bytes(),
        1,
        9,
        grant.receipt_id.as_bytes(),
        0x0901,
        0x0902,
        grant.use_sha256,
        Some(grant.receipt_id),
        grant.used_at,
    );
    let expected_store = authority_event_detail(
        8,
        4,
        store.store_id.as_bytes(),
        4,
        10,
        grant.grant_id.as_bytes(),
        0,
        0x0401,
        grant.use_sha256,
        Some(grant.receipt_id),
        grant.used_at,
    );
    if grant_event.sequence.checked_add(1) != Some(store_event.sequence)
        || grant_event.source != 1
        || store_event.source != 4
        || grant_event.occurred_at != grant.used_at
        || store_event.occurred_at != grant.used_at
        || grant_event.detail != expected_grant
        || store_event.detail != expected_store
        || grant_event.detail_sha256.as_slice() != Sha256::digest(&expected_grant).as_slice()
        || store_event.detail_sha256.as_slice() != Sha256::digest(&expected_store).as_slice()
    {
        return Err(recovery_error());
    }
    Ok(())
}

fn load_single_entity_event(
    connection: &Connection,
    entity_kind: i64,
    entity_id: &[u8],
    event_code: i64,
) -> Result<StoredAuthorityEvent, MailError> {
    record_validation_query(ValidationQueryKind::BoundedKeyed);
    let mut statement = connection
        .prepare(
            "SELECT sequence,entity_kind,entity_id,event_code,source,occurred_at,
                    detail,detail_sha256
             FROM authority_events INDEXED BY authority_events_entity_sequence
             WHERE entity_kind=?1 AND entity_id=?2 AND event_code=?3
             ORDER BY sequence LIMIT 2",
        )
        .map_err(|_| store_read_error())?;
    let mut rows = statement
        .query(params![entity_kind, entity_id, event_code])
        .map_err(|_| store_read_error())?;
    let first = rows
        .next()
        .map_err(|_| store_read_error())?
        .ok_or_else(recovery_error)?;
    let event = stored_authority_event_from_row(first).map_err(|_| recovery_error())?;
    if rows.next().map_err(|_| store_read_error())?.is_some() {
        return Err(recovery_error());
    }
    Ok(event)
}

struct StoredNonceUse {
    nonce: [u8; 32],
    challenge_id: Sha256Digest,
    receipt_id: AuthorizationReceiptId,
    consumed_at: i64,
}

fn nonce_preflight(connection: &Connection) -> Result<(), MailError> {
    record_validation_query(ValidationQueryKind::NoncePreflight);
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
    record_validation_query(ValidationQueryKind::BoundedKeyed);
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
            sequence if sequence > expected_prefix => match row.entity_kind {
                8 => validate_challenge_event(connection, &row, last_observed_at)?,
                4 | 6 | 7 | 10 => validate_registry_event_row(connection, &row)?,
                _ => return Err(recovery_error()),
            },
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
    record_validation_query(ValidationQueryKind::EventPreflight);
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

#[allow(clippy::too_many_lines)]
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
    let receipt = load_receipt_for_challenge(connection, challenge.challenge_id)?;
    let (event, source, occurred_at) = match row.event_code {
        3 => (ChallengeEvent::Created, 1_i64, challenge.issued_at),
        4 => {
            let receipt = receipt.as_ref().ok_or_else(recovery_error)?;
            (ChallengeEvent::Authorized, 3, receipt.verified_at)
        }
        5 if row.occurred_at > challenge.expires_at && row.occurred_at <= last_observed_at => {
            (ChallengeEvent::Expired, 1, row.occurred_at)
        }
        _ => return Err(recovery_error()),
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
        ChallengeEvent::Expired => {
            if let Some(receipt) = &receipt {
                let manifest =
                    ActionManifest::parse(&challenge.manifest).map_err(|_| recovery_error())?;
                let intent = match manifest.payload() {
                    ManifestPayload::StoreEnroll(_) => {
                        let enrollment =
                            store_enrollment_context(&manifest).map_err(|_| recovery_error())?;
                        enrollment_intent_from_rows(&challenge, receipt, enrollment)
                    }
                    ManifestPayload::AccountCreate(value)
                    | ManifestPayload::AccountUpdate(value)
                    | ManifestPayload::AccountRemove(value) => {
                        account_prepare_intent_from_rows(&challenge, receipt, value)?
                    }
                    ManifestPayload::CredentialSet(value)
                    | ManifestPayload::CredentialDelete(value) => {
                        account_prepare_intent_from_rows(&challenge, receipt, &value.account)?
                    }
                    ManifestPayload::CredentialCleanup(_) => challenge.manifest_sha256,
                    _ => return Err(recovery_error()),
                };
                (
                    9,
                    receipt.receipt_id.as_bytes().as_slice(),
                    0x0802,
                    0x0803,
                    intent,
                    Some(receipt.receipt_id),
                )
            } else {
                (
                    0,
                    &[] as &[u8],
                    0x0801,
                    0x0803,
                    challenge.context_sha256,
                    None,
                )
            }
        }
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

#[allow(clippy::too_many_lines)]
fn validate_registry_event_row(
    connection: &Connection,
    row: &StoredAuthorityEvent,
) -> Result<(), MailError> {
    match (row.entity_kind, row.event_code, row.entity_id.len()) {
        (7, 15, 16) => {
            let cleanup_id: CleanupId =
                uuid_from_blob_sql(row.entity_id.clone()).map_err(|_| recovery_error())?;
            let cleanup: Option<(Vec<u8>, String)> = connection
                .query_row(
                    "SELECT transition_id,state FROM credential_cleanup WHERE cleanup_id=?1",
                    [cleanup_id.as_bytes()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| store_read_error())?;
            let (transition_id, state) = cleanup.ok_or_else(recovery_error)?;
            let transition_id: TransitionId =
                uuid_from_blob_sql(transition_id).map_err(|_| recovery_error())?;
            let transition =
                load_account_transition(connection, transition_id)?.ok_or_else(recovery_error)?;
            let receipt_id = transition_receipt_id(connection, &transition)?;
            let occurred_at = transition.finalized_at.ok_or_else(recovery_error)?;
            let expected = authority_event_detail(
                15,
                7,
                cleanup_id.as_bytes(),
                6,
                6,
                transition.transition_id.as_bytes(),
                0x0701,
                0x0702,
                transition.transition_sha256,
                Some(receipt_id),
                occurred_at,
            );
            if !matches!(state.as_str(), "ready" | "claimed" | "deleted")
                || transition.state != AccountTransitionState::Finalized
                || row.source != 6
                || row.occurred_at != occurred_at
                || row.detail != expected
                || row.detail_sha256.as_slice() != Sha256::digest(&expected).as_slice()
            {
                return Err(recovery_error());
            }
        }
        (7, event_code @ (16 | 17), 16) => {
            let cleanup_id: CleanupId =
                uuid_from_blob_sql(row.entity_id.clone()).map_err(|_| recovery_error())?;
            let cleanup =
                load_credential_cleanup(connection, cleanup_id)?.ok_or_else(recovery_error)?;
            let grant_id = cleanup.claim_grant_id.ok_or_else(recovery_error)?;
            let grant = load_grant_use(connection, grant_id)?.ok_or_else(recovery_error)?;
            let (prior_state, next_state, occurred_at) = if event_code == 16 {
                (0x0702, 0x0703, grant.used_at)
            } else {
                (
                    0x0703,
                    0x0704,
                    cleanup.deleted_at.ok_or_else(recovery_error)?,
                )
            };
            let expected = authority_event_detail(
                u16::try_from(event_code).map_err(|_| recovery_error())?,
                7,
                cleanup_id.as_bytes(),
                4,
                10,
                grant_id.as_bytes(),
                prior_state,
                next_state,
                grant.use_sha256,
                Some(grant.receipt_id),
                occurred_at,
            );
            let state_reaches_event = if event_code == 16 {
                matches!(cleanup.state, CleanupState::Claimed | CleanupState::Deleted)
            } else {
                cleanup.state == CleanupState::Deleted
            };
            if !state_reaches_event
                || row.source != 4
                || row.occurred_at != occurred_at
                || row.detail != expected
                || row.detail_sha256.as_slice() != Sha256::digest(&expected).as_slice()
            {
                return Err(recovery_error());
            }
        }
        (6, 10..=14, 16) => {
            let transition_id: TransitionId =
                uuid_from_blob_sql(row.entity_id.clone()).map_err(|_| recovery_error())?;
            let transition =
                load_account_transition(connection, transition_id)?.ok_or_else(recovery_error)?;
            let receipt_id = transition_receipt_id(connection, &transition)?;
            validate_transition_events(connection, &transition, receipt_id)?;
            let event_is_reachable = match transition.state {
                AccountTransitionState::Prepared => row.event_code == 10,
                AccountTransitionState::ConfigCommitted => matches!(row.event_code, 10 | 11),
                AccountTransitionState::Finalized => matches!(row.event_code, 10..=12),
                AccountTransitionState::Aborted => matches!(row.event_code, 10 | 13),
                AccountTransitionState::RecoveryRequired => {
                    row.event_code == 10
                        || row.event_code == 14
                        || (transition.config_committed_at.is_some() && row.event_code == 11)
                }
            };
            if !event_is_reachable
                || row.detail_sha256.as_slice() != Sha256::digest(&row.detail).as_slice()
            {
                return Err(recovery_error());
            }
        }
        (4, 9, 16) => {
            let store_id: StoreId =
                uuid_from_blob_sql(row.entity_id.clone()).map_err(|_| recovery_error())?;
            if load_registered_store_by_id(connection, store_id)?.is_none()
                || parse_account_store_event_detail(row, store_id).is_err()
                || row.detail_sha256.as_slice() != Sha256::digest(&row.detail).as_slice()
            {
                return Err(recovery_error());
            }
        }
        (10, 7, 16) => {
            let grant_id: AuthorizationGrantId =
                uuid_from_blob_sql(row.entity_id.clone()).map_err(|_| recovery_error())?;
            let grant = load_grant_use(connection, grant_id)?.ok_or_else(recovery_error)?;
            let expected = authority_event_detail(
                7,
                10,
                grant.grant_id.as_bytes(),
                1,
                9,
                grant.receipt_id.as_bytes(),
                0x0901,
                0x0902,
                grant.use_sha256,
                Some(grant.receipt_id),
                grant.used_at,
            );
            if row.source != 1
                || row.occurred_at != grant.used_at
                || row.detail != expected
                || row.detail_sha256.as_slice() != Sha256::digest(&expected).as_slice()
            {
                return Err(recovery_error());
            }
        }
        (4, 8, 16) => {
            let store_id: StoreId =
                uuid_from_blob_sql(row.entity_id.clone()).map_err(|_| recovery_error())?;
            let store =
                load_registered_store_by_id(connection, store_id)?.ok_or_else(recovery_error)?;
            let receipt = load_receipt_by_id(connection, store.enrolled_receipt_id)?
                .ok_or_else(recovery_error)?;
            record_validation_query(ValidationQueryKind::BoundedKeyed);
            let grant_bytes: Vec<u8> = connection
                .query_row(
                    "SELECT grant_id FROM grant_uses WHERE receipt_id=?1",
                    [receipt.receipt_id.as_bytes()],
                    |value| value.get(0),
                )
                .map_err(|_| store_read_error())?;
            let grant_id: AuthorizationGrantId =
                uuid_from_blob_sql(grant_bytes).map_err(|_| recovery_error())?;
            let grant = load_grant_use(connection, grant_id)?.ok_or_else(recovery_error)?;
            let expected = authority_event_detail(
                8,
                4,
                store.store_id.as_bytes(),
                4,
                10,
                grant.grant_id.as_bytes(),
                0,
                0x0401,
                grant.use_sha256,
                Some(receipt.receipt_id),
                grant.used_at,
            );
            if row.source != 4
                || row.occurred_at != grant.used_at
                || row.detail != expected
                || row.detail_sha256.as_slice() != Sha256::digest(&expected).as_slice()
            {
                return Err(recovery_error());
            }
        }
        _ => return Err(recovery_error()),
    }
    Ok(())
}

fn account_store_event_is_exact(
    connection: &Connection,
    store: &StoredRegisteredStore,
    initial_version: &StoredRegisteredStoreVersion,
) -> Result<(), MailError> {
    let store_id = store.store_id;
    record_validation_query(ValidationQueryKind::RegistryStream);
    let mut statement = connection
        .prepare(
            "SELECT sequence,entity_kind,entity_id,event_code,source,occurred_at,
                    detail,detail_sha256
             FROM authority_events INDEXED BY authority_events_entity_sequence
             WHERE entity_kind=4 AND entity_id=?1 ORDER BY sequence",
        )
        .map_err(|_| store_read_error())?;
    let mut rows = statement
        .query([store_id.as_bytes()])
        .map_err(|_| store_read_error())?;
    let mut saw_enrollment = false;
    let mut derived_state = "active";
    let mut derived_generation = initial_version.config_generation;
    let mut derived_config_sha256 = initial_version.config_sha256;
    let mut derived_updated_at = store.created_at;
    let mut active_transition = None;
    while let Some(row) = rows.next().map_err(|_| store_read_error())? {
        let event = stored_authority_event_from_row(row).map_err(|_| recovery_error())?;
        match event.event_code {
            8 if !saw_enrollment && active_transition.is_none() => {
                saw_enrollment = true;
            }
            9 if saw_enrollment => {
                let (detail, transition) =
                    validate_account_store_event_row(connection, store_id, &event)?;
                match (detail.prior_state, detail.next_state) {
                    (0x0401, 0x0402) => {
                        if derived_state != "active"
                            || active_transition.is_some()
                            || transition.expected_generation != derived_generation
                            || transition.before_config_sha256 != derived_config_sha256
                        {
                            return Err(recovery_error());
                        }
                        derived_state = "blocked";
                        active_transition = Some(transition.transition_id);
                        derived_updated_at = transition.prepared_at;
                        if transition.config_committed_at.is_some() {
                            derived_generation = transition.next_generation;
                            derived_config_sha256 = transition.after_config_sha256;
                            derived_updated_at =
                                transition.config_committed_at.ok_or_else(recovery_error)?;
                        }
                    }
                    (0x0402, 0x0401) => {
                        if derived_state != "blocked"
                            || active_transition != Some(transition.transition_id)
                            || !matches!(
                                transition.state,
                                AccountTransitionState::Finalized | AccountTransitionState::Aborted
                            )
                        {
                            return Err(recovery_error());
                        }
                        derived_state = "active";
                        active_transition = None;
                        derived_updated_at = match transition.state {
                            AccountTransitionState::Finalized => {
                                transition.finalized_at.ok_or_else(recovery_error)?
                            }
                            AccountTransitionState::Aborted => {
                                transition.resolved_at.ok_or_else(recovery_error)?
                            }
                            _ => return Err(recovery_error()),
                        };
                    }
                    (0x0402, 0x0404) => {
                        if derived_state != "blocked"
                            || active_transition != Some(transition.transition_id)
                            || transition.state != AccountTransitionState::RecoveryRequired
                        {
                            return Err(recovery_error());
                        }
                        derived_state = "recovery_required";
                        derived_generation = store.config_generation;
                        derived_config_sha256 = store.config_sha256;
                        derived_updated_at = transition.resolved_at.ok_or_else(recovery_error)?;
                    }
                    _ => return Err(recovery_error()),
                }
            }
            _ => return Err(recovery_error()),
        }
    }
    if !saw_enrollment
        || derived_state != store.state
        || derived_generation != store.config_generation
        || derived_config_sha256 != store.config_sha256
        || derived_updated_at != store.updated_at
    {
        return Err(recovery_error());
    }
    Ok(())
}

struct AccountStoreEventDetail {
    source: u8,
    transition_id: TransitionId,
    prior_state: u16,
    next_state: u16,
    context_sha256: Sha256Digest,
    receipt_id: AuthorizationReceiptId,
    occurred_at: i64,
}

fn parse_account_store_event_detail(
    row: &StoredAuthorityEvent,
    store_id: StoreId,
) -> Result<AccountStoreEventDetail, MailError> {
    if row.entity_kind != 4
        || row.event_code != 9
        || row.entity_id.as_slice() != store_id.as_bytes()
        || !row.detail.starts_with(EVENT_DETAIL_DOMAIN)
    {
        return Err(recovery_error());
    }
    let mut cursor = EVENT_DETAIL_DOMAIN.len();
    if read_u16(&row.detail, &mut cursor)? != 11 {
        return Err(recovery_error());
    }
    let event_code = transcript_field(&row.detail, &mut cursor, 1)?;
    let entity_kind = transcript_field(&row.detail, &mut cursor, 2)?;
    let entity_id = transcript_field(&row.detail, &mut cursor, 3)?;
    let source = transcript_field(&row.detail, &mut cursor, 4)?;
    let related_kind = transcript_field(&row.detail, &mut cursor, 5)?;
    let related_id = transcript_field(&row.detail, &mut cursor, 6)?;
    let prior_state = transcript_field(&row.detail, &mut cursor, 7)?;
    let next_state = transcript_field(&row.detail, &mut cursor, 8)?;
    let context_sha256 = transcript_field(&row.detail, &mut cursor, 9)?;
    let receipt_id = transcript_field(&row.detail, &mut cursor, 10)?;
    let occurred_at = transcript_field(&row.detail, &mut cursor, 11)?;
    if cursor != row.detail.len()
        || u16::from_be_bytes(exact(event_code)?) != 9
        || u16::from_be_bytes(exact(entity_kind)?) != 4
        || entity_id != store_id.as_bytes()
        || u16::from_be_bytes(exact(related_kind)?) != 6
        || source.len() != 1
    {
        return Err(recovery_error());
    }
    Ok(AccountStoreEventDetail {
        source: source[0],
        transition_id: uuid_from_blob_sql(related_id.to_vec()).map_err(|_| recovery_error())?,
        prior_state: u16::from_be_bytes(exact(prior_state)?),
        next_state: u16::from_be_bytes(exact(next_state)?),
        context_sha256: digest_from_blob(context_sha256)?,
        receipt_id: uuid_from_blob_sql(receipt_id.to_vec()).map_err(|_| recovery_error())?,
        occurred_at: i64::from_be_bytes(exact(occurred_at)?),
    })
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, MailError> {
    let end = cursor.checked_add(2).ok_or_else(recovery_error)?;
    let value = bytes.get(*cursor..end).ok_or_else(recovery_error)?;
    *cursor = end;
    Ok(u16::from_be_bytes(exact(value)?))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, MailError> {
    let end = cursor.checked_add(4).ok_or_else(recovery_error)?;
    let value = bytes.get(*cursor..end).ok_or_else(recovery_error)?;
    *cursor = end;
    Ok(u32::from_be_bytes(exact(value)?))
}

fn transcript_field<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    expected_tag: u16,
) -> Result<&'a [u8], MailError> {
    if read_u16(bytes, cursor)? != expected_tag {
        return Err(recovery_error());
    }
    let length = usize::try_from(read_u32(bytes, cursor)?).map_err(|_| recovery_error())?;
    let end = cursor.checked_add(length).ok_or_else(recovery_error)?;
    let value = bytes.get(*cursor..end).ok_or_else(recovery_error)?;
    *cursor = end;
    Ok(value)
}

fn validate_account_store_event_row(
    connection: &Connection,
    store_id: StoreId,
    row: &StoredAuthorityEvent,
) -> Result<(AccountStoreEventDetail, StoredAccountTransition), MailError> {
    let detail = parse_account_store_event_detail(row, store_id)?;
    let transition =
        load_account_transition(connection, detail.transition_id)?.ok_or_else(recovery_error)?;
    let receipt_id = transition_receipt_id(connection, &transition)?;
    if transition.store_id != store_id
        || detail.receipt_id != receipt_id
        || row.source != i64::from(detail.source)
        || row.occurred_at != detail.occurred_at
        || row.detail_sha256.as_slice() != Sha256::digest(&row.detail).as_slice()
    {
        return Err(recovery_error());
    }
    let (source, prior, next, context, occurred_at, transition_event, store_follows) =
        match (detail.prior_state, detail.next_state) {
            (0x0401, 0x0402) => (
                4,
                0x0401,
                0x0402,
                transition.transition_sha256,
                transition.prepared_at,
                load_single_entity_event(connection, 6, transition.transition_id.as_bytes(), 10)?,
                false,
            ),
            (0x0402, 0x0401) if transition.state == AccountTransitionState::Finalized => (
                4,
                0x0402,
                0x0401,
                transition.transition_sha256,
                transition.finalized_at.ok_or_else(recovery_error)?,
                load_single_entity_event(connection, 6, transition.transition_id.as_bytes(), 12)?,
                true,
            ),
            (0x0402, 0x0401) if transition.state == AccountTransitionState::Aborted => (
                6,
                0x0402,
                0x0401,
                transition.transition_sha256,
                transition.resolved_at.ok_or_else(recovery_error)?,
                load_single_entity_event(connection, 6, transition.transition_id.as_bytes(), 13)?,
                true,
            ),
            (0x0402, 0x0404) if transition.state == AccountTransitionState::RecoveryRequired => {
                let store = load_registered_store_by_id(connection, store_id)?
                    .ok_or_else(recovery_error)?;
                let prior = if transition.config_committed_at.is_some() {
                    AccountTransitionState::ConfigCommitted
                } else {
                    AccountTransitionState::Prepared
                };
                (
                    5,
                    0x0402,
                    0x0404,
                    account_recovery_digest(
                        &transition,
                        prior,
                        store.config_generation,
                        store.config_sha256,
                    ),
                    transition.resolved_at.ok_or_else(recovery_error)?,
                    load_single_entity_event(
                        connection,
                        6,
                        transition.transition_id.as_bytes(),
                        14,
                    )?,
                    false,
                )
            }
            _ => return Err(recovery_error()),
        };
    let expected = authority_event_detail(
        9,
        4,
        store_id.as_bytes(),
        source,
        6,
        transition.transition_id.as_bytes(),
        prior,
        next,
        context,
        Some(receipt_id),
        occurred_at,
    );
    let ordered = if transition_event.event_code == 10 {
        row.sequence.checked_add(1) == Some(transition_event.sequence)
    } else if store_follows {
        transition_event.sequence.checked_add(1) == Some(row.sequence)
    } else {
        row.sequence.checked_add(1) == Some(transition_event.sequence)
    };
    if detail.source != source
        || detail.context_sha256 != context
        || detail.occurred_at != occurred_at
        || row.detail != expected
        || !ordered
    {
        return Err(recovery_error());
    }
    Ok((detail, transition))
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
    record_validation_query(ValidationQueryKind::BoundedKeyed);
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
        "expired"
            if authorized.is_some()
                && expired.is_some()
                && authorized
                    .zip(expired)
                    .is_some_and(|(left, right)| left < right) =>
        {
            authorized
        }
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

fn insert_enrollment_expiry_event(
    transaction: &Transaction<'_>,
    challenge: &StoredChallenge,
    receipt: &StoredReceipt,
    intent_sha256: Sha256Digest,
    occurred_at: i64,
) -> Result<(), MailError> {
    insert_typed_event(
        transaction,
        8,
        challenge.challenge_id.as_bytes(),
        5,
        1,
        9,
        receipt.receipt_id.as_bytes(),
        0x0802,
        0x0803,
        intent_sha256,
        Some(receipt.receipt_id),
        occurred_at,
    )
}

fn insert_grant_used_event(
    transaction: &Transaction<'_>,
    grant_id: AuthorizationGrantId,
    receipt_id: AuthorizationReceiptId,
    use_sha256: Sha256Digest,
    occurred_at: i64,
) -> Result<(), MailError> {
    insert_typed_event(
        transaction,
        10,
        grant_id.as_bytes(),
        7,
        1,
        9,
        receipt_id.as_bytes(),
        0x0901,
        0x0902,
        use_sha256,
        Some(receipt_id),
        occurred_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_cleanup_event(
    transaction: &Transaction<'_>,
    cleanup_id: CleanupId,
    event_code: u16,
    grant_id: AuthorizationGrantId,
    receipt_id: AuthorizationReceiptId,
    prior_state: u16,
    next_state: u16,
    context: Sha256Digest,
    occurred_at: i64,
) -> Result<(), MailError> {
    insert_typed_event(
        transaction,
        7,
        cleanup_id.as_bytes(),
        event_code,
        4,
        10,
        grant_id.as_bytes(),
        prior_state,
        next_state,
        context,
        Some(receipt_id),
        occurred_at,
    )
}

fn insert_store_enrolled_event(
    transaction: &Transaction<'_>,
    store_id: StoreId,
    grant_id: AuthorizationGrantId,
    receipt_id: AuthorizationReceiptId,
    use_sha256: Sha256Digest,
    occurred_at: i64,
) -> Result<(), MailError> {
    insert_typed_event(
        transaction,
        4,
        store_id.as_bytes(),
        8,
        4,
        10,
        grant_id.as_bytes(),
        0,
        0x0401,
        use_sha256,
        Some(receipt_id),
        occurred_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_typed_event(
    transaction: &Transaction<'_>,
    entity_kind: u16,
    entity_id: &[u8],
    event_code: u16,
    source: u8,
    related_kind: u16,
    related_id: &[u8],
    prior_state: u16,
    next_state: u16,
    context: Sha256Digest,
    receipt_id: Option<AuthorizationReceiptId>,
    occurred_at: i64,
) -> Result<(), MailError> {
    let detail = authority_event_detail(
        event_code,
        entity_kind,
        entity_id,
        source,
        related_kind,
        related_id,
        prior_state,
        next_state,
        context,
        receipt_id,
        occurred_at,
    );
    let digest = Sha256::digest(&detail);
    let inserted = transaction
        .execute(
            "INSERT INTO authority_events
             (entity_kind,entity_id,event_code,source,occurred_at,detail,detail_sha256)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                i64::from(entity_kind),
                entity_id,
                i64::from(event_code),
                i64::from(source),
                occurred_at,
                detail,
                digest.as_slice(),
            ],
        )
        .map_err(|_| store_write_error())?;
    if inserted != 1 {
        return Err(store_write_error());
    }
    Ok(())
}

fn validate_exact_enrollment_expiry(
    connection: &Connection,
    challenge: &StoredChallenge,
    receipt: &StoredReceipt,
    intent_sha256: Sha256Digest,
) -> Result<(), MailError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence,entity_kind,entity_id,event_code,source,occurred_at,
                    detail,detail_sha256
             FROM authority_events INDEXED BY authority_events_entity_sequence
             WHERE entity_kind=8 AND entity_id=?1 AND event_code=5
             ORDER BY sequence LIMIT 2",
        )
        .map_err(|_| store_read_error())?;
    let mut rows = statement
        .query([challenge.challenge_id.as_bytes()])
        .map_err(|_| store_read_error())?;
    let row = rows
        .next()
        .map_err(|_| store_read_error())?
        .ok_or_else(recovery_error)?;
    let event = stored_authority_event_from_row(row).map_err(|_| recovery_error())?;
    if rows.next().map_err(|_| store_read_error())?.is_some() {
        return Err(recovery_error());
    }
    let expected = authority_event_detail(
        5,
        8,
        challenge.challenge_id.as_bytes(),
        1,
        9,
        receipt.receipt_id.as_bytes(),
        0x0802,
        0x0803,
        intent_sha256,
        Some(receipt.receipt_id),
        event.occurred_at,
    );
    if event.source != 1
        || event.detail != expected
        || event.detail_sha256.as_slice() != Sha256::digest(&expected).as_slice()
    {
        return Err(authorization_context_stale_error());
    }
    Ok(())
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

fn grant_already_used_error() -> MailError {
    MailError::stable(
        MailErrorCode::GrantAlreadyUsed,
        "authorization grant was already used with different identity",
    )
}

fn config_store_identity_conflict_error() -> MailError {
    MailError::stable(
        MailErrorCode::ConfigStoreIdentityConflict,
        "config store identity conflicts with an existing registration",
    )
}

fn account_update_conflict_error() -> MailError {
    MailError::stable(
        MailErrorCode::AccountUpdateConflict,
        "account transition conflicts with the current registry state",
    )
}

fn account_identity_conflict_error() -> MailError {
    MailError::stable(
        MailErrorCode::AccountIdentityConflict,
        "account transition identity is already reserved",
    )
}

fn account_already_exists_error() -> MailError {
    MailError::stable(
        MailErrorCode::AccountAlreadyExists,
        "account display identity is already active",
    )
}

fn credential_cleanup_invalid_error() -> MailError {
    MailError::stable(
        MailErrorCode::CredentialCleanupInvalid,
        "credential cleanup is invalid",
    )
}

fn credential_delete_error() -> MailError {
    MailError::stable(
        MailErrorCode::SecretStoreUnavailable,
        "OS credential store is unavailable",
    )
}

#[cfg(test)]
mod tests {
    use super::private_material_length_is_bounded;

    #[test]
    fn private_material_numeric_boundaries_are_closed() {
        assert!(!private_material_length_is_bounded(0));
        assert!(private_material_length_is_bounded(1));
        assert!(private_material_length_is_bounded(4_095));
        assert!(private_material_length_is_bounded(4_096));
        assert!(!private_material_length_is_bounded(4_097));
        assert!(!private_material_length_is_bounded(usize::MAX));
    }
}
