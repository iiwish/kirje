use std::{
    collections::HashSet,
    num::{NonZeroU32, NonZeroU64},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    AccountBinding, AccountId, AccountStateReason, AuthorizationGrantId, AuthorizationReceiptId,
    BindingState, CleanupId, CredentialId, CredentialKind, Endpoint, InvocationId, JournalId,
    KeyFingerprint, MailAccountConfig, MailError, MailErrorCode, OperationId, OwnerRealmId,
    Protocol, RemoteEffectId, Sha256Digest, StoreId, StoredCredentialState, TransitionId,
    TransportSecurity, encode_fields, protocol_code, security_code,
};

const MANIFEST_DOMAIN: &[u8] = b"KIRJE-MANIFEST-V1\0";
const AUTHORIZATION_DOMAIN: &[u8] = b"KIRJE-AUTHORIZATION-V1\0";
const EFFECT_DOMAIN: &[u8] = b"KIRJE-EFFECT-V1\0";
const ADDRESS_DOMAIN: &[u8] = b"KIRJE-ADDRESS-V1\0";
const ATTACHMENT_DOMAIN: &[u8] = b"KIRJE-ATTACHMENT-V1\0";
const ATTACHMENT_SUMMARY_DOMAIN: &[u8] = b"KIRJE-ATTACHMENT-SUMMARY-V1\0";
const ENDPOINT_DOMAIN: &[u8] = b"KIRJE-ENDPOINT-V1\0";
const ACCOUNT_SNAPSHOT_DOMAIN: &[u8] = b"KIRJE-ACCOUNT-SNAPSHOT-V1\0";
const CONFIG_CAS_DOMAIN: &[u8] = b"KIRJE-CONFIG-CAS-V1\0";
const CLEANUP_DESCRIPTOR_DOMAIN: &[u8] = b"KIRJE-CLEANUP-DESCRIPTOR-V1\0";
const OWNER_KEY_DOMAIN: &[u8] = b"KIRJE-OWNER-KEY-V1\0";
const MAX_AUTHORIZATION_LIFETIME_MS: i64 = 900_000;
const MAX_AUTHORIZATION_EFFECTS: usize = 8;
const MAX_ASSERTION_TEXT_BYTES: usize = 1_024;

#[derive(Clone, Eq, PartialEq)]
pub struct OwnerPublicKey([u8; 32]);

impl OwnerPublicKey {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<[u8; 32]> for OwnerPublicKey {
    type Error = MailError;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| malformed("owner public key is malformed"))?;
        if key.is_weak() {
            return Err(malformed("owner public key is weak"));
        }
        Ok(Self(bytes))
    }
}

impl TryFrom<&[u8]> for OwnerPublicKey {
    type Error = MailError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let exact: [u8; 32] = bytes
            .try_into()
            .map_err(|_| malformed("owner public key must contain exactly 32 bytes"))?;
        Self::try_from(exact)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveAction {
    SendSubmit,
    MailSeen,
    MailStarred,
    MailMove,
    MailArchive,
    MailSafeDelete,
    StoreEnroll,
    AccountCreate,
    AccountUpdate,
    AccountRemove,
    CredentialSet,
    CredentialDelete,
    CredentialCleanup,
    PolicyUpdate,
    AssuranceUpdate,
    OwnerRotate,
    RecoveryRotate,
    OwnerRecover,
    AmbiguousClose,
}

impl SensitiveAction {
    pub const ALL: [Self; 19] = [
        Self::SendSubmit,
        Self::MailSeen,
        Self::MailStarred,
        Self::MailMove,
        Self::MailArchive,
        Self::MailSafeDelete,
        Self::StoreEnroll,
        Self::AccountCreate,
        Self::AccountUpdate,
        Self::AccountRemove,
        Self::CredentialSet,
        Self::CredentialDelete,
        Self::CredentialCleanup,
        Self::PolicyUpdate,
        Self::AssuranceUpdate,
        Self::OwnerRotate,
        Self::RecoveryRotate,
        Self::OwnerRecover,
        Self::AmbiguousClose,
    ];

    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::SendSubmit => 0x0001,
            Self::MailSeen => 0x0010,
            Self::MailStarred => 0x0011,
            Self::MailMove => 0x0012,
            Self::MailArchive => 0x0013,
            Self::MailSafeDelete => 0x0014,
            Self::StoreEnroll => 0x0100,
            Self::AccountCreate => 0x0110,
            Self::AccountUpdate => 0x0111,
            Self::AccountRemove => 0x0112,
            Self::CredentialSet => 0x0120,
            Self::CredentialDelete => 0x0121,
            Self::CredentialCleanup => 0x0122,
            Self::PolicyUpdate => 0x0200,
            Self::AssuranceUpdate => 0x0201,
            Self::OwnerRotate => 0x0210,
            Self::RecoveryRotate => 0x0211,
            Self::OwnerRecover => 0x0212,
            Self::AmbiguousClose => 0x0220,
        }
    }

    /// Decode one permanently assigned action code.
    ///
    /// # Errors
    ///
    /// Returns unsupported-capability for a code outside the closed table.
    pub fn from_code(code: u16) -> Result<Self, MailError> {
        Self::ALL
            .into_iter()
            .find(|action| action.code() == code)
            .ok_or_else(unsupported_action)
    }

    #[must_use]
    pub const fn policy(self) -> SensitiveActionPolicy {
        let (target_kind, effect_kind, required_role, mcp_mutation, manifest_support) = match self {
            Self::SendSubmit => (
                TargetKind::Operation,
                EffectKind::SmtpSubmit,
                OwnerKeyRole::Owner,
                McpMutationPolicy::ApplyOnly,
                ManifestSupport::Supported,
            ),
            Self::MailSeen => (
                TargetKind::Operation,
                EffectKind::ImapSeen,
                OwnerKeyRole::Owner,
                McpMutationPolicy::ApplyOnly,
                ManifestSupport::Supported,
            ),
            Self::MailStarred => (
                TargetKind::Operation,
                EffectKind::ImapStarred,
                OwnerKeyRole::Owner,
                McpMutationPolicy::ApplyOnly,
                ManifestSupport::Supported,
            ),
            Self::MailMove => (
                TargetKind::Operation,
                EffectKind::ImapMove,
                OwnerKeyRole::Owner,
                McpMutationPolicy::ApplyOnly,
                ManifestSupport::Supported,
            ),
            Self::MailArchive => (
                TargetKind::Operation,
                EffectKind::ImapArchive,
                OwnerKeyRole::Owner,
                McpMutationPolicy::ApplyOnly,
                ManifestSupport::Supported,
            ),
            Self::MailSafeDelete => (
                TargetKind::Operation,
                EffectKind::ImapSafeDelete,
                OwnerKeyRole::Owner,
                McpMutationPolicy::ApplyOnly,
                ManifestSupport::Supported,
            ),
            Self::StoreEnroll => control_policy(
                TargetKind::Store,
                OwnerKeyRole::Owner,
                ManifestSupport::Supported,
            ),
            Self::AccountCreate | Self::AccountUpdate | Self::AccountRemove => control_policy(
                TargetKind::Account,
                OwnerKeyRole::Owner,
                ManifestSupport::Supported,
            ),
            Self::CredentialSet | Self::CredentialDelete => control_policy(
                TargetKind::Credential,
                OwnerKeyRole::Owner,
                ManifestSupport::Supported,
            ),
            Self::CredentialCleanup => control_policy(
                TargetKind::Cleanup,
                OwnerKeyRole::Owner,
                ManifestSupport::Supported,
            ),
            Self::PolicyUpdate => control_policy(
                TargetKind::Policy,
                OwnerKeyRole::Owner,
                ManifestSupport::UnsupportedCapability,
            ),
            Self::AssuranceUpdate => control_policy(
                TargetKind::Assurance,
                OwnerKeyRole::Owner,
                ManifestSupport::UnsupportedCapability,
            ),
            Self::OwnerRotate | Self::RecoveryRotate => control_policy(
                TargetKind::TrustEpoch,
                OwnerKeyRole::Owner,
                ManifestSupport::Supported,
            ),
            Self::OwnerRecover => control_policy(
                TargetKind::TrustEpoch,
                OwnerKeyRole::Recovery,
                ManifestSupport::Supported,
            ),
            Self::AmbiguousClose => control_policy(
                TargetKind::RemoteEffect,
                OwnerKeyRole::Owner,
                ManifestSupport::Supported,
            ),
        };
        SensitiveActionPolicy {
            owner_receipt_required: true,
            target_kind,
            effect_kind,
            required_role,
            mcp_mutation,
            manifest_support,
        }
    }
}

const fn control_policy(
    target_kind: TargetKind,
    required_role: OwnerKeyRole,
    manifest_support: ManifestSupport,
) -> (
    TargetKind,
    EffectKind,
    OwnerKeyRole,
    McpMutationPolicy,
    ManifestSupport,
) {
    (
        target_kind,
        EffectKind::None,
        required_role,
        McpMutationPolicy::Prohibited,
        manifest_support,
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Operation,
    Store,
    Account,
    Credential,
    Cleanup,
    Policy,
    Assurance,
    TrustEpoch,
    RemoteEffect,
}

impl TargetKind {
    const fn code(self) -> u16 {
        match self {
            Self::Operation => 1,
            Self::Store => 2,
            Self::Account => 3,
            Self::Credential => 4,
            Self::Cleanup => 5,
            Self::Policy => 6,
            Self::Assurance => 7,
            Self::TrustEpoch => 8,
            Self::RemoteEffect => 9,
        }
    }

    fn from_code(code: u16) -> Result<Self, MailError> {
        match code {
            1 => Ok(Self::Operation),
            2 => Ok(Self::Store),
            3 => Ok(Self::Account),
            4 => Ok(Self::Credential),
            5 => Ok(Self::Cleanup),
            6 => Ok(Self::Policy),
            7 => Ok(Self::Assurance),
            8 => Ok(Self::TrustEpoch),
            9 => Ok(Self::RemoteEffect),
            _ => Err(malformed("unknown target kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    None,
    SmtpSubmit,
    ImapSeen,
    ImapStarred,
    ImapMove,
    ImapArchive,
    ImapSafeDelete,
}

impl EffectKind {
    const fn code(self) -> u16 {
        match self {
            Self::None => 0,
            Self::SmtpSubmit => 1,
            Self::ImapSeen => 2,
            Self::ImapStarred => 3,
            Self::ImapMove => 4,
            Self::ImapArchive => 5,
            Self::ImapSafeDelete => 6,
        }
    }

    fn from_code(code: u16) -> Result<Self, MailError> {
        match code {
            0 => Ok(Self::None),
            1 => Ok(Self::SmtpSubmit),
            2 => Ok(Self::ImapSeen),
            3 => Ok(Self::ImapStarred),
            4 => Ok(Self::ImapMove),
            5 => Ok(Self::ImapArchive),
            6 => Ok(Self::ImapSafeDelete),
            _ => Err(malformed("unknown effect kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerKeyRole {
    Owner,
    Recovery,
}

impl OwnerKeyRole {
    const fn code(self) -> u8 {
        match self {
            Self::Owner => 1,
            Self::Recovery => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpMutationPolicy {
    ApplyOnly,
    Prohibited,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestSupport {
    Supported,
    UnsupportedCapability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SensitiveActionPolicy {
    pub owner_receipt_required: bool,
    pub target_kind: TargetKind,
    pub effect_kind: EffectKind,
    pub required_role: OwnerKeyRole,
    pub mcp_mutation: McpMutationPolicy,
    pub manifest_support: ManifestSupport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestTarget {
    Operation(OperationId),
    Store(StoreId),
    Account(AccountId),
    Credential(crate::CredentialId),
    Cleanup(crate::CleanupId),
    Policy,
    Assurance,
    TrustEpoch(NonZeroU64),
    RemoteEffect(RemoteEffectId),
}

impl ManifestTarget {
    fn kind(&self) -> TargetKind {
        match self {
            Self::Operation(_) => TargetKind::Operation,
            Self::Store(_) => TargetKind::Store,
            Self::Account(_) => TargetKind::Account,
            Self::Credential(_) => TargetKind::Credential,
            Self::Cleanup(_) => TargetKind::Cleanup,
            Self::Policy => TargetKind::Policy,
            Self::Assurance => TargetKind::Assurance,
            Self::TrustEpoch(_) => TargetKind::TrustEpoch,
            Self::RemoteEffect(_) => TargetKind::RemoteEffect,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Operation(value) => value.as_bytes().to_vec(),
            Self::Store(value) => value.as_bytes().to_vec(),
            Self::Account(value) => value.as_bytes().to_vec(),
            Self::Credential(value) => value.as_bytes().to_vec(),
            Self::Cleanup(value) => value.as_bytes().to_vec(),
            Self::Policy | Self::Assurance => Vec::new(),
            Self::TrustEpoch(value) => value.get().to_be_bytes().to_vec(),
            Self::RemoteEffect(value) => value.as_bytes().to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestContext {
    pub target: ManifestTarget,
    pub store_id: Option<StoreId>,
    pub account_id: Option<AccountId>,
    pub account_binding_sha256: Option<Sha256Digest>,
    pub policy_sha256: Option<Sha256Digest>,
    pub effect_id: Option<RemoteEffectId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestAddress {
    display_name: Option<String>,
    email: String,
}

impl ManifestAddress {
    /// Construct one exact, validated address snapshot.
    ///
    /// # Errors
    ///
    /// Returns invalid-input when display or address bytes are malformed.
    pub fn new(display_name: Option<String>, email: String) -> Result<Self, MailError> {
        if display_name
            .as_ref()
            .is_some_and(|name| name.chars().count() > 256 || name.chars().any(char::is_control))
            || !valid_email(&email)
        {
            return Err(MailError::invalid_input("manifest address is malformed"));
        }
        Ok(Self {
            display_name,
            email,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, MailError> {
        encode_fields(
            ADDRESS_DOMAIN,
            &[
                (1, optional_text(self.display_name.as_deref())),
                (2, self.email.as_bytes().to_vec()),
            ],
        )
    }

    fn parse(bytes: &[u8]) -> Result<Self, MailError> {
        let fields = parse_fields(bytes, ADDRESS_DOMAIN, 2)?;
        expect_tags(&fields, &[1, 2])?;
        Self::new(parse_optional_text(fields[0].1)?, parse_text(fields[1].1)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MimeBuilderVersion {
    KirjeMimeV1,
}

impl MimeBuilderVersion {
    const fn code(self) -> u16 {
        match self {
            Self::KirjeMimeV1 => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentSummaryDisposition {
    Complete,
    Truncated,
    Omitted,
}

impl AttachmentSummaryDisposition {
    const fn code(self) -> u8 {
        match self {
            Self::Complete => 1,
            Self::Truncated => 2,
            Self::Omitted => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestAttachmentSummary {
    pub disposition: AttachmentSummaryDisposition,
    pub text: Option<String>,
    pub original_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestAttachment {
    pub filename: String,
    pub mime_type: String,
    pub decoded_size: u64,
    pub content_sha256: Sha256Digest,
    pub summary: Option<ManifestAttachmentSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendSubmitManifest {
    pub account_generation: NonZeroU64,
    pub from: ManifestAddress,
    pub to: Vec<ManifestAddress>,
    pub cc: Vec<ManifestAddress>,
    pub bcc: Vec<ManifestAddress>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachments: Vec<ManifestAttachment>,
    pub message_id: String,
    pub date_unix_ms: i64,
    pub mime_builder_version: MimeBuilderVersion,
    pub mime_boundary: String,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub canonical_rfc822_sha256: Option<Sha256Digest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxSpecialUseInput {
    None,
    Archive,
    Trash,
}

impl MailboxSpecialUseInput {
    const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Archive => 1,
            Self::Trash => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxStrategy {
    Store,
    UidMove,
    CopyThenMarkDeleted,
}

impl MailboxStrategy {
    const fn code(self) -> u8 {
        match self {
            Self::Store => 1,
            Self::UidMove => 2,
            Self::CopyThenMarkDeleted => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxManifest {
    pub account_generation: NonZeroU64,
    pub source_mailbox: String,
    pub uid_validity: NonZeroU32,
    pub uid: NonZeroU32,
    pub requested_value: Option<bool>,
    pub requested_destination: Option<String>,
    pub special_use: MailboxSpecialUseInput,
    pub resolved_destination: Option<String>,
    pub strategy: MailboxStrategy,
    pub capability_sha256: Sha256Digest,
    pub capability_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKind {
    Dns,
    Ipv4,
    Ipv6,
}

impl HostKind {
    const fn code(self) -> u8 {
        match self {
            Self::Dns => 1,
            Self::Ipv4 => 2,
            Self::Ipv6 => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointSnapshot {
    pub protocol: Protocol,
    pub exact_host: String,
    pub host_kind: HostKind,
    pub canonical_host: String,
    pub port: u16,
    pub security: TransportSecurity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupState {
    Provisional,
    Ready,
    Claimed,
    Deleted,
}

impl CleanupState {
    const fn code(self) -> u8 {
        match self {
            Self::Provisional => 1,
            Self::Ready => 2,
            Self::Claimed => 3,
            Self::Deleted => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocatorKind {
    ActiveV2,
    LegacyV1,
}

impl LocatorKind {
    const fn code(self) -> u8 {
        match self {
            Self::ActiveV2 => 1,
            Self::LegacyV1 => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigCas {
    pub store_id: StoreId,
    pub generation: NonZeroU64,
    pub exact_content_sha256: Sha256Digest,
    pub location_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupDescriptor {
    pub cleanup_id: CleanupId,
    pub locator_kind: LocatorKind,
    pub locator_sha256: Sha256Digest,
    pub expected_state: CleanupState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountSnapshot {
    pub display_id: String,
    pub account_id: AccountId,
    pub generation: NonZeroU64,
    pub email: String,
    pub username: String,
    pub credential_kind: CredentialKind,
    pub credential_id: CredentialId,
    pub binding_version: u16,
    pub binding_sha256: Sha256Digest,
    pub binding_state: BindingState,
    pub credential_state: StoredCredentialState,
    pub state_reason: Option<AccountStateReason>,
    pub incoming: EndpointSnapshot,
    pub outgoing: Option<EndpointSnapshot>,
    pub cleanup_ids: Vec<CleanupId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreEnrollmentState {
    Unregistered,
}

impl StoreEnrollmentState {
    const fn code(self) -> u8 {
        match self {
            Self::Unregistered => 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreEnrollManifest {
    pub transition_id: TransitionId,
    pub config_cas: ConfigCas,
    pub expected_store_state: StoreEnrollmentState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountMutationManifest {
    pub transition_id: TransitionId,
    pub config_cas: ConfigCas,
    pub before: Option<AccountSnapshot>,
    pub after: Option<AccountSnapshot>,
    pub next_config_generation: NonZeroU64,
    pub after_config_sha256: Sha256Digest,
    pub cleanup: Vec<CleanupDescriptor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialMutationManifest {
    pub account: AccountMutationManifest,
    pub active_locator_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialCleanupManifest {
    pub cleanup_id: CleanupId,
    pub locator_kind: LocatorKind,
    pub locator_sha256: Sha256Digest,
    pub tombstone_sha256: Sha256Digest,
    pub transition_id: Option<TransitionId>,
    pub expected_state: CleanupState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustPermissionMask {
    Owner,
    Recovery,
}

impl TrustPermissionMask {
    const fn code(self) -> u32 {
        match self {
            Self::Owner => 0x0000_0007,
            Self::Recovery => 0x0000_0008,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustRotationManifest {
    pub transition_id: TransitionId,
    pub role: OwnerKeyRole,
    pub old_key_id: Sha256Digest,
    pub old_public_key: [u8; 32],
    pub new_key_id: Sha256Digest,
    pub new_public_key: [u8; 32],
    pub old_epoch: NonZeroU64,
    pub new_epoch: NonZeroU64,
    pub old_bundle: Sha256Digest,
    pub new_bundle: Sha256Digest,
    pub permissions: TrustPermissionMask,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationScope {
    All,
}

impl InvalidationScope {
    const fn code(self) -> u8 {
        match self {
            Self::All => 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerRecoverManifest {
    pub transition_id: TransitionId,
    pub journal_id: JournalId,
    pub old_epoch: NonZeroU64,
    pub new_epoch: NonZeroU64,
    pub old_bundle: Sha256Digest,
    pub new_owner_id: Sha256Digest,
    pub new_owner_key: [u8; 32],
    pub new_recovery_id: Sha256Digest,
    pub new_recovery_key: [u8; 32],
    pub new_bundle: Sha256Digest,
    pub invalidation_scope: InvalidationScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmbiguousAssertion {
    Occurred,
    NoEffect,
    Unknown,
}

impl AmbiguousAssertion {
    const fn code(self) -> u8 {
        match self {
            Self::Occurred => 1,
            Self::NoEffect => 2,
            Self::Unknown => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmbiguousTerminal {
    Succeeded,
    FailedKnownNoEffect,
    AmbiguousClosed,
}

impl AmbiguousTerminal {
    const fn code(self) -> u8 {
        match self {
            Self::Succeeded => 1,
            Self::FailedKnownNoEffect => 2,
            Self::AmbiguousClosed => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmbiguousCloseManifest {
    pub operation_id: OperationId,
    pub invocation_id: InvocationId,
    pub original_manifest_sha256: Sha256Digest,
    pub claim_sha256: Sha256Digest,
    pub observation_sha256: Option<Sha256Digest>,
    pub assertion: AmbiguousAssertion,
    pub assertion_text: String,
    pub terminal: AmbiguousTerminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestPayload {
    SendSubmit(SendSubmitManifest),
    MailSeen(MailboxManifest),
    MailStarred(MailboxManifest),
    MailMove(MailboxManifest),
    MailArchive(MailboxManifest),
    MailSafeDelete(MailboxManifest),
    StoreEnroll(StoreEnrollManifest),
    AccountCreate(AccountMutationManifest),
    AccountUpdate(AccountMutationManifest),
    AccountRemove(AccountMutationManifest),
    CredentialSet(CredentialMutationManifest),
    CredentialDelete(CredentialMutationManifest),
    CredentialCleanup(CredentialCleanupManifest),
    OwnerRotate(TrustRotationManifest),
    RecoveryRotate(TrustRotationManifest),
    OwnerRecover(OwnerRecoverManifest),
    AmbiguousClose(AmbiguousCloseManifest),
}

impl ManifestPayload {
    fn action(&self) -> SensitiveAction {
        match self {
            Self::SendSubmit(_) => SensitiveAction::SendSubmit,
            Self::MailSeen(_) => SensitiveAction::MailSeen,
            Self::MailStarred(_) => SensitiveAction::MailStarred,
            Self::MailMove(_) => SensitiveAction::MailMove,
            Self::MailArchive(_) => SensitiveAction::MailArchive,
            Self::MailSafeDelete(_) => SensitiveAction::MailSafeDelete,
            Self::StoreEnroll(_) => SensitiveAction::StoreEnroll,
            Self::AccountCreate(_) => SensitiveAction::AccountCreate,
            Self::AccountUpdate(_) => SensitiveAction::AccountUpdate,
            Self::AccountRemove(_) => SensitiveAction::AccountRemove,
            Self::CredentialSet(_) => SensitiveAction::CredentialSet,
            Self::CredentialDelete(_) => SensitiveAction::CredentialDelete,
            Self::CredentialCleanup(_) => SensitiveAction::CredentialCleanup,
            Self::OwnerRotate(_) => SensitiveAction::OwnerRotate,
            Self::RecoveryRotate(_) => SensitiveAction::RecoveryRotate,
            Self::OwnerRecover(_) => SensitiveAction::OwnerRecover,
            Self::AmbiguousClose(_) => SensitiveAction::AmbiguousClose,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionManifest {
    context: ManifestContext,
    payload: ManifestPayload,
    canonical_bytes: Vec<u8>,
    sha256: Sha256Digest,
}

impl ActionManifest {
    /// Build an exact sealed action manifest.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error when the typed payload and common context disagree.
    pub fn new(context: ManifestContext, payload: ManifestPayload) -> Result<Self, MailError> {
        let action = payload.action();
        validate_manifest_context(&context, action)?;
        validate_payload_context(&context, &payload)?;
        let mut fields = common_manifest_fields(&context, action);
        fields.extend(encode_payload(&payload)?);
        let canonical_bytes = encode_fields(MANIFEST_DOMAIN, &fields)?;
        let sha256 = Sha256Digest::digest(&canonical_bytes);
        Ok(Self {
            context,
            payload,
            canonical_bytes,
            sha256,
        })
    }

    /// Parse and revalidate an exact V1 action manifest.
    ///
    /// # Errors
    ///
    /// Returns authorization-malformed for any unknown, missing, non-minimal, or trailing bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, MailError> {
        if bytes.len() > crate::MAX_AUTHORIZATION_MANIFEST_BYTES {
            return Err(MailError::stable(
                MailErrorCode::ResourceLimit,
                "authorization manifest is too large",
            ));
        }
        let fields = parse_fields_any(bytes, MANIFEST_DOMAIN)?;
        if fields.len() < 9 {
            return Err(malformed("manifest common fields are incomplete"));
        }
        expect_tags(&fields[..9], &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
        let action = SensitiveAction::from_code(parse_u16(fields[0].1)?)?;
        if action.policy().manifest_support == ManifestSupport::UnsupportedCapability {
            return Err(unsupported_action());
        }
        let target_kind = TargetKind::from_code(parse_u16(fields[1].1)?)?;
        let target = parse_target(target_kind, fields[2].1)?;
        let context = ManifestContext {
            target,
            store_id: parse_optional_uuid(fields[3].1)?,
            account_id: parse_optional_uuid(fields[4].1)?,
            account_binding_sha256: parse_optional_digest(fields[5].1)?,
            policy_sha256: parse_optional_digest(fields[6].1)?,
            effect_id: parse_optional_uuid(fields[8].1)?,
        };
        let encoded_effect = EffectKind::from_code(parse_u16(fields[7].1)?)?;
        if encoded_effect != action.policy().effect_kind {
            return Err(malformed("manifest effect does not match action"));
        }
        let payload = parse_payload(action, &fields[9..])?;
        let result = Self::new(context, payload)?;
        if result.canonical_bytes != bytes {
            return Err(malformed("manifest is not canonical"));
        }
        Ok(result)
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub const fn sha256(&self) -> Sha256Digest {
        self.sha256
    }

    #[must_use]
    pub fn action(&self) -> SensitiveAction {
        self.payload.action()
    }

    #[must_use]
    pub fn context(&self) -> &ManifestContext {
        &self.context
    }
}

fn validate_manifest_context(
    context: &ManifestContext,
    action: SensitiveAction,
) -> Result<(), MailError> {
    let policy = action.policy();
    if policy.manifest_support != ManifestSupport::Supported {
        return Err(unsupported_action());
    }
    if context.target.kind() != policy.target_kind {
        return Err(malformed("manifest target does not match action"));
    }
    let remote = policy.effect_kind != EffectKind::None;
    if remote {
        if context.store_id.is_none()
            || context.account_id.is_none()
            || context.account_binding_sha256.is_none()
            || context.policy_sha256.is_none()
            || context.effect_id.is_none()
        {
            return Err(malformed("remote manifest common context is incomplete"));
        }
    } else if context.effect_id.is_some() {
        return Err(malformed("control manifest cannot name a remote effect"));
    }
    Ok(())
}

fn validate_payload_context(
    context: &ManifestContext,
    payload: &ManifestPayload,
) -> Result<(), MailError> {
    match payload {
        ManifestPayload::SendSubmit(_)
        | ManifestPayload::MailSeen(_)
        | ManifestPayload::MailStarred(_)
        | ManifestPayload::MailMove(_)
        | ManifestPayload::MailArchive(_)
        | ManifestPayload::MailSafeDelete(_) => Ok(()),
        ManifestPayload::StoreEnroll(value) => {
            let ManifestTarget::Store(target_store) = context.target else {
                return Err(malformed("store enrollment target is malformed"));
            };
            if context.store_id != Some(target_store)
                || value.config_cas.store_id != target_store
                || context.account_id.is_some()
                || context.account_binding_sha256.is_some()
                || context.policy_sha256.is_some()
            {
                return Err(malformed("store enrollment context is inconsistent"));
            }
            Ok(())
        }
        ManifestPayload::AccountCreate(value)
        | ManifestPayload::AccountUpdate(value)
        | ManifestPayload::AccountRemove(value) => {
            validate_account_mutation_context(context, payload.action(), value)
        }
        ManifestPayload::CredentialSet(value) | ManifestPayload::CredentialDelete(value) => {
            validate_credential_mutation_context(context, payload.action(), value)
        }
        ManifestPayload::CredentialCleanup(value) => {
            let ManifestTarget::Cleanup(target_cleanup) = context.target else {
                return Err(malformed("credential cleanup target is malformed"));
            };
            if target_cleanup != value.cleanup_id
                || context.store_id.is_none()
                || context.account_id.is_none()
                || context.account_binding_sha256.is_none()
                || context.policy_sha256.is_some()
            {
                return Err(malformed("credential cleanup context is inconsistent"));
            }
            Ok(())
        }
        ManifestPayload::OwnerRotate(value) | ManifestPayload::RecoveryRotate(value) => {
            validate_trust_rotation_context(context, payload, value)
        }
        ManifestPayload::OwnerRecover(value) => validate_owner_recover_context(context, value),
        ManifestPayload::AmbiguousClose(value) => validate_ambiguous_context(context, value),
    }
}

fn validate_trust_rotation_context(
    context: &ManifestContext,
    payload: &ManifestPayload,
    value: &TrustRotationManifest,
) -> Result<(), MailError> {
    let ManifestTarget::TrustEpoch(target_epoch) = context.target else {
        return Err(malformed("trust rotation target is malformed"));
    };
    let expected_role = if matches!(payload, ManifestPayload::OwnerRotate(_)) {
        OwnerKeyRole::Owner
    } else {
        OwnerKeyRole::Recovery
    };
    let expected_permissions = if expected_role == OwnerKeyRole::Owner {
        TrustPermissionMask::Owner
    } else {
        TrustPermissionMask::Recovery
    };
    if target_epoch != value.old_epoch
        || value.role != expected_role
        || value.permissions != expected_permissions
        || value.old_key_id != owner_key_id(value.role, &value.old_public_key)
        || value.new_key_id != owner_key_id(value.role, &value.new_public_key)
        || value.old_key_id == value.new_key_id
        || !exact_increment(value.old_epoch, value.new_epoch)
        || context.store_id.is_some()
        || context.account_id.is_some()
        || context.account_binding_sha256.is_some()
        || context.policy_sha256.is_some()
    {
        return Err(malformed("trust rotation context is inconsistent"));
    }
    Ok(())
}

fn validate_owner_recover_context(
    context: &ManifestContext,
    value: &OwnerRecoverManifest,
) -> Result<(), MailError> {
    let ManifestTarget::TrustEpoch(target_epoch) = context.target else {
        return Err(malformed("owner recovery target is malformed"));
    };
    if target_epoch != value.old_epoch
        || value.new_owner_id != owner_key_id(OwnerKeyRole::Owner, &value.new_owner_key)
        || value.new_recovery_id != owner_key_id(OwnerKeyRole::Recovery, &value.new_recovery_key)
        || !exact_increment(value.old_epoch, value.new_epoch)
        || context.store_id.is_some()
        || context.account_id.is_some()
        || context.account_binding_sha256.is_some()
        || context.policy_sha256.is_some()
    {
        return Err(malformed("owner recovery context is inconsistent"));
    }
    Ok(())
}

fn exact_increment(previous: NonZeroU64, next: NonZeroU64) -> bool {
    previous.get().checked_add(1) == Some(next.get())
}

fn validate_ambiguous_context(
    context: &ManifestContext,
    value: &AmbiguousCloseManifest,
) -> Result<(), MailError> {
    if context.store_id.is_none()
        || context.account_id.is_none()
        || context.account_binding_sha256.is_none()
        || context.policy_sha256.is_none()
        || value.assertion_text.is_empty()
        || value.assertion_text.len() > MAX_ASSERTION_TEXT_BYTES
        || value.assertion_text.chars().count() > MAX_ASSERTION_TEXT_BYTES
        || value.assertion_text.chars().any(char::is_control)
    {
        return Err(malformed("ambiguous closure context is inconsistent"));
    }
    Ok(())
}

fn validate_account_mutation_context(
    context: &ManifestContext,
    action: SensitiveAction,
    value: &AccountMutationManifest,
) -> Result<(), MailError> {
    let ManifestTarget::Account(target_account) = context.target else {
        return Err(malformed("account mutation target is malformed"));
    };
    if context.store_id != Some(value.config_cas.store_id)
        || context.account_id != Some(target_account)
        || context.account_binding_sha256.is_none()
        || context.policy_sha256.is_some()
        || !exact_increment(value.config_cas.generation, value.next_config_generation)
        || value
            .before
            .as_ref()
            .is_some_and(|snapshot| snapshot.account_id != target_account)
        || value
            .after
            .as_ref()
            .is_some_and(|snapshot| snapshot.account_id != target_account)
    {
        return Err(malformed("account mutation context is inconsistent"));
    }
    for snapshot in value.before.iter().chain(value.after.iter()) {
        validate_account_snapshot(snapshot)?;
    }
    let shape_ok = match action {
        SensitiveAction::AccountCreate => {
            value.before.is_none()
                && value.after.as_ref().is_some_and(|after| {
                    after.generation.get() == 1
                        && after.binding_state == BindingState::Proposed
                        && after.credential_state == StoredCredentialState::ReentryRequired
                })
        }
        SensitiveAction::AccountUpdate => {
            let (Some(before), Some(after)) = (&value.before, &value.after) else {
                return Err(malformed("account update snapshots are incomplete"));
            };
            before.display_id == after.display_id
                && exact_increment(before.generation, after.generation)
                && before.credential_id != after.credential_id
                && account_binding_material_changed(before, after)
                && after.binding_state == BindingState::Authorized
                && after.credential_state == StoredCredentialState::ReentryRequired
        }
        SensitiveAction::AccountRemove => value.before.is_some() && value.after.is_none(),
        _ => false,
    };
    if !shape_ok {
        return Err(malformed("account mutation snapshot shape is invalid"));
    }
    let signed_binding = match action {
        SensitiveAction::AccountCreate | SensitiveAction::AccountUpdate => {
            value.after.as_ref().map(|snapshot| snapshot.binding_sha256)
        }
        SensitiveAction::AccountRemove => value
            .before
            .as_ref()
            .map(|snapshot| snapshot.binding_sha256),
        _ => None,
    };
    if context.account_binding_sha256 != signed_binding {
        return Err(malformed("account mutation binding digest is inconsistent"));
    }
    Ok(())
}

fn validate_credential_mutation_context(
    context: &ManifestContext,
    action: SensitiveAction,
    value: &CredentialMutationManifest,
) -> Result<(), MailError> {
    let ManifestTarget::Credential(target_credential) = context.target else {
        return Err(malformed("credential mutation target is malformed"));
    };
    let Some(account_id) = context.account_id else {
        return Err(malformed("credential mutation account is absent"));
    };
    let (Some(before), Some(after)) = (&value.account.before, &value.account.after) else {
        return Err(malformed(
            "credential mutation account snapshots are incomplete",
        ));
    };
    validate_account_snapshot(before)?;
    validate_account_snapshot(after)?;
    if context.store_id != Some(value.account.config_cas.store_id)
        || context.policy_sha256.is_some()
        || before.account_id != after.account_id
        || before.display_id != after.display_id
        || !exact_increment(before.generation, after.generation)
        || !same_account_binding_material(before, after)
        || value
            .account
            .before
            .as_ref()
            .is_some_and(|snapshot| snapshot.account_id != account_id)
        || value
            .account
            .after
            .as_ref()
            .is_some_and(|snapshot| snapshot.account_id != account_id)
        || !exact_increment(
            value.account.config_cas.generation,
            value.account.next_config_generation,
        )
    {
        return Err(malformed("credential mutation context is inconsistent"));
    }
    let lifecycle_ok = match action {
        SensitiveAction::CredentialSet => {
            matches!(
                before.credential_state,
                StoredCredentialState::ReentryRequired | StoredCredentialState::Missing
            ) && after.binding_state == BindingState::Authorized
                && after.credential_state == StoredCredentialState::Bound
        }
        SensitiveAction::CredentialDelete => {
            before.binding_state == BindingState::Authorized
                && before.credential_state == StoredCredentialState::Bound
                && after.binding_state == BindingState::Authorized
                && after.credential_state == StoredCredentialState::Missing
        }
        _ => false,
    };
    if !lifecycle_ok {
        return Err(malformed("credential mutation lifecycle is invalid"));
    }
    let expected = match action {
        SensitiveAction::CredentialSet => value
            .account
            .after
            .as_ref()
            .map(|snapshot| (snapshot.credential_id, snapshot.binding_sha256)),
        SensitiveAction::CredentialDelete => value
            .account
            .before
            .as_ref()
            .map(|snapshot| (snapshot.credential_id, snapshot.binding_sha256)),
        _ => None,
    };
    if expected
        != Some((
            target_credential,
            context
                .account_binding_sha256
                .ok_or_else(|| malformed("credential mutation binding digest is absent"))?,
        ))
    {
        return Err(malformed(
            "credential target or binding digest is inconsistent",
        ));
    }
    Ok(())
}

fn account_binding_material_changed(before: &AccountSnapshot, after: &AccountSnapshot) -> bool {
    before.email != after.email
        || before.username != after.username
        || before.credential_kind != after.credential_kind
        || before.incoming != after.incoming
        || before.outgoing != after.outgoing
}

fn same_account_binding_material(before: &AccountSnapshot, after: &AccountSnapshot) -> bool {
    before.email == after.email
        && before.username == after.username
        && before.credential_kind == after.credential_kind
        && before.credential_id == after.credential_id
        && before.binding_version == after.binding_version
        && before.binding_sha256 == after.binding_sha256
        && before.incoming == after.incoming
        && before.outgoing == after.outgoing
        && before.cleanup_ids == after.cleanup_ids
}

fn common_manifest_fields(
    context: &ManifestContext,
    action: SensitiveAction,
) -> Vec<(u16, Vec<u8>)> {
    vec![
        (0x0001, action.code().to_be_bytes().to_vec()),
        (0x0002, context.target.kind().code().to_be_bytes().to_vec()),
        (0x0003, context.target.bytes()),
        (
            0x0004,
            context
                .store_id
                .map(|value| value.as_bytes().to_vec())
                .unwrap_or_default(),
        ),
        (
            0x0005,
            context
                .account_id
                .map(|value| value.as_bytes().to_vec())
                .unwrap_or_default(),
        ),
        (
            0x0006,
            context
                .account_binding_sha256
                .map(|value| value.as_bytes().to_vec())
                .unwrap_or_default(),
        ),
        (
            0x0007,
            context
                .policy_sha256
                .map(|value| value.as_bytes().to_vec())
                .unwrap_or_default(),
        ),
        (
            0x0008,
            action.policy().effect_kind.code().to_be_bytes().to_vec(),
        ),
        (
            0x0009,
            context
                .effect_id
                .map(|value| value.as_bytes().to_vec())
                .unwrap_or_default(),
        ),
    ]
}

fn encode_payload(payload: &ManifestPayload) -> Result<Vec<(u16, Vec<u8>)>, MailError> {
    match payload {
        ManifestPayload::SendSubmit(send) => encode_send(send),
        ManifestPayload::MailSeen(mailbox) => encode_mailbox(SensitiveAction::MailSeen, mailbox),
        ManifestPayload::MailStarred(mailbox) => {
            encode_mailbox(SensitiveAction::MailStarred, mailbox)
        }
        ManifestPayload::MailMove(mailbox) => encode_mailbox(SensitiveAction::MailMove, mailbox),
        ManifestPayload::MailArchive(mailbox) => {
            encode_mailbox(SensitiveAction::MailArchive, mailbox)
        }
        ManifestPayload::MailSafeDelete(mailbox) => {
            encode_mailbox(SensitiveAction::MailSafeDelete, mailbox)
        }
        ManifestPayload::StoreEnroll(value) => encode_store_enroll(value),
        ManifestPayload::AccountCreate(value)
        | ManifestPayload::AccountUpdate(value)
        | ManifestPayload::AccountRemove(value) => encode_account_mutation(value),
        ManifestPayload::CredentialSet(value) | ManifestPayload::CredentialDelete(value) => {
            encode_credential_mutation(value)
        }
        ManifestPayload::CredentialCleanup(value) => Ok(encode_credential_cleanup(value)),
        ManifestPayload::OwnerRotate(value) | ManifestPayload::RecoveryRotate(value) => {
            Ok(encode_trust_rotation(value))
        }
        ManifestPayload::OwnerRecover(value) => Ok(encode_owner_recover(value)),
        ManifestPayload::AmbiguousClose(value) => Ok(encode_ambiguous_close(value)),
    }
}

fn encode_send(send: &SendSubmitManifest) -> Result<Vec<(u16, Vec<u8>)>, MailError> {
    let recipients = send.to.len() + send.cc.len() + send.bcc.len();
    if recipients == 0 || recipients > crate::MAX_SEND_RECIPIENTS {
        return Err(MailError::stable(
            MailErrorCode::ResourceLimit,
            "manifest recipient count is outside the contract",
        ));
    }
    if send.subject.chars().count() > crate::MAX_SEND_SUBJECT_CHARS
        || send.subject.chars().any(char::is_control)
        || (send.text.as_deref().is_none_or(str::is_empty)
            && send.html.as_deref().is_none_or(str::is_empty))
        || send
            .text
            .as_ref()
            .is_some_and(|value| value.chars().count() > crate::MAX_SEND_BODY_CHARS)
        || send
            .html
            .as_ref()
            .is_some_and(|value| value.chars().count() > crate::MAX_SEND_BODY_CHARS)
        || send.attachments.len() > crate::MAX_ATTACHMENTS
        || send.references.len() > 100
        || !valid_message_id(&send.message_id)
        || !valid_ascii_token(&send.mime_boundary)
        || send
            .in_reply_to
            .as_ref()
            .is_some_and(|value| !valid_message_id(value))
        || send.references.iter().any(|value| !valid_message_id(value))
    {
        return Err(MailError::invalid_input("send manifest is malformed"));
    }
    let mut attachment_total = 0_u64;
    for attachment in &send.attachments {
        validate_manifest_attachment(attachment)?;
        attachment_total = attachment_total
            .checked_add(attachment.decoded_size)
            .ok_or_else(|| limit("manifest attachment total is too large"))?;
        if attachment_total > crate::MAX_TOTAL_ATTACHMENT_BYTES as u64 {
            return Err(limit("manifest attachment total is too large"));
        }
    }

    Ok(vec![
        (0x0100, send.account_generation.get().to_be_bytes().to_vec()),
        (0x0101, send.from.encode()?),
        (0x0102, encode_list(&send.to, ManifestAddress::encode)?),
        (0x0103, encode_list(&send.cc, ManifestAddress::encode)?),
        (0x0104, encode_list(&send.bcc, ManifestAddress::encode)?),
        (0x0105, send.subject.as_bytes().to_vec()),
        (0x0106, optional_text(send.text.as_deref())),
        (0x0107, optional_text(send.html.as_deref())),
        (
            0x0108,
            encode_list(&send.attachments, encode_manifest_attachment)?,
        ),
        (0x0109, send.message_id.as_bytes().to_vec()),
        (0x010a, send.date_unix_ms.to_be_bytes().to_vec()),
        (
            0x010b,
            send.mime_builder_version.code().to_be_bytes().to_vec(),
        ),
        (0x010c, send.mime_boundary.as_bytes().to_vec()),
        (0x010d, optional_text(send.in_reply_to.as_deref())),
        (
            0x010e,
            encode_list(&send.references, |value| Ok(value.as_bytes().to_vec()))?,
        ),
        (
            0x010f,
            send.canonical_rfc822_sha256
                .map(|value| value.as_bytes().to_vec())
                .unwrap_or_default(),
        ),
    ])
}

fn validate_manifest_attachment(attachment: &ManifestAttachment) -> Result<(), MailError> {
    if attachment.filename.is_empty()
        || attachment.filename.chars().count() > crate::MAX_ATTACHMENT_FILENAME_CHARS
        || attachment.filename.chars().any(char::is_control)
        || attachment.filename.contains(['/', '\\'])
        || !valid_mime(&attachment.mime_type)
        || attachment.mime_type.len() > crate::MAX_ATTACHMENT_MIME_CHARS
        || attachment.decoded_size > crate::MAX_SEND_ATTACHMENT_BYTES as u64
    {
        return Err(MailError::invalid_input(
            "manifest attachment metadata is malformed",
        ));
    }
    if let Some(summary) = &attachment.summary {
        if summary
            .text
            .as_ref()
            .is_some_and(|value| value.chars().count() > crate::MAX_SUMMARY_CHARS)
        {
            return Err(limit("manifest attachment summary is too large"));
        }
        let correct_shape = match summary.disposition {
            AttachmentSummaryDisposition::Complete | AttachmentSummaryDisposition::Truncated => {
                summary.text.is_some()
            }
            AttachmentSummaryDisposition::Omitted => summary.text.is_none(),
        };
        if !correct_shape {
            return Err(MailError::invalid_input(
                "manifest attachment summary shape is malformed",
            ));
        }
    }
    Ok(())
}

fn encode_manifest_attachment(value: &ManifestAttachment) -> Result<Vec<u8>, MailError> {
    validate_manifest_attachment(value)?;
    encode_fields(
        ATTACHMENT_DOMAIN,
        &[
            (1, value.filename.as_bytes().to_vec()),
            (2, value.mime_type.as_bytes().to_vec()),
            (3, value.decoded_size.to_be_bytes().to_vec()),
            (4, value.content_sha256.as_bytes().to_vec()),
            (
                5,
                value
                    .summary
                    .as_ref()
                    .map(encode_manifest_attachment_summary)
                    .transpose()?
                    .unwrap_or_default(),
            ),
        ],
    )
}

fn encode_manifest_attachment_summary(
    value: &ManifestAttachmentSummary,
) -> Result<Vec<u8>, MailError> {
    encode_fields(
        ATTACHMENT_SUMMARY_DOMAIN,
        &[
            (1, vec![value.disposition.code()]),
            (2, optional_text(value.text.as_deref())),
            (
                3,
                value
                    .original_bytes
                    .map(|bytes| bytes.to_be_bytes().to_vec())
                    .unwrap_or_default(),
            ),
            (4, vec![1]),
        ],
    )
}

fn encode_mailbox(
    action: SensitiveAction,
    mailbox: &MailboxManifest,
) -> Result<Vec<(u16, Vec<u8>)>, MailError> {
    validate_mailbox(action, mailbox)?;
    Ok(vec![
        (
            0x0100,
            mailbox.account_generation.get().to_be_bytes().to_vec(),
        ),
        (0x0101, mailbox.source_mailbox.as_bytes().to_vec()),
        (0x0102, mailbox.uid_validity.get().to_be_bytes().to_vec()),
        (0x0103, mailbox.uid.get().to_be_bytes().to_vec()),
        (
            0x0104,
            mailbox
                .requested_value
                .map(|value| vec![u8::from(value)])
                .unwrap_or_default(),
        ),
        (
            0x0105,
            optional_text(mailbox.requested_destination.as_deref()),
        ),
        (0x0106, vec![mailbox.special_use.code()]),
        (
            0x0107,
            optional_text(mailbox.resolved_destination.as_deref()),
        ),
        (0x0108, vec![mailbox.strategy.code()]),
        (0x0109, mailbox.capability_sha256.as_bytes().to_vec()),
        (0x010a, vec![u8::from(mailbox.capability_complete)]),
    ])
}

fn validate_mailbox(action: SensitiveAction, mailbox: &MailboxManifest) -> Result<(), MailError> {
    if mailbox.source_mailbox.is_empty()
        || mailbox.source_mailbox.chars().count() > 4_096
        || mailbox.source_mailbox.chars().any(char::is_control)
        || !mailbox.capability_complete
        || mailbox
            .requested_destination
            .as_ref()
            .is_some_and(|value| invalid_mailbox(value))
        || mailbox
            .resolved_destination
            .as_ref()
            .is_some_and(|value| invalid_mailbox(value))
    {
        return Err(MailError::invalid_input("mailbox manifest is malformed"));
    }
    let shape_ok = match action {
        SensitiveAction::MailSeen | SensitiveAction::MailStarred => {
            mailbox.requested_value.is_some()
                && mailbox.requested_destination.is_none()
                && mailbox.special_use == MailboxSpecialUseInput::None
                && mailbox.resolved_destination.is_none()
                && mailbox.strategy == MailboxStrategy::Store
        }
        SensitiveAction::MailMove => {
            mailbox.requested_value.is_none()
                && mailbox.requested_destination.is_some()
                && mailbox.special_use == MailboxSpecialUseInput::None
                && mailbox.resolved_destination.is_some()
                && matches!(
                    mailbox.strategy,
                    MailboxStrategy::UidMove | MailboxStrategy::CopyThenMarkDeleted
                )
        }
        SensitiveAction::MailArchive => {
            mailbox.requested_value.is_none()
                && mailbox.requested_destination.is_none()
                && mailbox.special_use == MailboxSpecialUseInput::Archive
                && mailbox.resolved_destination.is_some()
                && matches!(
                    mailbox.strategy,
                    MailboxStrategy::UidMove | MailboxStrategy::CopyThenMarkDeleted
                )
        }
        SensitiveAction::MailSafeDelete => {
            mailbox.requested_value.is_none()
                && mailbox.requested_destination.is_none()
                && mailbox.special_use == MailboxSpecialUseInput::Trash
                && mailbox.resolved_destination.is_some()
                && matches!(
                    mailbox.strategy,
                    MailboxStrategy::UidMove | MailboxStrategy::CopyThenMarkDeleted
                )
        }
        _ => false,
    };
    if !shape_ok {
        return Err(MailError::invalid_input(
            "mailbox manifest action shape is invalid",
        ));
    }
    Ok(())
}

fn encode_store_enroll(value: &StoreEnrollManifest) -> Result<Vec<(u16, Vec<u8>)>, MailError> {
    Ok(vec![
        (0x0100, value.transition_id.as_bytes().to_vec()),
        (0x0101, encode_config_cas(&value.config_cas)?),
        (0x0102, vec![value.expected_store_state.code()]),
    ])
}

fn encode_account_mutation(
    value: &AccountMutationManifest,
) -> Result<Vec<(u16, Vec<u8>)>, MailError> {
    Ok(vec![
        (0x0100, value.transition_id.as_bytes().to_vec()),
        (0x0101, encode_config_cas(&value.config_cas)?),
        (
            0x0102,
            value
                .before
                .as_ref()
                .map(encode_account_snapshot)
                .transpose()?
                .unwrap_or_default(),
        ),
        (
            0x0103,
            value
                .after
                .as_ref()
                .map(encode_account_snapshot)
                .transpose()?
                .unwrap_or_default(),
        ),
        (
            0x0104,
            value.next_config_generation.get().to_be_bytes().to_vec(),
        ),
        (0x0105, value.after_config_sha256.as_bytes().to_vec()),
        (
            0x0106,
            encode_list(&value.cleanup, encode_cleanup_descriptor)?,
        ),
    ])
}

fn encode_credential_mutation(
    value: &CredentialMutationManifest,
) -> Result<Vec<(u16, Vec<u8>)>, MailError> {
    let mut fields = encode_account_mutation(&value.account)?;
    fields.push((0x0107, value.active_locator_sha256.as_bytes().to_vec()));
    Ok(fields)
}

fn encode_credential_cleanup(value: &CredentialCleanupManifest) -> Vec<(u16, Vec<u8>)> {
    vec![
        (0x0100, value.cleanup_id.as_bytes().to_vec()),
        (0x0101, vec![value.locator_kind.code()]),
        (0x0102, value.locator_sha256.as_bytes().to_vec()),
        (0x0103, value.tombstone_sha256.as_bytes().to_vec()),
        (
            0x0104,
            value
                .transition_id
                .map(|id| id.as_bytes().to_vec())
                .unwrap_or_default(),
        ),
        (0x0105, vec![value.expected_state.code()]),
    ]
}

fn encode_trust_rotation(value: &TrustRotationManifest) -> Vec<(u16, Vec<u8>)> {
    vec![
        (0x0100, value.transition_id.as_bytes().to_vec()),
        (0x0101, vec![value.role.code()]),
        (0x0102, value.old_key_id.as_bytes().to_vec()),
        (0x0103, value.old_public_key.to_vec()),
        (0x0104, value.new_key_id.as_bytes().to_vec()),
        (0x0105, value.new_public_key.to_vec()),
        (0x0106, value.old_epoch.get().to_be_bytes().to_vec()),
        (0x0107, value.new_epoch.get().to_be_bytes().to_vec()),
        (0x0108, value.old_bundle.as_bytes().to_vec()),
        (0x0109, value.new_bundle.as_bytes().to_vec()),
        (0x010a, value.permissions.code().to_be_bytes().to_vec()),
    ]
}

fn encode_owner_recover(value: &OwnerRecoverManifest) -> Vec<(u16, Vec<u8>)> {
    vec![
        (0x0100, value.transition_id.as_bytes().to_vec()),
        (0x0101, value.journal_id.as_bytes().to_vec()),
        (0x0102, value.old_epoch.get().to_be_bytes().to_vec()),
        (0x0103, value.new_epoch.get().to_be_bytes().to_vec()),
        (0x0104, value.old_bundle.as_bytes().to_vec()),
        (0x0105, value.new_owner_id.as_bytes().to_vec()),
        (0x0106, value.new_owner_key.to_vec()),
        (0x0107, value.new_recovery_id.as_bytes().to_vec()),
        (0x0108, value.new_recovery_key.to_vec()),
        (0x0109, value.new_bundle.as_bytes().to_vec()),
        (0x010a, vec![value.invalidation_scope.code()]),
    ]
}

fn encode_ambiguous_close(value: &AmbiguousCloseManifest) -> Vec<(u16, Vec<u8>)> {
    vec![
        (0x0100, value.operation_id.as_bytes().to_vec()),
        (0x0101, value.invocation_id.as_bytes().to_vec()),
        (0x0102, value.original_manifest_sha256.as_bytes().to_vec()),
        (0x0103, value.claim_sha256.as_bytes().to_vec()),
        (
            0x0104,
            value
                .observation_sha256
                .map(|digest| digest.as_bytes().to_vec())
                .unwrap_or_default(),
        ),
        (0x0105, vec![value.assertion.code()]),
        (0x0106, value.assertion_text.as_bytes().to_vec()),
        (0x0107, vec![value.terminal.code()]),
    ]
}

fn encode_config_cas(value: &ConfigCas) -> Result<Vec<u8>, MailError> {
    encode_fields(
        CONFIG_CAS_DOMAIN,
        &[
            (1, value.store_id.as_bytes().to_vec()),
            (2, value.generation.get().to_be_bytes().to_vec()),
            (3, value.exact_content_sha256.as_bytes().to_vec()),
            (4, value.location_sha256.as_bytes().to_vec()),
        ],
    )
}

fn encode_endpoint(value: &EndpointSnapshot) -> Result<Vec<u8>, MailError> {
    if value.exact_host.is_empty()
        || value.exact_host.len() > 4_096
        || value.exact_host.chars().any(char::is_control)
        || value.canonical_host.is_empty()
        || value.canonical_host.len() > 4_096
        || !value.canonical_host.is_ascii()
        || value.port == 0
        || match value.protocol {
            Protocol::Jmap => value.security != TransportSecurity::Https,
            Protocol::Imap | Protocol::Smtp => value.security == TransportSecurity::Https,
        }
    {
        return Err(MailError::invalid_input("endpoint snapshot is malformed"));
    }
    let canonical_matches = match value.host_kind {
        HostKind::Dns => {
            value.exact_host.parse::<std::net::IpAddr>().is_err()
                && value.canonical_host.parse::<std::net::IpAddr>().is_err()
                && value.canonical_host == value.canonical_host.to_ascii_lowercase()
                && value.exact_host.eq_ignore_ascii_case(&value.canonical_host)
        }
        HostKind::Ipv4 => value
            .exact_host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|host| host.to_string() == value.canonical_host),
        HostKind::Ipv6 => value
            .exact_host
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|host| host.to_string() == value.canonical_host),
    };
    if !canonical_matches {
        return Err(MailError::invalid_input(
            "endpoint host identity is inconsistent",
        ));
    }
    encode_fields(
        ENDPOINT_DOMAIN,
        &[
            (1, vec![protocol_code(value.protocol)]),
            (2, value.exact_host.as_bytes().to_vec()),
            (3, vec![value.host_kind.code()]),
            (4, value.canonical_host.as_bytes().to_vec()),
            (5, value.port.to_be_bytes().to_vec()),
            (6, vec![security_code(value.security)]),
        ],
    )
}

fn validate_account_snapshot(value: &AccountSnapshot) -> Result<(), MailError> {
    if value.display_id.is_empty()
        || value.display_id.len() > 64
        || !value
            .display_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !valid_email(&value.email)
        || value.username.trim().is_empty()
        || value.username.len() > 1_024
        || value.username.chars().any(char::is_control)
        || value.binding_version != 1
        || value.cleanup_ids.len() > 100
        || value
            .cleanup_ids
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len()
            != value.cleanup_ids.len()
    {
        return Err(MailError::invalid_input("account snapshot is malformed"));
    }

    encode_endpoint(&value.incoming)?;
    if value.incoming.protocol != Protocol::Imap
        || !matches!(
            value.incoming.security,
            TransportSecurity::ImplicitTls | TransportSecurity::StartTls
        )
    {
        return Err(MailError::invalid_input(
            "account snapshot incoming endpoint must use verified-TLS IMAP",
        ));
    }
    if let Some(outgoing) = &value.outgoing {
        encode_endpoint(outgoing)?;
        if outgoing.protocol != Protocol::Smtp
            || !matches!(
                outgoing.security,
                TransportSecurity::ImplicitTls | TransportSecurity::StartTls
            )
        {
            return Err(MailError::invalid_input(
                "account snapshot outgoing endpoint must use verified-TLS SMTP",
            ));
        }
    }

    let state_is_valid = match value.binding_state {
        BindingState::Quarantined => {
            value.credential_state == StoredCredentialState::LegacyQuarantined
        }
        BindingState::Proposed => matches!(
            value.credential_state,
            StoredCredentialState::ReentryRequired | StoredCredentialState::Missing
        ),
        BindingState::Authorized => matches!(
            value.credential_state,
            StoredCredentialState::ReentryRequired
                | StoredCredentialState::Missing
                | StoredCredentialState::Bound
        ),
        BindingState::Invalidated => value.credential_state != StoredCredentialState::Bound,
        BindingState::Mismatch => true,
    };
    if !state_is_valid
        || (value.credential_kind == CredentialKind::OAuth2
            && (value.binding_state == BindingState::Authorized
                || value.credential_state == StoredCredentialState::Bound))
    {
        return Err(MailError::invalid_input(
            "account snapshot state combination is invalid",
        ));
    }

    let binding_config = MailAccountConfig {
        id: value.display_id.clone(),
        email: value.email.clone(),
        username: value.username.clone(),
        incoming: endpoint_from_snapshot(&value.incoming),
        outgoing: value.outgoing.as_ref().map(endpoint_from_snapshot),
        credential_kind: value.credential_kind,
    };
    let mut validation_config = binding_config.clone();
    if validation_config.credential_kind == CredentialKind::OAuth2 {
        validation_config.credential_kind = CredentialKind::Password;
    }
    validation_config.validate()?;
    if AccountBinding::from_validated_config(&binding_config)?.sha256() != value.binding_sha256 {
        return Err(MailError::invalid_input(
            "account snapshot binding digest is inconsistent",
        ));
    }
    Ok(())
}

fn endpoint_from_snapshot(value: &EndpointSnapshot) -> Endpoint {
    Endpoint {
        protocol: value.protocol,
        host: value.exact_host.clone(),
        port: value.port,
        security: value.security,
    }
}

fn encode_account_snapshot(value: &AccountSnapshot) -> Result<Vec<u8>, MailError> {
    validate_account_snapshot(value)?;
    encode_fields(
        ACCOUNT_SNAPSHOT_DOMAIN,
        &[
            (1, value.display_id.as_bytes().to_vec()),
            (2, value.account_id.as_bytes().to_vec()),
            (3, value.generation.get().to_be_bytes().to_vec()),
            (4, value.email.as_bytes().to_vec()),
            (5, value.username.as_bytes().to_vec()),
            (6, vec![credential_kind_code(value.credential_kind)]),
            (7, value.credential_id.as_bytes().to_vec()),
            (8, value.binding_version.to_be_bytes().to_vec()),
            (9, value.binding_sha256.as_bytes().to_vec()),
            (10, vec![value.binding_state.code()]),
            (11, vec![value.credential_state.code()]),
            (
                12,
                value
                    .state_reason
                    .map(|reason| vec![reason.code()])
                    .unwrap_or_default(),
            ),
            (13, encode_endpoint(&value.incoming)?),
            (
                14,
                value
                    .outgoing
                    .as_ref()
                    .map(encode_endpoint)
                    .transpose()?
                    .unwrap_or_default(),
            ),
            (
                15,
                encode_list(&value.cleanup_ids, |id| Ok(id.as_bytes().to_vec()))?,
            ),
        ],
    )
}

fn encode_cleanup_descriptor(value: &CleanupDescriptor) -> Result<Vec<u8>, MailError> {
    encode_fields(
        CLEANUP_DESCRIPTOR_DOMAIN,
        &[
            (1, value.cleanup_id.as_bytes().to_vec()),
            (2, vec![value.locator_kind.code()]),
            (3, value.locator_sha256.as_bytes().to_vec()),
            (4, vec![value.expected_state.code()]),
        ],
    )
}

const fn credential_kind_code(value: CredentialKind) -> u8 {
    match value {
        CredentialKind::Password => 1,
        CredentialKind::AppPassword => 2,
        CredentialKind::OAuth2 => 3,
    }
}

fn parse_payload(
    action: SensitiveAction,
    fields: &[(u16, &[u8])],
) -> Result<ManifestPayload, MailError> {
    match action {
        SensitiveAction::SendSubmit => Ok(ManifestPayload::SendSubmit(parse_send(fields)?)),
        SensitiveAction::MailSeen => Ok(ManifestPayload::MailSeen(parse_mailbox(fields)?)),
        SensitiveAction::MailStarred => Ok(ManifestPayload::MailStarred(parse_mailbox(fields)?)),
        SensitiveAction::MailMove => Ok(ManifestPayload::MailMove(parse_mailbox(fields)?)),
        SensitiveAction::MailArchive => Ok(ManifestPayload::MailArchive(parse_mailbox(fields)?)),
        SensitiveAction::MailSafeDelete => {
            Ok(ManifestPayload::MailSafeDelete(parse_mailbox(fields)?))
        }
        SensitiveAction::StoreEnroll => {
            Ok(ManifestPayload::StoreEnroll(parse_store_enroll(fields)?))
        }
        SensitiveAction::AccountCreate => Ok(ManifestPayload::AccountCreate(
            parse_account_mutation(fields)?,
        )),
        SensitiveAction::AccountUpdate => Ok(ManifestPayload::AccountUpdate(
            parse_account_mutation(fields)?,
        )),
        SensitiveAction::AccountRemove => Ok(ManifestPayload::AccountRemove(
            parse_account_mutation(fields)?,
        )),
        SensitiveAction::CredentialSet => Ok(ManifestPayload::CredentialSet(
            parse_credential_mutation(fields)?,
        )),
        SensitiveAction::CredentialDelete => Ok(ManifestPayload::CredentialDelete(
            parse_credential_mutation(fields)?,
        )),
        SensitiveAction::CredentialCleanup => Ok(ManifestPayload::CredentialCleanup(
            parse_credential_cleanup(fields)?,
        )),
        SensitiveAction::OwnerRotate => {
            Ok(ManifestPayload::OwnerRotate(parse_trust_rotation(fields)?))
        }
        SensitiveAction::RecoveryRotate => Ok(ManifestPayload::RecoveryRotate(
            parse_trust_rotation(fields)?,
        )),
        SensitiveAction::OwnerRecover => {
            Ok(ManifestPayload::OwnerRecover(parse_owner_recover(fields)?))
        }
        SensitiveAction::AmbiguousClose => Ok(ManifestPayload::AmbiguousClose(
            parse_ambiguous_close(fields)?,
        )),
        SensitiveAction::PolicyUpdate | SensitiveAction::AssuranceUpdate => {
            Err(unsupported_action())
        }
    }
}

fn parse_send(fields: &[(u16, &[u8])]) -> Result<SendSubmitManifest, MailError> {
    expect_tags(
        fields,
        &[
            0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0109, 0x010a,
            0x010b, 0x010c, 0x010d, 0x010e, 0x010f,
        ],
    )?;
    let builder = match parse_u16(fields[11].1)? {
        1 => MimeBuilderVersion::KirjeMimeV1,
        _ => return Err(malformed("unknown MIME builder version")),
    };
    Ok(SendSubmitManifest {
        account_generation: parse_nonzero_u64(fields[0].1)?,
        from: ManifestAddress::parse(fields[1].1)?,
        to: parse_list(
            fields[2].1,
            ManifestAddress::parse,
            crate::MAX_SEND_RECIPIENTS,
        )?,
        cc: parse_list(
            fields[3].1,
            ManifestAddress::parse,
            crate::MAX_SEND_RECIPIENTS,
        )?,
        bcc: parse_list(
            fields[4].1,
            ManifestAddress::parse,
            crate::MAX_SEND_RECIPIENTS,
        )?,
        subject: parse_text(fields[5].1)?,
        text: parse_optional_text(fields[6].1)?,
        html: parse_optional_text(fields[7].1)?,
        attachments: parse_list(
            fields[8].1,
            parse_manifest_attachment,
            crate::MAX_ATTACHMENTS,
        )?,
        message_id: parse_text(fields[9].1)?,
        date_unix_ms: parse_i64(fields[10].1)?,
        mime_builder_version: builder,
        mime_boundary: parse_text(fields[12].1)?,
        in_reply_to: parse_optional_text(fields[13].1)?,
        references: parse_list(fields[14].1, parse_text, 100)?,
        canonical_rfc822_sha256: parse_optional_digest(fields[15].1)?,
    })
}

fn parse_manifest_attachment(bytes: &[u8]) -> Result<ManifestAttachment, MailError> {
    let fields = parse_fields(bytes, ATTACHMENT_DOMAIN, 5)?;
    expect_tags(&fields, &[1, 2, 3, 4, 5])?;
    let value = ManifestAttachment {
        filename: parse_text(fields[0].1)?,
        mime_type: parse_text(fields[1].1)?,
        decoded_size: parse_u64(fields[2].1)?,
        content_sha256: parse_digest(fields[3].1)?,
        summary: if fields[4].1.is_empty() {
            None
        } else {
            Some(parse_manifest_attachment_summary(fields[4].1)?)
        },
    };
    validate_manifest_attachment(&value)?;
    Ok(value)
}

fn parse_manifest_attachment_summary(bytes: &[u8]) -> Result<ManifestAttachmentSummary, MailError> {
    let fields = parse_fields(bytes, ATTACHMENT_SUMMARY_DOMAIN, 4)?;
    expect_tags(&fields, &[1, 2, 3, 4])?;
    let disposition = match parse_u8(fields[0].1)? {
        1 => AttachmentSummaryDisposition::Complete,
        2 => AttachmentSummaryDisposition::Truncated,
        3 => AttachmentSummaryDisposition::Omitted,
        _ => return Err(malformed("unknown attachment summary disposition")),
    };
    if !parse_bool(fields[3].1)? {
        return Err(malformed("attachment summaries must be untrusted"));
    }
    Ok(ManifestAttachmentSummary {
        disposition,
        text: parse_optional_text(fields[1].1)?,
        original_bytes: parse_optional_u64(fields[2].1)?,
    })
}

fn parse_mailbox(fields: &[(u16, &[u8])]) -> Result<MailboxManifest, MailError> {
    expect_tags(
        fields,
        &[
            0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0109, 0x010a,
        ],
    )?;
    let special_use = match parse_u8(fields[6].1)? {
        0 => MailboxSpecialUseInput::None,
        1 => MailboxSpecialUseInput::Archive,
        2 => MailboxSpecialUseInput::Trash,
        _ => return Err(malformed("unknown mailbox special-use code")),
    };
    let strategy = match parse_u8(fields[8].1)? {
        1 => MailboxStrategy::Store,
        2 => MailboxStrategy::UidMove,
        3 => MailboxStrategy::CopyThenMarkDeleted,
        _ => return Err(malformed("unknown mailbox strategy code")),
    };
    Ok(MailboxManifest {
        account_generation: parse_nonzero_u64(fields[0].1)?,
        source_mailbox: parse_text(fields[1].1)?,
        uid_validity: parse_nonzero_u32(fields[2].1)?,
        uid: parse_nonzero_u32(fields[3].1)?,
        requested_value: parse_optional_bool(fields[4].1)?,
        requested_destination: parse_optional_text(fields[5].1)?,
        special_use,
        resolved_destination: parse_optional_text(fields[7].1)?,
        strategy,
        capability_sha256: parse_digest(fields[9].1)?,
        capability_complete: parse_bool(fields[10].1)?,
    })
}

fn parse_store_enroll(fields: &[(u16, &[u8])]) -> Result<StoreEnrollManifest, MailError> {
    expect_tags(fields, &[0x0100, 0x0101, 0x0102])?;
    let expected_store_state = match parse_u8(fields[2].1)? {
        0 => StoreEnrollmentState::Unregistered,
        _ => return Err(malformed("unknown store enrollment state")),
    };
    Ok(StoreEnrollManifest {
        transition_id: parse_uuid(fields[0].1)?,
        config_cas: parse_config_cas(fields[1].1)?,
        expected_store_state,
    })
}

fn parse_account_mutation(fields: &[(u16, &[u8])]) -> Result<AccountMutationManifest, MailError> {
    expect_tags(
        fields,
        &[0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106],
    )?;
    Ok(AccountMutationManifest {
        transition_id: parse_uuid(fields[0].1)?,
        config_cas: parse_config_cas(fields[1].1)?,
        before: parse_optional_account_snapshot(fields[2].1)?,
        after: parse_optional_account_snapshot(fields[3].1)?,
        next_config_generation: parse_nonzero_u64(fields[4].1)?,
        after_config_sha256: parse_digest(fields[5].1)?,
        cleanup: parse_list(fields[6].1, parse_cleanup_descriptor, 100)?,
    })
}

fn parse_credential_mutation(
    fields: &[(u16, &[u8])],
) -> Result<CredentialMutationManifest, MailError> {
    expect_tags(
        fields,
        &[
            0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107,
        ],
    )?;
    Ok(CredentialMutationManifest {
        account: parse_account_mutation(&fields[..7])?,
        active_locator_sha256: parse_digest(fields[7].1)?,
    })
}

fn parse_credential_cleanup(
    fields: &[(u16, &[u8])],
) -> Result<CredentialCleanupManifest, MailError> {
    expect_tags(fields, &[0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105])?;
    Ok(CredentialCleanupManifest {
        cleanup_id: parse_uuid(fields[0].1)?,
        locator_kind: parse_locator_kind(fields[1].1)?,
        locator_sha256: parse_digest(fields[2].1)?,
        tombstone_sha256: parse_digest(fields[3].1)?,
        transition_id: parse_optional_uuid(fields[4].1)?,
        expected_state: parse_cleanup_state(fields[5].1)?,
    })
}

fn parse_trust_rotation(fields: &[(u16, &[u8])]) -> Result<TrustRotationManifest, MailError> {
    expect_tags(
        fields,
        &[
            0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0109, 0x010a,
        ],
    )?;
    let role = parse_owner_role(fields[1].1)?;
    let permissions = match parse_u32(fields[10].1)? {
        0x0000_0007 => TrustPermissionMask::Owner,
        0x0000_0008 => TrustPermissionMask::Recovery,
        _ => return Err(malformed("unknown trust permission mask")),
    };
    Ok(TrustRotationManifest {
        transition_id: parse_uuid(fields[0].1)?,
        role,
        old_key_id: parse_digest(fields[2].1)?,
        old_public_key: parse_array(fields[3].1)?,
        new_key_id: parse_digest(fields[4].1)?,
        new_public_key: parse_array(fields[5].1)?,
        old_epoch: parse_nonzero_u64(fields[6].1)?,
        new_epoch: parse_nonzero_u64(fields[7].1)?,
        old_bundle: parse_digest(fields[8].1)?,
        new_bundle: parse_digest(fields[9].1)?,
        permissions,
    })
}

fn parse_owner_recover(fields: &[(u16, &[u8])]) -> Result<OwnerRecoverManifest, MailError> {
    expect_tags(
        fields,
        &[
            0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0109, 0x010a,
        ],
    )?;
    let invalidation_scope = match parse_u8(fields[10].1)? {
        1 => InvalidationScope::All,
        _ => return Err(malformed("unknown invalidation scope")),
    };
    Ok(OwnerRecoverManifest {
        transition_id: parse_uuid(fields[0].1)?,
        journal_id: parse_uuid(fields[1].1)?,
        old_epoch: parse_nonzero_u64(fields[2].1)?,
        new_epoch: parse_nonzero_u64(fields[3].1)?,
        old_bundle: parse_digest(fields[4].1)?,
        new_owner_id: parse_digest(fields[5].1)?,
        new_owner_key: parse_array(fields[6].1)?,
        new_recovery_id: parse_digest(fields[7].1)?,
        new_recovery_key: parse_array(fields[8].1)?,
        new_bundle: parse_digest(fields[9].1)?,
        invalidation_scope,
    })
}

fn parse_ambiguous_close(fields: &[(u16, &[u8])]) -> Result<AmbiguousCloseManifest, MailError> {
    expect_tags(
        fields,
        &[
            0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107,
        ],
    )?;
    let assertion = match parse_u8(fields[5].1)? {
        1 => AmbiguousAssertion::Occurred,
        2 => AmbiguousAssertion::NoEffect,
        3 => AmbiguousAssertion::Unknown,
        _ => return Err(malformed("unknown ambiguous assertion")),
    };
    let terminal = match parse_u8(fields[7].1)? {
        1 => AmbiguousTerminal::Succeeded,
        2 => AmbiguousTerminal::FailedKnownNoEffect,
        3 => AmbiguousTerminal::AmbiguousClosed,
        _ => return Err(malformed("unknown ambiguous terminal")),
    };
    Ok(AmbiguousCloseManifest {
        operation_id: parse_uuid(fields[0].1)?,
        invocation_id: parse_uuid(fields[1].1)?,
        original_manifest_sha256: parse_digest(fields[2].1)?,
        claim_sha256: parse_digest(fields[3].1)?,
        observation_sha256: parse_optional_digest(fields[4].1)?,
        assertion,
        assertion_text: parse_text(fields[6].1)?,
        terminal,
    })
}

fn parse_config_cas(bytes: &[u8]) -> Result<ConfigCas, MailError> {
    let fields = parse_fields(bytes, CONFIG_CAS_DOMAIN, 4)?;
    expect_tags(&fields, &[1, 2, 3, 4])?;
    Ok(ConfigCas {
        store_id: parse_uuid(fields[0].1)?,
        generation: parse_nonzero_u64(fields[1].1)?,
        exact_content_sha256: parse_digest(fields[2].1)?,
        location_sha256: parse_digest(fields[3].1)?,
    })
}

fn parse_optional_account_snapshot(bytes: &[u8]) -> Result<Option<AccountSnapshot>, MailError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        parse_account_snapshot(bytes).map(Some)
    }
}

fn parse_account_snapshot(bytes: &[u8]) -> Result<AccountSnapshot, MailError> {
    let fields = parse_fields(bytes, ACCOUNT_SNAPSHOT_DOMAIN, 15)?;
    expect_tags(
        &fields,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    )?;
    Ok(AccountSnapshot {
        display_id: parse_text(fields[0].1)?,
        account_id: parse_uuid(fields[1].1)?,
        generation: parse_nonzero_u64(fields[2].1)?,
        email: parse_text(fields[3].1)?,
        username: parse_text(fields[4].1)?,
        credential_kind: parse_credential_kind(fields[5].1)?,
        credential_id: parse_uuid(fields[6].1)?,
        binding_version: parse_u16(fields[7].1)?,
        binding_sha256: parse_digest(fields[8].1)?,
        binding_state: parse_binding_state(fields[9].1)?,
        credential_state: parse_stored_credential_state(fields[10].1)?,
        state_reason: parse_account_state_reason(fields[11].1)?,
        incoming: parse_endpoint(fields[12].1)?,
        outgoing: if fields[13].1.is_empty() {
            None
        } else {
            Some(parse_endpoint(fields[13].1)?)
        },
        cleanup_ids: parse_list(fields[14].1, parse_uuid, 100)?,
    })
}

fn parse_endpoint(bytes: &[u8]) -> Result<EndpointSnapshot, MailError> {
    let fields = parse_fields(bytes, ENDPOINT_DOMAIN, 6)?;
    expect_tags(&fields, &[1, 2, 3, 4, 5, 6])?;
    let protocol = match parse_u8(fields[0].1)? {
        1 => Protocol::Imap,
        2 => Protocol::Smtp,
        3 => Protocol::Jmap,
        _ => return Err(malformed("unknown endpoint protocol")),
    };
    let host_kind = match parse_u8(fields[2].1)? {
        1 => HostKind::Dns,
        2 => HostKind::Ipv4,
        3 => HostKind::Ipv6,
        _ => return Err(malformed("unknown endpoint host kind")),
    };
    let security = match parse_u8(fields[5].1)? {
        1 => TransportSecurity::ImplicitTls,
        2 => TransportSecurity::StartTls,
        3 => TransportSecurity::Https,
        _ => return Err(malformed("unknown endpoint security code")),
    };
    let value = EndpointSnapshot {
        protocol,
        exact_host: parse_text(fields[1].1)?,
        host_kind,
        canonical_host: parse_text(fields[3].1)?,
        port: parse_u16(fields[4].1)?,
        security,
    };
    encode_endpoint(&value)?;
    Ok(value)
}

fn parse_cleanup_descriptor(bytes: &[u8]) -> Result<CleanupDescriptor, MailError> {
    let fields = parse_fields(bytes, CLEANUP_DESCRIPTOR_DOMAIN, 4)?;
    expect_tags(&fields, &[1, 2, 3, 4])?;
    Ok(CleanupDescriptor {
        cleanup_id: parse_uuid(fields[0].1)?,
        locator_kind: parse_locator_kind(fields[1].1)?,
        locator_sha256: parse_digest(fields[2].1)?,
        expected_state: parse_cleanup_state(fields[3].1)?,
    })
}

fn parse_locator_kind(bytes: &[u8]) -> Result<LocatorKind, MailError> {
    match parse_u8(bytes)? {
        1 => Ok(LocatorKind::ActiveV2),
        2 => Ok(LocatorKind::LegacyV1),
        _ => Err(malformed("unknown locator kind")),
    }
}

fn parse_cleanup_state(bytes: &[u8]) -> Result<CleanupState, MailError> {
    match parse_u8(bytes)? {
        1 => Ok(CleanupState::Provisional),
        2 => Ok(CleanupState::Ready),
        3 => Ok(CleanupState::Claimed),
        4 => Ok(CleanupState::Deleted),
        _ => Err(malformed("unknown cleanup state")),
    }
}

fn parse_owner_role(bytes: &[u8]) -> Result<OwnerKeyRole, MailError> {
    match parse_u8(bytes)? {
        1 => Ok(OwnerKeyRole::Owner),
        2 => Ok(OwnerKeyRole::Recovery),
        _ => Err(malformed("unknown owner key role")),
    }
}

fn parse_credential_kind(bytes: &[u8]) -> Result<CredentialKind, MailError> {
    match parse_u8(bytes)? {
        1 => Ok(CredentialKind::Password),
        2 => Ok(CredentialKind::AppPassword),
        3 => Ok(CredentialKind::OAuth2),
        _ => Err(malformed("unknown credential kind")),
    }
}

fn parse_binding_state(bytes: &[u8]) -> Result<BindingState, MailError> {
    match parse_u8(bytes)? {
        1 => Ok(BindingState::Quarantined),
        2 => Ok(BindingState::Proposed),
        3 => Ok(BindingState::Authorized),
        4 => Ok(BindingState::Invalidated),
        5 => Ok(BindingState::Mismatch),
        _ => Err(malformed("unknown binding state")),
    }
}

fn parse_stored_credential_state(bytes: &[u8]) -> Result<StoredCredentialState, MailError> {
    match parse_u8(bytes)? {
        1 => Ok(StoredCredentialState::LegacyQuarantined),
        2 => Ok(StoredCredentialState::ReentryRequired),
        3 => Ok(StoredCredentialState::Missing),
        4 => Ok(StoredCredentialState::Bound),
        5 => Ok(StoredCredentialState::Invalidated),
        _ => Err(malformed("unknown stored credential state")),
    }
}

fn parse_account_state_reason(bytes: &[u8]) -> Result<Option<AccountStateReason>, MailError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    match parse_u8(bytes)? {
        1 => Ok(Some(AccountStateReason::LegacyUnbound)),
        2 => Ok(Some(AccountStateReason::CredentialReentryRequired)),
        3 => Ok(Some(AccountStateReason::BindingChanged)),
        4 => Ok(Some(AccountStateReason::OwnerRecovery)),
        5 => Ok(Some(AccountStateReason::AuthorityMismatch)),
        6 => Ok(Some(AccountStateReason::ConfigMigration)),
        _ => Err(malformed("unknown account state reason")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    pub owner_realm: OwnerRealmId,
    pub trust_bundle_sha256: Sha256Digest,
    pub owner_key_id: Sha256Digest,
    pub trust_epoch: NonZeroU64,
    pub grant_id: AuthorizationGrantId,
    pub nonce: [u8; 32],
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizationEffect {
    effect_id: RemoteEffectId,
    kind: EffectKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationPayload {
    owner_realm: OwnerRealmId,
    action: SensitiveAction,
    target: ManifestTarget,
    store_id: Option<StoreId>,
    account_id: Option<AccountId>,
    manifest_sha256: Sha256Digest,
    account_binding_sha256: Option<Sha256Digest>,
    policy_sha256: Option<Sha256Digest>,
    trust_bundle_sha256: Sha256Digest,
    owner_key_id: Sha256Digest,
    trust_epoch: NonZeroU64,
    grant_id: AuthorizationGrantId,
    nonce: [u8; 32],
    issued_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    effects: Vec<AuthorizationEffect>,
    canonical_bytes: Vec<u8>,
    challenge_id: Sha256Digest,
}

impl AuthorizationPayload {
    /// Derive an authorization transcript from a complete immutable manifest.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error for invalid time or effect context.
    pub fn new(
        manifest: &ActionManifest,
        context: AuthorizationContext,
    ) -> Result<Self, MailError> {
        validate_authorization_time(context.issued_at_unix_ms, context.expires_at_unix_ms)?;
        let action = manifest.action();
        let effects = match (manifest.context.effect_id, action.policy().effect_kind) {
            (Some(effect_id), kind) if kind != EffectKind::None => {
                vec![AuthorizationEffect { effect_id, kind }]
            }
            (None, EffectKind::None) => Vec::new(),
            _ => return Err(malformed("authorization effect context is malformed")),
        };
        let canonical_bytes = encode_authorization(
            context.owner_realm,
            action,
            &manifest.context.target,
            manifest.context.store_id,
            manifest.context.account_id,
            manifest.sha256,
            manifest.context.account_binding_sha256,
            manifest.context.policy_sha256,
            context.trust_bundle_sha256,
            context.owner_key_id,
            context.trust_epoch,
            context.grant_id,
            &context.nonce,
            context.issued_at_unix_ms,
            context.expires_at_unix_ms,
            &effects,
        )?;
        let challenge_id = Sha256Digest::digest(&canonical_bytes);
        Ok(Self {
            owner_realm: context.owner_realm,
            action,
            target: manifest.context.target.clone(),
            store_id: manifest.context.store_id,
            account_id: manifest.context.account_id,
            manifest_sha256: manifest.sha256,
            account_binding_sha256: manifest.context.account_binding_sha256,
            policy_sha256: manifest.context.policy_sha256,
            trust_bundle_sha256: context.trust_bundle_sha256,
            owner_key_id: context.owner_key_id,
            trust_epoch: context.trust_epoch,
            grant_id: context.grant_id,
            nonce: context.nonce,
            issued_at_unix_ms: context.issued_at_unix_ms,
            expires_at_unix_ms: context.expires_at_unix_ms,
            effects,
            canonical_bytes,
            challenge_id,
        })
    }

    /// Strictly parse one exact authorization transcript.
    ///
    /// # Errors
    ///
    /// Returns authorization-malformed before verification for any noncanonical input.
    pub fn parse(bytes: &[u8]) -> Result<Self, MailError> {
        if bytes.len() > crate::MAX_AUTHORIZATION_MANIFEST_BYTES {
            return Err(limit("authorization transcript is too large"));
        }
        let fields = parse_fields(bytes, AUTHORIZATION_DOMAIN, 17)?;
        expect_tags(
            &fields,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        )?;
        let owner_realm = OwnerRealmId::from_bytes(parse_array(fields[0].1)?);
        let action = SensitiveAction::from_code(parse_u16(fields[1].1)?)?;
        let target_kind = TargetKind::from_code(parse_u16(fields[2].1)?)?;
        if target_kind != action.policy().target_kind {
            return Err(malformed("authorization target does not match action"));
        }
        let target = parse_target(target_kind, fields[3].1)?;
        let store_id = parse_optional_uuid(fields[4].1)?;
        let account_id = parse_optional_uuid(fields[5].1)?;
        let manifest_sha256 = parse_digest(fields[6].1)?;
        let account_binding_sha256 = parse_optional_digest(fields[7].1)?;
        let policy_sha256 = parse_optional_digest(fields[8].1)?;
        validate_authorization_presence(
            action,
            &target,
            store_id,
            account_id,
            account_binding_sha256,
            policy_sha256,
        )?;
        let trust_bundle_sha256 = parse_digest(fields[9].1)?;
        let owner_key_id = parse_digest(fields[10].1)?;
        let trust_epoch = parse_nonzero_u64(fields[11].1)?;
        let grant_id = parse_uuid(fields[12].1)?;
        let nonce = parse_array(fields[13].1)?;
        let issued_at_unix_ms = parse_i64(fields[14].1)?;
        let expires_at_unix_ms = parse_i64(fields[15].1)?;
        validate_authorization_time(issued_at_unix_ms, expires_at_unix_ms)?;
        let effects = parse_list(
            fields[16].1,
            parse_authorization_effect,
            MAX_AUTHORIZATION_EFFECTS,
        )?;
        validate_authorization_effects(action, &effects)?;
        let canonical_bytes = encode_authorization(
            owner_realm,
            action,
            &target,
            store_id,
            account_id,
            manifest_sha256,
            account_binding_sha256,
            policy_sha256,
            trust_bundle_sha256,
            owner_key_id,
            trust_epoch,
            grant_id,
            &nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
            &effects,
        )?;
        if canonical_bytes != bytes {
            return Err(malformed("authorization transcript is not canonical"));
        }
        let challenge_id = Sha256Digest::digest(&canonical_bytes);
        Ok(Self {
            owner_realm,
            action,
            target,
            store_id,
            account_id,
            manifest_sha256,
            account_binding_sha256,
            policy_sha256,
            trust_bundle_sha256,
            owner_key_id,
            trust_epoch,
            grant_id,
            nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
            effects,
            canonical_bytes,
            challenge_id,
        })
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_bytes.clone()
    }

    #[must_use]
    pub const fn challenge_id(&self) -> Sha256Digest {
        self.challenge_id
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_authorization(
    owner_realm: OwnerRealmId,
    action: SensitiveAction,
    target: &ManifestTarget,
    store_id: Option<StoreId>,
    account_id: Option<AccountId>,
    manifest_sha256: Sha256Digest,
    account_binding_sha256: Option<Sha256Digest>,
    policy_sha256: Option<Sha256Digest>,
    trust_bundle_sha256: Sha256Digest,
    owner_key_id: Sha256Digest,
    trust_epoch: NonZeroU64,
    grant_id: AuthorizationGrantId,
    nonce: &[u8; 32],
    issued_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    effects: &[AuthorizationEffect],
) -> Result<Vec<u8>, MailError> {
    encode_fields(
        AUTHORIZATION_DOMAIN,
        &[
            (1, owner_realm.as_bytes().to_vec()),
            (2, action.code().to_be_bytes().to_vec()),
            (3, target.kind().code().to_be_bytes().to_vec()),
            (4, target.bytes()),
            (
                5,
                store_id
                    .map(|value| value.as_bytes().to_vec())
                    .unwrap_or_default(),
            ),
            (
                6,
                account_id
                    .map(|value| value.as_bytes().to_vec())
                    .unwrap_or_default(),
            ),
            (7, manifest_sha256.as_bytes().to_vec()),
            (
                8,
                account_binding_sha256
                    .map(|value| value.as_bytes().to_vec())
                    .unwrap_or_default(),
            ),
            (
                9,
                policy_sha256
                    .map(|value| value.as_bytes().to_vec())
                    .unwrap_or_default(),
            ),
            (10, trust_bundle_sha256.as_bytes().to_vec()),
            (11, owner_key_id.as_bytes().to_vec()),
            (12, trust_epoch.get().to_be_bytes().to_vec()),
            (13, grant_id.as_bytes().to_vec()),
            (14, nonce.to_vec()),
            (15, issued_at_unix_ms.to_be_bytes().to_vec()),
            (16, expires_at_unix_ms.to_be_bytes().to_vec()),
            (
                17,
                encode_list(effects, |effect| {
                    encode_fields(
                        EFFECT_DOMAIN,
                        &[
                            (1, effect.effect_id.as_bytes().to_vec()),
                            (2, effect.kind.code().to_be_bytes().to_vec()),
                        ],
                    )
                })?,
            ),
        ],
    )
}

fn parse_authorization_effect(bytes: &[u8]) -> Result<AuthorizationEffect, MailError> {
    let fields = parse_fields(bytes, EFFECT_DOMAIN, 2)?;
    expect_tags(&fields, &[1, 2])?;
    let kind = EffectKind::from_code(parse_u16(fields[1].1)?)?;
    if kind == EffectKind::None {
        return Err(malformed("authorization effect cannot be none"));
    }
    Ok(AuthorizationEffect {
        effect_id: parse_uuid(fields[0].1)?,
        kind,
    })
}

fn validate_authorization_effects(
    action: SensitiveAction,
    effects: &[AuthorizationEffect],
) -> Result<(), MailError> {
    let expected = action.policy().effect_kind;
    if expected == EffectKind::None {
        if !effects.is_empty() {
            return Err(malformed("control authorization has remote effects"));
        }
    } else if effects.len() != 1 || effects[0].kind != expected {
        return Err(malformed("authorization effects do not match action"));
    }
    Ok(())
}

fn validate_authorization_presence(
    action: SensitiveAction,
    target: &ManifestTarget,
    store_id: Option<StoreId>,
    account_id: Option<AccountId>,
    binding: Option<Sha256Digest>,
    policy: Option<Sha256Digest>,
) -> Result<(), MailError> {
    if target.kind() != action.policy().target_kind {
        return Err(malformed("authorization target does not match action"));
    }
    let shape_ok = match action {
        SensitiveAction::SendSubmit
        | SensitiveAction::MailSeen
        | SensitiveAction::MailStarred
        | SensitiveAction::MailMove
        | SensitiveAction::MailArchive
        | SensitiveAction::MailSafeDelete
        | SensitiveAction::AmbiguousClose => {
            store_id.is_some() && account_id.is_some() && binding.is_some() && policy.is_some()
        }
        SensitiveAction::StoreEnroll => {
            store_id.is_some() && account_id.is_none() && binding.is_none() && policy.is_none()
        }
        SensitiveAction::AccountCreate
        | SensitiveAction::AccountUpdate
        | SensitiveAction::AccountRemove
        | SensitiveAction::CredentialSet
        | SensitiveAction::CredentialDelete
        | SensitiveAction::CredentialCleanup => {
            store_id.is_some() && account_id.is_some() && binding.is_some() && policy.is_none()
        }
        SensitiveAction::OwnerRotate
        | SensitiveAction::RecoveryRotate
        | SensitiveAction::OwnerRecover => {
            store_id.is_none() && account_id.is_none() && binding.is_none() && policy.is_none()
        }
        SensitiveAction::PolicyUpdate | SensitiveAction::AssuranceUpdate => false,
    };
    if !shape_ok {
        return Err(malformed("authorization common context is inconsistent"));
    }
    Ok(())
}

fn validate_authorization_time(issued: i64, expires: i64) -> Result<(), MailError> {
    let duration = expires
        .checked_sub(issued)
        .ok_or_else(|| malformed("authorization time range overflowed"))?;
    if duration <= 0 || duration > MAX_AUTHORIZATION_LIFETIME_MS {
        return Err(malformed("authorization lifetime is outside the contract"));
    }
    Ok(())
}

/// Verify a detached Ed25519 signature with strict scalar and point checks.
///
/// # Errors
///
/// Returns authorization-signature-invalid for malformed keys or invalid signatures.
pub fn verify_authorization_signature(
    public_key: &[u8; 32],
    payload: &[u8],
    signature: &[u8; 64],
) -> Result<(), MailError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| signature_error("owner public key is malformed"))?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(payload, &signature)
        .map_err(|_| signature_error("authorization signature is invalid"))
}

#[must_use]
pub fn owner_key_id(role: OwnerKeyRole, public_key: &[u8; 32]) -> Sha256Digest {
    let mut bytes = Vec::with_capacity(OWNER_KEY_DOMAIN.len() + 1 + public_key.len());
    bytes.extend_from_slice(OWNER_KEY_DOMAIN);
    bytes.push(role.code());
    bytes.extend_from_slice(public_key);
    Sha256Digest::digest(&bytes)
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationProof {
    pub contract_version: String,
    pub challenge_id: Sha256Digest,
    pub key_id: Sha256Digest,
    pub signing_payload_sha256: Sha256Digest,
    #[serde(deserialize_with = "deserialize_signature_base64url")]
    pub signature_base64url: String,
}

impl AuthorizationProof {
    /// Decode the exact 64-byte detached signature.
    ///
    /// # Errors
    ///
    /// Returns authorization-malformed when the string is not canonical Base64url.
    pub fn signature_bytes(&self) -> Result<[u8; 64], MailError> {
        decode_signature_base64url(&self.signature_base64url)
    }
}

fn deserialize_signature_base64url<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    decode_signature_base64url(&value).map_err(de::Error::custom)?;
    Ok(value)
}

fn decode_signature_base64url(value: &str) -> Result<[u8; 64], MailError> {
    if value.len() != 86 || value.contains('=') {
        return Err(malformed(
            "authorization signature Base64url length is invalid",
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| malformed("authorization signature is not canonical Base64url"))?;
    let signature: [u8; 64] = decoded
        .try_into()
        .map_err(|_| malformed("authorization signature must contain 64 bytes"))?;
    if URL_SAFE_NO_PAD.encode(signature) != value {
        return Err(malformed(
            "authorization signature is not canonical Base64url",
        ));
    }
    Ok(signature)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationReceiptState {
    Unclaimed,
    Claimed,
    Used,
    Invalidated,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationReceiptProjection {
    pub contract_version: String,
    pub receipt_id: AuthorizationReceiptId,
    pub challenge_id: Sha256Digest,
    pub action: SensitiveAction,
    pub target_kind: TargetKind,
    pub target_id: String,
    pub key_fingerprint: KeyFingerprint,
    pub trust_epoch: NonZeroU64,
    pub manifest_sha256: Sha256Digest,
    pub receipt_sha256: Sha256Digest,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub state: AuthorizationReceiptState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedOperationStatus {
    AuthorizationRequired,
    Authorized,
    Applying,
    Succeeded,
    Failed,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationAuthorizationState {
    Pending,
    Unclaimed,
    Claimed,
    Used,
    Invalidated,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedOperationAuthorization {
    pub contract_version: String,
    pub operation_id: OperationId,
    pub account_id: AccountId,
    pub action: SensitiveAction,
    pub status: GovernedOperationStatus,
    pub authorization_state: OperationAuthorizationState,
    pub manifest_sha256: Sha256Digest,
    pub challenge_id: Option<Sha256Digest>,
    pub receipt_id: Option<AuthorizationReceiptId>,
    pub expires_at: Option<DateTime<Utc>>,
}

fn parse_fields<'a>(
    bytes: &'a [u8],
    domain: &[u8],
    expected_count: usize,
) -> Result<Vec<(u16, &'a [u8])>, MailError> {
    let fields = parse_fields_any(bytes, domain)?;
    if fields.len() != expected_count {
        return Err(malformed("transcript field count is invalid"));
    }
    Ok(fields)
}

fn parse_fields_any<'a>(bytes: &'a [u8], domain: &[u8]) -> Result<Vec<(u16, &'a [u8])>, MailError> {
    if !bytes.starts_with(domain) {
        return Err(malformed("transcript domain is invalid"));
    }
    let mut cursor = domain.len();
    let count_bytes = take(bytes, &mut cursor, 2)?;
    let count = usize::from(u16::from_be_bytes(
        count_bytes
            .try_into()
            .map_err(|_| malformed("transcript field count is malformed"))?,
    ));
    if count > 256 {
        return Err(limit("transcript has too many fields"));
    }
    let mut fields = Vec::new();
    fields
        .try_reserve_exact(count)
        .map_err(|_| limit("transcript field allocation failed"))?;
    let mut previous = None;
    for _ in 0..count {
        let tag = u16::from_be_bytes(
            take(bytes, &mut cursor, 2)?
                .try_into()
                .map_err(|_| malformed("transcript tag is malformed"))?,
        );
        if previous.is_some_and(|value| tag <= value) {
            return Err(malformed("transcript tags are not strictly increasing"));
        }
        previous = Some(tag);
        let length = usize::try_from(u32::from_be_bytes(
            take(bytes, &mut cursor, 4)?
                .try_into()
                .map_err(|_| malformed("transcript length is malformed"))?,
        ))
        .map_err(|_| limit("transcript field length is too large"))?;
        let value = take(bytes, &mut cursor, length)?;
        fields.push((tag, value));
    }
    if cursor != bytes.len() {
        return Err(malformed("transcript contains trailing bytes"));
    }
    Ok(fields)
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], MailError> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| malformed("transcript length overflowed"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| malformed("transcript is truncated"))?;
    *cursor = end;
    Ok(value)
}

fn expect_tags(fields: &[(u16, &[u8])], tags: &[u16]) -> Result<(), MailError> {
    if fields.len() != tags.len()
        || fields
            .iter()
            .zip(tags)
            .any(|((actual, _), expected)| actual != expected)
    {
        return Err(malformed("transcript tag set is invalid"));
    }
    Ok(())
}

fn encode_list<T, F>(items: &[T], mut encode: F) -> Result<Vec<u8>, MailError>
where
    F: FnMut(&T) -> Result<Vec<u8>, MailError>,
{
    let count =
        u16::try_from(items.len()).map_err(|_| limit("canonical list contains too many items"))?;
    let mut output = Vec::new();
    output.extend_from_slice(&count.to_be_bytes());
    for (ordinal, item) in items.iter().enumerate() {
        let ordinal =
            u16::try_from(ordinal).map_err(|_| limit("canonical list ordinal overflowed"))?;
        let item = encode(item)?;
        let length =
            u32::try_from(item.len()).map_err(|_| limit("canonical list item is too large"))?;
        output.extend_from_slice(&ordinal.to_be_bytes());
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(&item);
    }
    Ok(output)
}

fn parse_list<T, F>(bytes: &[u8], mut parse: F, maximum: usize) -> Result<Vec<T>, MailError>
where
    F: FnMut(&[u8]) -> Result<T, MailError>,
{
    let mut cursor = 0;
    let count = usize::from(u16::from_be_bytes(
        take(bytes, &mut cursor, 2)?
            .try_into()
            .map_err(|_| malformed("canonical list count is malformed"))?,
    ));
    if count > maximum {
        return Err(limit("canonical list contains too many items"));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| limit("canonical list allocation failed"))?;
    for expected in 0..count {
        let ordinal = usize::from(u16::from_be_bytes(
            take(bytes, &mut cursor, 2)?
                .try_into()
                .map_err(|_| malformed("canonical list ordinal is malformed"))?,
        ));
        if ordinal != expected {
            return Err(malformed("canonical list ordinals are not contiguous"));
        }
        let length = usize::try_from(u32::from_be_bytes(
            take(bytes, &mut cursor, 4)?
                .try_into()
                .map_err(|_| malformed("canonical list length is malformed"))?,
        ))
        .map_err(|_| limit("canonical list item is too large"))?;
        output.push(parse(take(bytes, &mut cursor, length)?)?);
    }
    if cursor != bytes.len() {
        return Err(malformed("canonical list contains trailing bytes"));
    }
    Ok(output)
}

fn parse_target(kind: TargetKind, bytes: &[u8]) -> Result<ManifestTarget, MailError> {
    match kind {
        TargetKind::Operation => Ok(ManifestTarget::Operation(parse_uuid(bytes)?)),
        TargetKind::Store => Ok(ManifestTarget::Store(parse_uuid(bytes)?)),
        TargetKind::Account => Ok(ManifestTarget::Account(parse_uuid(bytes)?)),
        TargetKind::Credential => Ok(ManifestTarget::Credential(parse_uuid(bytes)?)),
        TargetKind::Cleanup => Ok(ManifestTarget::Cleanup(parse_uuid(bytes)?)),
        TargetKind::Policy if bytes.is_empty() => Ok(ManifestTarget::Policy),
        TargetKind::Assurance if bytes.is_empty() => Ok(ManifestTarget::Assurance),
        TargetKind::TrustEpoch => Ok(ManifestTarget::TrustEpoch(parse_nonzero_u64(bytes)?)),
        TargetKind::RemoteEffect => Ok(ManifestTarget::RemoteEffect(parse_uuid(bytes)?)),
        TargetKind::Policy | TargetKind::Assurance => {
            Err(malformed("zero-length target contains bytes"))
        }
    }
}

fn parse_uuid<T>(bytes: &[u8]) -> Result<T, MailError>
where
    T: TryFrom<uuid::Uuid, Error = MailError>,
{
    let raw: [u8; 16] = parse_array(bytes)?;
    T::try_from(uuid::Uuid::from_bytes(raw))
}

fn parse_optional_uuid<T>(bytes: &[u8]) -> Result<Option<T>, MailError>
where
    T: TryFrom<uuid::Uuid, Error = MailError>,
{
    if bytes.is_empty() {
        Ok(None)
    } else {
        parse_uuid(bytes).map(Some)
    }
}

fn parse_digest(bytes: &[u8]) -> Result<Sha256Digest, MailError> {
    Ok(Sha256Digest::from_bytes(parse_array(bytes)?))
}

fn parse_optional_digest(bytes: &[u8]) -> Result<Option<Sha256Digest>, MailError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        parse_digest(bytes).map(Some)
    }
}

fn parse_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], MailError> {
    bytes
        .try_into()
        .map_err(|_| malformed("transcript fixed-width field has the wrong length"))
}

fn parse_u8(bytes: &[u8]) -> Result<u8, MailError> {
    Ok(parse_array::<1>(bytes)?[0])
}

fn parse_u16(bytes: &[u8]) -> Result<u16, MailError> {
    Ok(u16::from_be_bytes(parse_array(bytes)?))
}

fn parse_u32(bytes: &[u8]) -> Result<u32, MailError> {
    Ok(u32::from_be_bytes(parse_array(bytes)?))
}

fn parse_u64(bytes: &[u8]) -> Result<u64, MailError> {
    Ok(u64::from_be_bytes(parse_array(bytes)?))
}

fn parse_i64(bytes: &[u8]) -> Result<i64, MailError> {
    Ok(i64::from_be_bytes(parse_array(bytes)?))
}

fn parse_nonzero_u32(bytes: &[u8]) -> Result<NonZeroU32, MailError> {
    NonZeroU32::new(parse_u32(bytes)?).ok_or_else(|| malformed("positive u32 field cannot be zero"))
}

fn parse_nonzero_u64(bytes: &[u8]) -> Result<NonZeroU64, MailError> {
    NonZeroU64::new(parse_u64(bytes)?).ok_or_else(|| malformed("positive u64 field cannot be zero"))
}

fn parse_optional_u64(bytes: &[u8]) -> Result<Option<u64>, MailError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        parse_u64(bytes).map(Some)
    }
}

fn parse_bool(bytes: &[u8]) -> Result<bool, MailError> {
    match parse_u8(bytes)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(malformed("boolean field is not zero or one")),
    }
}

fn parse_optional_bool(bytes: &[u8]) -> Result<Option<bool>, MailError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        parse_bool(bytes).map(Some)
    }
}

fn optional_text(value: Option<&str>) -> Vec<u8> {
    match value {
        None => vec![0],
        Some(value) => {
            let mut output = Vec::with_capacity(value.len() + 1);
            output.push(1);
            output.extend_from_slice(value.as_bytes());
            output
        }
    }
}

fn parse_optional_text(bytes: &[u8]) -> Result<Option<String>, MailError> {
    match bytes {
        [0] => Ok(None),
        [1, rest @ ..] => parse_text(rest).map(Some),
        _ => Err(malformed("optional text presence encoding is malformed")),
    }
}

fn parse_text(bytes: &[u8]) -> Result<String, MailError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| malformed("transcript text is not UTF-8"))
}

fn valid_email(value: &str) -> bool {
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !local.contains('@')
        && !domain.contains('@')
        && domain.contains('.')
        && value.len() <= 320
        && !value.chars().any(char::is_whitespace)
        && !value.chars().any(char::is_control)
}

fn valid_message_id(value: &str) -> bool {
    value.is_ascii()
        && value.len() >= 3
        && value.len() <= 998
        && value.starts_with('<')
        && value.ends_with('>')
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
}

fn valid_ascii_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

fn valid_mime(value: &str) -> bool {
    let mut parts = value.split('/');
    let Some(top) = parts.next() else {
        return false;
    };
    let Some(subtype) = parts.next() else {
        return false;
    };
    !top.is_empty()
        && !subtype.is_empty()
        && parts.next().is_none()
        && top
            .bytes()
            .chain(subtype.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn invalid_mailbox(value: &str) -> bool {
    value.is_empty() || value.chars().count() > 4_096 || value.chars().any(char::is_control)
}

fn malformed(message: &'static str) -> MailError {
    MailError::stable(MailErrorCode::AuthorizationMalformed, message)
}

fn signature_error(message: &'static str) -> MailError {
    MailError::stable(MailErrorCode::AuthorizationSignatureInvalid, message)
}

fn unsupported_action() -> MailError {
    MailError::stable(
        MailErrorCode::UnsupportedCapability,
        "sensitive action has no supported manifest contract",
    )
}

fn limit(message: &'static str) -> MailError {
    MailError::stable(MailErrorCode::ResourceLimit, message)
}
