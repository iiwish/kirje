use std::{fmt, net::IpAddr, str::FromStr};

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest as _, Sha256};
use uuid::{Uuid, Version};

use crate::{
    CredentialKind, MailAccountConfig, MailError, MailErrorCode, Protocol, TransportSecurity,
};

const ACCOUNT_BINDING_DOMAIN: &[u8] = b"KIRJE-ACCOUNT-BINDING-V1\0";
const CONFIG_LOCATION_DOMAIN: &[u8] = b"KIRJE-CONFIG-LOCATION-V1\0";
const MAX_LOCATION_COMPONENT_BYTES: usize = 4_096;

macro_rules! uuid_v4_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl TryFrom<Uuid> for $name {
            type Error = MailError;

            fn try_from(value: Uuid) -> Result<Self, Self::Error> {
                if value.get_version() != Some(Version::Random) {
                    return Err(MailError::invalid_input(concat!(
                        stringify!($name),
                        " must be a canonical UUIDv4"
                    )));
                }
                Ok(Self(value))
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl FromStr for $name {
            type Err = MailError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let parsed = Uuid::parse_str(value).map_err(|_| {
                    MailError::invalid_input(concat!(stringify!($name), " is malformed"))
                })?;
                if value != parsed.as_hyphenated().to_string() {
                    return Err(MailError::invalid_input(concat!(
                        stringify!($name),
                        " must use canonical lowercase hyphenated UUID text"
                    )));
                }
                Self::try_from(parsed)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                schemars::json_schema!({
                    "type": "string",
                    "format": "uuid",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                })
            }
        }
    };
}

uuid_v4_id!(StoreId);
uuid_v4_id!(AccountId);
uuid_v4_id!(CredentialId);
uuid_v4_id!(AuthorizationGrantId);
uuid_v4_id!(RemoteEffectId);
uuid_v4_id!(AuthorizationReceiptId);
uuid_v4_id!(OperationId);
uuid_v4_id!(CleanupId);
uuid_v4_id!(TransitionId);
uuid_v4_id!(InvocationId);
uuid_v4_id!(JournalId);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OwnerRealmId([u8; 32]);

impl OwnerRealmId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    #[must_use]
    pub fn fingerprint(self) -> KeyFingerprint {
        KeyFingerprint(hex_lower(&self.0[..8]))
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex_lower(&self.0))
    }
}

impl FromStr for Sha256Digest {
    type Err = MailError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(MailError::invalid_input(
                "SHA-256 digest must contain 64 lowercase hexadecimal characters",
            ));
        }
        let mut bytes = [0; 32];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| MailError::invalid_input("SHA-256 digest is malformed"))?;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl JsonSchema for Sha256Digest {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Sha256Digest".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^[0-9a-f]{64}$"
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct KeyFingerprint(String);

impl KeyFingerprint {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub type BindingDigest = Sha256Digest;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountBinding {
    canonical_bytes: Vec<u8>,
    sha256: BindingDigest,
}

impl AccountBinding {
    /// Build the exact V1 account-binding transcript from one validated adapter snapshot.
    ///
    /// # Errors
    ///
    /// Returns a stable input error when the account or endpoint shape is invalid.
    pub fn from_config(config: &MailAccountConfig) -> Result<Self, MailError> {
        config.validate()?;
        Self::from_validated_config(config)
    }

    pub(crate) fn from_validated_config(config: &MailAccountConfig) -> Result<Self, MailError> {
        let mut fields = vec![
            (0x0001, config.email.as_bytes().to_vec()),
            (0x0002, config.username.as_bytes().to_vec()),
            (0x0003, vec![credential_kind_code(config.credential_kind)]),
            (0x0010, vec![protocol_code(config.incoming.protocol)]),
            (0x0011, normalized_host_bytes(&config.incoming.host)?),
            (0x0012, config.incoming.port.to_be_bytes().to_vec()),
            (0x0013, vec![security_code(config.incoming.security)]),
            (0x0020, vec![u8::from(config.outgoing.is_some())]),
        ];
        let outgoing = config.outgoing.as_ref();
        fields.extend([
            (
                0x0021,
                outgoing
                    .map(|endpoint| vec![protocol_code(endpoint.protocol)])
                    .unwrap_or_default(),
            ),
            (
                0x0022,
                outgoing
                    .map(|endpoint| normalized_host_bytes(&endpoint.host))
                    .transpose()?
                    .unwrap_or_default(),
            ),
            (
                0x0023,
                outgoing
                    .map(|endpoint| endpoint.port.to_be_bytes().to_vec())
                    .unwrap_or_default(),
            ),
            (
                0x0024,
                outgoing
                    .map(|endpoint| vec![security_code(endpoint.security)])
                    .unwrap_or_default(),
            ),
        ]);

        let canonical_bytes = encode_fields(ACCOUNT_BINDING_DOMAIN, &fields)?;
        let sha256 = Sha256Digest::digest(&canonical_bytes);
        Ok(Self {
            canonical_bytes,
            sha256,
        })
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub const fn sha256(&self) -> BindingDigest {
        self.sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformLocationMaterial {
    Unix {
        parent_device: u64,
        parent_inode: u64,
        final_component: Vec<u8>,
    },
    Windows {
        volume_serial: u64,
        parent_file_index: u64,
        final_component_utf16: Vec<u16>,
    },
}

impl PlatformLocationMaterial {
    /// Encode OS-provided identity material without performing filesystem I/O.
    ///
    /// # Errors
    ///
    /// Returns a resource or validation error for an empty or oversized component.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MailError> {
        let fields = match self {
            Self::Unix {
                parent_device,
                parent_inode,
                final_component,
            } => {
                validate_location_component(final_component)?;
                vec![
                    (0x0001, vec![1]),
                    (0x0010, parent_device.to_be_bytes().to_vec()),
                    (0x0011, parent_inode.to_be_bytes().to_vec()),
                    (0x0012, final_component.clone()),
                ]
            }
            Self::Windows {
                volume_serial,
                parent_file_index,
                final_component_utf16,
            } => {
                if final_component_utf16.is_empty() {
                    return Err(MailError::invalid_input(
                        "config final component cannot be empty",
                    ));
                }
                let byte_len = final_component_utf16.len().checked_mul(2).ok_or_else(|| {
                    MailError::stable(
                        MailErrorCode::ResourceLimit,
                        "config component is too large",
                    )
                })?;
                if byte_len > MAX_LOCATION_COMPONENT_BYTES {
                    return Err(MailError::stable(
                        MailErrorCode::ResourceLimit,
                        "config component is too large",
                    ));
                }
                let component = final_component_utf16
                    .iter()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect();
                vec![
                    (0x0001, vec![2]),
                    (0x0020, volume_serial.to_be_bytes().to_vec()),
                    (0x0021, parent_file_index.to_be_bytes().to_vec()),
                    (0x0022, component),
                ]
            }
        };
        encode_fields(CONFIG_LOCATION_DOMAIN, &fields)
    }

    /// Digest the exact platform location transcript.
    ///
    /// # Errors
    ///
    /// Returns the same error as `canonical_bytes`.
    pub fn sha256(&self) -> Result<Sha256Digest, MailError> {
        Ok(Sha256Digest::digest(&self.canonical_bytes()?))
    }
}

fn validate_location_component(component: &[u8]) -> Result<(), MailError> {
    if component.is_empty() {
        return Err(MailError::invalid_input(
            "config final component cannot be empty",
        ));
    }
    if component.len() > MAX_LOCATION_COMPONENT_BYTES {
        return Err(MailError::stable(
            MailErrorCode::ResourceLimit,
            "config component is too large",
        ));
    }
    Ok(())
}

fn normalized_host_bytes(host: &str) -> Result<Vec<u8>, MailError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        let family = match ip {
            IpAddr::V4(_) => 2,
            IpAddr::V6(_) => 3,
        };
        let mut bytes = vec![family];
        bytes.extend_from_slice(ip.to_string().as_bytes());
        return Ok(bytes);
    }
    if !host.is_ascii() {
        return Err(MailError::invalid_input(
            "account-binding DNS hosts must be ASCII",
        ));
    }
    let mut bytes = vec![1];
    bytes.extend_from_slice(host.to_ascii_lowercase().as_bytes());
    Ok(bytes)
}

const fn credential_kind_code(kind: CredentialKind) -> u8 {
    match kind {
        CredentialKind::Password => 1,
        CredentialKind::AppPassword => 2,
        CredentialKind::OAuth2 => 3,
    }
}

pub(crate) const fn protocol_code(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Imap => 1,
        Protocol::Smtp => 2,
        Protocol::Jmap => 3,
    }
}

pub(crate) const fn security_code(security: TransportSecurity) -> u8 {
    match security {
        TransportSecurity::ImplicitTls => 1,
        TransportSecurity::StartTls => 2,
        TransportSecurity::Https => 3,
    }
}

pub(crate) fn encode_fields(
    domain: &[u8],
    fields: &[(u16, Vec<u8>)],
) -> Result<Vec<u8>, MailError> {
    let field_count = u16::try_from(fields.len())
        .map_err(|_| MailError::stable(MailErrorCode::ResourceLimit, "too many fields"))?;
    let mut output = Vec::with_capacity(domain.len() + 2 + fields.len() * 8);
    output.extend_from_slice(domain);
    output.extend_from_slice(&field_count.to_be_bytes());
    let mut previous = None;
    for (tag, value) in fields {
        if previous.is_some_and(|seen| *tag <= seen) {
            return Err(MailError::invalid_input(
                "field tags must be strictly increasing",
            ));
        }
        previous = Some(*tag);
        let length = u32::try_from(value.len())
            .map_err(|_| MailError::stable(MailErrorCode::ResourceLimit, "field is too large"))?;
        output.extend_from_slice(&tag.to_be_bytes());
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(value);
    }
    Ok(output)
}

fn hex_lower(bytes: &[u8]) -> String {
    use fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreState {
    Unregistered,
    Registered,
    LocationConflict,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerState {
    Absent,
    Ready,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingState {
    Quarantined,
    Proposed,
    Authorized,
    Invalidated,
    Mismatch,
}

impl BindingState {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Quarantined => 1,
            Self::Proposed => 2,
            Self::Authorized => 3,
            Self::Invalidated => 4,
            Self::Mismatch => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredCredentialState {
    LegacyQuarantined,
    ReentryRequired,
    Missing,
    Bound,
    Invalidated,
}

impl StoredCredentialState {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::LegacyQuarantined => 1,
            Self::ReentryRequired => 2,
            Self::Missing => 3,
            Self::Bound => 4,
            Self::Invalidated => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicCredentialState {
    LegacyQuarantined,
    ReentryRequired,
    Missing,
    Ready,
    Invalidated,
    StoreUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStateReason {
    LegacyUnbound,
    CredentialReentryRequired,
    BindingChanged,
    OwnerRecovery,
    AuthorityMismatch,
    ConfigMigration,
}

impl AccountStateReason {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::LegacyUnbound => 1,
            Self::CredentialReentryRequired => 2,
            Self::BindingChanged => 3,
            Self::OwnerRecovery => 4,
            Self::AuthorityMismatch => 5,
            Self::ConfigMigration => 6,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusProjection {
    pub display_id: String,
    pub account_id: AccountId,
    pub store_state: StoreState,
    pub owner_state: OwnerState,
    pub binding_state: BindingState,
    pub credential_state: PublicCredentialState,
    pub ready_for_authentication: bool,
    pub reason_code: Option<MailErrorCode>,
}
