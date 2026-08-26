//! Provider-neutral contracts shared by every Kirje interface.

use std::{collections::HashSet, sync::LazyLock};

use chrono::NaiveDate;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod mail;

pub use mail::*;

pub const CONTRACT_VERSION: &str = "2026-08-26.3";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Imap,
    Smtp,
    Jmap,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportSecurity {
    ImplicitTls,
    StartTls,
    Https,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    AppPassword,
    #[serde(rename = "oauth2")]
    OAuth2,
    Password,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Endpoint {
    pub protocol: Protocol,
    pub host: String,
    #[schemars(schema_with = "port_schema")]
    pub port: u16,
    pub security: TransportSecurity,
}

fn port_schema(_: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({
        "type": "integer",
        "minimum": 1,
        "maximum": 65_535
    })
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderDiscovery {
    pub contract_version: String,
    pub email: String,
    pub valid: bool,
    pub matched: bool,
    pub provider_id: Option<String>,
    pub provider_name: Option<String>,
    pub incoming: Vec<Endpoint>,
    pub outgoing: Vec<Endpoint>,
    pub credential_kind: Option<CredentialKind>,
    pub guidance: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProtocol {
    Imap,
    Smtp,
    Pop3,
    Jmap,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderEndpointPreset {
    pub protocol: ProviderProtocol,
    pub host: String,
    #[schemars(schema_with = "port_schema")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub security: TransportSecurity,
    pub runtime_default: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderSource {
    pub title: String,
    pub url: String,
    pub verified_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderPreset {
    pub id: String,
    pub provider_id: String,
    pub name: String,
    pub domains: Vec<String>,
    pub credential_kind: CredentialKind,
    pub endpoints: Vec<ProviderEndpointPreset>,
    pub guidance: Vec<String>,
    pub sources: Vec<ProviderSource>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ProviderRegistry {
    pub schema_version: u32,
    pub updated_at: String,
    pub providers: Vec<ProviderPreset>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderRegistryError {
    #[error("unsupported provider registry schema version: {0}")]
    UnsupportedSchema(u32),
    #[error("invalid provider registry update date")]
    InvalidUpdateDate,
    #[error("provider preset is incomplete: {0}")]
    IncompletePreset(String),
    #[error("duplicate provider profile id: {0}")]
    DuplicateProfileId(String),
    #[error("invalid or duplicate provider domain: {0}")]
    InvalidDomain(String),
    #[error("invalid provider endpoint in profile: {0}")]
    InvalidEndpoint(String),
    #[error("provider profile must have one default IMAP and SMTP endpoint: {0}")]
    MissingRuntimeDefaults(String),
    #[error("invalid provider source in profile: {0}")]
    InvalidSource(String),
}

const PROVIDER_PRESETS_JSON: &str = include_str!("../data/provider-presets.json");

static PROVIDER_REGISTRY: LazyLock<ProviderRegistry> = LazyLock::new(|| {
    let registry: ProviderRegistry = serde_json::from_str(PROVIDER_PRESETS_JSON)
        .expect("embedded provider registry must contain valid JSON");
    registry
        .validate()
        .expect("embedded provider registry must satisfy its invariants");
    registry
});

impl ProviderRegistry {
    /// Validate the complete built-in catalog before it can drive discovery.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the schema, identifiers, endpoints, or source
    /// evidence violate the registry contract.
    pub fn validate(&self) -> Result<(), ProviderRegistryError> {
        if self.schema_version != 1 {
            return Err(ProviderRegistryError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if NaiveDate::parse_from_str(&self.updated_at, "%Y-%m-%d").is_err() {
            return Err(ProviderRegistryError::InvalidUpdateDate);
        }

        let mut profile_ids = HashSet::new();
        let mut domains = HashSet::new();
        for preset in &self.providers {
            if preset.id.is_empty()
                || preset.provider_id.is_empty()
                || preset.name.is_empty()
                || preset.domains.is_empty()
                || preset.endpoints.is_empty()
                || preset.sources.is_empty()
            {
                return Err(ProviderRegistryError::IncompletePreset(preset.id.clone()));
            }
            if !profile_ids.insert(preset.id.as_str()) {
                return Err(ProviderRegistryError::DuplicateProfileId(preset.id.clone()));
            }

            for domain in &preset.domains {
                if domain.is_empty()
                    || domain.contains('@')
                    || !domain.contains('.')
                    || domain != &domain.to_ascii_lowercase()
                    || !domains.insert(domain.as_str())
                {
                    return Err(ProviderRegistryError::InvalidDomain(domain.clone()));
                }
            }

            let mut endpoint_keys = HashSet::new();
            let mut default_imap = 0_u8;
            let mut default_smtp = 0_u8;
            for endpoint in &preset.endpoints {
                let valid_host = !endpoint.host.is_empty()
                    && endpoint.host.contains('.')
                    && !endpoint.host.contains([' ', '@', '/'])
                    && endpoint.host == endpoint.host.to_ascii_lowercase();
                let secure_transport = match endpoint.protocol {
                    ProviderProtocol::Jmap => endpoint.security == TransportSecurity::Https,
                    ProviderProtocol::Imap | ProviderProtocol::Smtp | ProviderProtocol::Pop3 => {
                        endpoint.security != TransportSecurity::Https
                    }
                };
                let valid_path = match endpoint.protocol {
                    ProviderProtocol::Jmap => endpoint.path.as_deref().is_some_and(|path| {
                        path.starts_with('/') && !path.contains(char::is_whitespace)
                    }),
                    ProviderProtocol::Imap | ProviderProtocol::Smtp | ProviderProtocol::Pop3 => {
                        endpoint.path.is_none()
                    }
                };
                let runtime_protocol = matches!(
                    endpoint.protocol,
                    ProviderProtocol::Imap | ProviderProtocol::Smtp
                );
                if !valid_host
                    || endpoint.port == 0
                    || !secure_transport
                    || !valid_path
                    || (endpoint.runtime_default && !runtime_protocol)
                    || !endpoint_keys.insert((
                        endpoint.protocol,
                        endpoint.host.as_str(),
                        endpoint.port,
                        endpoint.path.as_deref(),
                        endpoint.security,
                    ))
                {
                    return Err(ProviderRegistryError::InvalidEndpoint(preset.id.clone()));
                }
                if endpoint.runtime_default {
                    match endpoint.protocol {
                        ProviderProtocol::Imap => default_imap += 1,
                        ProviderProtocol::Smtp => default_smtp += 1,
                        ProviderProtocol::Pop3 | ProviderProtocol::Jmap => {}
                    }
                }
            }
            if default_imap != 1 || default_smtp != 1 {
                return Err(ProviderRegistryError::MissingRuntimeDefaults(
                    preset.id.clone(),
                ));
            }

            for source in &preset.sources {
                if source.title.is_empty()
                    || !source.url.starts_with("https://")
                    || NaiveDate::parse_from_str(&source.verified_at, "%Y-%m-%d").is_err()
                {
                    return Err(ProviderRegistryError::InvalidSource(preset.id.clone()));
                }
            }
        }
        Ok(())
    }
}

#[must_use]
pub fn provider_registry() -> &'static ProviderRegistry {
    &PROVIDER_REGISTRY
}

#[must_use]
pub fn find_provider_preset(selector: &str) -> Option<&'static ProviderPreset> {
    let normalized = selector.trim().to_ascii_lowercase();
    provider_registry().providers.iter().find(|preset| {
        preset.id == normalized || preset.domains.iter().any(|domain| domain == &normalized)
    })
}

#[must_use]
pub fn discover_account(email: &str) -> ProviderDiscovery {
    let normalized = email.trim().to_ascii_lowercase();
    let Some((local, domain)) = normalized.rsplit_once('@') else {
        return invalid_discovery(normalized, "Email address must contain @.");
    };

    if local.is_empty() || domain.is_empty() || domain.contains('@') || !domain.contains('.') {
        return invalid_discovery(
            normalized,
            "Email address has an invalid local part or domain.",
        );
    }

    if let Some(preset) = find_provider_preset(domain) {
        let incoming = preset
            .endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.runtime_default && endpoint.protocol == ProviderProtocol::Imap
            })
            .map(|endpoint| Endpoint {
                protocol: Protocol::Imap,
                host: endpoint.host.clone(),
                port: endpoint.port,
                security: endpoint.security,
            })
            .collect();
        let outgoing = preset
            .endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.runtime_default && endpoint.protocol == ProviderProtocol::Smtp
            })
            .map(|endpoint| Endpoint {
                protocol: Protocol::Smtp,
                host: endpoint.host.clone(),
                port: endpoint.port,
                security: endpoint.security,
            })
            .collect();
        let mut guidance = preset.guidance.clone();
        guidance.push(
            "Never pass a primary password or client credential on the command line.".to_owned(),
        );
        guidance.push("Verify discovered endpoints before saving credentials.".to_owned());
        return ProviderDiscovery {
            contract_version: CONTRACT_VERSION.to_owned(),
            email: normalized,
            valid: true,
            matched: true,
            provider_id: Some(preset.provider_id.clone()),
            provider_name: Some(preset.name.clone()),
            incoming,
            outgoing,
            credential_kind: Some(preset.credential_kind),
            guidance,
        };
    }

    ProviderDiscovery {
        contract_version: CONTRACT_VERSION.to_owned(),
        email: normalized,
        valid: true,
        matched: false,
        provider_id: None,
        provider_name: None,
        incoming: Vec::new(),
        outgoing: Vec::new(),
        credential_kind: None,
        guidance: vec![
            "No built-in preset matched. Try JMAP discovery, RFC 6186 SRV records, or provider autoconfiguration before entering hosts manually.".to_owned(),
            "Do not guess server endpoints or disable TLS verification.".to_owned(),
        ],
    }
}

fn invalid_discovery(email: String, message: &str) -> ProviderDiscovery {
    ProviderDiscovery {
        contract_version: CONTRACT_VERSION.to_owned(),
        email,
        valid: false,
        matched: false,
        provider_id: None,
        provider_name: None,
        incoming: Vec::new(),
        outgoing: Vec::new(),
        credential_kind: None,
        guidance: vec![message.to_owned()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_netease_without_exposing_a_password_field() {
        let result = discover_account(" Agent@163.com ");

        assert!(result.valid);
        assert!(result.matched);
        assert_eq!(result.provider_id.as_deref(), Some("netease"));
        assert_eq!(result.email, "agent@163.com");
        assert_eq!(result.incoming[0].host, "imap.163.com");
        assert_eq!(result.outgoing[0].host, "smtp.163.com");
        assert_eq!(result.credential_kind, Some(CredentialKind::AppPassword));
    }

    #[test]
    fn netease_domains_use_their_documented_hosts() {
        for (address, expected_host) in [
            ("agent@163.com", "imap.163.com"),
            ("agent@126.com", "imap.126.com"),
            ("agent@yeah.net", "imap.yeah.net"),
        ] {
            let result = discover_account(address);
            assert_eq!(result.incoming[0].host, expected_host);
        }
    }

    #[test]
    fn embedded_provider_registry_is_valid_and_secret_free() {
        let registry = provider_registry();

        assert_eq!(registry.schema_version, 1);
        assert!(registry.validate().is_ok());
        let serialized = serde_json::to_value(registry).expect("serialize registry");
        assert_no_secret_keys(&serialized);
    }

    #[test]
    fn registry_validation_rejects_unsafe_or_ambiguous_data() {
        let mut duplicate_domain = provider_registry().clone();
        duplicate_domain.providers[1].domains[0] = "163.com".to_owned();
        assert!(matches!(
            duplicate_domain.validate(),
            Err(ProviderRegistryError::InvalidDomain(_))
        ));

        let mut missing_source = provider_registry().clone();
        missing_source.providers[0].sources.clear();
        assert!(matches!(
            missing_source.validate(),
            Err(ProviderRegistryError::IncompletePreset(_))
        ));

        let mut runtime_pop3 = provider_registry().clone();
        let pop3 = runtime_pop3.providers[0]
            .endpoints
            .iter_mut()
            .find(|endpoint| endpoint.protocol == ProviderProtocol::Pop3)
            .expect("POP3 endpoint");
        pop3.runtime_default = true;
        assert!(matches!(
            runtime_pop3.validate(),
            Err(ProviderRegistryError::InvalidEndpoint(_))
        ));

        let mut invalid_port = provider_registry().clone();
        invalid_port.providers[0].endpoints[0].port = 0;
        assert!(matches!(
            invalid_port.validate(),
            Err(ProviderRegistryError::InvalidEndpoint(_))
        ));
    }

    #[test]
    fn every_preset_domain_discovers_one_runtime_imap_and_smtp_endpoint() {
        for preset in &provider_registry().providers {
            for domain in &preset.domains {
                let result = discover_account(&format!("agent@{domain}"));
                assert!(result.matched, "{domain}");
                assert_eq!(result.incoming.len(), 1, "{domain}");
                assert_eq!(result.outgoing.len(), 1, "{domain}");
                assert_eq!(result.incoming[0].protocol, Protocol::Imap, "{domain}");
                assert_eq!(result.outgoing[0].protocol, Protocol::Smtp, "{domain}");
            }
        }
    }

    #[test]
    fn netease_163_includes_secure_reference_only_pop3() {
        let preset = find_provider_preset("163.com").expect("163 preset");

        assert!(preset.endpoints.iter().any(|endpoint| {
            endpoint.protocol == ProviderProtocol::Pop3
                && endpoint.host == "pop.163.com"
                && endpoint.port == 995
                && endpoint.security == TransportSecurity::ImplicitTls
                && !endpoint.runtime_default
        }));
    }

    #[test]
    fn icloud_uses_documented_smtp_submission_port() {
        let result = discover_account("agent@icloud.com");

        assert_eq!(result.outgoing[0].host, "smtp.mail.me.com");
        assert_eq!(result.outgoing[0].port, 587);
        assert_eq!(result.outgoing[0].security, TransportSecurity::StartTls);
    }

    #[test]
    fn fastmail_records_reference_only_jmap_session_endpoint() {
        let preset = find_provider_preset("fastmail").expect("Fastmail preset");

        assert!(preset.endpoints.iter().any(|endpoint| {
            endpoint.protocol == ProviderProtocol::Jmap
                && endpoint.host == "api.fastmail.com"
                && endpoint.port == 443
                && endpoint.path.as_deref() == Some("/jmap/session")
                && endpoint.security == TransportSecurity::Https
                && !endpoint.runtime_default
        }));
    }

    #[test]
    fn aliyun_personal_uses_the_documented_mailbox_password_class() {
        let preset = find_provider_preset("aliyun.com").expect("Aliyun personal preset");

        assert_eq!(preset.credential_kind, CredentialKind::Password);
    }

    #[test]
    fn leaves_unknown_domains_explicitly_unmatched() {
        let result = discover_account("agent@example.org");

        assert!(result.valid);
        assert!(!result.matched);
        assert!(result.incoming.is_empty());
        assert!(
            result
                .guidance
                .iter()
                .any(|line| line.contains("Do not guess"))
        );
    }

    #[test]
    fn rejects_malformed_addresses() {
        let result = discover_account("not-an-email");

        assert!(!result.valid);
        assert!(!result.matched);
    }

    fn assert_no_secret_keys(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                for (key, nested) in object {
                    assert!(!matches!(
                        key.to_ascii_lowercase().as_str(),
                        "password" | "secret" | "token" | "credential"
                    ));
                    assert_no_secret_keys(nested);
                }
            }
            serde_json::Value::Array(values) => {
                for nested in values {
                    assert_no_secret_keys(nested);
                }
            }
            _ => {}
        }
    }
}
