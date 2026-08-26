//! Provider-neutral contracts shared by every Kirje interface.

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

mod mail;

pub use mail::*;

pub const CONTRACT_VERSION: &str = "2026-08-26.2";

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Imap,
    Smtp,
    Jmap,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
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

#[derive(Clone, Copy)]
struct Preset {
    id: &'static str,
    name: &'static str,
    domains: &'static [&'static str],
    imap_host: &'static str,
    smtp_host: &'static str,
    credential_kind: CredentialKind,
}

const PRESETS: &[Preset] = &[
    Preset {
        id: "netease",
        name: "NetEase 163 Mail",
        domains: &["163.com"],
        imap_host: "imap.163.com",
        smtp_host: "smtp.163.com",
        credential_kind: CredentialKind::AppPassword,
    },
    Preset {
        id: "netease",
        name: "NetEase 126 Mail",
        domains: &["126.com"],
        imap_host: "imap.126.com",
        smtp_host: "smtp.126.com",
        credential_kind: CredentialKind::AppPassword,
    },
    Preset {
        id: "netease",
        name: "NetEase Yeah Mail",
        domains: &["yeah.net"],
        imap_host: "imap.yeah.net",
        smtp_host: "smtp.yeah.net",
        credential_kind: CredentialKind::AppPassword,
    },
    Preset {
        id: "tencent",
        name: "QQ Mail / Foxmail",
        domains: &["qq.com", "foxmail.com"],
        imap_host: "imap.qq.com",
        smtp_host: "smtp.qq.com",
        credential_kind: CredentialKind::AppPassword,
    },
    Preset {
        id: "china-mobile",
        name: "China Mobile 139 Mail",
        domains: &["139.com"],
        imap_host: "imap.139.com",
        smtp_host: "smtp.139.com",
        credential_kind: CredentialKind::AppPassword,
    },
    Preset {
        id: "china-telecom",
        name: "China Telecom 189 Mail",
        domains: &["189.cn"],
        imap_host: "imap.189.cn",
        smtp_host: "smtp.189.cn",
        credential_kind: CredentialKind::AppPassword,
    },
    Preset {
        id: "sina",
        name: "Sina Mail",
        domains: &["sina.com", "sina.cn", "vip.sina.com", "vip.sina.cn"],
        imap_host: "imap.sina.com",
        smtp_host: "smtp.sina.com",
        credential_kind: CredentialKind::AppPassword,
    },
    Preset {
        id: "aliyun",
        name: "Aliyun Mail",
        domains: &["aliyun.com", "qiye.aliyun.com"],
        imap_host: "imap.aliyun.com",
        smtp_host: "smtp.aliyun.com",
        credential_kind: CredentialKind::AppPassword,
    },
    Preset {
        id: "fastmail",
        name: "Fastmail",
        domains: &["fastmail.com", "fastmail.fm"],
        imap_host: "imap.fastmail.com",
        smtp_host: "smtp.fastmail.com",
        credential_kind: CredentialKind::AppPassword,
    },
    Preset {
        id: "icloud",
        name: "iCloud Mail",
        domains: &["icloud.com", "me.com", "mac.com"],
        imap_host: "imap.mail.me.com",
        smtp_host: "smtp.mail.me.com",
        credential_kind: CredentialKind::AppPassword,
    },
];

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

    if let Some(preset) = PRESETS
        .iter()
        .find(|preset| preset.domains.contains(&domain))
    {
        return ProviderDiscovery {
            contract_version: CONTRACT_VERSION.to_owned(),
            email: normalized,
            valid: true,
            matched: true,
            provider_id: Some(preset.id.to_owned()),
            provider_name: Some(preset.name.to_owned()),
            incoming: vec![Endpoint {
                protocol: Protocol::Imap,
                host: preset.imap_host.to_owned(),
                port: 993,
                security: TransportSecurity::ImplicitTls,
            }],
            outgoing: vec![Endpoint {
                protocol: Protocol::Smtp,
                host: preset.smtp_host.to_owned(),
                port: 465,
                security: TransportSecurity::ImplicitTls,
            }],
            credential_kind: Some(preset.credential_kind),
            guidance: vec![
                "Use a provider-issued app password or authorization code; never pass a primary password on the command line.".to_owned(),
                "Verify discovered endpoints before saving credentials.".to_owned(),
            ],
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
}
