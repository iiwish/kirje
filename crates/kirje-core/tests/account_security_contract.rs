use std::str::FromStr;

use kirje_core::{
    AccountBinding, AccountId, CredentialId, CredentialKind, Endpoint, MailAccountConfig,
    OwnerRealmId, PlatformLocationMaterial, Protocol, PublicCredentialState, StoreId,
    StoredCredentialState, TransportSecurity,
};
use uuid::Uuid;

const GOLDEN_BINDING_HEX: &str = "4b49524a452d4143434f554e542d42494e44494e472d563100000c00010000001443617365404578616d706c652e496e76616c696400020000000a436173652e4c6f67696e000300000001020010000000010100110000001501696d61702e6578616d706c652e696e76616c696400120000000203e100130000000101002000000001010021000000010200220000000c03323030313a6462383a3a3100230000000201d100240000000101";
const GOLDEN_BINDING_SHA256: &str =
    "b5eae4a61e4167da9657db2ab180b9a542c1f2afb8125fb750f2610b92f76ec8";
const GOLDEN_BINDING_WITHOUT_SMTP_HEX: &str = "4b49524a452d4143434f554e542d42494e44494e472d563100000c00010000001443617365404578616d706c652e496e76616c696400020000000a436173652e4c6f67696e000300000001020010000000010100110000001501696d61702e6578616d706c652e696e76616c696400120000000203e10013000000010100200000000100002100000000002200000000002300000000002400000000";
const GOLDEN_UNIX_LOCATION_HEX: &str = "4b49524a452d434f4e4649472d4c4f434154494f4e2d5631000004000100000001010010000000080000000000000007001100000008000000000000000900120000000d6163636f756e74732e746f6d6c";
const GOLDEN_WINDOWS_LOCATION_HEX: &str = "4b49524a452d434f4e4649472d4c4f434154494f4e2d5631000004000100000001020020000000080000000000000007002100000008000000000000000900220000001a4100630063006f0075006e00740073002e0074006f006d006c00";

fn account() -> MailAccountConfig {
    MailAccountConfig {
        id: "synthetic".to_owned(),
        email: "Case@Example.Invalid".to_owned(),
        username: "Case.Login".to_owned(),
        incoming: Endpoint {
            protocol: Protocol::Imap,
            host: "IMAP.Example.Invalid".to_owned(),
            port: 993,
            security: TransportSecurity::ImplicitTls,
        },
        outgoing: Some(Endpoint {
            protocol: Protocol::Smtp,
            host: "2001:0db8:0:0:0:0:0:1".to_owned(),
            port: 465,
            security: TransportSecurity::ImplicitTls,
        }),
        credential_kind: CredentialKind::AppPassword,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        },
    )
}

#[test]
fn account_binding_has_byte_and_digest_goldens() {
    let binding = AccountBinding::from_config(&account()).expect("valid account binding");
    assert_eq!(hex(binding.canonical_bytes()), GOLDEN_BINDING_HEX);
    assert_eq!(binding.sha256().to_string(), GOLDEN_BINDING_SHA256);

    let mut without_smtp = account();
    without_smtp.outgoing = None;
    assert_eq!(
        hex(AccountBinding::from_config(&without_smtp)
            .expect("binding without SMTP")
            .canonical_bytes()),
        GOLDEN_BINDING_WITHOUT_SMTP_HEX
    );
}

#[test]
fn every_account_binding_field_changes_or_invalidates_the_contract() {
    let baseline = AccountBinding::from_config(&account())
        .expect("baseline")
        .sha256();
    let mut mutations = Vec::new();

    let mut candidate = account();
    candidate.email = "case@Example.Invalid".to_owned();
    mutations.push(candidate);
    let mut candidate = account();
    candidate.username = "case.Login".to_owned();
    mutations.push(candidate);
    let mut candidate = account();
    candidate.credential_kind = CredentialKind::Password;
    mutations.push(candidate);
    let mut candidate = account();
    candidate.incoming.host = "mail.example.invalid".to_owned();
    mutations.push(candidate);
    let mut candidate = account();
    candidate.incoming.port = 143;
    mutations.push(candidate);
    let mut candidate = account();
    candidate.incoming.security = TransportSecurity::StartTls;
    mutations.push(candidate);
    let mut candidate = account();
    candidate.outgoing = None;
    mutations.push(candidate);
    let mut candidate = account();
    candidate.outgoing.as_mut().unwrap().host = "smtp.example.invalid".to_owned();
    mutations.push(candidate);
    let mut candidate = account();
    candidate.outgoing.as_mut().unwrap().port = 587;
    mutations.push(candidate);
    let mut candidate = account();
    candidate.outgoing.as_mut().unwrap().security = TransportSecurity::StartTls;
    mutations.push(candidate);

    for candidate in mutations {
        assert_ne!(
            AccountBinding::from_config(&candidate)
                .expect("valid mutation")
                .sha256(),
            baseline
        );
    }

    let mut invalid_incoming_protocol = account();
    invalid_incoming_protocol.incoming.protocol = Protocol::Jmap;
    assert!(AccountBinding::from_config(&invalid_incoming_protocol).is_err());

    let mut invalid_outgoing_protocol = account();
    invalid_outgoing_protocol
        .outgoing
        .as_mut()
        .unwrap()
        .protocol = Protocol::Imap;
    assert!(AccountBinding::from_config(&invalid_outgoing_protocol).is_err());
}

#[test]
fn host_normalization_is_narrow_and_identity_bytes_remain_exact() {
    let baseline = AccountBinding::from_config(&account()).expect("baseline");
    let mut equivalent = account();
    equivalent.incoming.host = "imap.example.invalid".to_owned();
    equivalent.outgoing.as_mut().unwrap().host = "2001:db8::1".to_owned();
    assert_eq!(
        AccountBinding::from_config(&equivalent).expect("equivalent hosts"),
        baseline
    );

    let mut changed_email = account();
    changed_email.email = "case@Example.Invalid".to_owned();
    assert_ne!(
        AccountBinding::from_config(&changed_email).unwrap(),
        baseline
    );
    let mut changed_username = account();
    changed_username.username = "case.Login".to_owned();
    assert_ne!(
        AccountBinding::from_config(&changed_username).unwrap(),
        baseline
    );
}

#[test]
fn stable_identities_reject_noncanonical_or_non_v4_text() {
    let canonical = "11111111-1111-4111-8111-111111111111";
    let v4 = Uuid::parse_str(canonical).unwrap();
    assert_eq!(StoreId::try_from(v4).unwrap().to_string(), canonical);
    assert_eq!(AccountId::from_str(canonical).unwrap().as_uuid(), v4);
    assert_eq!(CredentialId::from_str(canonical).unwrap().as_uuid(), v4);

    for invalid in [
        "11111111111141118111111111111111",
        "11111111-1111-4111-8111-11111111111A",
        "11111111-1111-1111-8111-111111111111",
    ] {
        assert!(StoreId::from_str(invalid).is_err(), "accepted {invalid}");
        assert!(serde_json::from_str::<AccountId>(&format!("\"{invalid}\"")).is_err());
    }

    let realm = OwnerRealmId::from_bytes([0x5a; 32]);
    assert_eq!(realm.as_bytes(), &[0x5a; 32]);
}

#[test]
fn platform_location_material_has_independent_byte_goldens() {
    let unix = PlatformLocationMaterial::Unix {
        parent_device: 7,
        parent_inode: 9,
        final_component: b"accounts.toml".to_vec(),
    };
    assert_eq!(
        hex(&unix.canonical_bytes().unwrap()),
        GOLDEN_UNIX_LOCATION_HEX
    );

    let windows = PlatformLocationMaterial::Windows {
        volume_serial: 7,
        parent_file_index: 9,
        final_component_utf16: "Accounts.toml".encode_utf16().collect(),
    };
    assert_eq!(
        hex(&windows.canonical_bytes().unwrap()),
        GOLDEN_WINDOWS_LOCATION_HEX
    );
}

#[test]
fn stored_and_public_credential_states_are_distinct() {
    assert_eq!(
        serde_json::to_string(&StoredCredentialState::Bound).unwrap(),
        "\"bound\""
    );
    assert_eq!(
        serde_json::to_string(&PublicCredentialState::StoreUnavailable).unwrap(),
        "\"store_unavailable\""
    );
    assert!(serde_json::from_str::<StoredCredentialState>("\"store_unavailable\"").is_err());
}
