//! Local account, credential, and mailbox orchestration for every Kirje interface.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use directories::ProjectDirs;
use kirje_core::{
    ConnectionReport, MailAccountConfig, MailError, MailErrorCode, MailboxPage, MailboxReader,
    MessageContent, MessagePage, MessageRead, MessageSearch,
};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

const CONFIG_VERSION: u16 = 1;
const KEYRING_SERVICE: &str = "dev.kirje.mail";
const MAX_ACCOUNTS: usize = 100;

/// Storage contract for non-secret account configuration.
pub trait AccountRepository: Send + Sync {
    /// List accounts in deterministic identifier order.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration error when storage cannot be read.
    fn list(&self) -> Result<Vec<MailAccountConfig>, MailError>;

    /// Look up one account.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration error when storage cannot be read.
    fn get(&self, account_id: &str) -> Result<Option<MailAccountConfig>, MailError>;

    /// Insert or replace one validated account using an atomic write.
    ///
    /// # Errors
    ///
    /// Returns a stable validation or configuration error.
    fn upsert(&self, account: MailAccountConfig) -> Result<(), MailError>;
}

/// Storage contract for credentials. Implementations must never expose values
/// through debug output or configuration serialization.
pub trait SecretStore: Send + Sync {
    /// Store a credential for one configured account.
    ///
    /// # Errors
    ///
    /// Returns a stable credential-store error when persistence fails.
    fn set(&self, account_id: &str, secret: &SecretString) -> Result<(), MailError>;

    /// Load a credential for an authenticated operation.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::SecretMissing`] when no value exists.
    fn get(&self, account_id: &str) -> Result<SecretString, MailError>;

    /// Check credential presence without returning the value.
    ///
    /// # Errors
    ///
    /// Returns a stable credential-store error when the store is unavailable.
    fn contains(&self, account_id: &str) -> Result<bool, MailError>;

    /// Delete a credential for one account.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::SecretMissing`] when no value exists or a
    /// stable credential-store error when deletion fails.
    fn delete(&self, account_id: &str) -> Result<(), MailError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ConfigDocument {
    version: u16,
    #[serde(default)]
    accounts: Vec<MailAccountConfig>,
}

impl Default for ConfigDocument {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            accounts: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TomlAccountRepository {
    path: PathBuf,
}

impl TomlAccountRepository {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Resolve the platform-native Kirje configuration path.
    ///
    /// # Errors
    ///
    /// Returns [`MailErrorCode::ConfigRead`] when the operating system does not
    /// expose a home/configuration directory.
    pub fn default_path() -> Result<PathBuf, MailError> {
        ProjectDirs::from("", "", "kirje")
            .map(|dirs| dirs.config_dir().join("accounts.toml"))
            .ok_or_else(|| {
                MailError::new(
                    MailErrorCode::ConfigRead,
                    "cannot determine the Kirje configuration directory",
                    false,
                )
            })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Result<ConfigDocument, MailError> {
        match fs::read_to_string(&self.path) {
            Ok(source) => {
                let document: ConfigDocument = toml::from_str(&source).map_err(|_| {
                    MailError::new(
                        MailErrorCode::ConfigRead,
                        "account configuration is invalid TOML",
                        false,
                    )
                })?;
                if document.version != CONFIG_VERSION {
                    return Err(MailError::new(
                        MailErrorCode::ConfigRead,
                        "account configuration version is unsupported",
                        false,
                    ));
                }
                if document.accounts.len() > MAX_ACCOUNTS {
                    return Err(MailError::new(
                        MailErrorCode::ResourceLimit,
                        "account configuration exceeds the 100-account limit",
                        false,
                    ));
                }
                for account in &document.accounts {
                    account.validate()?;
                }
                Ok(document)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ConfigDocument::default())
            }
            Err(_) => Err(MailError::new(
                MailErrorCode::ConfigRead,
                "cannot read account configuration",
                false,
            )),
        }
    }

    fn save(&self, document: &ConfigDocument) -> Result<(), MailError> {
        let parent = self.path.parent().ok_or_else(|| {
            MailError::new(
                MailErrorCode::ConfigWrite,
                "account configuration path has no parent directory",
                false,
            )
        })?;
        fs::create_dir_all(parent).map_err(|_| config_write_error())?;
        let serialized = toml::to_string_pretty(document).map_err(|_| config_write_error())?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(parent).map_err(|_| config_write_error())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| config_write_error())?;
        }

        temporary
            .write_all(serialized.as_bytes())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|_| config_write_error())?;
        temporary
            .persist(&self.path)
            .map_err(|_| config_write_error())?;
        Ok(())
    }
}

impl AccountRepository for TomlAccountRepository {
    fn list(&self) -> Result<Vec<MailAccountConfig>, MailError> {
        let mut accounts = self.load()?.accounts;
        accounts.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(accounts)
    }

    fn get(&self, account_id: &str) -> Result<Option<MailAccountConfig>, MailError> {
        Ok(self
            .load()?
            .accounts
            .into_iter()
            .find(|account| account.id == account_id))
    }

    fn upsert(&self, account: MailAccountConfig) -> Result<(), MailError> {
        account.validate()?;
        let mut document = self.load()?;
        if let Some(existing) = document
            .accounts
            .iter_mut()
            .find(|candidate| candidate.id == account.id)
        {
            *existing = account;
        } else {
            if document.accounts.len() >= MAX_ACCOUNTS {
                return Err(MailError::new(
                    MailErrorCode::ResourceLimit,
                    "account configuration cannot exceed 100 accounts",
                    false,
                ));
            }
            document.accounts.push(account);
        }
        document
            .accounts
            .sort_by(|left, right| left.id.cmp(&right.id));
        self.save(&document)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KeyringSecretStore;

impl KeyringSecretStore {
    #[must_use]
    pub fn available() -> bool {
        keyring::Entry::store_status().is_ok()
    }

    fn entry(account_id: &str) -> Result<keyring::Entry, MailError> {
        keyring::Entry::new(KEYRING_SERVICE, account_id).map_err(|_| secret_store_error())
    }
}

impl SecretStore for KeyringSecretStore {
    fn set(&self, account_id: &str, secret: &SecretString) -> Result<(), MailError> {
        Self::entry(account_id)?
            .set_password(secret.expose_secret())
            .map_err(|_| secret_store_error())
    }

    fn get(&self, account_id: &str) -> Result<SecretString, MailError> {
        Self::entry(account_id)?
            .get_password()
            .map(SecretString::from)
            .map_err(|error| match error {
                keyring::Error::NoEntry => MailError::new(
                    MailErrorCode::SecretMissing,
                    "no credential is stored for this account",
                    false,
                ),
                _ => secret_store_error(),
            })
    }

    fn contains(&self, account_id: &str) -> Result<bool, MailError> {
        match Self::entry(account_id)?.get_password() {
            Ok(_) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(_) => Err(secret_store_error()),
        }
    }

    fn delete(&self, account_id: &str) -> Result<(), MailError> {
        Self::entry(account_id)?
            .delete_credential()
            .map_err(|error| match error {
                keyring::Error::NoEntry => MailError::new(
                    MailErrorCode::SecretMissing,
                    "no credential is stored for this account",
                    false,
                ),
                _ => secret_store_error(),
            })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AccountStatus {
    pub account: MailAccountConfig,
    pub secret_present: bool,
}

#[derive(Clone)]
pub struct KirjeRuntime {
    accounts: Arc<dyn AccountRepository>,
    secrets: Arc<dyn SecretStore>,
    reader: Arc<dyn MailboxReader>,
}

impl KirjeRuntime {
    /// Build the production runtime using local TOML configuration, the OS
    /// credential store, and the Pimalaya IMAP adapter.
    ///
    /// # Errors
    ///
    /// Returns a configuration-path error when no default path is available.
    pub fn local(config_path: Option<PathBuf>) -> Result<Self, MailError> {
        let path = match config_path {
            Some(path) => path,
            None => TomlAccountRepository::default_path()?,
        };
        Ok(Self::new(
            Arc::new(TomlAccountRepository::new(path)),
            Arc::new(KeyringSecretStore),
            Arc::new(kirje_protocol::PimalayaImapReader),
        ))
    }

    #[must_use]
    pub fn new(
        accounts: Arc<dyn AccountRepository>,
        secrets: Arc<dyn SecretStore>,
        reader: Arc<dyn MailboxReader>,
    ) -> Self {
        Self {
            accounts,
            secrets,
            reader,
        }
    }

    /// Save a validated non-secret account configuration.
    ///
    /// # Errors
    ///
    /// Returns validation or configuration persistence errors.
    pub fn upsert_account(
        &self,
        account: MailAccountConfig,
    ) -> Result<MailAccountConfig, MailError> {
        self.accounts.upsert(account.clone())?;
        Ok(account)
    }

    /// List configured accounts without consulting the credential store.
    ///
    /// # Errors
    ///
    /// Returns configuration errors.
    pub fn list_accounts(&self) -> Result<Vec<MailAccountConfig>, MailError> {
        self.accounts.list()
    }

    /// Return status for one account without exposing its secret.
    ///
    /// # Errors
    ///
    /// Returns account, configuration, or credential-store errors.
    pub fn account_status(&self, account_id: &str) -> Result<AccountStatus, MailError> {
        let account = self.account(account_id)?;
        Ok(AccountStatus {
            secret_present: self.secrets.contains(account_id)?,
            account,
        })
    }

    /// Persist a secret in the OS credential store.
    ///
    /// # Errors
    ///
    /// Returns account lookup, validation, or credential-store errors.
    pub fn set_secret(&self, account_id: &str, secret: &SecretString) -> Result<(), MailError> {
        let _account = self.account(account_id)?;
        if secret.expose_secret().is_empty() || secret.expose_secret().len() > 16_384 {
            return Err(MailError::invalid_input(
                "credential must contain 1-16384 bytes",
            ));
        }
        self.secrets.set(account_id, secret)
    }

    /// Delete a secret from the OS credential store.
    ///
    /// # Errors
    ///
    /// Returns account lookup or credential-store errors.
    pub fn delete_secret(&self, account_id: &str) -> Result<(), MailError> {
        let _account = self.account(account_id)?;
        self.secrets.delete(account_id)
    }

    /// Authenticate to an account and report negotiated capabilities.
    ///
    /// # Errors
    ///
    /// Returns account, credential, network, TLS, authentication, or protocol errors.
    pub fn check_account(&self, account_id: &str) -> Result<ConnectionReport, MailError> {
        let (account, secret) = self.credentials(account_id)?;
        self.reader.check(&account, &secret)
    }

    /// List selectable mailboxes.
    ///
    /// # Errors
    ///
    /// Returns account, credential, or protocol-adapter errors.
    pub fn list_mailboxes(
        &self,
        account_id: &str,
        include_counts: bool,
    ) -> Result<MailboxPage, MailError> {
        let (account, secret) = self.credentials(account_id)?;
        let mailboxes = self
            .reader
            .list_mailboxes(&account, &secret, include_counts)?;
        Ok(MailboxPage {
            returned: u16::try_from(mailboxes.len()).unwrap_or(u16::MAX),
            mailboxes,
        })
    }

    /// Search one mailbox using structured bounded criteria.
    ///
    /// # Errors
    ///
    /// Returns account, credential, validation, or protocol-adapter errors.
    pub fn search_messages(&self, search: &MessageSearch) -> Result<MessagePage, MailError> {
        search.validate()?;
        let (account, secret) = self.credentials(&search.account_id)?;
        self.reader.search_messages(&account, &secret, search)
    }

    /// Read one scoped message without marking it seen.
    ///
    /// # Errors
    ///
    /// Returns account, credential, validation, or protocol-adapter errors.
    pub fn read_message(&self, read: &MessageRead) -> Result<MessageContent, MailError> {
        read.validate()?;
        let (account, secret) = self.credentials(&read.reference.account_id)?;
        self.reader.read_message(&account, &secret, read)
    }

    fn account(&self, account_id: &str) -> Result<MailAccountConfig, MailError> {
        self.accounts.get(account_id)?.ok_or_else(|| {
            MailError::new(
                MailErrorCode::AccountNotFound,
                "account is not configured",
                false,
            )
        })
    }

    fn credentials(
        &self,
        account_id: &str,
    ) -> Result<(MailAccountConfig, SecretString), MailError> {
        let account = self.account(account_id)?;
        let secret = self.secrets.get(account_id)?;
        Ok((account, secret))
    }
}

fn config_write_error() -> MailError {
    MailError::new(
        MailErrorCode::ConfigWrite,
        "cannot write account configuration",
        false,
    )
}

fn secret_store_error() -> MailError {
    MailError::new(
        MailErrorCode::SecretStoreUnavailable,
        "OS credential store is unavailable",
        false,
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Mutex};

    use kirje_core::{CredentialKind, Endpoint, Mailbox, Protocol, TransportSecurity};

    use super::*;

    #[derive(Default)]
    struct MemorySecrets(Mutex<BTreeMap<String, String>>);

    impl SecretStore for MemorySecrets {
        fn set(&self, account_id: &str, secret: &SecretString) -> Result<(), MailError> {
            self.0
                .lock()
                .expect("secret lock")
                .insert(account_id.to_owned(), secret.expose_secret().to_owned());
            Ok(())
        }

        fn get(&self, account_id: &str) -> Result<SecretString, MailError> {
            self.0
                .lock()
                .expect("secret lock")
                .get(account_id)
                .cloned()
                .map(SecretString::from)
                .ok_or_else(|| {
                    MailError::new(MailErrorCode::SecretMissing, "missing secret", false)
                })
        }

        fn contains(&self, account_id: &str) -> Result<bool, MailError> {
            Ok(self.0.lock().expect("secret lock").contains_key(account_id))
        }

        fn delete(&self, account_id: &str) -> Result<(), MailError> {
            self.0
                .lock()
                .expect("secret lock")
                .remove(account_id)
                .map(|_| ())
                .ok_or_else(|| {
                    MailError::new(MailErrorCode::SecretMissing, "missing secret", false)
                })
        }
    }

    #[derive(Default)]
    struct NoopReader;

    impl MailboxReader for NoopReader {
        fn check(
            &self,
            _account: &MailAccountConfig,
            _secret: &SecretString,
        ) -> Result<ConnectionReport, MailError> {
            unreachable!("not used")
        }

        fn list_mailboxes(
            &self,
            _account: &MailAccountConfig,
            _secret: &SecretString,
            _include_counts: bool,
        ) -> Result<Vec<Mailbox>, MailError> {
            unreachable!("not used")
        }

        fn search_messages(
            &self,
            _account: &MailAccountConfig,
            _secret: &SecretString,
            _search: &MessageSearch,
        ) -> Result<MessagePage, MailError> {
            unreachable!("not used")
        }

        fn read_message(
            &self,
            _account: &MailAccountConfig,
            _secret: &SecretString,
            _read: &MessageRead,
        ) -> Result<MessageContent, MailError> {
            unreachable!("not used")
        }
    }

    fn account() -> MailAccountConfig {
        MailAccountConfig {
            id: "work".to_owned(),
            email: "agent@163.com".to_owned(),
            username: "agent@163.com".to_owned(),
            incoming: Endpoint {
                protocol: Protocol::Imap,
                host: "imap.163.com".to_owned(),
                port: 993,
                security: TransportSecurity::ImplicitTls,
            },
            credential_kind: CredentialKind::AppPassword,
        }
    }

    #[test]
    fn config_round_trip_is_sorted_and_contains_no_secret() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("accounts.toml");
        let repository = TomlAccountRepository::new(path.clone());
        let mut second = account();
        second.id = "zeta".to_owned();
        repository.upsert(second).expect("save zeta");
        repository.upsert(account()).expect("save work");

        let accounts = repository.list().expect("load accounts");
        assert_eq!(accounts[0].id, "work");
        let source = fs::read_to_string(path).expect("read config");
        assert!(!source.contains("very-secret"));
        assert!(!source.contains("credential_value"));
    }

    #[test]
    fn runtime_reports_secret_presence_without_exposing_value() {
        let directory = tempfile::tempdir().expect("temp dir");
        let repository = Arc::new(TomlAccountRepository::new(
            directory.path().join("accounts.toml"),
        ));
        let secrets = Arc::new(MemorySecrets::default());
        let runtime = KirjeRuntime::new(repository, secrets, Arc::new(NoopReader));
        runtime.upsert_account(account()).expect("save account");
        runtime
            .set_secret("work", &SecretString::from("very-secret".to_owned()))
            .expect("save secret");

        let status = runtime.account_status("work").expect("status");
        let serialized = toml::to_string(&status.account).expect("serialize account");
        assert!(status.secret_present);
        assert!(!serialized.contains("very-secret"));
        runtime.delete_secret("work").expect("delete secret");
        assert!(
            !runtime
                .account_status("work")
                .expect("status")
                .secret_present
        );
    }

    #[test]
    fn missing_accounts_have_a_stable_error() {
        let directory = tempfile::tempdir().expect("temp dir");
        let runtime = KirjeRuntime::new(
            Arc::new(TomlAccountRepository::new(
                directory.path().join("accounts.toml"),
            )),
            Arc::new(MemorySecrets::default()),
            Arc::new(NoopReader),
        );

        assert_eq!(
            runtime.account_status("missing").unwrap_err().code,
            MailErrorCode::AccountNotFound
        );
    }
}
