//! Local account, credential, and mailbox orchestration for every Kirje interface.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use chrono::Utc;
use directories::ProjectDirs;
use kirje_core::{
    AttachmentContent, AttachmentRead, ConnectionReport, Draft, DraftInput, DraftSummary,
    LocalMessageSearch, MAX_OPERATION_LIMIT, MailAccountConfig, MailError, MailErrorCode,
    MailOperationKind, MailSender, MailboxMutator, MailboxOperationRequest, MailboxPage,
    MailboxReader, MailboxSpecialUse, MailboxSyncReport, MailboxSyncRequest, MailboxSyncState,
    MessageContent, MessageIndex, MessagePage, MessageRead, MessageSearch, OperationEvent,
    OperationLedger, OperationRecord, OperationSummary, Outbox, RemoteAttemptError,
    SendAttemptError, SendPlan, SendPlanSummary, SendReceipt, SendRequest, SyncCursor, digest_json,
    operation_record,
};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
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
        if keyring::Entry::store_status().is_err() {
            return false;
        }
        let Ok(probe) = keyring::Entry::new(KEYRING_SERVICE, "__kirje_readiness_probe__") else {
            return false;
        };
        matches!(probe.get_password(), Ok(_) | Err(keyring::Error::NoEntry))
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
    mutator: Arc<dyn MailboxMutator>,
    index: Arc<dyn MessageIndex>,
    outbox: Arc<dyn Outbox>,
    sender: Arc<dyn MailSender>,
}

impl KirjeRuntime {
    /// Build the production runtime using local TOML configuration, the OS
    /// credential store, and the Pimalaya IMAP adapter.
    ///
    /// # Errors
    ///
    /// Returns a configuration-path error when no default path is available.
    pub fn local(config_path: Option<PathBuf>) -> Result<Self, MailError> {
        Self::local_with_index(config_path, None)
    }

    /// Build the production runtime with an optional explicit `SQLite` index path.
    ///
    /// # Errors
    ///
    /// Returns stable configuration or store initialization errors.
    pub fn local_with_index(
        config_path: Option<PathBuf>,
        index_path: Option<PathBuf>,
    ) -> Result<Self, MailError> {
        Self::local_with_paths(config_path, index_path, None)
    }

    /// Build the production runtime with explicit local data paths.
    ///
    /// # Errors
    ///
    /// Returns stable configuration or store initialization errors.
    pub fn local_with_paths(
        config_path: Option<PathBuf>,
        index_path: Option<PathBuf>,
        outbox_path: Option<PathBuf>,
    ) -> Result<Self, MailError> {
        let custom_config = config_path.is_some();
        let path = match config_path {
            Some(path) => path,
            None => TomlAccountRepository::default_path()?,
        };
        let index_path = resolve_index_path(custom_config.then_some(path.as_path()), index_path)?;
        let outbox_path =
            resolve_outbox_path(custom_config.then_some(path.as_path()), outbox_path)?;
        Ok(Self::with_services_and_mutator(
            Arc::new(TomlAccountRepository::new(path)),
            Arc::new(KeyringSecretStore),
            Arc::new(kirje_protocol::PimalayaImapReader),
            Arc::new(kirje_protocol::PimalayaImapReader),
            Arc::new(kirje_store::SqliteMessageIndex::open(index_path)?),
            Arc::new(kirje_store::SqliteOutbox::open(outbox_path)?),
            Arc::new(kirje_protocol::LettreSmtpSender),
        ))
    }

    #[must_use]
    pub fn new(
        accounts: Arc<dyn AccountRepository>,
        secrets: Arc<dyn SecretStore>,
        reader: Arc<dyn MailboxReader>,
    ) -> Self {
        Self::with_index(accounts, secrets, reader, Arc::new(UnavailableMessageIndex))
    }

    #[must_use]
    pub fn with_index(
        accounts: Arc<dyn AccountRepository>,
        secrets: Arc<dyn SecretStore>,
        reader: Arc<dyn MailboxReader>,
        index: Arc<dyn MessageIndex>,
    ) -> Self {
        Self::with_services(
            accounts,
            secrets,
            reader,
            index,
            Arc::new(UnavailableOutbox),
            Arc::new(UnavailableSender),
        )
    }

    #[must_use]
    pub fn with_services(
        accounts: Arc<dyn AccountRepository>,
        secrets: Arc<dyn SecretStore>,
        reader: Arc<dyn MailboxReader>,
        index: Arc<dyn MessageIndex>,
        outbox: Arc<dyn Outbox>,
        sender: Arc<dyn MailSender>,
    ) -> Self {
        Self {
            accounts,
            secrets,
            reader,
            mutator: Arc::new(UnavailableMutator),
            index,
            outbox,
            sender,
        }
    }

    #[must_use]
    pub fn with_services_and_mutator(
        accounts: Arc<dyn AccountRepository>,
        secrets: Arc<dyn SecretStore>,
        reader: Arc<dyn MailboxReader>,
        mutator: Arc<dyn MailboxMutator>,
        index: Arc<dyn MessageIndex>,
        outbox: Arc<dyn Outbox>,
        sender: Arc<dyn MailSender>,
    ) -> Self {
        Self {
            accounts,
            secrets,
            reader,
            mutator,
            index,
            outbox,
            sender,
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
            untrusted: true,
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

    /// Synchronize one bounded mailbox metadata batch into the local index.
    ///
    /// # Errors
    ///
    /// Returns account, credential, protocol, validation, or store errors.
    pub fn sync_mailbox(
        &self,
        account_id: &str,
        mailbox: &str,
        limit: u16,
        refresh: bool,
    ) -> Result<MailboxSyncReport, MailError> {
        let previous = if refresh {
            None
        } else {
            self.index.state(account_id, mailbox)?
        };
        let cursor = previous.as_ref().map(|state| SyncCursor {
            uid_validity: state.uid_validity,
            highest_uid: state.highest_uid,
        });
        let request = MailboxSyncRequest {
            account_id: account_id.to_owned(),
            mailbox: mailbox.to_owned(),
            cursor,
            limit,
        };
        request.validate()?;
        let (account, secret) = self.credentials(account_id)?;
        let batch = self.reader.sync_mailbox(&account, &secret, &request)?;
        self.index
            .apply_sync(&batch, refresh || batch.reset_required)
    }

    /// Return local sync state without consulting credentials or the network.
    ///
    /// # Errors
    ///
    /// Returns account, validation, or store errors.
    pub fn index_status(
        &self,
        account_id: &str,
        mailbox: &str,
    ) -> Result<Option<MailboxSyncState>, MailError> {
        let _account = self.account(account_id)?;
        self.index.state(account_id, mailbox)
    }

    /// Search indexed metadata without consulting credentials or the network.
    ///
    /// # Errors
    ///
    /// Returns account, validation, or store errors.
    pub fn search_index(&self, search: &LocalMessageSearch) -> Result<MessagePage, MailError> {
        search.validate()?;
        let _account = self.account(&search.account_id)?;
        self.index.search(search)
    }

    /// Read one explicitly selected attachment without remote mailbox mutation.
    ///
    /// # Errors
    ///
    /// Returns account, credential, validation, protocol, or resource errors.
    pub fn read_attachment(&self, read: &AttachmentRead) -> Result<AttachmentContent, MailError> {
        read.validate()?;
        let (account, secret) = self.credentials(&read.reference.account_id)?;
        self.reader.read_attachment(&account, &secret, read)
    }

    /// Compose and persist one private local draft. The source snapshot, if
    /// present, is stored with the draft and never fetched implicitly.
    ///
    /// # Errors
    ///
    /// Returns account, validation, or local-ledger errors.
    pub fn create_draft(&self, input: DraftInput) -> Result<Draft, MailError> {
        let account = self.account(&input.account_id)?;
        let draft = Draft::create(input, &account.email, Utc::now())?;
        self.outbox.create_draft(&draft)
    }

    /// Return one draft, including its immutable attachment summaries.
    ///
    /// # Errors
    ///
    /// Returns a stable not-found or local-ledger error.
    pub fn draft(&self, draft_id: &str) -> Result<Draft, MailError> {
        self.outbox.get_draft(draft_id)?.ok_or_else(|| {
            MailError::new(
                MailErrorCode::SendPlanNotFound,
                "draft was not found",
                false,
            )
        })
    }

    /// List private drafts for one configured account.
    ///
    /// # Errors
    ///
    /// Returns account, validation, or local-ledger errors.
    pub fn list_drafts(
        &self,
        account_id: &str,
        limit: u16,
    ) -> Result<Vec<DraftSummary>, MailError> {
        let _account = self.account(account_id)?;
        self.outbox
            .list_drafts(account_id, limit)
            .map(|drafts| drafts.iter().map(Draft::summary).collect())
    }

    /// Replace a draft while preserving its local identity.
    ///
    /// # Errors
    ///
    /// Returns account, validation, state, or local-ledger errors.
    pub fn update_draft(&self, draft_id: &str, input: DraftInput) -> Result<Draft, MailError> {
        let account = self.account(&input.account_id)?;
        let existing = self.draft(draft_id)?;
        if existing.account_id != input.account_id {
            return Err(MailError::invalid_input(
                "draft account does not match the configured account",
            ));
        }
        let updated = existing.update(input, &account.email, Utc::now())?;
        self.outbox.update_draft(&updated)
    }

    /// Mark a draft discarded without deleting its audit record.
    ///
    /// # Errors
    ///
    /// Returns not-found, state, or local-ledger errors.
    pub fn discard_draft(&self, draft_id: &str) -> Result<Draft, MailError> {
        let _draft = self.draft(draft_id)?;
        self.outbox.discard_draft(draft_id, Utc::now())
    }

    /// Create an immutable send plan from an active private draft.
    ///
    /// # Errors
    ///
    /// Returns draft, account, validation, SMTP configuration, or local-ledger
    /// errors.
    pub fn plan_send_from_draft(&self, draft_id: &str) -> Result<SendPlan, MailError> {
        let draft = self.draft(draft_id)?;
        if draft.status != kirje_core::DraftStatus::Draft {
            return Err(MailError::new(
                MailErrorCode::SendPlanState,
                "discarded draft cannot become a send plan",
                false,
            ));
        }
        self.plan_send(draft.request)
    }

    /// Plan one exact governed IMAP mutation. Archive and safe-delete resolve
    /// only server-declared special-use mailboxes; no conventional names are guessed.
    ///
    /// # Errors
    ///
    /// Returns account, validation, special-use resolution, or local-ledger
    /// errors. Explicit destinations do not require credentials until apply.
    pub fn plan_mail_operation(
        &self,
        mut request: MailboxOperationRequest,
    ) -> Result<OperationRecord, MailError> {
        request.validate()?;
        if request.destination.is_none()
            && matches!(
                request.kind,
                MailOperationKind::Archive | MailOperationKind::Delete
            )
        {
            let account = self.account(&request.account_id)?;
            let secret = self.secrets.get(&request.account_id)?;
            let special_use = match request.kind {
                MailOperationKind::Archive => MailboxSpecialUse::Archive,
                MailOperationKind::Delete => MailboxSpecialUse::Trash,
                _ => unreachable!(),
            };
            request.destination = Some(
                self.reader
                    .special_mailbox(&account, &secret, special_use)?
                    .ok_or_else(|| MailError::invalid_input("server did not declare the requested special-use mailbox; provide --destination"))?,
            );
        }
        request.validate()?;
        let (payload_json, payload_sha256) = digest_json(&request)?;
        let mut record = operation_record(
            Uuid::new_v4().to_string(),
            mail_operation_kind_name(request.kind),
            request.account_id.clone(),
            payload_json,
            payload_sha256,
            Utc::now(),
        );
        record.message_id = Some(format!(
            "{}:{}",
            request.reference.mailbox, request.reference.uid
        ));
        self.outbox.create_operation(&record)
    }

    /// Read one governed IMAP operation and reconcile stale applying state.
    ///
    /// # Errors
    ///
    /// Returns validation, local-ledger, or not-found errors.
    pub fn mail_operation(&self, operation_id: &str) -> Result<OperationRecord, MailError> {
        self.outbox
            .get_operation(operation_id, Utc::now())?
            .ok_or_else(|| {
                MailError::new(
                    MailErrorCode::SendPlanNotFound,
                    "operation was not found",
                    false,
                )
            })
    }

    /// List bounded operation records for audit and operational inspection.
    ///
    /// # Errors
    ///
    /// Returns account, validation, or local-ledger errors.
    pub fn list_operations(
        &self,
        account_id: Option<&str>,
        kind: Option<&str>,
        limit: u16,
    ) -> Result<Vec<OperationSummary>, MailError> {
        if limit == 0 || limit > MAX_OPERATION_LIMIT {
            return Err(MailError::invalid_input(format!(
                "limit must be between 1 and {MAX_OPERATION_LIMIT}"
            )));
        }
        if let Some(account_id) = account_id {
            let _account = self.account(account_id)?;
        }
        self.outbox
            .list_operations(account_id, kind, limit, Utc::now())
            .map(|operations| operations.iter().map(OperationRecord::summary).collect())
    }

    /// Record interactive human approval for a send or IMAP operation.
    ///
    /// # Errors
    ///
    /// Returns validation, expiry, state, or local-ledger errors.
    pub fn approve_operation(&self, operation_id: &str) -> Result<OperationRecord, MailError> {
        self.outbox.approve_operation(operation_id, Utc::now())
    }

    /// Apply one approved governed IMAP operation at most once.
    ///
    /// # Errors
    ///
    /// Returns validation, credential, remote-operation, state, or local-ledger
    /// errors.
    pub fn apply_mail_operation(&self, operation_id: &str) -> Result<OperationRecord, MailError> {
        let pending = self.mail_operation(operation_id)?;
        if pending.kind == "send" || pending.kind == "draft" {
            return Err(MailError::new(
                MailErrorCode::SendPlanState,
                "operation is not an IMAP mailbox mutation",
                false,
            ));
        }
        let claimed = self.outbox.claim_operation(operation_id, Utc::now())?;
        let operation: MailboxOperationRequest = match serde_json::from_str(&claimed.payload_json) {
            Ok(operation) => operation,
            Err(_) => {
                return self.outbox.fail_operation(
                    operation_id,
                    MailError::new(
                        MailErrorCode::StoreRead,
                        "stored operation payload is invalid",
                        false,
                    ),
                    Utc::now(),
                );
            }
        };
        if claimed.kind != mail_operation_kind_name(operation.kind)
            || claimed.account_id != operation.account_id
        {
            return self.outbox.fail_operation(
                operation_id,
                MailError::new(
                    MailErrorCode::StoreRead,
                    "stored operation payload does not match its ledger record",
                    false,
                ),
                Utc::now(),
            );
        }
        let (account, secret) = match self.credentials(&operation.account_id) {
            Ok(credentials) => credentials,
            Err(error) => return self.outbox.fail_operation(operation_id, error, Utc::now()),
        };
        match self
            .mutator
            .apply(&account, &secret, operation_id, &operation)
        {
            Ok(receipt) => {
                let (receipt_json, _) = digest_json(&receipt)?;
                self.outbox
                    .succeed_operation(operation_id, receipt_json, Utc::now())
            }
            Err(RemoteAttemptError {
                error,
                mutation_started: true,
            }) => self
                .outbox
                .ambiguous_operation(operation_id, error, Utc::now()),
            Err(RemoteAttemptError {
                error,
                mutation_started: false,
            }) => self.outbox.fail_operation(operation_id, error, Utc::now()),
        }
    }

    /// Return the append-only audit trail for one operation.
    ///
    /// # Errors
    ///
    /// Returns validation or local-ledger errors.
    pub fn operation_audit(
        &self,
        operation_id: &str,
        limit: u16,
    ) -> Result<Vec<OperationEvent>, MailError> {
        self.outbox.audit(operation_id, limit)
    }

    /// Validate and persist a credential-free immutable send plan.
    ///
    /// # Errors
    ///
    /// Returns account, validation, or outbox errors.
    pub fn plan_send(&self, request: SendRequest) -> Result<SendPlan, MailError> {
        request.validate()?;
        let account = self.account(&request.account_id)?;
        account.validate()?;
        if account.outgoing.is_none() {
            return Err(MailError::invalid_input(
                "account has no SMTP endpoint; update its account configuration",
            ));
        }
        let plan = SendPlan::create(request, Utc::now())?;
        self.outbox.create(&plan)
    }

    /// Return one send plan, reconciling local expiry and stale applying state.
    ///
    /// # Errors
    ///
    /// Returns validation, store, or not-found errors.
    pub fn send_plan(&self, plan_id: &str) -> Result<SendPlan, MailError> {
        self.outbox.get(plan_id, Utc::now())?.ok_or_else(|| {
            MailError::new(
                MailErrorCode::SendPlanNotFound,
                "send plan was not found",
                false,
            )
        })
    }

    /// List bounded send-plan summaries without bodies.
    ///
    /// # Errors
    ///
    /// Returns validation or store errors.
    pub fn list_send_plans(
        &self,
        account_id: Option<&str>,
        limit: u16,
    ) -> Result<Vec<SendPlanSummary>, MailError> {
        if let Some(account_id) = account_id {
            let _account = self.account(account_id)?;
        }
        self.outbox.list(account_id, limit, Utc::now())
    }

    /// Record local human approval for an immutable plan.
    ///
    /// This service does not decide interactivity; only the CLI calls it after
    /// enforcing a TTY confirmation. MCP intentionally has no approval tool.
    ///
    /// # Errors
    ///
    /// Returns not-found, expired, invalid-state, or store errors.
    pub fn approve_send(&self, plan_id: &str) -> Result<SendPlan, MailError> {
        self.outbox.approve(plan_id, Utc::now())
    }

    /// Claim and apply an approved plan once.
    ///
    /// SMTP errors after invocation are recorded as ambiguous and never retried.
    /// Pre-invocation failures are recorded as failed.
    ///
    /// # Errors
    ///
    /// Returns state or outbox errors. Delivery failures are returned as a
    /// persisted terminal plan so callers can inspect certainty.
    pub fn apply_send(&self, plan_id: &str) -> Result<SendPlan, MailError> {
        let claimed = self.outbox.claim(plan_id, Utc::now())?;
        let credentials = self.credentials(&claimed.request.account_id);
        let (account, secret) = match credentials {
            Ok(credentials) => credentials,
            Err(error) => {
                return self.outbox.mark_failed(plan_id, error, Utc::now());
            }
        };
        match self.sender.send(&account, &secret, &claimed) {
            Ok(receipt) => self.outbox.mark_sent(plan_id, receipt),
            Err(SendAttemptError {
                error,
                delivery_started: true,
            }) => self.outbox.mark_ambiguous(plan_id, error, Utc::now()),
            Err(SendAttemptError {
                error,
                delivery_started: false,
            }) => self.outbox.mark_failed(plan_id, error, Utc::now()),
        }
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

fn mail_operation_kind_name(kind: MailOperationKind) -> &'static str {
    match kind {
        MailOperationKind::SetRead => "set_read",
        MailOperationKind::SetStarred => "set_starred",
        MailOperationKind::Move => "move",
        MailOperationKind::Archive => "archive",
        MailOperationKind::Delete => "delete",
    }
}

/// Resolve an explicit, config-colocated, or platform-native index path.
///
/// # Errors
///
/// Returns a stable store error when the platform data directory is unavailable.
pub fn resolve_index_path(
    config_path: Option<&Path>,
    explicit_index: Option<PathBuf>,
) -> Result<PathBuf, MailError> {
    if let Some(path) = explicit_index {
        return Ok(path);
    }
    if let Some(config_path) = config_path
        && let Some(parent) = config_path.parent()
    {
        return Ok(parent.join("index.sqlite3"));
    }
    ProjectDirs::from("", "", "kirje")
        .map(|dirs| dirs.data_local_dir().join("index.sqlite3"))
        .ok_or_else(|| {
            MailError::new(
                MailErrorCode::StoreRead,
                "cannot determine the Kirje data directory",
                false,
            )
        })
}

/// Resolve an explicit, config-colocated, or platform-native outbox path.
///
/// # Errors
///
/// Returns a stable store error when the platform data directory is unavailable.
pub fn resolve_outbox_path(
    config_path: Option<&Path>,
    explicit_outbox: Option<PathBuf>,
) -> Result<PathBuf, MailError> {
    if let Some(path) = explicit_outbox {
        return Ok(path);
    }
    if let Some(config_path) = config_path
        && let Some(parent) = config_path.parent()
    {
        return Ok(parent.join("outbox.sqlite3"));
    }
    ProjectDirs::from("", "", "kirje")
        .map(|dirs| dirs.data_local_dir().join("outbox.sqlite3"))
        .ok_or_else(|| {
            MailError::new(
                MailErrorCode::StoreRead,
                "cannot determine the Kirje data directory",
                false,
            )
        })
}

struct UnavailableMutator;

impl MailboxMutator for UnavailableMutator {
    fn apply(
        &self,
        _account: &MailAccountConfig,
        _secret: &SecretString,
        _operation_id: &str,
        _operation: &kirje_core::MailboxOperationRequest,
    ) -> Result<kirje_core::MailboxOperationReceipt, RemoteAttemptError> {
        Err(RemoteAttemptError::before_mutation(MailError::new(
            MailErrorCode::Network,
            "IMAP mutation service is not configured",
            false,
        )))
    }
}

struct UnavailableMessageIndex;

struct UnavailableOutbox;

impl OperationLedger for UnavailableOutbox {
    fn create_operation(&self, _operation: &OperationRecord) -> Result<OperationRecord, MailError> {
        Err(outbox_unavailable())
    }

    fn get_operation(
        &self,
        _operation_id: &str,
        _now: chrono::DateTime<Utc>,
    ) -> Result<Option<OperationRecord>, MailError> {
        Err(outbox_unavailable())
    }

    fn list_operations(
        &self,
        _account_id: Option<&str>,
        _kind: Option<&str>,
        _limit: u16,
        _now: chrono::DateTime<Utc>,
    ) -> Result<Vec<OperationRecord>, MailError> {
        Err(outbox_unavailable())
    }

    fn approve_operation(
        &self,
        _operation_id: &str,
        _now: chrono::DateTime<Utc>,
    ) -> Result<OperationRecord, MailError> {
        Err(outbox_unavailable())
    }

    fn claim_operation(
        &self,
        _operation_id: &str,
        _now: chrono::DateTime<Utc>,
    ) -> Result<OperationRecord, MailError> {
        Err(outbox_unavailable())
    }

    fn succeed_operation(
        &self,
        _operation_id: &str,
        _receipt_json: String,
        _now: chrono::DateTime<Utc>,
    ) -> Result<OperationRecord, MailError> {
        Err(outbox_unavailable())
    }

    fn fail_operation(
        &self,
        _operation_id: &str,
        _error: MailError,
        _now: chrono::DateTime<Utc>,
    ) -> Result<OperationRecord, MailError> {
        Err(outbox_unavailable())
    }

    fn ambiguous_operation(
        &self,
        _operation_id: &str,
        _error: MailError,
        _now: chrono::DateTime<Utc>,
    ) -> Result<OperationRecord, MailError> {
        Err(outbox_unavailable())
    }

    fn audit(&self, _operation_id: &str, _limit: u16) -> Result<Vec<OperationEvent>, MailError> {
        Err(outbox_unavailable())
    }

    fn create_draft(&self, _draft: &Draft) -> Result<Draft, MailError> {
        Err(outbox_unavailable())
    }

    fn get_draft(&self, _draft_id: &str) -> Result<Option<Draft>, MailError> {
        Err(outbox_unavailable())
    }

    fn list_drafts(&self, _account_id: &str, _limit: u16) -> Result<Vec<Draft>, MailError> {
        Err(outbox_unavailable())
    }

    fn update_draft(&self, _draft: &Draft) -> Result<Draft, MailError> {
        Err(outbox_unavailable())
    }

    fn discard_draft(
        &self,
        _draft_id: &str,
        _now: chrono::DateTime<Utc>,
    ) -> Result<Draft, MailError> {
        Err(outbox_unavailable())
    }
}

impl Outbox for UnavailableOutbox {
    fn create(&self, _plan: &SendPlan) -> Result<SendPlan, MailError> {
        Err(outbox_unavailable())
    }
    fn get(
        &self,
        _plan_id: &str,
        _now: chrono::DateTime<Utc>,
    ) -> Result<Option<SendPlan>, MailError> {
        Err(outbox_unavailable())
    }
    fn list(
        &self,
        _account_id: Option<&str>,
        _limit: u16,
        _now: chrono::DateTime<Utc>,
    ) -> Result<Vec<SendPlanSummary>, MailError> {
        Err(outbox_unavailable())
    }
    fn approve(&self, _plan_id: &str, _now: chrono::DateTime<Utc>) -> Result<SendPlan, MailError> {
        Err(outbox_unavailable())
    }
    fn claim(&self, _plan_id: &str, _now: chrono::DateTime<Utc>) -> Result<SendPlan, MailError> {
        Err(outbox_unavailable())
    }
    fn mark_sent(&self, _plan_id: &str, _receipt: SendReceipt) -> Result<SendPlan, MailError> {
        Err(outbox_unavailable())
    }
    fn mark_failed(
        &self,
        _plan_id: &str,
        _error: MailError,
        _now: chrono::DateTime<Utc>,
    ) -> Result<SendPlan, MailError> {
        Err(outbox_unavailable())
    }
    fn mark_ambiguous(
        &self,
        _plan_id: &str,
        _error: MailError,
        _now: chrono::DateTime<Utc>,
    ) -> Result<SendPlan, MailError> {
        Err(outbox_unavailable())
    }
}

struct UnavailableSender;

impl MailSender for UnavailableSender {
    fn send(
        &self,
        _account: &MailAccountConfig,
        _secret: &SecretString,
        _plan: &SendPlan,
    ) -> Result<SendReceipt, SendAttemptError> {
        Err(SendAttemptError::before_delivery(outbox_unavailable()))
    }
}

impl MessageIndex for UnavailableMessageIndex {
    fn state(
        &self,
        _account_id: &str,
        _mailbox: &str,
    ) -> Result<Option<MailboxSyncState>, MailError> {
        Err(index_unavailable())
    }

    fn apply_sync(
        &self,
        _batch: &kirje_core::MailboxSyncBatch,
        _replace: bool,
    ) -> Result<MailboxSyncReport, MailError> {
        Err(index_unavailable())
    }

    fn search(&self, _search: &LocalMessageSearch) -> Result<MessagePage, MailError> {
        Err(index_unavailable())
    }
}

fn index_unavailable() -> MailError {
    MailError::new(
        MailErrorCode::StoreRead,
        "local message index is not configured",
        false,
    )
}

fn outbox_unavailable() -> MailError {
    MailError::new(
        MailErrorCode::StoreRead,
        "local send outbox is not configured",
        false,
    )
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
    use std::{
        collections::BTreeMap,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use chrono::{TimeZone as _, Utc};
    use kirje_core::{
        CredentialKind, Endpoint, MailAddress, MailOperationKind, MailSender, Mailbox,
        MailboxMutator, MailboxOperationReceipt, MailboxOperationRequest, MailboxSyncBatch,
        MessageEnvelope, MessageReference, Protocol, RemoteAttemptError, SendAttemptError,
        SendPlan, SendPlanStatus, SendReceipt, SendRequest, TransportSecurity,
    };

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

        fn sync_mailbox(
            &self,
            _account: &MailAccountConfig,
            _secret: &SecretString,
            _request: &MailboxSyncRequest,
        ) -> Result<kirje_core::MailboxSyncBatch, MailError> {
            unreachable!("not used")
        }

        fn read_attachment(
            &self,
            _account: &MailAccountConfig,
            _secret: &SecretString,
            _read: &AttachmentRead,
        ) -> Result<AttachmentContent, MailError> {
            unreachable!("not used")
        }
    }

    #[derive(Default)]
    struct SyncReader(Mutex<Vec<Option<SyncCursor>>>);

    impl MailboxReader for SyncReader {
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

        fn sync_mailbox(
            &self,
            _account: &MailAccountConfig,
            _secret: &SecretString,
            request: &MailboxSyncRequest,
        ) -> Result<MailboxSyncBatch, MailError> {
            self.0
                .lock()
                .expect("sync lock")
                .push(request.cursor.clone());
            let uid = request
                .cursor
                .as_ref()
                .and_then(|cursor| cursor.highest_uid)
                .map_or(10, |uid| uid + 1);
            Ok(MailboxSyncBatch {
                account_id: request.account_id.clone(),
                mailbox: request.mailbox.clone(),
                uid_validity: 7,
                messages: vec![message(uid)],
                remote_total: Some(u64::from(uid)),
                has_more: false,
                reset_required: false,
            })
        }

        fn read_attachment(
            &self,
            _account: &MailAccountConfig,
            _secret: &SecretString,
            _read: &AttachmentRead,
        ) -> Result<AttachmentContent, MailError> {
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
            outgoing: Some(Endpoint {
                protocol: Protocol::Smtp,
                host: "smtp.163.com".to_owned(),
                port: 465,
                security: TransportSecurity::ImplicitTls,
            }),
            credential_kind: CredentialKind::AppPassword,
        }
    }

    #[derive(Default)]
    struct RecordingSender {
        calls: AtomicUsize,
        ambiguous: bool,
    }

    impl MailSender for RecordingSender {
        fn send(
            &self,
            _account: &MailAccountConfig,
            _secret: &SecretString,
            _plan: &SendPlan,
        ) -> Result<SendReceipt, SendAttemptError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.ambiguous {
                Err(SendAttemptError::after_delivery_started(MailError::new(
                    MailErrorCode::Network,
                    "unknown SMTP result",
                    true,
                )))
            } else {
                Ok(SendReceipt {
                    accepted: true,
                    server_response: Some("250 accepted".to_owned()),
                    sent_at: Utc::now(),
                })
            }
        }
    }

    #[derive(Default)]
    struct RecordingMutator {
        calls: AtomicUsize,
    }

    impl MailboxMutator for RecordingMutator {
        fn apply(
            &self,
            _account: &MailAccountConfig,
            _secret: &SecretString,
            operation_id: &str,
            operation: &MailboxOperationRequest,
        ) -> Result<MailboxOperationReceipt, RemoteAttemptError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(MailboxOperationReceipt {
                operation_id: operation_id.to_owned(),
                kind: operation.kind,
                account_id: operation.account_id.clone(),
                reference: operation.reference.clone(),
                destination: operation.destination.clone(),
                changed: true,
                applied_at: Utc::now(),
                untrusted: true,
            })
        }
    }

    fn send_request() -> SendRequest {
        SendRequest {
            account_id: "work".to_owned(),
            to: vec![MailAddress {
                name: None,
                email: "agent@163.com".to_owned(),
            }],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: "Runtime send".to_owned(),
            text: Some("body".to_owned()),
            html: None,
            attachments: Vec::new(),
        }
    }

    fn send_runtime(
        directory: &tempfile::TempDir,
        secrets: Arc<MemorySecrets>,
        sender: Arc<RecordingSender>,
    ) -> KirjeRuntime {
        let accounts = Arc::new(TomlAccountRepository::new(
            directory.path().join("accounts.toml"),
        ));
        accounts.upsert(account()).expect("account");
        KirjeRuntime::with_services(
            accounts,
            secrets,
            Arc::new(NoopReader),
            Arc::new(
                kirje_store::SqliteMessageIndex::open(directory.path().join("index.sqlite3"))
                    .expect("index"),
            ),
            Arc::new(
                kirje_store::SqliteOutbox::open(directory.path().join("outbox.sqlite3"))
                    .expect("outbox"),
            ),
            sender,
        )
    }

    fn mailbox_runtime(
        directory: &tempfile::TempDir,
        secrets: Arc<MemorySecrets>,
        mutator: Arc<RecordingMutator>,
    ) -> KirjeRuntime {
        let accounts = Arc::new(TomlAccountRepository::new(
            directory.path().join("accounts.toml"),
        ));
        accounts.upsert(account()).expect("account");
        KirjeRuntime::with_services_and_mutator(
            accounts,
            secrets,
            Arc::new(NoopReader),
            mutator,
            Arc::new(
                kirje_store::SqliteMessageIndex::open(directory.path().join("index.sqlite3"))
                    .expect("index"),
            ),
            Arc::new(
                kirje_store::SqliteOutbox::open(directory.path().join("outbox.sqlite3"))
                    .expect("outbox"),
            ),
            Arc::new(RecordingSender::default()),
        )
    }

    #[test]
    fn planning_is_local_and_apply_is_at_most_once() {
        let directory = tempfile::tempdir().expect("temp dir");
        let secrets = Arc::new(MemorySecrets::default());
        secrets
            .set("work", &SecretString::from("secret"))
            .expect("secret");
        let sender = Arc::new(RecordingSender::default());
        let runtime = send_runtime(&directory, secrets, sender.clone());

        let planned = runtime.plan_send(send_request()).expect("plan");
        assert_eq!(planned.status, SendPlanStatus::Planned);
        runtime.approve_send(&planned.id).expect("approve");
        let sent = runtime.apply_send(&planned.id).expect("apply");
        assert_eq!(sent.status, SendPlanStatus::Sent);
        assert_eq!(sender.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            runtime.apply_send(&planned.id).unwrap_err().code,
            MailErrorCode::SendPlanState
        );
        assert_eq!(sender.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failure_after_smtp_invocation_becomes_ambiguous() {
        let directory = tempfile::tempdir().expect("temp dir");
        let secrets = Arc::new(MemorySecrets::default());
        secrets
            .set("work", &SecretString::from("secret"))
            .expect("secret");
        let sender = Arc::new(RecordingSender {
            calls: AtomicUsize::new(0),
            ambiguous: true,
        });
        let runtime = send_runtime(&directory, secrets, sender.clone());
        let planned = runtime.plan_send(send_request()).expect("plan");
        runtime.approve_send(&planned.id).expect("approve");

        let result = runtime.apply_send(&planned.id).expect("record ambiguity");
        assert_eq!(result.status, SendPlanStatus::Ambiguous);
        assert_eq!(sender.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            runtime.apply_send(&planned.id).unwrap_err().code,
            MailErrorCode::SendPlanState
        );
    }

    #[test]
    fn drafts_and_mail_operations_use_the_shared_runtime_services() {
        let directory = tempfile::tempdir().expect("temp dir");
        let secrets = Arc::new(MemorySecrets::default());
        secrets
            .set("work", &SecretString::from("secret"))
            .expect("secret");
        let mutator = Arc::new(RecordingMutator::default());
        let runtime = mailbox_runtime(&directory, secrets, mutator.clone());

        let draft = runtime
            .create_draft(kirje_core::DraftInput {
                account_id: "work".to_owned(),
                mode: kirje_core::DraftMode::New,
                source: None,
                to: vec![MailAddress {
                    name: None,
                    email: "recipient@example.com".to_owned(),
                }],
                cc: Vec::new(),
                bcc: Vec::new(),
                subject: Some("Local draft".to_owned()),
                text: Some("body".to_owned()),
                html: None,
                attachments: Vec::new(),
            })
            .expect("draft");
        assert_eq!(runtime.list_drafts("work", 10).expect("list").len(), 1);
        runtime.discard_draft(&draft.id).expect("discard");

        let operation = runtime
            .plan_mail_operation(MailboxOperationRequest {
                account_id: "work".to_owned(),
                kind: MailOperationKind::Move,
                reference: MessageReference {
                    account_id: "work".to_owned(),
                    mailbox: "INBOX".to_owned(),
                    uid_validity: Some(7),
                    uid: 42,
                },
                value: None,
                destination: Some("Archive".to_owned()),
            })
            .expect("operation");
        runtime.approve_operation(&operation.id).expect("approve");
        let applied = runtime.apply_mail_operation(&operation.id).expect("apply");
        assert_eq!(applied.status, kirje_core::OperationStatus::Succeeded);
        assert_eq!(mutator.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            runtime
                .apply_mail_operation(&operation.id)
                .unwrap_err()
                .code,
            MailErrorCode::SendPlanState
        );
    }

    #[test]
    fn explicit_mail_operation_planning_does_not_need_a_credential() {
        let directory = tempfile::tempdir().expect("temp dir");
        let runtime = mailbox_runtime(
            &directory,
            Arc::new(MemorySecrets::default()),
            Arc::new(RecordingMutator::default()),
        );
        let operation = runtime
            .plan_mail_operation(MailboxOperationRequest {
                account_id: "work".to_owned(),
                kind: MailOperationKind::SetStarred,
                reference: MessageReference {
                    account_id: "work".to_owned(),
                    mailbox: "INBOX".to_owned(),
                    uid_validity: Some(7),
                    uid: 42,
                },
                value: Some(true),
                destination: None,
            })
            .expect("local plan");
        assert_eq!(operation.status, kirje_core::OperationStatus::Planned);
    }

    #[test]
    fn missing_secret_fails_without_invoking_smtp() {
        let directory = tempfile::tempdir().expect("temp dir");
        let sender = Arc::new(RecordingSender::default());
        let runtime = send_runtime(
            &directory,
            Arc::new(MemorySecrets::default()),
            sender.clone(),
        );
        let planned = runtime.plan_send(send_request()).expect("plan");
        runtime.approve_send(&planned.id).expect("approve");

        let result = runtime.apply_send(&planned.id).expect("record failure");
        assert_eq!(result.status, SendPlanStatus::Failed);
        assert_eq!(
            result.last_error.expect("error").code,
            MailErrorCode::SecretMissing
        );
        assert_eq!(sender.calls.load(Ordering::SeqCst), 0);
    }

    fn message(uid: u32) -> MessageEnvelope {
        MessageEnvelope {
            reference: MessageReference {
                account_id: "work".to_owned(),
                mailbox: "INBOX".to_owned(),
                uid_validity: Some(7),
                uid,
            },
            message_id: Some(format!("{uid}@example.com")),
            in_reply_to: Vec::new(),
            subject: format!("Message {uid}"),
            from: vec![MailAddress {
                name: None,
                email: "alice@example.com".to_owned(),
            }],
            to: Vec::new(),
            sent_at: Utc.with_ymd_and_hms(2026, 8, 26, 0, 0, 0).single(),
            size: 10,
            is_read: false,
            is_starred: false,
            has_attachment: Some(false),
            truncated: false,
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

    #[test]
    fn local_index_search_does_not_read_credentials() {
        let directory = tempfile::tempdir().expect("temp dir");
        let repository = Arc::new(TomlAccountRepository::new(
            directory.path().join("accounts.toml"),
        ));
        repository.upsert(account()).expect("account");
        let index = Arc::new(
            kirje_store::SqliteMessageIndex::open(directory.path().join("index.sqlite3"))
                .expect("index"),
        );
        let runtime = KirjeRuntime::with_index(
            repository,
            Arc::new(MemorySecrets::default()),
            Arc::new(NoopReader),
            index,
        );
        let page = runtime
            .search_index(&LocalMessageSearch {
                account_id: "work".to_owned(),
                mailbox: "INBOX".to_owned(),
                from: None,
                to: None,
                subject: None,
                unread: None,
                limit: 10,
            })
            .expect("offline search");
        assert!(page.messages.is_empty());
    }

    #[test]
    fn repeated_sync_passes_the_persisted_high_water_cursor() {
        let directory = tempfile::tempdir().expect("temp dir");
        let repository = Arc::new(TomlAccountRepository::new(
            directory.path().join("accounts.toml"),
        ));
        repository.upsert(account()).expect("account");
        let secrets = Arc::new(MemorySecrets::default());
        secrets
            .set("work", &SecretString::from("secret".to_owned()))
            .expect("secret");
        let reader = Arc::new(SyncReader::default());
        let runtime = KirjeRuntime::with_index(
            repository,
            secrets,
            reader.clone(),
            Arc::new(
                kirje_store::SqliteMessageIndex::open(directory.path().join("index.sqlite3"))
                    .expect("index"),
            ),
        );

        runtime
            .sync_mailbox("work", "INBOX", 20, false)
            .expect("initial sync");
        let report = runtime
            .sync_mailbox("work", "INBOX", 20, false)
            .expect("incremental sync");
        let refreshed = runtime
            .sync_mailbox("work", "INBOX", 20, true)
            .expect("refresh sync");

        let cursors = reader.0.lock().expect("sync lock");
        assert!(cursors[0].is_none());
        assert_eq!(
            cursors[1].as_ref().and_then(|cursor| cursor.highest_uid),
            Some(10)
        );
        assert!(cursors[2].is_none());
        assert_eq!(report.state.highest_uid, Some(11));
        assert_eq!(report.state.indexed_messages, 2);
        assert!(refreshed.reset);
        assert_eq!(refreshed.state.highest_uid, Some(10));
        assert_eq!(refreshed.state.indexed_messages, 1);
    }
}
