use std::{
    fs,
    io::{self, IsTerminal as _, Read as _},
    path::PathBuf,
    process::ExitCode,
};

use anyhow::Context as _;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use clap::{Parser, Subcommand, ValueEnum};
use kirje_core::{
    AttachmentRead, CONTRACT_VERSION, CredentialKind, DraftInput, Endpoint, LocalMessageSearch,
    MailAccountConfig, MailError, MailErrorCode, MailboxOperationRequest, MessageRead,
    MessageReference, MessageSearch, Protocol, SendAttachment, SendRequest, TransportSecurity,
    discover_account, find_provider_preset, provider_registry,
};
use kirje_runtime::{
    AccountRepository, KeyringSecretStore, KirjeRuntime, TomlAccountRepository, resolve_index_path,
    resolve_outbox_path,
};
use secrecy::SecretString;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

#[derive(Parser)]
#[command(
    name = "kirje",
    version,
    about = "Local-first email runtime for AI agents"
)]
struct Cli {
    /// Indent JSON output for human inspection.
    #[arg(long, global = true)]
    pretty: bool,

    /// Override the platform-native account configuration path.
    #[arg(long, global = true, env = "KIRJE_CONFIG")]
    config: Option<PathBuf>,

    /// Override the local `SQLite` message index path.
    #[arg(long, global = true, env = "KIRJE_INDEX")]
    index: Option<PathBuf>,

    /// Override the private local `SQLite` send outbox path.
    #[arg(long, global = true, env = "KIRJE_OUTBOX")]
    outbox: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the stable machine contract exposed by this binary.
    Schema,
    /// Inspect local runtime readiness without accessing a mailbox.
    Doctor,
    /// Discover, configure, and inspect email accounts.
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    /// Inspect the built-in, source-backed provider preset registry.
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    /// Manage credentials through the OS credential store.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Inspect remote mailboxes without modifying them.
    Mailbox {
        #[command(subcommand)]
        command: MailboxCommand,
    },
    /// Search and read messages without modifying them.
    Message {
        #[command(subcommand)]
        command: MessageCommand,
    },
    /// Explicitly synchronize mailbox metadata into the local index.
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },
    /// Read explicitly selected attachment content without modifying mail.
    Attachment {
        #[command(subcommand)]
        command: AttachmentCommand,
    },
    /// Plan, inspect, approve, and apply governed email sends.
    Send {
        #[command(subcommand)]
        command: SendCommand,
    },
    /// Compose and manage private local drafts.
    Draft {
        #[command(subcommand)]
        command: DraftCommand,
    },
    /// Plan, approve, apply, and audit governed remote operations.
    Operation {
        #[command(subcommand)]
        command: OperationCommand,
    },
    /// Run protocol adapters for agent harnesses.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
}

#[derive(Subcommand)]
enum AccountCommand {
    /// Discover safe provider settings without accepting credentials.
    Discover { email: String },
    /// Save a non-secret IMAP account configuration.
    Add {
        id: String,
        email: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        imap_host: Option<String>,
        #[arg(long)]
        imap_port: Option<u16>,
        #[arg(long)]
        security: Option<SecurityArg>,
        #[arg(long)]
        smtp_host: Option<String>,
        #[arg(long)]
        smtp_port: Option<u16>,
        #[arg(long)]
        smtp_security: Option<SecurityArg>,
        #[arg(long)]
        credential_kind: Option<CredentialArg>,
    },
    /// List configured accounts without credentials.
    List,
    /// Inspect one account and credential presence.
    Status { account_id: String },
    /// Verify TLS, IMAP negotiation, and authentication.
    Check { account_id: String },
}

#[derive(Subcommand)]
enum ProviderCommand {
    /// List the bounded built-in provider profiles.
    List,
    /// Show one provider profile by profile id or mailbox domain.
    Show { selector: String },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Prompt for and store a credential. Interactive terminal input is required.
    Set { account_id: String },
    /// Delete a stored credential after interactive account-bound confirmation.
    Delete { account_id: String },
}

#[derive(Subcommand)]
enum MailboxCommand {
    /// List selectable mailboxes for an account.
    List {
        #[arg(long)]
        account: String,
        #[arg(long)]
        counts: bool,
    },
}

#[derive(Subcommand)]
enum MessageCommand {
    /// Search bounded message metadata using structured fields.
    Search {
        #[arg(long)]
        account: String,
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        unread: Option<bool>,
        #[arg(long, default_value_t = kirje_core::DEFAULT_MESSAGE_LIMIT)]
        limit: u16,
    },
    /// Search indexed envelope metadata without network or credentials.
    SearchLocal {
        #[arg(long)]
        account: String,
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        unread: Option<bool>,
        #[arg(long, default_value_t = kirje_core::DEFAULT_MESSAGE_LIMIT)]
        limit: u16,
    },
    /// Read one scoped message using IMAP BODY.PEEK.
    Read {
        #[arg(long)]
        account: String,
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        uid_validity: Option<u32>,
        #[arg(long, default_value_t = kirje_core::DEFAULT_BODY_CHARS)]
        max_body_chars: u32,
    },
}

#[derive(Subcommand)]
enum SyncCommand {
    /// Fetch one bounded metadata batch and transactionally update the index.
    Run {
        #[arg(long)]
        account: String,
        #[arg(long)]
        mailbox: String,
        #[arg(long, default_value_t = kirje_core::DEFAULT_SYNC_LIMIT)]
        limit: u16,
        /// Rebuild the indexed newest window for this mailbox.
        #[arg(long)]
        refresh: bool,
    },
    /// Inspect local mailbox coverage without network or credentials.
    Status {
        #[arg(long)]
        account: String,
        #[arg(long)]
        mailbox: String,
    },
}

#[derive(Subcommand)]
enum AttachmentCommand {
    /// Import a bounded local file as a sendable attachment snapshot.
    Import {
        path: PathBuf,
        #[arg(long)]
        filename: Option<String>,
        #[arg(long)]
        mime_type: String,
    },
    /// Read one server-returned attachment id as bounded untrusted base64.
    Read {
        #[arg(long)]
        account: String,
        #[arg(long)]
        mailbox: String,
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        uid_validity: Option<u32>,
        #[arg(long)]
        part_id: String,
        #[arg(long, default_value_t = kirje_core::DEFAULT_ATTACHMENT_BYTES)]
        max_bytes: u32,
    },
}

#[derive(Subcommand)]
enum SendCommand {
    /// Create an immutable local send plan from bounded JSON input.
    Plan {
        /// JSON file path, or '-' to read from stdin.
        #[arg(long)]
        input: String,
    },
    /// Create an immutable send plan from one active private draft.
    FromDraft { draft_id: String },
    /// Inspect one full immutable plan and its current state.
    Show { plan_id: String },
    /// List bounded plan summaries without message bodies.
    List {
        #[arg(long)]
        account: Option<String>,
        #[arg(long, default_value_t = kirje_core::DEFAULT_SEND_PLAN_LIMIT)]
        limit: u16,
    },
    /// Approve one exact plan in an interactive human terminal.
    Approve { plan_id: String },
    /// Apply an already approved plan at most once.
    Apply { plan_id: String },
}

#[derive(Subcommand)]
enum DraftCommand {
    /// Create a private draft from bounded JSON input.
    Create {
        /// JSON file path, or '-' to read from stdin.
        #[arg(long)]
        input: String,
    },
    /// Inspect one private draft.
    Show { draft_id: String },
    /// List bounded private drafts for one account.
    List {
        #[arg(long)]
        account: String,
        #[arg(long, default_value_t = kirje_core::DEFAULT_OPERATION_LIMIT)]
        limit: u16,
    },
    /// Replace a private draft while preserving its id.
    Update {
        draft_id: String,
        #[arg(long)]
        input: String,
    },
    /// Discard a private draft while retaining its audit record.
    Discard { draft_id: String },
}

#[derive(Subcommand)]
enum OperationCommand {
    /// Create a governed remote-operation record from bounded JSON input.
    Plan {
        /// JSON file path, or '-' to read from stdin.
        #[arg(long)]
        input: String,
    },
    /// Inspect one operation and its certainty state.
    Show { operation_id: String },
    /// List bounded operation records.
    List {
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = kirje_core::DEFAULT_OPERATION_LIMIT)]
        limit: u16,
    },
    /// Approve one exact operation in an interactive human terminal.
    Approve { operation_id: String },
    /// Apply one already-approved operation at most once.
    Apply { operation_id: String },
    /// Read the append-only audit trail for one operation.
    Audit {
        operation_id: String,
        #[arg(long, default_value_t = kirje_core::DEFAULT_OPERATION_LIMIT)]
        limit: u16,
    },
}

#[derive(Subcommand)]
enum McpCommand {
    /// Start the typed MCP server over standard input/output.
    Serve,
}

#[derive(Clone, Copy, ValueEnum)]
enum SecurityArg {
    ImplicitTls,
    StartTls,
}

impl From<SecurityArg> for TransportSecurity {
    fn from(value: SecurityArg) -> Self {
        match value {
            SecurityArg::ImplicitTls => Self::ImplicitTls,
            SecurityArg::StartTls => Self::StartTls,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CredentialArg {
    AppPassword,
    Password,
}

impl From<CredentialArg> for CredentialKind {
    fn from(value: CredentialArg) -> Self {
        match value {
            CredentialArg::AppPassword => Self::AppPassword,
            CredentialArg::Password => Self::Password,
        }
    }
}

#[derive(Serialize)]
struct Envelope {
    contract_version: &'static str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<MailError>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct DoctorReport {
    name: &'static str,
    version: &'static str,
    interfaces: [&'static str; 2],
    default_mode: &'static str,
    safety: SafetyReport,
    config: FileStatus,
    configured_accounts: usize,
    index: FileStatus,
    outbox: FileStatus,
    credential_store: &'static str,
    credential_store_backend_available: bool,
    credential_store_operation_check: &'static str,
}

#[derive(Serialize)]
struct SafetyReport {
    exposed_remote_write_tools: bool,
    local_index_write_tools: bool,
    human_send_approval_required: bool,
}

#[derive(Serialize)]
struct FileStatus {
    path: String,
    exists: bool,
}

#[derive(Serialize)]
struct CommandContract {
    name: &'static str,
    safety: &'static str,
    output: &'static str,
}

#[derive(Serialize)]
struct SchemaReport {
    name: &'static str,
    version: &'static str,
    commands: Vec<CommandContract>,
    stable_exit_codes: Vec<ExitCodeContract>,
}

#[derive(Serialize)]
struct ExitCodeContract {
    code: u8,
    meaning: &'static str,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{error}");
            let pretty = std::env::args().any(|argument| argument == "--pretty");
            let _ = print_error(
                MailError::invalid_input("invalid command arguments; inspect `kirje schema`"),
                pretty,
            );
            return ExitCode::from(2);
        }
    };
    let pretty = cli.pretty;
    match run(cli).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("kirje: {error:#}");
            let _ = print_error(
                MailError::new(
                    MailErrorCode::Internal,
                    "Kirje could not complete the local operation",
                    false,
                ),
                pretty,
            );
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    if matches!(
        cli.command,
        Command::Mcp {
            command: McpCommand::Serve
        }
    ) {
        kirje_mcp::serve_stdio(cli.config, cli.index, cli.outbox)
            .await
            .context("MCP stdio server stopped unexpectedly")?;
        return Ok(ExitCode::SUCCESS);
    }

    let result = execute_local(&cli);
    match result {
        Ok(value) => {
            print_success(value, cli.pretty)?;
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            let exit = if error.code == MailErrorCode::InvalidInput {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            };
            print_error(error, cli.pretty)?;
            Ok(exit)
        }
    }
}

fn execute_local(cli: &Cli) -> Result<Value, MailError> {
    match &cli.command {
        Command::Schema => json_value(schema_report()),
        Command::Doctor => json_value(doctor_report(
            cli.config.clone(),
            cli.index.clone(),
            cli.outbox.clone(),
        )?),
        Command::Account { command } => handle_account(cli, command),
        Command::Provider { command } => handle_provider(command),
        Command::Secret { command } => handle_secret(cli, command),
        Command::Mailbox { command } => handle_mailbox(cli, command),
        Command::Message { command } => handle_message(cli, command),
        Command::Sync { command } => handle_sync(cli, command),
        Command::Attachment { command } => handle_attachment(cli, command),
        Command::Send { command } => handle_send(cli, command),
        Command::Draft { command } => handle_draft(cli, command),
        Command::Operation { command } => handle_operation(cli, command),
        Command::Mcp { .. } => unreachable!("MCP command handled before local dispatch"),
    }
}

fn handle_provider(command: &ProviderCommand) -> Result<Value, MailError> {
    match command {
        ProviderCommand::List => {
            let registry = provider_registry();
            json_value(serde_json::json!({
                "schema_version": registry.schema_version,
                "updated_at": registry.updated_at,
                "returned": registry.providers.len(),
                "providers": registry.providers.iter().map(|preset| serde_json::json!({
                    "id": preset.id,
                    "provider_id": preset.provider_id,
                    "name": preset.name,
                    "domains": preset.domains,
                })).collect::<Vec<_>>()
            }))
        }
        ProviderCommand::Show { selector } => find_provider_preset(selector)
            .ok_or_else(|| MailError::invalid_input("provider preset was not found"))
            .and_then(json_value),
    }
}

fn handle_account(cli: &Cli, command: &AccountCommand) -> Result<Value, MailError> {
    match command {
        AccountCommand::Discover { email } => {
            let result = discover_account(email);
            if !result.valid {
                return Err(MailError::invalid_input("email address is malformed"));
            }
            json_value(result)
        }
        AccountCommand::Add {
            id,
            email,
            username,
            imap_host,
            imap_port,
            security,
            smtp_host,
            smtp_port,
            smtp_security,
            credential_kind,
        } => {
            let account = build_account(
                id,
                email,
                username.as_deref(),
                imap_host.as_deref(),
                *imap_port,
                *security,
                smtp_host.as_deref(),
                *smtp_port,
                *smtp_security,
                *credential_kind,
            )?;
            json_value(runtime(cli)?.upsert_account(account)?)
        }
        AccountCommand::List => json_value(runtime(cli)?.list_accounts()?),
        AccountCommand::Status { account_id } => {
            json_value(runtime(cli)?.account_status(account_id)?)
        }
        AccountCommand::Check { account_id } => {
            json_value(runtime(cli)?.check_account(account_id)?)
        }
    }
}

fn handle_secret(cli: &Cli, command: &SecretCommand) -> Result<Value, MailError> {
    match command {
        SecretCommand::Set { account_id } => {
            require_interactive_secret_terminal()?;
            let secret = rpassword::prompt_password("Credential: ").map_err(|_| {
                MailError::new(
                    MailErrorCode::SecretStoreUnavailable,
                    "cannot read credential from the terminal",
                    false,
                )
            })?;
            runtime(cli)?.set_secret(account_id, &SecretString::from(secret))?;
            json_value(serde_json::json!({
                "account_id": account_id,
                "stored": true
            }))
        }
        SecretCommand::Delete { account_id } => {
            require_interactive_secret_terminal()?;
            let confirmation = rpassword::prompt_password(format!(
                "Type account id '{account_id}' to delete its credential: "
            ))
            .map_err(|_| {
                MailError::new(
                    MailErrorCode::SecretStoreUnavailable,
                    "cannot read confirmation from the terminal",
                    false,
                )
            })?;
            if confirmation != *account_id {
                return Err(MailError::invalid_input(
                    "credential deletion confirmation did not match the account id",
                ));
            }
            runtime(cli)?.delete_secret(account_id)?;
            json_value(serde_json::json!({
                "account_id": account_id,
                "stored": false
            }))
        }
    }
}

fn handle_mailbox(cli: &Cli, command: &MailboxCommand) -> Result<Value, MailError> {
    match command {
        MailboxCommand::List { account, counts } => {
            json_value(runtime(cli)?.list_mailboxes(account, *counts)?)
        }
    }
}

fn handle_message(cli: &Cli, command: &MessageCommand) -> Result<Value, MailError> {
    match command {
        MessageCommand::Search {
            account,
            mailbox,
            from,
            to,
            subject,
            text,
            unread,
            limit,
        } => json_value(runtime(cli)?.search_messages(&MessageSearch {
            account_id: account.clone(),
            mailbox: mailbox.clone(),
            from: from.clone(),
            to: to.clone(),
            subject: subject.clone(),
            text: text.clone(),
            unread: *unread,
            limit: *limit,
        })?),
        MessageCommand::Read {
            account,
            mailbox,
            uid,
            uid_validity,
            max_body_chars,
        } => json_value(runtime(cli)?.read_message(&MessageRead {
            reference: MessageReference {
                account_id: account.clone(),
                mailbox: mailbox.clone(),
                uid_validity: *uid_validity,
                uid: *uid,
            },
            max_body_chars: *max_body_chars,
        })?),
        MessageCommand::SearchLocal {
            account,
            mailbox,
            from,
            to,
            subject,
            unread,
            limit,
        } => json_value(runtime(cli)?.search_index(&LocalMessageSearch {
            account_id: account.clone(),
            mailbox: mailbox.clone(),
            from: from.clone(),
            to: to.clone(),
            subject: subject.clone(),
            unread: *unread,
            limit: *limit,
        })?),
    }
}

fn handle_sync(cli: &Cli, command: &SyncCommand) -> Result<Value, MailError> {
    match command {
        SyncCommand::Run {
            account,
            mailbox,
            limit,
            refresh,
        } => json_value(runtime(cli)?.sync_mailbox(account, mailbox, *limit, *refresh)?),
        SyncCommand::Status { account, mailbox } => {
            json_value(runtime(cli)?.index_status(account, mailbox)?)
        }
    }
}

fn handle_attachment(cli: &Cli, command: &AttachmentCommand) -> Result<Value, MailError> {
    match command {
        AttachmentCommand::Import {
            path,
            filename,
            mime_type,
        } => import_attachment(path, filename.as_deref(), mime_type),
        AttachmentCommand::Read {
            account,
            mailbox,
            uid,
            uid_validity,
            part_id,
            max_bytes,
        } => json_value(runtime(cli)?.read_attachment(&AttachmentRead {
            reference: MessageReference {
                account_id: account.clone(),
                mailbox: mailbox.clone(),
                uid_validity: *uid_validity,
                uid: *uid,
            },
            part_id: part_id.clone(),
            max_bytes: *max_bytes,
        })?),
    }
}

fn import_attachment(
    path: &PathBuf,
    filename: Option<&str>,
    mime_type: &str,
) -> Result<Value, MailError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| MailError::invalid_input("cannot read attachment file metadata"))?;
    if !metadata.file_type().is_file() {
        return Err(MailError::invalid_input(
            "attachment import requires a regular file",
        ));
    }
    if metadata.len() > kirje_core::MAX_SEND_ATTACHMENT_BYTES as u64 {
        return Err(MailError::new(
            MailErrorCode::ResourceLimit,
            format!(
                "each imported attachment cannot exceed {} bytes",
                kirje_core::MAX_SEND_ATTACHMENT_BYTES
            ),
            false,
        ));
    }
    let bytes =
        fs::read(path).map_err(|_| MailError::invalid_input("cannot read attachment file"))?;
    let default_filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| MailError::invalid_input("attachment filename is not valid UTF-8"))?;
    let attachment = SendAttachment {
        filename: filename.unwrap_or(default_filename).to_owned(),
        mime_type: mime_type.to_owned(),
        content_base64: BASE64_STANDARD.encode(bytes),
    };
    let summary = attachment.summary()?;
    json_value(serde_json::json!({
        "attachment": attachment,
        "summary": summary,
        "untrusted": true,
    }))
}

fn handle_send(cli: &Cli, command: &SendCommand) -> Result<Value, MailError> {
    match command {
        SendCommand::Plan { input } => {
            let request = read_send_request(input)?;
            json_value(runtime(cli)?.plan_send(request)?)
        }
        SendCommand::FromDraft { draft_id } => {
            json_value(runtime(cli)?.plan_send_from_draft(draft_id)?)
        }
        SendCommand::Show { plan_id } => json_value(runtime(cli)?.send_plan(plan_id)?),
        SendCommand::List { account, limit } => {
            json_value(runtime(cli)?.list_send_plans(account.as_deref(), *limit)?)
        }
        SendCommand::Approve { plan_id } => {
            require_interactive_approval_terminal()?;
            let runtime = runtime(cli)?;
            let plan = runtime.send_plan(plan_id)?;
            let review = serde_json::to_string_pretty(&serde_json::json!({
                "account_id": plan.request.account_id,
                "to": plan.request.to,
                "cc": plan.request.cc,
                "bcc": plan.request.bcc,
                "subject": plan.request.subject,
                "text": plan.request.text,
                "html": plan.request.html,
                "attachment_summaries": plan.attachment_summaries,
            }))
            .map_err(|_| {
                MailError::new(MailErrorCode::Internal, "cannot render send plan", false)
            })?;
            eprintln!(
                "Review immutable send plan {} (sha256 {}):\n{}",
                plan.id, plan.content_sha256, review
            );
            let confirmation =
                rpassword::prompt_password(format!("Type plan id '{}' to approve: ", plan.id))
                    .map_err(|_| {
                        MailError::new(
                            MailErrorCode::InvalidInput,
                            "cannot read approval from the terminal",
                            false,
                        )
                    })?;
            if confirmation != plan.id {
                return Err(MailError::invalid_input(
                    "send approval did not match the plan id",
                ));
            }
            json_value(runtime.approve_send(plan_id)?)
        }
        SendCommand::Apply { plan_id } => json_value(runtime(cli)?.apply_send(plan_id)?),
    }
}

const MAX_SEND_INPUT_BYTES: u64 = 12 * 1024 * 1024;
const MAX_OPERATION_INPUT_BYTES: u64 = 600 * 1024;
const MAX_DRAFT_INPUT_BYTES: u64 = 12 * 1024 * 1024;

fn read_send_request(input: &str) -> Result<SendRequest, MailError> {
    let request: SendRequest = read_json_input(input, MAX_SEND_INPUT_BYTES, "send request")?;
    request.validate()?;
    Ok(request)
}

fn handle_draft(cli: &Cli, command: &DraftCommand) -> Result<Value, MailError> {
    match command {
        DraftCommand::Create { input } => {
            let draft: DraftInput = read_json_input(input, MAX_DRAFT_INPUT_BYTES, "draft input")?;
            json_value(runtime(cli)?.create_draft(draft)?)
        }
        DraftCommand::Show { draft_id } => json_value(runtime(cli)?.draft(draft_id)?),
        DraftCommand::List { account, limit } => {
            json_value(runtime(cli)?.list_drafts(account, *limit)?)
        }
        DraftCommand::Update { draft_id, input } => {
            let draft: DraftInput = read_json_input(input, MAX_DRAFT_INPUT_BYTES, "draft input")?;
            json_value(runtime(cli)?.update_draft(draft_id, draft)?)
        }
        DraftCommand::Discard { draft_id } => json_value(runtime(cli)?.discard_draft(draft_id)?),
    }
}

fn handle_operation(cli: &Cli, command: &OperationCommand) -> Result<Value, MailError> {
    match command {
        OperationCommand::Plan { input } => {
            let request: MailboxOperationRequest =
                read_json_input(input, MAX_OPERATION_INPUT_BYTES, "operation input")?;
            json_value(runtime(cli)?.plan_mail_operation(request)?)
        }
        OperationCommand::Show { operation_id } => {
            json_value(runtime(cli)?.mail_operation(operation_id)?)
        }
        OperationCommand::List {
            account,
            kind,
            limit,
        } => json_value(runtime(cli)?.list_operations(
            account.as_deref(),
            kind.as_deref(),
            *limit,
        )?),
        OperationCommand::Approve { operation_id } => {
            require_interactive_approval_terminal()?;
            let runtime = runtime(cli)?;
            let operation = runtime.mail_operation(operation_id)?;
            let review = serde_json::to_string_pretty(&operation).map_err(|_| {
                MailError::new(MailErrorCode::Internal, "cannot render operation", false)
            })?;
            eprintln!(
                "Review immutable operation {} (sha256 {}):\n{}",
                operation.id, operation.payload_sha256, review
            );
            let confirmation = rpassword::prompt_password(format!(
                "Type operation id '{}' to approve: ",
                operation.id
            ))
            .map_err(|_| {
                MailError::new(
                    MailErrorCode::InvalidInput,
                    "cannot read approval from the terminal",
                    false,
                )
            })?;
            if confirmation != operation.id {
                return Err(MailError::invalid_input(
                    "operation approval did not match the operation id",
                ));
            }
            json_value(runtime.approve_operation(operation_id)?)
        }
        OperationCommand::Apply { operation_id } => {
            json_value(runtime(cli)?.apply_mail_operation(operation_id)?)
        }
        OperationCommand::Audit {
            operation_id,
            limit,
        } => json_value(runtime(cli)?.operation_audit(operation_id, *limit)?),
    }
}

fn read_json_input<T: DeserializeOwned>(
    input: &str,
    max_bytes: u64,
    label: &str,
) -> Result<T, MailError> {
    let bytes = if input == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .take(max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| MailError::invalid_input(format!("cannot read {label} from stdin")))?;
        bytes
    } else {
        let metadata = fs::metadata(input)
            .map_err(|_| MailError::invalid_input(format!("cannot read {label} file")))?;
        if !metadata.is_file() || metadata.len() > max_bytes {
            return Err(MailError::new(
                MailErrorCode::ResourceLimit,
                format!("{label} file exceeds the configured input limit"),
                false,
            ));
        }
        fs::read(input)
            .map_err(|_| MailError::invalid_input(format!("cannot read {label} file")))?
    };
    if bytes.len() as u64 > max_bytes {
        return Err(MailError::new(
            MailErrorCode::ResourceLimit,
            format!("{label} exceeds the configured input limit"),
            false,
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| MailError::invalid_input(format!("{label} must be valid JSON")))
}

fn runtime(cli: &Cli) -> Result<KirjeRuntime, MailError> {
    KirjeRuntime::local_with_paths(cli.config.clone(), cli.index.clone(), cli.outbox.clone())
}

fn require_interactive_secret_terminal() -> Result<(), MailError> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(MailError::invalid_input(
            "secret operations require an interactive terminal; credentials are never accepted as arguments or piped stdin",
        ));
    }
    Ok(())
}

fn require_interactive_approval_terminal() -> Result<(), MailError> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(MailError::invalid_input(
            "send approval requires an interactive human terminal and is unavailable through piped stdin",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_account(
    id: &str,
    email: &str,
    username: Option<&str>,
    imap_host: Option<&str>,
    imap_port: Option<u16>,
    security: Option<SecurityArg>,
    smtp_host: Option<&str>,
    smtp_port: Option<u16>,
    smtp_security: Option<SecurityArg>,
    credential_kind: Option<CredentialArg>,
) -> Result<MailAccountConfig, MailError> {
    let discovery = discover_account(email);
    if !discovery.valid {
        return Err(MailError::invalid_input("email address is malformed"));
    }
    let discovered_endpoint = discovery.incoming.first();
    let discovered_outgoing = discovery.outgoing.first();
    let host = imap_host
        .map(str::to_owned)
        .or_else(|| discovered_endpoint.map(|endpoint| endpoint.host.clone()))
        .ok_or_else(|| {
            MailError::invalid_input("unknown providers require an explicit --imap-host")
        })?;
    let port = imap_port
        .or_else(|| discovered_endpoint.map(|endpoint| endpoint.port))
        .ok_or_else(|| {
            MailError::invalid_input("unknown providers require an explicit --imap-port")
        })?;
    let transport = security
        .map(TransportSecurity::from)
        .or_else(|| discovered_endpoint.map(|endpoint| endpoint.security))
        .ok_or_else(|| MailError::invalid_input("unknown providers require explicit --security"))?;
    let credential = credential_kind
        .map(CredentialKind::from)
        .or(discovery.credential_kind)
        .ok_or_else(|| {
            MailError::invalid_input("unknown providers require explicit --credential-kind")
        })?;

    let outgoing_requested = smtp_host.is_some() || smtp_port.is_some() || smtp_security.is_some();
    let outgoing = if discovered_outgoing.is_some() || outgoing_requested {
        let smtp_host = smtp_host
            .map(str::to_owned)
            .or_else(|| discovered_outgoing.map(|endpoint| endpoint.host.clone()))
            .ok_or_else(|| {
                MailError::invalid_input("unknown providers require an explicit --smtp-host")
            })?;
        let smtp_port = smtp_port
            .or_else(|| discovered_outgoing.map(|endpoint| endpoint.port))
            .ok_or_else(|| {
                MailError::invalid_input("unknown providers require an explicit --smtp-port")
            })?;
        let smtp_security = smtp_security
            .map(TransportSecurity::from)
            .or_else(|| discovered_outgoing.map(|endpoint| endpoint.security))
            .ok_or_else(|| {
                MailError::invalid_input("unknown providers require explicit --smtp-security")
            })?;
        Some(Endpoint {
            protocol: Protocol::Smtp,
            host: smtp_host,
            port: smtp_port,
            security: smtp_security,
        })
    } else {
        None
    };

    let account = MailAccountConfig {
        id: id.to_owned(),
        email: email.trim().to_ascii_lowercase(),
        username: username.unwrap_or(email).to_owned(),
        incoming: Endpoint {
            protocol: Protocol::Imap,
            host,
            port,
            security: transport,
        },
        outgoing,
        credential_kind: credential,
    };
    account.validate()?;
    Ok(account)
}

fn doctor_report(
    config: Option<PathBuf>,
    index: Option<PathBuf>,
    outbox: Option<PathBuf>,
) -> Result<DoctorReport, MailError> {
    let custom_config = config.is_some();
    let path = match config {
        Some(path) => path,
        None => TomlAccountRepository::default_path()?,
    };
    let index_path = resolve_index_path(custom_config.then_some(path.as_path()), index)?;
    let outbox_path = resolve_outbox_path(custom_config.then_some(path.as_path()), outbox)?;
    let configured_accounts = TomlAccountRepository::new(path.clone()).list()?.len();
    Ok(DoctorReport {
        name: "kirje",
        version: env!("CARGO_PKG_VERSION"),
        interfaces: ["cli", "mcp_stdio"],
        default_mode: "governed_send",
        safety: SafetyReport {
            exposed_remote_write_tools: true,
            local_index_write_tools: true,
            human_send_approval_required: true,
        },
        config: FileStatus {
            exists: path.exists(),
            path: path.display().to_string(),
        },
        configured_accounts,
        index: FileStatus {
            exists: index_path.exists(),
            path: index_path.display().to_string(),
        },
        outbox: FileStatus {
            exists: outbox_path.exists(),
            path: outbox_path.display().to_string(),
        },
        credential_store: "os_native",
        credential_store_backend_available: KeyringSecretStore::available(),
        credential_store_operation_check: "use_secret_set_or_account_status",
    })
}

fn schema_report() -> SchemaReport {
    SchemaReport {
        name: "kirje",
        version: env!("CARGO_PKG_VERSION"),
        commands: vec![
            command("schema", "read_only", "command contract"),
            command("doctor", "local_read_only", "runtime readiness"),
            command(
                "account discover <email>",
                "read_only_no_credentials",
                "provider discovery",
            ),
            command(
                "provider list|show <id-or-domain>",
                "local_read_only",
                "source-backed provider presets",
            ),
            command(
                "account add|list|status|check",
                "local_config_or_remote_read_only",
                "account state",
            ),
            command(
                "secret set|delete <account-id>",
                "interactive_local_secret_write",
                "credential presence only",
            ),
            command("mailbox list", "remote_read_only", "mailbox metadata"),
            command(
                "message search|read",
                "remote_read_only_bounded_untrusted",
                "message metadata or sanitized content",
            ),
            command(
                "message search-local",
                "local_read_only_bounded_untrusted",
                "indexed message metadata",
            ),
            command(
                "sync run|status",
                "remote_read_only_local_index_write",
                "sync report or local coverage",
            ),
            command(
                "attachment import|read",
                "local_import_or_remote_read_only_bounded_untrusted",
                "attachment snapshot or base64 attachment content",
            ),
            command(
                "send plan|from-draft|show|list",
                "local_outbox",
                "immutable plan or bounded summary",
            ),
            command(
                "send approve <plan-id>",
                "interactive_human_local_write",
                "approved immutable plan",
            ),
            command(
                "send apply <plan-id>",
                "approved_remote_write_at_most_once",
                "terminal send state",
            ),
            command(
                "draft create|show|list|update|discard",
                "private_local_draft",
                "draft content and attachment summaries",
            ),
            command(
                "operation plan|show|list|audit",
                "governed_remote_operation",
                "immutable operation state and audit trail",
            ),
            command(
                "operation approve|apply",
                "interactive_approval_or_approved_remote_write",
                "remote operation certainty state",
            ),
            command("mcp serve", "governed_send_tools", "MCP stdio transport"),
        ],
        stable_exit_codes: vec![
            ExitCodeContract {
                code: 0,
                meaning: "success",
            },
            ExitCodeContract {
                code: 1,
                meaning: "runtime failure",
            },
            ExitCodeContract {
                code: 2,
                meaning: "invalid input",
            },
        ],
    }
}

const fn command(
    name: &'static str,
    safety: &'static str,
    output: &'static str,
) -> CommandContract {
    CommandContract {
        name,
        safety,
        output,
    }
}

fn json_value(value: impl Serialize) -> Result<Value, MailError> {
    serde_json::to_value(value).map_err(|_| {
        MailError::new(
            MailErrorCode::Internal,
            "cannot serialize command result",
            false,
        )
    })
}

fn print_success(value: Value, pretty: bool) -> anyhow::Result<()> {
    print_json(
        &Envelope {
            contract_version: CONTRACT_VERSION,
            ok: true,
            data: Some(value),
            error: None,
            warnings: Vec::new(),
        },
        pretty,
    )
}

fn print_error(error: MailError, pretty: bool) -> anyhow::Result<()> {
    print_json(
        &Envelope {
            contract_version: CONTRACT_VERSION,
            ok: false,
            data: None,
            error: Some(error),
            warnings: Vec::new(),
        },
        pretty,
    )
}

fn print_json(value: &impl Serialize, pretty: bool) -> anyhow::Result<()> {
    let output = if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    }
    .context("failed to serialize command result")?;
    println!("{output}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_provider_builds_a_safe_account_without_a_secret() {
        let account = build_account(
            "personal",
            "Agent@163.com",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("build account");
        assert_eq!(account.incoming.host, "imap.163.com");
        assert_eq!(account.email, "agent@163.com");
        let serialized = serde_json::to_string(&account).expect("serialize account");
        assert!(!serialized.contains("password\":"));
    }

    #[test]
    fn unknown_provider_requires_explicit_transport_configuration() {
        let error = build_account(
            "work",
            "agent@example.org",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(error.code, MailErrorCode::InvalidInput);
    }

    #[test]
    fn schema_contains_governed_send_commands() {
        let schema = schema_report();
        assert!(schema.commands.iter().any(|entry| {
            entry.name == "send apply <plan-id>"
                && entry.safety == "approved_remote_write_at_most_once"
        }));
        assert!(schema.commands.iter().any(|entry| {
            entry.name == "send approve <plan-id>"
                && entry.safety == "interactive_human_local_write"
        }));
    }

    #[test]
    fn provider_registry_has_bounded_inspection_commands() {
        let list = Cli::try_parse_from(["kirje", "provider", "list"]);
        let show = Cli::try_parse_from(["kirje", "provider", "show", "163.com"]);

        assert!(list.is_ok());
        assert!(show.is_ok());
    }
}
