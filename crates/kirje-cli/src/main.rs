use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use kirje_core::{CONTRACT_VERSION, discover_account};
use serde::Serialize;

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

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the stable machine contract exposed by this binary.
    Schema,
    /// Inspect local runtime readiness without accessing a mailbox.
    Doctor,
    /// Discover and manage email accounts.
    Account {
        #[command(subcommand)]
        command: AccountCommand,
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
}

#[derive(Subcommand)]
enum McpCommand {
    /// Start the typed MCP server over standard input/output.
    Serve,
}

#[derive(Serialize)]
struct Envelope<T> {
    contract_version: &'static str,
    ok: bool,
    data: T,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct DoctorReport {
    name: &'static str,
    version: &'static str,
    interfaces: [&'static str; 2],
    default_mode: &'static str,
    exposed_write_tools: bool,
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
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("kirje: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Schema => {
            print_json(
                &Envelope {
                    contract_version: CONTRACT_VERSION,
                    ok: true,
                    data: schema_report(),
                    warnings: Vec::new(),
                },
                cli.pretty,
            )?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Doctor => {
            print_json(
                &Envelope {
                    contract_version: CONTRACT_VERSION,
                    ok: true,
                    data: doctor_report(),
                    warnings: vec![
                        "Mailbox connections are not part of the bootstrap release yet.".to_owned(),
                    ],
                },
                cli.pretty,
            )?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Account {
            command: AccountCommand::Discover { email },
        } => handle_discovery(&email, cli.pretty),
        Command::Mcp {
            command: McpCommand::Serve,
        } => {
            kirje_mcp::serve_stdio()
                .await
                .context("MCP stdio server stopped unexpectedly")?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn schema_report() -> SchemaReport {
    SchemaReport {
        name: "kirje",
        version: env!("CARGO_PKG_VERSION"),
        commands: vec![
            CommandContract {
                name: "schema",
                safety: "read_only",
                output: "command contract",
            },
            CommandContract {
                name: "doctor",
                safety: "read_only",
                output: "runtime readiness",
            },
            CommandContract {
                name: "account discover <email>",
                safety: "read_only_no_credentials",
                output: "provider discovery",
            },
            CommandContract {
                name: "mcp serve",
                safety: "read_only_tools_only",
                output: "MCP stdio transport",
            },
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

fn doctor_report() -> DoctorReport {
    DoctorReport {
        name: "kirje",
        version: env!("CARGO_PKG_VERSION"),
        interfaces: ["cli", "mcp_stdio"],
        default_mode: "read_only",
        exposed_write_tools: false,
    }
}

fn handle_discovery(email: &str, pretty: bool) -> anyhow::Result<ExitCode> {
    let result = discover_account(email);
    let exit_code = if result.valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    };
    print_json(
        &Envelope {
            contract_version: CONTRACT_VERSION,
            ok: result.valid,
            data: result,
            warnings: Vec::new(),
        },
        pretty,
    )?;
    Ok(exit_code)
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
    fn envelopes_carry_the_contract_version() {
        let json = serde_json::to_value(Envelope {
            contract_version: CONTRACT_VERSION,
            ok: true,
            data: "ready",
            warnings: Vec::new(),
        })
        .expect("serialize envelope");

        assert_eq!(json["contract_version"], CONTRACT_VERSION);
        assert_eq!(json["ok"], true);
    }
}
