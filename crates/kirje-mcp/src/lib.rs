//! Typed MCP tools backed by the same contracts as the Kirje CLI.

use kirje_core::{CONTRACT_VERSION, ProviderDiscovery, discover_account};
use rmcp::{
    Json, ServiceExt, handler::server::wrapper::Parameters, schemars, tool, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct AccountDiscoverParams {
    /// Full mailbox address used to select a known provider preset.
    pub email: String,
}

#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct RuntimeStatus {
    pub name: String,
    pub version: String,
    pub contract_version: String,
    pub interfaces: Vec<String>,
    pub exposed_write_tools: bool,
}

#[derive(Clone, Default)]
pub struct KirjeMcp;

#[tool_router(server_handler)]
#[allow(clippy::unused_self)]
impl KirjeMcp {
    #[tool(
        description = "Discover safe IMAP and SMTP settings for an email address. This read-only tool never accepts or returns credentials.",
        annotations(
            title = "Discover email provider settings",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn account_discover(
        &self,
        Parameters(params): Parameters<AccountDiscoverParams>,
    ) -> Json<ProviderDiscovery> {
        Json(discover_account(&params.email))
    }

    #[tool(
        description = "Report the Kirje runtime contract and currently exposed interface capabilities.",
        annotations(
            title = "Inspect Kirje runtime",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn system_status(&self) -> Json<RuntimeStatus> {
        Json(RuntimeStatus {
            name: "kirje".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            interfaces: vec!["cli".to_owned(), "mcp_stdio".to_owned()],
            exposed_write_tools: false,
        })
    }
}

/// Run the MCP server until the stdio transport closes.
///
/// # Errors
///
/// Returns an error when the transport cannot start or the MCP service exits
/// unexpectedly.
pub async fn serve_stdio() -> anyhow::Result<()> {
    let service = KirjeMcp.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_declares_no_write_tools() {
        let Json(status) = KirjeMcp.system_status();

        assert!(!status.exposed_write_tools);
        assert_eq!(status.contract_version, CONTRACT_VERSION);
    }

    #[test]
    fn mcp_discovery_uses_the_core_contract() {
        let Json(result) = KirjeMcp.account_discover(Parameters(AccountDiscoverParams {
            email: "agent@qq.com".to_owned(),
        }));

        assert_eq!(result.provider_id.as_deref(), Some("tencent"));
    }
}
