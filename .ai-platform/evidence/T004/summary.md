# T004: CLI And MCP Read Surface

## Result

The CLI supports discovery, account add/list/status/check, interactive keyring
set/delete, mailbox list, structured message search, and scoped message read.
Every non-help command uses the versioned JSON envelope, including malformed
argument errors. No command accepts a credential value.

MCP exposes `account_discover`, `account_status`, `mailbox_list`,
`message_search`, `message_read`, and `system_status`. All are read-only and
non-destructive; runtime failures are caller-visible structured tool errors.

## Verification

- 7 CLI and stdio integration tests passed.
- 5 MCP unit/contract tests passed.
- MCP Inspector listed all six tools and no send, move, flag, delete, or secret
  tool.
- The stdio handshake test proved stdout contains only JSON-RPC responses.
