# Kirje

**Local-first email CLI and MCP server built for AI agents.**

Kirje is a standards-first runtime for agents that need to work with existing
email accounts. The project targets IMAP, SMTP, and JMAP across consumer,
enterprise, and self-hosted providers without routing mailbox data through a
Kirje cloud service.

> Status: read-only mailbox MVP. Kirje can configure an IMAP account, keep its
> credential in the operating-system keyring, list mailboxes, search bounded
> metadata, and read bounded sanitized messages through CLI or MCP.

## Why Kirje

- One local binary for CLI and MCP clients.
- JSON-first, versioned output designed for deterministic automation.
- Read-only remote access, with no mailbox write or send tools.
- Provider presets for NetEase 163/126, QQ/Foxmail, 139, 189, Sina, Aliyun,
  Fastmail, and iCloud.
- No credential arguments, shell bridges, telemetry, or hosted control plane.
- Explicit treatment of email content as untrusted input.

## Quick Start

```bash
cargo build --release
./target/release/kirje doctor --pretty
./target/release/kirje account discover agent@163.com --pretty
./target/release/kirje account add personal agent@163.com --pretty
./target/release/kirje secret set personal
./target/release/kirje account check personal --pretty
./target/release/kirje mailbox list --account personal --pretty
./target/release/kirje message search --account personal --mailbox INBOX --limit 10 --pretty
./target/release/kirje schema --pretty
```

Every non-MCP command emits a stable JSON envelope. Use `--pretty` only for
interactive inspection. `secret set` and `secret delete` are the exceptions:
they require a terminal and never accept secret material through flags or pipes.

## MCP

Start the typed stdio server:

```bash
kirje mcp serve
```

Example client configuration:

```json
{
  "mcpServers": {
    "kirje": {
      "command": "/absolute/path/to/kirje",
      "args": ["mcp", "serve"]
    }
  }
}
```

The MCP server exposes six read-only tools:

- `account_discover`: discover provider endpoints without credentials.
- `account_status`: inspect one configured account and credential presence.
- `mailbox_list`: list selectable remote mailboxes.
- `message_search`: search bounded envelope metadata using structured filters.
- `message_read`: read bounded text and sanitized HTML using `BODY.PEEK`.
- `system_status`: inspect the runtime contract and safety mode.

## For Agents

Agents should read [docs/agent-guide.md](docs/agent-guide.md) before invoking
Kirje. A reusable Agent Skill is available at [skills/kirje/SKILL.md](skills/kirje/SKILL.md).
The skill documents safe configuration, reference handling, and prompt-injection
boundaries for autonomous agents.

## Design Contract

```text
Agent decides what should happen.
Kirje reports mailbox facts and executes approved operations.
```

The core product invariants are:

1. CLI, MCP, and future SDKs share one application contract.
2. Read operations and write operations have separate permission boundaries.
3. Sending, deletion, movement, and credential changes use plan/approve/apply.
4. Email bodies, headers, links, and attachments are untrusted data.
5. Unknown providers remain unknown; Kirje does not guess unsafe endpoints.
6. Local operation never requires a Kirje account or Kirje-hosted relay.

See [docs/architecture.md](docs/architecture.md) and
[docs/security.md](docs/security.md) for the full technical boundary. Provider
testing is documented in [docs/conformance.md](docs/conformance.md).

## Roadmap

- IMAP flags, attachment retrieval, incremental sync, and local SQLite index.
- SMTP draft, plan, approval, send, and idempotency support.
- JMAP discovery and mail operations.
- Local SQLite index, threads, search, and event watching.
- Compact MCP tools generated from the same command contract.
- Provider conformance fixtures and real-mailbox compatibility reports.

The archived desktop predecessor is preserved at
[iiwish/kirje-desktop-archive](https://github.com/iiwish/kirje-desktop-archive).
Its protocol lessons and sanitized compatibility evidence will be migrated
selectively rather than copying the desktop architecture.

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --all-features
cargo deny check
```

Kirje is licensed under Apache-2.0. Contributions are welcome after reading
[CONTRIBUTING.md](CONTRIBUTING.md).
