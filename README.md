# Kirje

**Local-first email CLI and MCP server built for AI agents.**

Kirje is a standards-first runtime for agents that need to work with existing
email accounts. The project targets IMAP, SMTP, and JMAP across consumer,
enterprise, and self-hosted providers without routing mailbox data through a
Kirje cloud service.

> Status: agent-first bootstrap. The current binary provides a versioned JSON
> contract, provider discovery, runtime diagnostics, and a typed read-only MCP
> server. Mailbox synchronization and message operations are the next milestone.

## Why Kirje

- One local binary for CLI and MCP clients.
- JSON-first, versioned output designed for deterministic automation.
- Read-only by default, with no write tools in the bootstrap release.
- Provider presets for NetEase 163/126, QQ/Foxmail, 139, 189, Sina, Aliyun,
  Fastmail, and iCloud.
- No credential arguments, shell bridges, telemetry, or hosted control plane.
- Explicit treatment of email content as untrusted input.

## Quick Start

```bash
cargo build --release
./target/release/kirje doctor --pretty
./target/release/kirje account discover agent@163.com --pretty
./target/release/kirje schema --pretty
```

Every non-MCP command emits a stable JSON envelope. Use `--pretty` only for
interactive inspection.

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

The bootstrap server exposes two read-only tools:

- `account_discover`: discover provider endpoints without credentials.
- `system_status`: inspect the runtime contract and safety mode.

## For Agents

Agents should read [docs/agent-guide.md](docs/agent-guide.md) before invoking
Kirje. A reusable Agent Skill is available at [skills/kirje/SKILL.md](skills/kirje/SKILL.md).
The skill is intentionally honest about the current command surface and forbids
inventing unsupported mail operations.

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
[docs/security.md](docs/security.md) for the full technical boundary.

## Roadmap

- Account configuration with OS keyring-backed secret references.
- IMAP receive, folder, flag, attachment, and incremental sync support.
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
```

Kirje is licensed under Apache-2.0. Contributions are welcome after reading
[CONTRIBUTING.md](CONTRIBUTING.md).
