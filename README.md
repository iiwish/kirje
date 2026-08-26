# Kirje

**Local-first email CLI and MCP server built for AI agents.**

Kirje is a standards-first runtime for agents that need to work with existing
email accounts. The project targets IMAP, SMTP, and JMAP across consumer,
enterprise, and self-hosted providers without routing mailbox data through a
Kirje cloud service.

> Status: v0.3 Agent Mail Operations. Kirje provides bounded IMAP reads, private
> local drafts, multipart SMTP sending, and governed IMAP mailbox operations
> through one auditable local operation ledger.

## Why Kirje

- One local binary for CLI and MCP clients.
- JSON-first, versioned output designed for deterministic automation.
- Bounded IMAP mailbox access plus separately governed SMTP and IMAP writes.
- Explicit incremental sync into a private local SQLite metadata index.
- Private local drafts with reply, reply-all, and forward composition.
- Local attachment import and bounded content summaries; multipart SMTP bodies.
- A unified transactional operation ledger with immutable plans, migration,
  audit events, crash recovery, and explicit ambiguous states.
- Credential-free offline envelope search and sync coverage inspection.
- A source-backed JSON provider registry for NetEase 163/126/Yeah, QQ/Foxmail,
  139, 189, Sina, Aliyun, Fastmail, and iCloud.
- No credential arguments, shell bridges, telemetry, or hosted control plane.
- Explicit treatment of email content as untrusted input.

## Quick Start

```bash
cargo build --release
./target/release/kirje doctor --pretty
./target/release/kirje provider show 163.com --pretty
./target/release/kirje account discover agent@163.com --pretty
./target/release/kirje account add personal agent@163.com --pretty
./target/release/kirje secret set personal
./target/release/kirje account check personal --pretty
./target/release/kirje mailbox list --account personal --pretty
./target/release/kirje message search --account personal --mailbox INBOX --limit 10 --pretty
./target/release/kirje sync run --account personal --mailbox INBOX --pretty
./target/release/kirje message search-local --account personal --mailbox INBOX --pretty
./target/release/kirje send plan --input ./send-request.json --pretty
./target/release/kirje send approve <plan-id> --pretty
./target/release/kirje send apply <plan-id> --pretty
./target/release/kirje draft create --input ./draft.json --pretty
./target/release/kirje send from-draft <draft-id> --pretty
./target/release/kirje operation plan --input ./mail-operation.json --pretty
./target/release/kirje operation approve <operation-id> --pretty
./target/release/kirje operation apply <operation-id> --pretty
./target/release/kirje schema --pretty
```

Every non-MCP command emits a stable JSON envelope. Use `--pretty` only for
interactive inspection. Secret changes and send approval require a terminal;
credentials and approval confirmations are never accepted through flags or
pipes. Send message content is accepted as bounded JSON from a file or stdin,
not as subject/body command arguments.

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

The MCP server exposes 24 task-level tools. It can create private drafts,
prepare and apply governed operations, and inspect the ledger. MCP deliberately
has no approval tool; approval is an interactive CLI-only boundary:

- `account_discover`: discover provider endpoints without credentials.
- `account_status`: inspect one configured account and credential presence.
- `mailbox_list`: list selectable remote mailboxes.
- `message_search`: search bounded envelope metadata using structured filters.
- `message_read`: read bounded text and sanitized HTML using `BODY.PEEK`.
- `mailbox_sync`: update one bounded local mailbox metadata index.
- `index_status`: inspect local sync cursor and coverage without network access.
- `message_search_local`: search indexed envelope metadata offline.
- `attachment_read`: retrieve one bounded attachment as untrusted base64.
- `message_send_plan`: persist an immutable local plan without credentials.
- `message_send_plan_draft`: plan a send from a private local draft.
- `message_send_status`: inspect plan state and delivery certainty.
- `message_send_apply`: apply a separately human-approved plan at most once.
- `draft_create`, `draft_status`, `draft_update`, `draft_list`, `draft_discard`:
  manage bounded local draft snapshots.
- `mail_operation_plan`, `mail_operation_status`, `mail_operation_list`:
  prepare or inspect governed IMAP flag, move, archive, and safe-delete work.
- `mail_operation_apply`: apply an operation after CLI approval.
- `mail_operation_audit`: inspect bounded operation audit events.
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
3. Sending, deletion, movement, flag changes, and credential changes use
   plan/approve/apply. MCP has no approval entrypoint.
4. Email bodies, headers, links, and attachments are untrusted data.
5. Unknown providers remain unknown; Kirje does not guess unsafe endpoints.
6. Local operation never requires a Kirje account or Kirje-hosted relay.

See [docs/architecture.md](docs/architecture.md) and
[docs/security.md](docs/security.md) for the full technical boundary. Provider
testing is documented in [docs/conformance.md](docs/conformance.md).
Registry ownership and source policy are documented in
[docs/provider-presets.md](docs/provider-presets.md).

## Local Index And Ledger

Kirje stores envelope metadata only. It does not persist message bodies,
attachments, credentials, or raw MIME. The first sync imports the newest
bounded window; later runs request UIDs above the stored cursor. Use `sync run
--refresh` to rebuild that window after flags or deletions change. Full archive
backfill and background `IDLE` watching are outside the current scope. The
private `outbox.sqlite3` database contains the unified operation ledger. Schema
version 2 migrates legacy send rows transactionally and records operation
events. Stale `applying` operations become `ambiguous`; Kirje never retries
them automatically.

## Governed Send

The private ledger binds approval to the account, operation kind, scoped message
reference, payload digest, and 24-hour expiry. `send approve` and `operation
approve` display the immutable request and require the exact id in a human
terminal. Remote work is invoked only after an atomic `approved -> applying`
claim. A lost or unclear result becomes `ambiguous` and Kirje will not retry it
automatically.

Archive and safe delete use a server-declared `\\Archive` or `\\Trash` mailbox,
or an explicit destination supplied by the caller. Safe delete never issues
`EXPUNGE`; the default is a reversible move to Trash.

## Roadmap

- Historical backfill, thread reconstruction, reconciliation, and event watching.
- JMAP discovery and JMAP mailbox operations.
- Provider conformance fixtures and real-mailbox compatibility reports.
- Permanent deletion, bulk mailbox workflows, and automatic ambiguous-state
  reconciliation.

The archived desktop predecessor is preserved at
[iiwish/kirje-desktop-archive](https://github.com/iiwish/kirje-desktop-archive).
Its protocol lessons and sanitized compatibility evidence will be migrated
selectively rather than copying the desktop architecture.

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --locked
cargo deny check
```

Kirje is licensed under Apache-2.0. Contributions are welcome after reading
[CONTRIBUTING.md](CONTRIBUTING.md).
