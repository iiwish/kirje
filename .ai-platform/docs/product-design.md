# Product Design: Kirje

## Metadata

- Status: Confirmed
- Product: Kirje
- Updated: 2026-08-26

## Definition

Kirje is a local-first email CLI and MCP server designed from the first command
for AI agents. It gives agents a deterministic, provider-neutral, and governed
interface to existing IMAP, SMTP, and JMAP mailboxes.

## Users

- Individuals giving a local agent bounded access to an existing mailbox.
- Developers building agent workflows across Gmail, Outlook, Chinese consumer
  providers, enterprise mail, and self-hosted servers.
- Teams requiring local data handling, explicit permissions, and auditability.

## Core Promise

One local binary exposes the same versioned contract through CLI and MCP. It
does not require a Kirje cloud account and does not route mailbox content through
a Kirje service.

## Product Principles

1. Agent-first, not AI-decorated.
2. Standards-first and provider-neutral.
3. Local-first and credential-minimizing.
4. Read-only by default.
5. Explicit planning and approval for writes.
6. Email content is untrusted input.
7. Honest capabilities and documented provider limits.
8. Compact tools with stable machine output.

## Current Scope

- Rust workspace and single `kirje` binary.
- Versioned JSON envelope and schema discovery.
- Provider discovery for an initial domestic and international preset set.
- Verified-TLS IMAP account diagnostics, mailbox listing, envelope search, and
  bounded sanitized message reads without remote mutation.
- Explicit bounded incremental sync into a private SQLite envelope index.
- Credential-free local search and sync coverage inspection.
- Explicit bounded attachment reads as untrusted base64.
- Typed stdio MCP server with the same task-level services as the CLI.
- Agent guide, reusable Skill, security model, architecture, and CI.

## Current Exclusions

- Graphical UI or Tauri runtime.
- Hosted mailboxes, relay, or control plane.
- Embedded LLM inference.
- Background sync, full historical backfill, body indexing, semantic search,
  and attachment persistence or execution.
- Remote flag, move, delete, draft, or send operations.

## Success Criteria

- An agent can inspect, configure, read, synchronize, and search a 163 or QQ
  mailbox without receiving credentials in its process interface.
- CLI and MCP use the same runtime and domain contracts.
- MCP exposes no remote mailbox-write tool and declares local index writes.
- Format, lint, tests, and build pass locally and in GitHub Actions.
