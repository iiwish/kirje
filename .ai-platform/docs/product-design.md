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
- Typed stdio MCP server with read-only bootstrap tools.
- Agent guide, reusable Skill, security model, architecture, and CI.

## Current Exclusions

- Graphical UI or Tauri runtime.
- Hosted mailboxes, relay, or control plane.
- Embedded LLM inference.
- Live mailbox authentication, synchronization, reading, or writing in the
  bootstrap release.

## Success Criteria

- An agent can inspect the contract and discover a 163 or QQ account without
  receiving credentials.
- CLI and MCP return the same core discovery result.
- MCP exposes no write tool.
- Format, lint, tests, and build pass locally and in GitHub Actions.
