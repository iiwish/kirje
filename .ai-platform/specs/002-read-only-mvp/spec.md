# Spec: Read-Only Mailbox MVP

## Metadata

- Feature ID: `002-read-only-mvp`
- Status: Confirmed
- Approved direction: 2026-08-26

## Goal

An agent can configure and inspect a real IMAP mailbox, search bounded message
metadata, and read a bounded sanitized message through either CLI or MCP without
receiving credentials or gaining write access.

## Requirements

- R1: Account configuration is stored locally without credential values.
- R2: A human can store, replace, and delete an account secret through a TTY-only
  command backed by the operating-system credential store.
- R3: Provider discovery remains credential-free and supports explicit endpoint
  overrides without disabling TLS verification.
- R4: Account diagnostics distinguish configuration, missing-secret,
  authentication, TLS, network, and protocol failures with stable codes.
- R5: The runtime uses a Kirje-owned adapter over Pimalaya `io-imap`; interface
  crates contain no protocol logic.
- R6: Agents can list configured accounts and selectable mailboxes.
- R7: Agents can list or search message envelopes using structured filters and a
  bounded limit no greater than 100.
- R8: Agents can read a message by a scoped message reference without setting
  `\\Seen`; decoded text and HTML are bounded and marked untrusted.
- R9: Raw message bytes and attachment contents are not exposed in this phase.
- R10: CLI and MCP invoke the same runtime methods and return the same domain
  objects.
- R11: MCP exposes discovery and system status plus account status, mailbox
  listing, message search, and message read; all tools are annotated read-only
  and non-destructive.
- R12: Unit, contract, transcript, and MCP Inspector tests cover the public
  behavior; live-provider tests remain opt-in and credential-free in CI.

## Non-Requirements

- SMTP sending, drafts, flag changes, move, archive, trash, or delete.
- Background synchronization, SQLite indexing, watch/IDLE, or offline search.
- OAuth browser grants, Gmail API, Microsoft Graph, or remote HTTP MCP.
- JMAP mailbox operations beyond provider discovery and architecture readiness.

## Acceptance Scenarios

1. A 163 account can be added from its preset, while its authorization code is
   absent from the config and every machine response.
2. A missing secret returns `secret_missing`, is non-retryable without human
   configuration, and does not attempt a network connection.
3. Listing/searching never returns more than the requested bounded limit.
4. Reading uses `BODY.PEEK[]` and returns `untrusted: true` with truncation
   metadata.
5. An MCP client cannot discover a write or secret-management tool.
