# Architecture

Kirje uses a ports-and-adapters structure with one provider-neutral application
contract.

```text
Agent harness
  |-- CLI JSON
  `-- MCP stdio
          |
     kirje-runtime
     /       |          \
 config   keyring    kirje-core ports
                    /       |       \
       kirje-protocol  kirje-store  services
        (IMAP + SMTP)  (index + ledger)
```

The CLI is the durable automation contract. MCP maps typed tools to the same
application services and must not become a second implementation.

## Current Boundaries

- `kirje-core`: provider-neutral accounts, mailboxes, messages, drafts,
  attachments, governed operation records, limits, stable errors,
  `MailboxReader` / `MailboxMutator` / `MailSender` / `OperationLedger` ports,
  and the validated embedded provider registry.
- `kirje-protocol`: Pimalaya `io-imap` reads and capability-aware mailbox
  mutations plus Lettre MIME/SMTP submission.
- `kirje-runtime`: atomic TOML account repository, OS keyring adapter, draft
  composition, plan/approve/apply orchestration, and the application services
  shared by CLI and MCP.
- `kirje-store`: private SQLite envelope index and unified operation ledger. The
  index stores no bodies; ledger records store bounded immutable request
  snapshots, attachment summaries, digests, receipts, and audit events. Neither
  stores credentials.
- `kirje-cli`: versioned JSON envelope, local attachment import, interactive
  secret setup, and the only approval surface for send and mailbox operations.
- `kirje-mcp`: compact typed tools with explicit local-write and remote-write
  annotations over the runtime. It has no approval tool.

Provider data is canonical JSON embedded into `kirje-core`. The registry keeps
reference-only POP3 and JMAP facts separate from the IMAP/SMTP defaults consumed
by account discovery. CLI and MCP never maintain independent endpoint tables.

Sync is explicit rather than a daemon. Initial sync stores the newest bounded
window, incremental sync advances by IMAP UID, and UIDVALIDITY changes replace
one mailbox scope atomically. Drafts are private local snapshots; reply,
reply-all, and forward composition is deterministic and does not fetch content.
Attachments remain bounded, hashed, and untrusted until a user explicitly
includes them in a send request.

The operation ledger uses `planned -> approved -> applying -> succeeded`, with
`failed`, `ambiguous`, and `expired` terminal states. SQLite atomically claims
approved work, records every transition, migrates legacy send rows, and marks
stale applying work ambiguous without retrying it. IMAP mutations validate
UIDVALIDITY and use `UID MOVE` when available or `UID COPY` plus `\\Deleted`
without `EXPUNGE`. Archive and safe-delete destinations come from server
special-use declarations or explicit caller input. JMAP, background watching,
and permanent deletion fit behind these boundaries but are outside v0.3.

The project intentionally excludes React, Tauri, an embedded LLM, and a hosted
mail relay from the core architecture.
