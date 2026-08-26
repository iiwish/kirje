# Architecture

Kirje uses a ports-and-adapters structure with one provider-neutral application
contract.

```text
Agent harness
  |-- CLI JSON
  `-- MCP stdio
          |
     kirje-runtime
     /       |        \
 config   keyring    kirje-core ports
                    /          \
       kirje-protocol         kirje-store
        (IMAP + SMTP)      (index + outbox)
```

The CLI is the durable automation contract. MCP maps typed tools to the same
application services and must not become a second implementation.

## Current Boundaries

- `kirje-core`: provider-neutral accounts, mailboxes, messages, send plans,
  limits, stable errors, `MailboxReader` / `MailSender` / `Outbox` ports, and the
  validated embedded provider registry.
- `kirje-protocol`: Pimalaya `io-imap` reads plus Lettre MIME/SMTP submission.
- `kirje-runtime`: atomic TOML account repository, OS keyring adapter, and the
  application services coordinating remote reads and local transactions.
- `kirje-store`: separate private SQLite envelope index and send outbox. The
  index stores no bodies; the outbox stores the bounded immutable message
  snapshot covered by approval. Neither stores credentials.
- `kirje-cli`: versioned JSON envelope, interactive secret setup, and the only
  send approval surface.
- `kirje-mcp`: compact typed tools with explicit remote-read and local-write
  annotations over the runtime.

Provider data is canonical JSON embedded into `kirje-core`. The registry keeps
reference-only POP3 and JMAP facts separate from the IMAP/SMTP defaults consumed
by account discovery. CLI and MCP never maintain independent endpoint tables.

Sync is explicit rather than a daemon. Initial sync stores the newest bounded
window, incremental sync advances by IMAP UID, and UIDVALIDITY changes replace
one mailbox scope atomically. Sending uses `planned -> approved -> applying ->
sent`, with `failed`, `ambiguous`, and `expired` terminal states. JMAP, durable
threads, background watching, and remote mailbox mutation fit behind these
boundaries.

The project intentionally excludes React, Tauri, an embedded LLM, and a hosted
mail relay from the core architecture.
