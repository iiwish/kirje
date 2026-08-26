# Architecture

Kirje uses a ports-and-adapters structure with one provider-neutral application
contract.

```text
Agent harness
  |-- CLI JSON
  `-- MCP stdio
          |
     kirje-runtime
     /     |      \
 config  keyring  kirje-core ports
                  /          \
       kirje-protocol       kirje-store
           (IMAP)             (SQLite)
```

The CLI is the durable automation contract. MCP maps typed tools to the same
application services and must not become a second implementation.

## Current Boundaries

- `kirje-core`: provider-neutral accounts, mailboxes, messages, scoped
  references, limits, stable errors, and the `MailboxReader` port.
- `kirje-protocol`: Pimalaya `io-imap` adapter, TLS/SASL, structured search,
  MIME decoding, HTML sanitization, and `BODY.PEEK` reads.
- `kirje-runtime`: atomic TOML account repository, OS keyring adapter, and the
  application services coordinating remote reads and local transactions.
- `kirje-store`: private, versioned SQLite envelope index and sync cursor
  adapter. It stores no bodies, raw MIME, attachments, or credentials.
- `kirje-cli`: versioned JSON command envelope and interactive secret setup.
- `kirje-mcp`: compact typed tools with explicit remote-read and local-write
  annotations over the runtime.

Sync is explicit rather than a daemon. Initial sync stores the newest bounded
window, incremental sync advances by IMAP UID, and UIDVALIDITY changes replace
one mailbox scope atomically. SMTP, JMAP, durable threads, background watching,
operation plans, and audit records fit behind these boundaries.

The project intentionally excludes React, Tauri, an embedded LLM, and a hosted
mail relay from the core architecture.
