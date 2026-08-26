# Architecture

Kirje uses a ports-and-adapters structure with one provider-neutral application
contract.

```text
Agent harness
  |-- CLI JSON
  `-- MCP stdio
          |
     kirje-runtime
      /          \
account config  secret store
          |
      kirje-core ports
          |
  kirje-protocol (IMAP)
```

The CLI is the durable automation contract. MCP maps typed tools to the same
application services and must not become a second implementation.

## Current Boundaries

- `kirje-core`: provider-neutral accounts, mailboxes, messages, scoped
  references, limits, stable errors, and the `MailboxReader` port.
- `kirje-protocol`: Pimalaya `io-imap` adapter, TLS/SASL, structured search,
  MIME decoding, HTML sanitization, and `BODY.PEEK` reads.
- `kirje-runtime`: atomic TOML account repository, OS keyring adapter, and the
  application services shared by every interface.
- `kirje-cli`: versioned JSON command envelope and interactive secret setup.
- `kirje-mcp`: compact typed read-only tools over the runtime.

SMTP, JMAP, SQLite indexing, durable threads, operation plans, and audit records
fit behind these boundaries but are not implemented in the read-only MVP.

The project intentionally excludes React, Tauri, an embedded LLM, and a hosted
mail relay from the core architecture.
