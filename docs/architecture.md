# Architecture

Kirje uses a ports-and-adapters structure with one provider-neutral application
contract.

```text
Agent harness
  |-- CLI JSON
  `-- MCP stdio
          |
    application services
          |
  provider-neutral domain
     /      |       \
  IMAP     SMTP     JMAP
          |
   local SQLite store
```

The CLI is the durable automation contract. MCP maps typed tools to the same
application services and must not become a second implementation.

## Planned Boundaries

- Core: accounts, capabilities, messages, threads, drafts, operation plans.
- Protocol adapters: IMAP, SMTP, JMAP and provider-specific capability mapping.
- Store: SQLite index, sync cursors, operation journal, audit records.
- Interfaces: versioned JSON CLI, typed MCP, reusable Agent Skill.

The project intentionally excludes React, Tauri, an embedded LLM, and a hosted
mail relay from the core architecture.
