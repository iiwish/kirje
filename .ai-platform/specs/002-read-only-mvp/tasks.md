# Tasks: Read-Only Mailbox MVP

## T002 Protocol And Domain Foundation

- Status: Complete
- Dependencies: none
- Allowed files: workspace manifests, `crates/kirje-core`,
  `crates/kirje-protocol`, `NOTICE`
- Deliverable: typed mailbox contract and Pimalaya-backed read adapter
- Validation: core/protocol unit and transcript tests, Clippy, build

## T003 Account Runtime

- Status: Complete
- Dependencies: T002
- Allowed files: workspace manifests, `crates/kirje-runtime`, `crates/kirje-core`
- Deliverable: atomic config repository, secret-store port and keyring adapter,
  account lifecycle and diagnostics
- Validation: tempfile and in-memory secret-store tests

## T004 CLI And MCP Read Surface

- Status: Complete
- Dependencies: T002, T003
- Allowed files: `crates/kirje-cli`, `crates/kirje-mcp`, interface documentation
- Deliverable: account, mailbox, search, and read commands/tools
- Validation: CLI integration tests, schema parity, MCP Inspector

## T005 Release Readiness

- Status: In review; local gates passed, GitHub CI pending
- Dependencies: T002-T004
- Allowed files: CI, documentation, Agent Skill, evidence and release metadata
- Deliverable: public MVP documentation and complete verification evidence
- Validation: complete workspace suite and GitHub CI
