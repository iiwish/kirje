# Release Report

## Metadata

- Status: Complete
- Product: Kirje
- Contract: `2026-08-26.4`
- Updated: 2026-08-26

## Product State

Kirje is a local-first email CLI and MCP runtime for agents. It supports secure
provider discovery, non-mutating IMAP reads, explicit SQLite metadata sync,
offline envelope search, bounded attachment reads, and governed SMTP sending.
An immutable private outbox separates agent planning, human TTY approval, and
at-most-once apply. Unknown SMTP outcomes remain terminal `ambiguous` states.

## Verification

- Workspace formatting and Clippy with warnings denied pass.
- 75 automated tests and the complete locked workspace build pass.
- Cargo deny reports advisories, bans, licenses, and sources as acceptable.
- MCP stdio contract tests report thirteen protocol-clean tools, including
  plan/status/apply and no approval operation.
- Manual CLI validation confirms contract `2026-08-26.4`, secure provider SMTP
  defaults, governed command metadata, bounded local planning, and TTY rejection
  for redirected approval.
- SQLite tests prove private files, immutable requests, expiry, concurrent claim
  exclusion, successful receipts, and terminal ambiguous outcomes.

## Live Provider Result

The isolated 163 check reached the normal interactive credential flow, but the
macOS login keychain rejected the credential write with
`secret_store_unavailable`. No keychain item was created and the isolated
configuration, index, and outbox were removed. Authenticated IMAP and SMTP were
therefore not invoked. Kirje did not use an argument, environment variable,
pipe, or plaintext credential fallback.

The keyring backend-detection field in `doctor` is explicitly advisory;
`secret set` and `account status` are the authoritative operation checks.
