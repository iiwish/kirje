# T012 Evidence: Registry Contract And Discovery

## Outcome

- Added the validated, versioned embedded JSON registry with 13 provider
  profiles and provider-owned source evidence.
- Migrated account discovery to registry lookups and retained stable provider
  family ids.
- Added bounded `provider list` and `provider show` CLI inspection.
- Kept POP3 and JMAP reference-only; Fastmail records its official JMAP session
  endpoint without enabling a runtime adapter.
- Corrected iCloud SMTP discovery to port 587 with STARTTLS from Apple guidance.

## TDD Evidence

- Registry, 163 POP3, iCloud SMTP, Fastmail JMAP, and CLI parsing tests failed
  before their types and commands existed.
- Target validation: `cargo test -p kirje-core -p kirje-cli --all-features`.
- Target Clippy: `cargo clippy -p kirje-core -p kirje-cli --all-targets
  --all-features -- -D warnings`.
- Full workspace gates pass with 57 tests, a locked all-feature build, and
  `cargo deny check` reporting advisories, bans, licenses, and sources as OK.
- MCP Inspector reports the same ten task-level tools with no added provider
  lookup tool or remote-write capability.

## Safety Review

- No credential value or secret-shaped JSON field exists in the registry.
- Every endpoint is encrypted and exactly one IMAP plus one SMTP endpoint is a
  runtime default per profile.
- POP3 and JMAP cannot flow into `MailAccountConfig`.
