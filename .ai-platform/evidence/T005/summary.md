# T005: Release Readiness

## Local Verification

Verified on 2026-08-26 with Rust 1.95.0:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features --locked` (30 passed)
- `cargo build --workspace --all-features --locked`
- `cargo deny check` (advisories, licenses, bans, and sources passed)
- MCP Inspector `tools/list` (6 read-only tools)
- `bash -n scripts/live-imap-smoke.sh`

## Boundaries

No provider credentials were available, so the credentialed 163/QQ smoke check
was not run. The repository includes a read-only, content-suppressing smoke
script and a conformance evidence format for dedicated test accounts. Public CI
does not receive mailbox credentials.

GitHub CI evidence is pending the feature-branch push.
