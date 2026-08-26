# T012 Test Results

- `cargo fmt --all --check`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  passed.
- `cargo test --workspace --all-features --locked`: passed, 57 tests.
- `cargo build --workspace --all-features --locked`: passed.
- `cargo deny check`: passed for advisories, bans, licenses, and sources.
- MCP Inspector `tools/list`: passed, ten task-level tools.
- Manual CLI checks: registry schema 1, 13 profiles, 163 secure endpoint set,
  and iCloud SMTP 587 STARTTLS all returned contract `2026-08-26.3`.
