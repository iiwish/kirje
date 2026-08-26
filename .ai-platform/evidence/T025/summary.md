# T025 Evidence: Full QA And Delivery

Local gates pass on the v0.3 worktree:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked` (90 tests)
- `cargo build --workspace --all-features --locked`
- `cargo deny check`
- `bash -n scripts/live-imap-smoke.sh scripts/live-send-smoke.sh scripts/live-operations-smoke.sh`

Manual contract checks report `2026-08-27.5`, private empty-account behavior,
bounded schema output, and MCP stdio with 24 tools and no approval tool. The
controlled live mailbox check is blocked in this environment because no
dedicated account or OS-stored credential is configured. No secret fallback or
remote mutation was attempted.

Delivery references:

- Feature commit: `069a09e`
- CI/manual-validation commit: `0835ded`
- Evidence commit: `70bdcd1`
- Pull request: `https://github.com/iiwish/kirje/pull/5`
- CI run: `https://github.com/iiwish/kirje/actions/runs/33024740375` (green)
- Final-head CI run: `https://github.com/iiwish/kirje/actions/runs/33024829162` (green)
- Merge: pending final review and merge command.
