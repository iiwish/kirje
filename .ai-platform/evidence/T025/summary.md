# T025 Evidence: Full QA And Delivery

Local gates pass on the v0.3 worktree:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked` (91 tests)
- `cargo build --workspace --all-features --locked`
- `cargo deny check`
- `bash -n scripts/live-imap-smoke.sh scripts/live-send-smoke.sh scripts/live-operations-smoke.sh`

Manual contract checks report `2026-08-27.5`, private empty-account behavior,
bounded schema output, and MCP stdio with 24 tools and no approval tool. A
controlled live attempt reached the 163 IMAP endpoint over verified TLS and
confirmed the OS credential boundary, but authentication returned a sanitized
failure. No authenticated mailbox read, send, or remote mutation was attempted
after that failure; no secret fallback or remote mutation was used.

Delivery references:

- Feature commit: `069a09e`
- CI/manual-validation commit: `0835ded`
- Evidence commit: `70bdcd1`
- Pull request: `https://github.com/iiwish/kirje/pull/5`
- CI run: `https://github.com/iiwish/kirje/actions/runs/33024740375` (green)
- Final-head CI run: `https://github.com/iiwish/kirje/actions/runs/33024829162` (green)
- Latest branch CI run: `https://github.com/iiwish/kirje/actions/runs/33024924816` (green)
- Merge commit: `5799332` on `main` (PR #5 merged).
- Post-merge main CI run: `https://github.com/iiwish/kirje/actions/runs/33025196060` (green, head `a0070b9`).
