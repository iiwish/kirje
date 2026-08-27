# T025 Evidence: Full QA And Delivery

Local gates pass on the v0.3 worktree:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked` (91 tests)
- `cargo build --workspace --all-features --locked`
- `cargo deny check`
- `bash -n scripts/live-imap-smoke.sh scripts/live-send-smoke.sh scripts/live-operations-smoke.sh`

Manual contract checks report `2026-08-27.5`, private empty-account behavior,
bounded schema output, and MCP stdio with 24 tools and no approval tool.

Controlled 163/Coremail verification on 2026-08-27 used the normal interactive
OS-keyring workflow and verified TLS. The authenticated read-only smoke listed
9 mailboxes, sampled 1 remote envelope, synchronized 10 bounded envelopes, found
1 local result, and completed a bounded body read without recording mailbox
content. The governed self-addressed SMTP plan received interactive approval,
reached `sent`, and recorded a positive SMTP acceptance receipt; the unique
message was not visible in INBOX during the bounded polling window, which is
recorded separately from SMTP acceptance. A governed star operation reached
`succeeded`, and its separately approved restoration also reached `succeeded`;
the final flag state matched the starting state. No address, UID, subject,
credential, or mailbox content is retained in this evidence.

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
- Coremail compatibility fix: `e527615`
- Compatibility PR: `https://github.com/iiwish/kirje/pull/7` (merged)
- Compatibility PR CI: `https://github.com/iiwish/kirje/actions/runs/33030916793` (green)
- Compatibility merge commit: `d657950` on `main`
- Latest post-merge main CI: `https://github.com/iiwish/kirje/actions/runs/33031001611` (green, head `d657950`).
