# T018 Evidence: Documentation, Live Verification, And Release

## Result

Complete with a documented external live-test blocker. Canonical product,
architecture, security, agent, provider-conformance, and Skill documents cover
the governed send contract. The reusable live script sends only to the same
dedicated mailbox and requires human TTY approval.

## Validation

- `cargo fmt --all --check`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed.
- `cargo test --workspace --all-features --locked`: 75 passed, 0 failed.
- `cargo build --workspace --all-features --locked`: passed.
- `cargo deny check`: advisories, bans, licenses, and sources passed.
- `bash -n scripts/live-imap-smoke.sh scripts/live-send-smoke.sh`: passed.
- `git diff --check`: passed.

## Live 163 Check

An isolated account configuration used the reviewed IMAP 993 and SMTP 465
implicit-TLS endpoints. TTY credential entry reached the OS keyring adapter, but
macOS returned `secret_store_unavailable` before authentication. A direct
metadata check found no created keychain item, and all isolated local files were
removed. No plaintext fallback or remote write occurred.

## Residual Risk

Authenticated 163 IMAP and SMTP conformance remains unverified in this host
session. The deterministic SMTP adapter, MIME, state-machine, concurrency, and
interface contracts are covered locally; a human can rerun
`scripts/live-send-smoke.sh` after the login keychain is accessible.
