# T018 Test Results

- Format: passed (`cargo fmt --all --check`).
- Clippy: passed for workspace, all targets, all features, warnings denied.
- Tests: 75 passed, 0 failed (`cargo test --workspace --all-features --locked`).
- Build: passed for locked workspace and all features.
- Dependency policy: advisories, bans, licenses, and sources passed.
- Shell syntax: both live smoke scripts passed `bash -n`.
- Patch hygiene: `git diff --check` passed.
- Live provider: stopped before authentication because macOS rejected the OS
  keyring write; no keychain item or temporary state remained.
