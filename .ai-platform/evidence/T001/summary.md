# T001: Agent-First Bootstrap

## Result

The repository builds one `kirje` binary with a versioned JSON CLI and a typed
read-only MCP stdio server. CLI and MCP provider discovery reuse
`kirje-core`. The public write-tool surface is empty.

## Verification

Verified locally on 2026-08-26 with Rust 1.95.0:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features --locked` (6 passed)
- `cargo build --workspace --all-features --locked`
- MCP Inspector `tools/list` exposed only `account_discover` and
  `system_status`.
- MCP Inspector `tools/call` returned the NetEase preset for `agent@163.com`.
- CLI smoke checks covered schema, doctor, QQ discovery, and invalid input exit
  code 2.

## Safety Evidence

- Discovery schemas contain no credential value field.
- Unknown providers return `matched: false` without guessed endpoints.
- MCP annotations declare both tools read-only, non-destructive, and
  idempotent.
- `doctor` and `system_status` report `exposed_write_tools: false`.

GitHub Actions run
[`32927350693`](https://github.com/iiwish/kirje/actions/runs/32927350693)
passed formatting, Clippy, tests, and the locked workspace build for the initial
public commit.
