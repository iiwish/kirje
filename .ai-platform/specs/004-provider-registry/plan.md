# Plan: Provider Preset Registry

## Architecture

`kirje-core` embeds `data/provider-presets.json`, parses it once, validates the
catalog, and exposes typed read-only lookup helpers. Account discovery filters
default IMAP and SMTP endpoints into the existing provider-neutral contract.
The CLI adds inspection commands but MCP keeps its compact task-level surface.

## Decisions

- JSON is the canonical provider-data artifact and ships inside the binary.
- Provider family ids remain stable while profile ids are unique per endpoint
  set, such as `netease-163` and `netease-126`.
- POP3 facts may be present for operator visibility but are never selected by
  account configuration in this phase.
- Sources must be provider-owned documentation with a verification date.
- The live check uses a disposable account id, isolated config/index paths, and
  the OS credential store. Only aggregate counts are retained as evidence.

## Validation

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --locked
cargo deny check
./target/debug/kirje provider show 163.com
```

The credentialed smoke check is local and opt-in; public CI remains secret-free.
