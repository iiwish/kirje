# Plan: Governed Send

## Architecture

`kirje-core` owns provider-neutral send types, validation, state transitions,
and the `Outbox` / `MailSender` ports. `kirje-store` persists immutable plans in
a dedicated SQLite outbox. `kirje-protocol` implements SMTP with Lettre while
the runtime coordinates account, credential, outbox, and sender services. CLI
and MCP are thin interfaces over that runtime.

## Decisions

- Use Lettre 0.11 for mature MIME and SMTP transport rather than implementing
  either protocol. Keep the adapter behind Kirje's provider-neutral port.
- Store message bodies only in the private outbox, never in the metadata index.
- Use UUIDv4 plan ids and Message-IDs plus SHA-256 over canonical request JSON.
- The only approval interface is an interactive CLI prompt that requires the
  exact plan id. Agent-accessible stdin and MCP cannot approve.
- Claim `approved -> applying` in a SQLite transaction before credential access.
- Treat every SMTP send-call error as ambiguous. This trades convenience for
  protection against duplicates when the server accepted data but the response
  was lost.
- No automatic retry path exists for failed or ambiguous plans in this phase.

## State Model

`planned -> approved -> applying -> sent`

- `planned -> expired` when the approval window elapses.
- `approved -> expired` when apply occurs after expiry.
- `applying -> failed` only when no delivery attempt began.
- `applying -> ambiguous` for every error returned by the SMTP invocation.
- Terminal states are immutable.

## Validation

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --locked
cargo deny check
cargo run -p kirje-cli -- schema --pretty
cargo run -p kirje-cli -- doctor --pretty
```

The credentialed 163 self-send is local and opt-in. Public CI remains
secret-free and exercises the same state machine with fakes.
