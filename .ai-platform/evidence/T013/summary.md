# T013 Evidence: Provider Verification And Release Readiness

## Status

Blocked on the local macOS login keychain session; provider authentication was
not attempted.

## Live Check Evidence

- An isolated 163 account configuration selected `imap.163.com:993` with
  implicit TLS and the app-password credential class.
- Unauthenticated TLS protocol probes reached `imap.163.com:993`,
  `smtp.163.com:465`, and `pop.163.com:995`; each returned a valid Coremail
  service greeting and a clean protocol shutdown. This proves endpoint
  reachability, not account authentication.
- `secret set` used a real TTY and refused to continue because the OS credential
  store reported unavailable.
- The macOS `security` utility independently reported that the login keychain
  could not be accessed. No argument, environment variable, pipe, or plaintext
  credential fallback was used.
- Keychain lookup confirmed no `dev.kirje.mail` item existed for the disposable
  account id.
- The isolated configuration, SQLite index, and captured non-secret output were
  deleted; cleanup checks reported both credential and temporary state absent.

## Residual Risk

Live NetEase TLS negotiation, SASL authentication, mailbox listing, bounded
message read, sync, and offline query remain unverified in this environment.
They require an unlocked user keychain with `kirje doctor` reporting the
credential store available.
