# Provider Conformance

Kirje separates deterministic protocol tests from credentialed provider smoke
checks. Public CI never receives mailbox credentials.

## Automated Contract Coverage

- IMAP sessions use platform-verified TLS and PLAIN SASL over encrypted transport.
- NetEase Coremail disables the falsely advertised SASL initial response.
- QQ Mail and Fastmail receive the RFC 2971 client ID exchange they require.
- Mailboxes open with `EXAMINE`; message bodies use bounded `BODY.PEEK[]`.
- Initial and incremental sync use bounded UID FETCH batches and persist scoped
  UIDVALIDITY cursors transactionally.
- Search input, result counts, mailbox counts, message bytes, decoded bodies,
  headers, addresses, attachment metadata, and attachment content are bounded.
- MIME parsing, UTF-8 truncation, HTML sanitization, stale reference handling,
  JSON envelopes, MCP schemas, and stdout cleanliness are regression-tested.

## Preset Evidence

NetEase documents domain-specific `imap.163.com`, `imap.126.com`, and
`imap.yeah.net` endpoints with TLS port 993 and client authorization passwords.
The preset tests keep those hosts distinct. Other presets remain explicit code
and require live smoke evidence before a compatibility guarantee is published.
See the [NetEase client settings guide](https://help.mail.126.com/faqDetail.do?code=d7a5dc8471cd0c0e8b4b8f4f8e49998b374173cfe9171305fa1ce630d7f67ac25c12dcb3d46222b6).

## Credentialed Smoke Check

Configure a dedicated test mailbox through the normal TTY/keyring workflow,
build Kirje, and run:

```bash
cargo build -p kirje-cli
./scripts/live-imap-smoke.sh <account-id>
```

The script authenticates, lists mailboxes, searches one INBOX envelope, reads at
most one bounded message, synchronizes a temporary local index, and verifies an
offline query. It performs no remote mailbox writes and prints no message
content. Record provider, server capabilities, Kirje commit, date, and the final
JSON summary; never record addresses, UIDs, subjects, or credentials.
