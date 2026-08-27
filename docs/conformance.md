# Provider Conformance

Kirje separates deterministic protocol tests from credentialed provider smoke
checks. Public CI never receives mailbox credentials.

## Automated Contract Coverage

- IMAP sessions use platform-verified TLS and PLAIN SASL over encrypted transport.
- NetEase Coremail uses encrypted IMAP `LOGIN` for app-password accounts and
  disables the falsely advertised SASL initial response; this provider quirk
  stays inside the IMAP adapter.
- QQ Mail and Fastmail receive the RFC 2971 client ID exchange they require.
- Mailboxes open with `EXAMINE`; message bodies use bounded `BODY.PEEK[]`.
- Initial and incremental sync use bounded UID FETCH batches and persist scoped
  UIDVALIDITY cursors transactionally.
- Search input, result counts, mailbox counts, message bytes, decoded bodies,
  headers, addresses, attachment metadata, and attachment content are bounded.
- MIME parsing, UTF-8 truncation, HTML sanitization, stale reference handling,
  JSON envelopes, MCP schemas, and stdout cleanliness are regression-tested.
- Draft composition, reply-all self-removal, recipient de-duplication, forward
  recipient requirements, local attachment bounds and summaries, and private
  draft audit records are regression-tested.
- Send request bounds, MIME generation, hidden Bcc headers, immutable plan
  identity, ledger migration, expiry, concurrent claim exclusion, terminal
  receipts, and ambiguous outcomes are regression-tested.
- Governed IMAP flag, move, archive, and safe-delete requests validate scoped
  UID references, use capability-aware commands, and never issue `EXPUNGE`.

## Preset Evidence

Provider presets live in an embedded, versioned JSON registry. Every entry has
provider-owned source evidence and a verification date. Registry validation
rejects duplicate profiles or domains, missing source evidence, invalid ports,
plaintext transport, and reference-only POP3/JMAP endpoints marked as runtime
defaults. See [provider-presets.md](provider-presets.md).

The 163 profile records secure IMAP `993`, SMTP `465`, and reference-only POP3
`995`. The runtime uses IMAP and SMTP; POP3 is not implemented. NetEase's
current guide also documents a
client authorization password and encrypted client ports. See the
[NetEase client settings guide](https://help.mail.126.com/faqDetail.do?code=d7a5dc8471cd0c0e8b4b8f4f8e49998b374173cfe9171305fa1ce630d7f67ac25c12dcb3d46222b6).

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

On macOS, `kirje doctor` reports whether an OS keyring backend is detectable;
that signal cannot prove the current process may read or write the login
keychain. `secret set` or `account status` is the authoritative operation check.
A locked or unavailable login keychain is a hard stop; the smoke check must not
fall back to an argument, environment variable, pipe, or plaintext file.

For a governed send check, use only a dedicated mailbox and send only to the
same configured address:

```bash
./scripts/live-send-smoke.sh <account-id>
```

The script creates an isolated outbox and benign self-addressed plan, pauses for
the human's exact interactive approval, applies it once, and searches INBOX for
the unique subject. It emits only aggregate delivery state and match count.

For a governed IMAP mutation check, use a dedicated mailbox and a message whose
initial state is known. The script toggles the star flag on one exact scoped
message and toggles it back, leaving the mailbox in its starting state:

```bash
KIRJE_ALLOW_REMOTE_MUTATION=1 \
KIRJE_LIVE_MAILBOX=INBOX \
KIRJE_LIVE_UID=<known-uid> \
KIRJE_LIVE_UID_VALIDITY=<known-uidvalidity> \
./scripts/live-operations-smoke.sh <account-id>
```

The operation script requires an interactive human terminal for both approvals,
uses an isolated ledger, prints no mailbox content, and does not test delete or
expunge. Record only provider, capability summary, Kirje commit, date, and the
aggregate JSON result. A missing keychain credential, unknown UIDVALIDITY, or
uncertain remote result is a hard stop; do not retry an ambiguous operation.
