# T002: Protocol And Domain Foundation

## Result

Kirje owns a provider-neutral read contract and a Pimalaya `io-imap` adapter.
The adapter uses verified TLS, encrypted SASL, `EXAMINE`, structured search,
scoped UIDVALIDITY references, bounded `BODY.PEEK[]`, MIME decoding, HTML
sanitization, bounded metadata, and stable sanitized errors.

Provider compatibility policy includes the NetEase Coremail SASL-IR override
and the QQ Mail/Fastmail RFC 2971 ID exchange. Pimalaya attribution is retained
in `NOTICE`.

## Verification

- 7 core tests passed.
- 8 protocol tests passed, including an in-memory IMAP FETCH transcript.
- Clippy passed with warnings denied.
- The workspace build passed with all features.
