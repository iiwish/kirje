# Spec: Provider Preset Registry

## Metadata

- Feature ID: `004-provider-registry`
- Status: Confirmed
- Approved direction: 2026-08-26

## Goal

An agent can obtain reviewed, secure-by-default mailbox endpoints from a
versioned embedded JSON registry and use the same data for account discovery.
Kirje can validate a real provider through an isolated, read-only smoke check
without retaining credentials or mailbox content.

## Functional Requirements

- FR-001: Replace hard-coded provider presets with one embedded, versioned JSON
  registry owned by `kirje-core`.
- FR-002: Each preset records a unique profile id, stable provider family id,
  domains, credential kind, endpoints, guidance, and dated source evidence.
- FR-003: Endpoint records distinguish IMAP, SMTP, POP3, and JMAP facts from
  runtime support. Only IMAP and SMTP defaults feed current account discovery.
- FR-004: Only encrypted endpoints may be stored. Plaintext ports are omitted
  even when provider documentation lists them.
- FR-005: `account discover` retains stable behavior and uses the registry as
  its sole preset source.
- FR-006: `provider list` and `provider show <id-or-domain>` expose the bounded
  non-secret registry through the CLI. No new MCP tool is added.
- FR-007: The 163 preset uses IMAP `imap.163.com:993`, SMTP
  `smtp.163.com:465`, and reference-only POP3 `pop.163.com:995`, all with
  implicit TLS and an authorization-code credential.
- FR-008: A credentialed 163 smoke check may authenticate, list mailboxes,
  sample one bounded message, sync at most ten envelopes, and query offline.
  It performs no remote write and records no mailbox content.
- FR-009: Smoke credentials are entered only through the existing TTY/keyring
  flow, deleted immediately after the check, and never committed or logged.

## Non-Requirements

- POP3 runtime support, SMTP sending, JMAP implementation, or OAuth2.
- Plaintext or opportunistic-TLS fallback endpoints.
- Public CI credentials or committed live mailbox fixtures.
- Automatic network discovery or endpoint guessing.

## Success Criteria

1. Registry validation rejects duplicate ids/domains, missing source evidence,
   unsafe transports, invalid ports, and unsupported default protocols.
2. Existing provider discovery tests pass from JSON-backed data.
3. iCloud discovery uses the documented SMTP STARTTLS port 587 rather than a
   global port assumption.
4. The isolated 163 read-only smoke check either passes or produces a sanitized
   provider/authentication finding, followed by verified credential cleanup.
