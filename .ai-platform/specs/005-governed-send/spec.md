# Spec: Governed Send

## Metadata

- Feature ID: `005-governed-send`
- Status: Confirmed
- Approved direction: 2026-08-26

## Goal

An agent can prepare and inspect an immutable email send plan, while a human
retains the only approval path. Kirje sends an approved plan exactly once when
the delivery result is known, and stops for operator reconciliation whenever
the SMTP outcome is ambiguous.

## Functional Requirements

- FR-001: Account configuration stores one optional secure SMTP endpoint in
  addition to the existing IMAP endpoint. Provider presets supply both defaults.
- FR-002: A bounded `SendRequest` requires an account, at least one recipient,
  a subject, and at least one text or HTML body. Attachments are out of scope.
- FR-003: Planning validates the request, assigns a stable plan id and
  Message-ID, computes a content hash, and persists an immutable snapshot in a
  private local SQLite outbox without reading credentials or using the network.
- FR-004: Plans expire after 24 hours unless already applying, sent, or
  ambiguous. A changed request always creates a new plan and approval boundary.
- FR-005: Approval is local, account-bound, plan-bound, and available only in an
  interactive terminal. MCP exposes no approval operation.
- FR-006: Apply atomically claims an approved plan before reading credentials or
  invoking SMTP. Concurrent or repeated apply calls cannot cause a second send.
- FR-007: A successful SMTP transaction produces a bounded receipt and the
  terminal `sent` state. Failure before SMTP invocation is `failed`; any error
  after delivery invocation begins is conservatively `ambiguous`.
- FR-008: Ambiguous plans cannot be automatically retried. Operators inspect
  status and create a new plan only after external reconciliation.
- FR-009: CLI and MCP call the same runtime services. MCP exposes task-level
  plan, status, and apply tools, but never approval.
- FR-010: Secrets remain in the OS credential store and are never accepted in
  command arguments, input JSON, plan storage, receipts, logs, or stdout.
- FR-011: SMTP uses implicit TLS or mandatory STARTTLS only. Plaintext and
  opportunistic downgrade are rejected.
- FR-012: A credentialed live smoke test, when the OS credential boundary is
  available, sends one clearly labelled message only to the dedicated test
  mailbox itself and verifies it through the read path.

## Non-Requirements

- Attachments, drafts, scheduled sending, bulk mail, templates, tracking, or
  automatic follow-up.
- Agent-generated prose or autonomous approval.
- Automatic retry after SMTP invocation.
- Remote deletion of the smoke-test message.
- POP3 sending or provider-specific SMTP behavior in command handlers.

## Success Criteria

1. Tests prove validation bounds, immutable plans, TTY-only approval, guarded
   transitions, concurrent apply exclusion, and ambiguous-outcome handling.
2. CLI JSON remains versioned and protocol-clean; MCP stdio emits no banners.
3. SMTP MIME construction preserves recipients, Unicode content, and the stable
   Message-ID while enforcing encrypted transports.
4. Full format, Clippy, tests, build, and dependency-policy gates pass.
5. The isolated 163 self-send passes, or a sanitized credential-store blocker
   is recorded without weakening the secret boundary.
