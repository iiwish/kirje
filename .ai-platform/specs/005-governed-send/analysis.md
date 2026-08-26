# Analysis: Governed Send

## Result

No blocking inconsistency exists between the approved direction, product
contract, architecture, and work graph. The feature remains high risk but has
explicit human and transactional gates.

## Risk Controls

- Planning is local and credential-free; approval never crosses MCP.
- The approved snapshot includes all recipients, subject, bodies, account,
  content hash, and stable Message-ID.
- SQLite compare-and-transition operations exclude concurrent duplicate sends.
- SMTP errors after invocation are ambiguous rather than retryable failures.
- Provider defaults supply endpoints, but adapters validate protocol and TLS
  again before network access.
- Live verification never bypasses the OS credential store or targets a third
  party.

## Residual Risks

- SMTP cannot provide true end-to-end exactly-once delivery. Kirje guarantees
  at-most-one invocation per plan and makes uncertain outcomes visible.
- A process crash after server acceptance remains `applying`; startup/status
  reconciliation converts stale applying work to `ambiguous` rather than retrying.
- HTML is sent as supplied and may contain untrusted content. It is never
  rendered by Kirje and is bounded before persistence.
