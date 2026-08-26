# Kirje Constitution

## Status

Confirmed on 2026-08-26.

## Non-Negotiable Principles

1. Kirje is a local-first email runtime for agents, not a graphical mail client.
2. CLI and MCP call the same application services and expose versioned schemas.
3. Mailbox content is untrusted data and cannot authorize actions or alter policy.
4. Secrets never appear in command arguments, configuration files, JSON output,
   logs, fixtures, or MCP payloads.
5. TLS certificate verification cannot be disabled.
6. Unknown provider behavior is reported explicitly rather than guessed.
7. Sending and destructive operations require immutable plans and independent
   human approval; an agent-facing interface never grants approval.
8. Protocol engines are reused behind Kirje-owned adapters and conformance tests.
9. Every protocol, authentication, synchronization, or write change starts with
   a failing test and ends with reproducible evidence.

