# Requirements Checklist: Governed Send

- [x] Human approval and agent-accessible operations are explicitly separated.
- [x] The immutable content covered by approval is defined.
- [x] Concurrent apply and duplicate-send prevention are testable requirements.
- [x] SMTP uncertainty is represented explicitly and disables automatic retry.
- [x] Secret entry, retrieval, storage, output, and log boundaries are explicit.
- [x] Plaintext and opportunistic TLS are forbidden.
- [x] CLI and MCP share runtime services, while MCP cannot approve.
- [x] Message, recipient, result, and listing bounds are explicit.
- [x] Attachments, scheduling, bulk mail, and autonomous writing are out of scope.
- [x] Live testing is self-addressed, bounded, and conditional on the OS keyring.
