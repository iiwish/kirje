# T017 Evidence: Runtime, CLI, And MCP Workflow

## Result

Complete. CLI and MCP use the same runtime plan, status, and apply services.
Only the CLI exposes approval, and it rejects redirected stdin or stderr before
reading a confirmation.

## TDD Evidence

- RED: runtime lifecycle and MCP contract tests failed before shared services
  and the three send tools existed.
- GREEN: targeted runtime, CLI, and MCP suites passed 25 tests.
- Review gate: workspace Clippy passed with all features and warnings denied.

## Review

The runtime claims before credential access, records missing credentials as a
definite pre-delivery failure, records every post-invocation SMTP error as
ambiguous, and cannot claim a plan twice. CLI planning accepts only bounded JSON
from a file or stdin. MCP exposes `message_send_plan`, `message_send_status`, and
`message_send_apply`; no tool name or handler contains approval.
