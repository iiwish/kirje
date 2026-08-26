# Requirements Checklist

- [x] Read-only product boundary is explicit.
- [x] Secrets cannot enter CLI arguments, config, JSON, logs, or MCP.
- [x] TLS verification cannot be disabled.
- [x] Protocol reuse has an adapter boundary.
- [x] Output bounds and untrusted-content marking are specified.
- [x] CLI and MCP parity is required.
- [x] Write operations and approval remain out of scope.
- [x] Test categories and live-test boundary are explicit.
- [x] All implementation tasks have passed local validation.
- [ ] GitHub CI has passed the completed feature branch.
