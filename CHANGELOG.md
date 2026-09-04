# Changelog

All notable changes to Kirje are documented here. The project follows Semantic
Versioning and uses prerelease versions while the stable 1.0 contract is being
completed.

## [1.0.0-alpha.1] - 2026-09-04

### Added

- First distributable Security Alpha for the Kirje CLI and MCP server.
- Capability-anchored, no-follow, bounded local file input and private atomic
  configuration replacement.
- Authority-backed credential cleanup with atomic grant claim, opaque delete
  permits, idempotent OS-keyring deletion, durable terminal events, and exact
  failure recovery.
- Cross-platform CI and tagged binary release automation.

### Changed

- Raised the source-build minimum Rust version to 1.95.
- Raised JSON send/draft input to the documented 24 MiB envelope and mailbox
  operation input to 1 MiB while retaining lower domain limits.
- Updated `chacha20` to 0.10.2, removing the yanked dependency blocker.

### Security

- File metadata and consumed bytes come from the same opened handle.
- Final-component links and non-regular file inputs are rejected.
- Concurrent Kirje configuration writers are serialized before the opened-file
  identity check, so exactly one stale compare-and-swap contender succeeds.
- Credential cleanup does not expose credential presence or locator material.

[1.0.0-alpha.1]: https://github.com/iiwish/kirje/releases/tag/v1.0.0-alpha.1
