# Requirements Checklist: Provider Preset Registry

- [x] Scope is limited to provider data, discovery, CLI inspection, and a
  read-only live check.
- [x] Runtime support and reference-only protocols are distinguished.
- [x] Plaintext endpoint fallback is explicitly forbidden.
- [x] Registry entries require unique identifiers, domains, and provider-owned
  source evidence.
- [x] Secret entry, retention, output, and cleanup boundaries are explicit.
- [x] CLI and MCP behavior remain backed by the same core discovery contract.
- [x] Validation covers malformed embedded data and provider-specific ports.
- [x] POP3, remote writes, OAuth2, and background activity are out of scope.
