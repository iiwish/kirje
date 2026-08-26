# T010 Evidence

- Result: complete
- Scope: CLI and MCP sync, index, and attachment surface
- RED: CLI contract test failed because `--index` and the new commands were not
  yet recognized.
- GREEN: CLI tests cover empty credential-free status/search and untrusted
  output. MCP stdio tests list ten tools and verify `mailbox_sync` is a
  non-destructive local write while local search is closed-world read-only.
- Inspector: MCP Inspector returned ten object-schema tools; sync limit is 500,
  attachment limit is 1,048,576 bytes, and safety annotations match behavior.
- Review: CLI and MCP are thin adapters over the same runtime methods; stdout is
  protocol-clean.
