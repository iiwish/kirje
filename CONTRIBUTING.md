# Contributing

Kirje welcomes focused contributions that strengthen protocol correctness,
agent safety, provider compatibility, or machine-interface quality.

Before opening a pull request:

1. Open or reference an issue for behavior, protocol, auth, or storage changes.
2. Add tests before implementation for high-risk behavior.
3. Keep provider fixtures sanitized and free of credentials or message content.
4. Run the complete validation suite documented in `AGENTS.md`.
5. Describe the safety boundary and residual provider limitations in the PR.

Use Conventional Commits. Features should remain small enough to review without
mailbox access. Real-mailbox verification belongs in sanitized evidence, never
in committed raw messages or logs.
