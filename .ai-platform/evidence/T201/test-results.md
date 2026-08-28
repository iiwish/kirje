# T201 Test Results

## T201-A001

- RED: expected failure, exit 101.
- GREEN: not run; packet remediation required.
- Core regression: not run.
- Format, Clippy, and Rust 1.88 checks: not run.

No acceptance claim is made for T201-A001.

## T201-A002

- RED: expected missing-contract failure, exit 101; additional sealed-control
  and Unicode-boundary RED failures also matched T201.
- GREEN: targeted five-test-binary command passed 26 tests.
- Core regression: passed 52 tests.
- Format: passed.
- Clippy with warnings denied: passed after lint-only fixes.
- Rust 1.88 check: passed.
- Independent orchestrator rerun: all commands above passed with exit 0.
- Review: failed on five blocking invariant classes; A003 required.

No acceptance claim is made for T201-A002.

## T201-A003

- Initial review-remediation RED: expected contract failures, exit 101, across
  the five A002 invariant classes.
- Additional orchestration-review RED: expected endpoint host-kind and
  `mismatch + bound` state-matrix failures, exit 101.
- GREEN: the final five-test-binary targeted command passed 34 tests.
- Core regression: passed 60 tests.
- Workspace regression: all workspace tests and doc tests passed.
- Workspace Clippy with warnings denied: passed.
- Workspace all-features build: passed.
- Format: passed.
- Clippy with warnings denied: passed.
- Rust 1.88 check: passed.
- Cargo deny advisories, bans, licenses, and sources: passed.
- Git diff check: passed.
- Strict-verifier/dependency review: passed; one production `verify_strict`
  path, exact `ed25519-dalek` 3.0.0 with only `fast` enabled.
- Privacy scan: passed with no mailbox secret, real account, private material,
  or raw provider response.
- Independent spec, cryptographic, engineering, and QA review: accepted with
  no blocking finding.

T201 acceptance is based on the final A003 worktree state.
