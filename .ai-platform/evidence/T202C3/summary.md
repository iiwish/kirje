# T202C3 Evidence Summary

## Status

The credential-cleanup challenge, atomic claim, opaque permit, delete-only
keyring call, retry, and terminal event implementation is present in production
commit `2be6ce6`. The challenge-precedence repair is commit `5323855`. The
workspace release closure is commit `bebb9ce`.

This implementation is locally validated for the `v1.0.0-alpha.1` security
foundation. T202C3 and its T110 umbrella remain Running: the full Security
Baseline is targeted at `v1.0.0-alpha.2`, and the exhaustive production AST
allowlist and aggregate independent acceptance review remain outstanding.

## Delivered

- Cleanup challenge creation uses public eligibility precedence before
  request-directed private classification.
- Grant consumption and `ready -> claimed` commit in one authority transaction.
- Exact recovery of a claimed cleanup returns a fresh opaque delete permit;
  terminal deletion returns no permit and no locator material.
- The non-`Clone`, non-`Debug`, non-serializable permit is consumed by the one
  high-level store apply method.
- `kirje-credential` is unpublished and directly depended on only by
  `kirje-store`; it exposes delete-only keyring access and collapses missing and
  deleted credentials to the same success result.
- Backend failure leaves the cleanup claimed and retryable. Success commits the
  terminal event exactly once.
- Capability-anchored local input, create-only account configuration,
  dependency remediation, and release packaging are integrated in the alpha.1
  release candidate.

## Verification

The fresh release-candidate gate on macOS arm64 passed:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-features --locked` (248 tests on macOS)
- `cargo build --workspace --all-features --locked`
- `cargo build --release --locked --package kirje-cli`
- `cargo deny check`

Focused cleanup tests cover atomic/exact claim recovery, adjacent grant/event
order, changed-grant rejection, terminal no-recall, idempotent deletion,
backend-failure retry, restart validation, and absence of locator material from
public projections. The release binary also passed isolated `schema`, `doctor`,
archive-content, and SHA-256 checksum smoke tests without credentials or network
access.

## Residual Scope

- Add the exhaustive syntax-tree allowlist that proves the low-level credential
  API has no indirect or re-exported production call site.
- Complete the remaining owner rotation/recovery, config v2, ledger v3, runtime
  authorization, CLI owner workflow, MCP framing, and protocol-response gates
  owned by the `alpha.2` Security Baseline.
- Obtain remote Linux/macOS/Windows CI evidence before creating a release tag.

## Evidence Index

Historical T202C3 attempts and packet reviews remain under
`.ai-platform/evidence/T202C3/attempts/`. Their returned-candidate findings are
historical inputs, not descriptions of the production state above. Detailed
RED/GREEN history and the fresh alpha.1 closure gate are recorded in
`test-results.md`.
