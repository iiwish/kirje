# T202C3-A006 Cleanup Contract Fix A003

## Scope

This governance-only attempt fixes the remaining High finding from repeat A006
review. It changes no production code, test, schema, core transcript, runtime,
keyring, protocol, CLI, MCP, network, or external-provider behavior.

## Finding Addressed

`H-A006-R2-001` found that the shared public locator constructor and pluggable
deletion method still allowed runtime to bypass authority. The approved
architecture is one unpublished `crates/kirje-credential` crate directly
depended on by `kirje-store` only. Runtime, core, CLI, MCP, protocol, and every
other crate may neither depend directly on nor receive or re-export it.

Rust provides no friend-crate visibility. The checked locator constructor and
`delete_only` function may therefore be Rust-visible only as needed by their
sole direct Cargo consumer; the enforceable boundary is the workspace direct-
dependency allowlist plus no-re-export and compile-fail checks. There is no
public or sealed deletion trait. The low-level success type is exactly
`Result<(), MailError>`; deletion and `NoEntry` both return `Ok(())` without a
presence signal.

## Ownership

- A007 creates the unpublished low-level crate, opaque locator, root/store-only
  dependency entries, store-private fake deletion hook, permit/claim foundation,
  and event 16.
- A008 adds the real low-level keyring delete, the sole production
  `kirje_credential::delete_only(` call in the combined store apply method,
  terminal cleanup behavior, event 17, and dependency/call-site/compile-fail/
  no-re-export checks.
- T204 migrates/removes legacy runtime `SecretStore` paths and wires runtime/CLI
  only to the high-level store cleanup API. It owns no low-level backend code and
  never receives locator material.

Authority open, read, challenge, claim validation, and recovery-validation
paths never call the keyring. The store's consuming combined apply method is the
sole adapter-call boundary: under the permit/apply lock it constructs the
opaque locator, calls the low-level function exactly once, and records terminal
state only after success.

## Architecture Decision

On 2026-08-31 the orchestrator exercised the user's standing delegated
acceptance authority for the same material workspace/dependency decision and
approved this implementable store-only formulation, superseding the flawed
shared runtime/pluggable formulation. This records delegated orchestrator
approval, not personal user review of this unseen artifact and not
implementation evidence.

## Validation

- Ruby YAML parse of all 32 `.ai-platform/**/*.yaml` files: passed.
- 007 delivery artifact validator: passed with zero errors or warnings.
- 008 delivery artifact validator: passed with zero errors or warnings.
- `git diff --check`: passed.

## Result

The A006 packet remains `ready_for_review`; production and test permissions
remain closed pending another independent packet review. A007 and A008 remain
non-executable. `H-A006-R2-001` is proposed fixed but remains open until that
review passes.
