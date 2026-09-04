# T202C3-A006 Cleanup Contract Fix A004

## Scope

This governance-only attempt fixes the one Medium returned by final QA of
commit `b971153`. It changes no production code, test, schema, dependency,
lockfile, core transcript, runtime, keyring, protocol, CLI, MCP, network, or
external-provider behavior.

## Finding Addressed

`M-A006-R3-001` found that a literal sole-call scan can miss Rust use aliases,
wildcards, re-exports, macro indirection, function pointers, or indirect
bindings. A008 therefore owns a dedicated AST-based allowlist test that
recursively parses every production Rust file under `crates/kirje-store/src`.
Any parse failure or unvisited production source fails the test.

The only allowed low-level location is private module
`credential_cleanup_delete_adapter` and its combined permit-consuming method
`AuthorityStore::apply_credential_cleanup_delete`. Production source contains
no low-level import, alias, wildcard, re-export, macro/function-pointer/indirect
binding, constructor/type/API reference, or call outside that exact method.
Only that method may mention `DeleteOnlyLocator`; it calls the fully qualified
`kirje_credential::delete_only` exactly once.

The AST allowlist composes with the Cargo-metadata/tree direct-dependency
allowlist, store no-re-export checks, and runtime compile-fail fixture proving
`kirje_credential` cannot be imported or named because runtime has no direct
dependency. If a parser dependency is necessary, A008 may add one scoped
test-only dev dependency to `kirje-store`; A008 owns the reviewed `Cargo.lock`
change and proof that the parser is absent from the production dependency tree.
No parser dependency or AST test is implemented by this governance attempt.

## Ownership And Gates

- A008 owns the AST test, exact adapter, optional test-only parser dependency,
  lockfile evidence, and all composed dependency/compile-fail/no-re-export
  checks.
- T204 reruns these controls and may not weaken, remove, or bypass them. It
  continues to own only high-level runtime/CLI integration and legacy
  `SecretStore` path removal.
- A006's final packet gate is recorded separately in
  `T202C3-A006-packet-review.md`. A007 and A008 remain non-executable.

## Validation

- Ruby YAML parse of all 32 `.ai-platform/**/*.yaml` files: passed.
- 007 and 008 delivery artifact validators: passed with zero errors or warnings.
- `git diff --check`: passed.

## Result

Final independent review at governance HEAD `3533054` closed
`M-A006-R3-001` with zero finding and issued
`T202C3_A006_PACKET_REVIEW_PASS`. This attempt claims no implementation or user
review of unseen work.
