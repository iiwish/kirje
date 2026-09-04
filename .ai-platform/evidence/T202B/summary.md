# T202B Evidence Summary

T202B is accepted under the delegated project-owner authority at production
commit `43f0788`. Four bounded, test-first attempts delivered sealed core
authorization projections, a serializer-independent detached-proof codec,
transactional challenge creation, immutable receipts and nonce consumption,
exact replay, effective-time expiry, canonical events, deterministic crash and
concurrency behavior, bounded public output, and fail-closed restart validation.

The accepted Authority SQLite v1 fence has SHA-256
`572a73ba5fa83c763188d804ce9767a3c21373410d8b170f6d97b49be0a86454`.
It contains 17 tables, 15 declared indexes, and 3 triggers with application ID
`0x4B49524A` and user version 1. Each challenge stores the exact sequence of its
created event. Restart validation streams same-context lifecycles through the
declared lifecycle index with O(1) application memory and bounded indexed event
lookups; authorized or expired predecessors must terminate before successor
creation, while pending is legal only as the final lifecycle row.

Independent final review found no Critical, High, Medium, or Low issue. The
orchestrator independently reran all packet gates and the full workspace test,
Clippy, and build gates. Targeted results are 16/16 core authorization tests,
27/27 schema tests, 33/33 authority authorization tests, 142/142 core/store
tests, and 19/19 no-default-feature tests. Workspace tests, warnings-as-errors,
build, Rust 1.88, schema digest, artifact, scope, whitespace, and privacy gates
pass.

`cargo deny check licenses bans sources` passes. Advisory-only checking still
reports the pre-existing yanked `chacha20 0.10.1` through the unchanged
`io-imap` dependency chain. T202B changes neither Cargo manifests nor the
lockfile and does not use that protocol dependency; dependency remediation
remains assigned to protocol/release work.

T202C is the next serial authority task and remains Draft until its packet is
complete and independently reviewed. The T202 umbrella remains Draft through
T202E aggregate acceptance.
