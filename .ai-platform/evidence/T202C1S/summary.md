# T202C1S Evidence Summary

T202C1S is accepted under the delegated project-owner authority at production
commit `8eceaff`. One bounded test-first attempt corrected the unreleased
canonical Authority SQLite v1 before any account-transition or remote-effect
writer exists.

The accepted schema has 20 tables, 15 explicit indexes, and 3 triggers. Its
SHA-256 is
`5d01739b89246a5f495a965e57e416eee9fd0b5016995add41c6edee7f3e970d`;
application ID `1263096394` and user version `1` are unchanged. Historical
remote effects now terminate at immutable store and account version rows rather
than mutable current projections. Exact composite transition origins,
credential ownership, nullable store-version origins, and version parent
cardinality are enforced by SQLite keys and foreign keys.

Accepted store enrollment inserts one receipt-origin immutable store version in
the existing grant/store/event/clock transaction. Ordinary exact retry validates
and returns that immutable enrollment projection without a second row, event,
timestamp, or entropy draw. Every pre-commit fault, including the new
post-version-insert boundary, rolls the complete graph back; response loss after
commit and concurrent exact retry recover one durable result.

Schema tests prove that legal current store and account projections can advance
while historical effects remain valid. Missing, duplicate, malformed,
cross-store, cross-account, cross-credential, cross-transition, mutable-parent-
only, and old 17-table developer inventories fail closed. Foreign-key check is
empty and integrity check is `ok` for valid graphs.

The 128-row restart proof uses four registry streams and `28 * 128` bounded
keyed lookups with O(1) additional Rust history memory. Store-version ordering
and relationship lookups use primary or unique autoindexes with no temporary
B-tree or correlated scan.

Independent final review reported zero Critical, High, or Medium finding and
issued `T202C1S_A001_CODE_REVIEW_PASS`. One accepted Low watch item remains:
the new whole-table registry-parent preflight is not represented by its own
test-support query counter. Production currently invokes it once, so no
quadratic behavior exists; T202C2 must retain the one-time preflight placement
or add explicit counting before expanding validator loops.

The orchestrator independently reran package, no-default-feature, workspace,
Rust 1.88, format, Clippy, build, schema digest, cargo-deny policy, artifact,
scope, whitespace, privacy, and secret gates. The feature-wide artifact
validator passes; its known inability to select suffixed task IDs is documented
in analysis L-003. Advisory-only checking still reports only the pre-existing
yanked `chacha20 0.10.1` through the unchanged `io-imap` dependency chain.

T202C2 owns account-create challenge and transition writers, legal-successor
enrollment retry, and immutable credential/account/store-version production
updates. No T202C2 operation or public CLI/MCP/runtime surface is introduced by
this task.
