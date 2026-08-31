# Plan: Security Baseline

## Metadata

- Feature ID: `008-security-baseline`
- Status: Confirmed
- Target checkpoint: `v1.0.0-alpha.1`
- Source spec: `spec.md`
- Updated: 2026-08-31
- Review authority: delegated project owner

## Decision Summary

Kirje Security Alpha establishes one fail-closed security path for account identity,
mailbox credentials, owner authorization, local input, MCP framing, and remote
response data. The fixed owner authority store is the only source of owner
trust, config-store enrollment, authorization receipts, and global remote-effect
claims. The caller-selected operation ledger remains the detailed workflow and
audit projection, but it cannot grant or replay authority by itself.

The release is a security and compatibility slice. It adds no new mailbox
effect. Existing v0.3 accounts and ledgers migrate conservatively: metadata
remains inspectable, legacy credentials are quarantined, legacy TTY approval is
historical only, and every pending remote effect needs a new owner-signed grant.

## Constitution Check

- Local-first and no GUI: satisfied. Trust, receipts, account state, and audit
  remain on the operator's machine.
- Deterministic infrastructure: satisfied. Kirje verifies typed manifests and
  detached signatures; it does not author mail or make policy judgments with a
  model.
- Read/write authorization separation: satisfied. Read-only inspection does not
  create a grant, and a grant does not expose credentials.
- Plan/authorize/apply: satisfied. Every remote effect and sensitive control
  action uses one shared authorization service.
- Secret exclusion: satisfied. Mailbox credentials remain in the OS credential
  store; owner private keys remain outside Kirje.
- Shared CLI/MCP services: satisfied. MCP uses shared read/status/apply services
  but has no owner, proof, account, credential, policy, or reconciliation
  mutation.
- Protocol neutrality: satisfied. Account binding and capability contracts are
  provider-neutral; IMAP/SMTP details remain in adapters.
- Stable bounded machine output: satisfied. New states, errors, limits, and
  schemas are versioned and covered by golden tests.
- TDD and release evidence: satisfied. Every behavioral task starts with a
  verified RED test and ends with full gates and sanitized evidence.

No constitution exception is proposed.

## Architecture

### Core

`kirje-core` owns stable identifiers, account-binding canonicalization,
authorization action/manifest contracts, deterministic signing transcripts,
bounded untrusted-value types, effect IDs, authorization-aware operation states,
and stable error codes. It performs no filesystem, keyring, SQLite, network, or
terminal work.

### Store

`kirje-store` owns two distinct SQLite roles:

1. The platform-pinned authority database stores the owner realm, public trust
   history, config-store registrations, challenges, receipts, and global effect
   claims.
2. The caller-selected operation ledger stores operation payloads, state
   projections, receipts, and append-only application events.

The authority database never accepts a normal `--outbox`, `--index`, `--config`,
environment, or MCP path override. Its application ID is fixed to
`0x4B49524A` (`KIRJ`) and its v1 schema is created completely before later
authority operations exist. Production paths come only from
`ProjectDirs::from("", "", "kirje")`.
Tests inject a complete isolated authority home and deterministic entropy only
through the explicit non-default `test-support` feature.

### Credential Capability Boundary

`kirje-credential` is a lower-level unpublished (`publish = false`) workspace
crate and a direct dependency of `kirje-store` only. It owns the opaque
non-`Clone`, non-`Debug`, non-serializable `DeleteOnlyLocator` and the concrete
delete-only keyring function/backend. No public or sealed janitor trait exists.
Every other workspace crate, including runtime, core, CLI, MCP, and protocol,
must not directly depend on, receive, or re-export the crate or locator. The
constructor and function may be Rust-public only because cross-crate use
requires it; the enforceable boundary is the Cargo dependency allowlist, not a
friend-visibility claim.

`kirje-store` owns `CleanupDeletePermit` and the fixed authority apply lock. Its
only public deletion surface consumes the permit, constructs the locator, calls
`kirje_credential::delete_only` exactly once under that lock, and commits the
terminal state after `Ok(())`. Deleted and `NoEntry` have the same success;
there is no outcome enum or presence signal. Open/read/validation paths never
call the keyring, and store never re-exports low-level APIs. A007 introduces the
crate, opaque locator, root/store dependency entries, and store-private fake
deletion hook. A008 adds the concrete low-level keyring delete and sole
production store call site in private module
`credential_cleanup_delete_adapter`, method
`AuthorityStore::apply_credential_cleanup_delete`. Its dedicated AST test
parses every production store Rust file and rejects imports, aliases, wildcards,
re-exports, macro/function-pointer/indirect bindings, low-level type/API
references, and calls outside that exact method. It composes with the Cargo
direct-dependency allowlist and runtime no-dependency compile-fail fixture. A008
may add a scoped store test-only parser dev dependency and owns its reviewed
lockfile change. T204 wires runtime/CLI only to the high-level store API and
migrates/removes legacy runtime `SecretStore` paths.

### Runtime

`kirje-runtime` owns bounded same-handle file access, config v2 migration and
compare-and-swap writes, owner authorization orchestration, credential binding,
shared action policy, and the crash-recovery protocol between authority claims
and operation-ledger projections. One authenticated call carries one validated
account snapshot from authorization recheck through keyring lookup and adapter
invocation.

`kirje-local-io` is a small platform boundary shared by runtime and CLI. It
owns capability-relative no-follow regular-file open, limit-plus-one reads,
private temporary files, and parent-directory sync. It contains no mail,
authorization, parsing, or command behavior.

### Adapters

`kirje-protocol` converts IMAP and SMTP input into bounded typed values before
returning core objects. Security decisions use complete typed capability sets,
not display strings. Unsupported or over-budget capability input fails closed.

`kirje-cli` owns human/operator command shape, hidden credential entry, bounded
file/stdin ingestion, challenge export, and proof submission. `kirje-mcp` owns a
reviewed tool allowlist plus a custom bounded stdio transport. Neither adapter
implements approval rules independently.

## Technical Decisions

### D-001 Separate Stable Identities

Configuration store, account, credential, authorization grant, operation, and
remote effect use independent UUIDv4 identities. The owner realm is an
independent 32-byte CSPRNG value; a challenge ID is SHA-256 of its exact signing
payload. The existing account `id` becomes `display_id`; it remains immutable
and human-facing. Operations use `account_id`, never `display_id`, as the
durable reference.

Account binding uses a `KIRJE-ACCOUNT-BINDING-V1` transcript with fixed field
order and length-prefixed bytes. DNS hosts are lowercase ASCII, IP addresses
use canonical `IpAddr` text, and email/authentication username bytes retain
their exact validated case. Protocol, transport, port, authentication kind, and
SMTP presence have explicit tags. SHA-256 of the transcript is the binding
digest.

### D-002 Config V2 Is Locked, Bounded, And Compare-And-Swap

`accounts.toml` schema v2 contains `store_id`, `generation`, and typed stored
accounts with stable `account_id` and `display_id` plus versioned
`credential_id`, `account_generation`, binding digest, and credential readiness. The whole file
is limited to 1 MiB and 100 accounts. Duplicate or malformed identities and
invalid state combinations fail closed.

All load/migrate/write operations:

1. Open one stable parent-directory capability.
2. Open a sibling lock file without following the final component and acquire
   an exclusive `fs4` lock.
3. Open the config final component once with `FollowSymlinks::No` and nonblocking
   semantics, verify the opened handle is regular, and read at most limit plus
   one.
4. Verify the expected generation and loaded content digest.
5. Write a private random sibling temp file through the same opened directory,
   flush file data, persist a replacement journal, and use Unix same-parent
   overwrite rename or Windows locked two-rename recovery through that
   directory. Sync every supported durability boundary.

`cap-std` plus `cap-fs-ext` provides safe no-follow/reparse-point and
directory-relative operations without adding project `unsafe` code. `fs4`
coordinates Kirje processes; generation and content-digest CAS remains the
correctness boundary.

### D-003 Conservative V1 Migration

A v1 TOML document migrates in one locked write. The migration assigns one
store ID and one account and credential ID per unique display ID. Every account
enters `legacy_quarantined`; no account-ID keyring entry is read, tested, copied,
or deleted. Generated IDs become durable only when the v2 replacement commits.
A restart reads the committed IDs rather than generating new values.

Operation-ledger schema v3 preserves terminal v2 records. Pending `planned` and
`approved` records become `authorization_required`; `applying` becomes
`ambiguous`; existing `ambiguous`, `failed`, `succeeded`, and compatibility
`sent` outcomes remain terminal with a bounded legacy provenance marker.

### D-004 Fixed Owner Realm And Authority Home

The production anchor, authority database, and apply lock resolve only from the
exact `ProjectDirs::from("", "", "kirje")` namespace:

- configuration anchor: `config_dir/owner-trust.toml`
- authority journal: `data_local_dir/authority.sqlite3`
- authority apply lock: `data_local_dir/authority.apply.lock`

The strict anchor stores an immutable 256-bit realm ID, journal ID, journal
location digest, current owner and offline-recovery Ed25519 public keys, minimum
trust epoch, and trust-bundle digest. `normal` is its only v1 state; recovery is
derived. `KIRJE-TRUST-BUNDLE-V1` binds realm, journal, epoch, both role-separated
key IDs, and both public keys. The location digest remains a separate pin.

T202A first adds the minimal core `OwnerPublicKey`: an exact 32-byte value only
when `ed25519-dalek` parses it and reports it non-weak. It has no serde, default,
private-key, key-generation, signature, or signing surface. Bootstrap and the
typed anchor use it and require distinct owner/recovery values before any side
effect. SQLite also requires unique public keys, exact owner/recovery role masks,
an exact active initial epoch 1, and checked successor `predecessor + 1` rows.

Bootstrap is create-once and database-first under the fixed apply lock.
The checked-in DDL is a transaction body with no transaction-control or PRAGMA
statement. `prepare_bootstrap` owns one `BEGIN IMMEDIATE`, executes that body,
inserts initial keys/epoch/meta/event, sets application ID/version, and issues one
`COMMIT`; rollback leaves zero user objects, rows, or version markers. Safe local
I/O writes the create-only anchor; `confirm_anchor` marks the exact match ready.
Missing-anchor pending state resumes from committed DB values.
Anchor-present/database-missing and every third-state mismatch enter recovery
and are never silently regenerated. Normal path flags and environment variables
cannot influence any production authority location.

T202A treats every staged epoch row or staged anchor as `recovery_required`; it
cannot yet prove the receipt or POP chain. T202E may introduce
`staged_finalize_required` only after T202B's core snapshot and exact transition
receipt plus role-required POP verification succeed.

The owner-authorized config-store enrollment binds `store_id` to a tagged
location digest over the opened parent directory's filesystem identity and the
final component's native bytes. Unix uses device/inode and native bytes;
Windows uses volume serial, file index, and UTF-16LE units. Missing stable
identity support fails closed. A bounded display form is diagnostic only.
Copying the same store ID elsewhere returns `config_store_identity_conflict`.

### D-005 Ed25519 Strict Detached Authorization

Kirje verifies Ed25519 signatures with `ed25519-dalek` 3.0 and
`VerifyingKey::verify_strict`. The dependency uses `fast` and `zeroize`; batch,
hazmat, legacy compatibility, private-key generation, PEM, and serde key
features remain disabled in production.

Every manifest and signing payload is a deterministic binary transcript:

```text
domain || field-count || repeated(tag-u16 || value-length-u32 || value)
```

Lengths and tags are unsigned big-endian integers; integer values use
fixed-width big-endian bytes; UUIDs use 16 network-order bytes; timestamps use
signed Unix milliseconds; optional fields and lists have explicit
presence/count tags. Tags are strictly increasing. Duplicate, unrecognized, missing,
out-of-order, or non-minimal fields are rejected.
The signed `KIRJE-AUTHORIZATION-V1` transcript binds realm, trust bundle, key and
epoch, grant, action, object, store/account context, manifest digest, binding,
policy, nonce, issuance, expiry, and effect IDs. Challenge expiry is at most 15
minutes and nonce material is 256 random bits.

The CLI exports Base64url-no-padding transcript bytes, SHA-256 digest, and the
exact bounded manifest. A proof document contains only format, challenge ID,
key ID, payload digest, and detached 64-byte signature. It is limited to 4 KiB.
Private signing keys and signing operations are not part of Kirje.

### D-006 Authority Receipts And Global Effect Claims

Proof verification, nonce consumption, and immutable receipt insertion happen
in one `BEGIN IMMEDIATE` authority transaction. Proof, receipt, grant use, effect
claim, invocation start, and effect observation each use a domain-separated,
strict-tag binary transcript independent of JSON serialization. Exact proof
replay always returns the same immutable receipt projection, including after
expiry/rotation, but cannot refresh authority; any changed replay fails.

The v1 schema duplicates only the context needed for local fail-closed checks and
binds each copied set with exact parent composite `UNIQUE` keys and child
composite foreign keys. Receipt, nonce, grant, challenge-effect/remote-effect,
effect-claim, invocation, and observation chains cannot be assembled from
individually valid rows belonging to different parents. Store and account copied
context is bound as a whole. All relationships retain `ON DELETE RESTRICT`; an
application comparison is defense in depth, not the sole integrity boundary.

Each remote effect has a globally unique random effect ID bound into its
manifest and registered with its receipt. Apply receives typed request snapshots
and performs one authority transaction that revalidates expiry, anchor/meta,
trust epoch/key/bundle, store location/config generation/digest, account
generation/credential/binding/state, policy, manifest, operation, and effect,
then inserts one global claim. Caller booleans cannot replace comparisons. This
happens before credential lookup or network access.

The operation ledger records authority receipt and effect-claim projection in a
separate durable transaction. The process then holds the fixed apply lock and
inserts one unique authority `effect_invocation`; only the transaction winner
receives an in-memory invocation permit. Credential lookup and network access
require that permit. Authority records the bounded outcome before mirroring it
to the ledger.

Crash recovery compares immutable IDs in both stores. A claim without a ledger
projection is restored as a claimed projection. An invocation without an
observation becomes `ambiguous` after the crashed process releases the fixed
lock and is never invoked again. A ledger claim without matching authority
state fails closed as `authority_projection_conflict`. An outbox copy or
rollback cannot acquire the same effect or invocation twice. A known
pre-network failure still consumes the grant/effect and records
`known_no_effect`; it cannot become retry authority.

### D-007 One Authorization Policy Map

A closed `SensitiveAction` enum and exhaustive policy function cover send,
mailbox mutation, account create/update/remove, credential set/delete and
retired cleanup, config-store enrollment, policy/assurance changes, owner and
recovery rotation, and ambiguous closure. New enum variants cause an exhaustive
compile failure and require a golden action-matrix update. Unrecognized serialized
actions fail closed.

Existing `approve` commands become compatibility diagnostics that return
`owner_authorization_required`; they cannot change ledger state. CLI challenge
and proof commands call shared runtime services. MCP has no challenge/proof or
sensitive control-plane mutation and its request schemas accept no inline
authorization material.

### D-008 Credential Locator And Crash Ordering

The keyring service is `dev.kirje.mail.credentials.v2`, and its username becomes
`v2:` plus a lowercase SHA-256 digest over owner realm, store ID, account ID,
credential ID, and account-binding digest. Active lookup has no display-ID or
legacy fallback. The pinned authority registration and one config snapshot
must agree before any keyring operation.

Credential set writes the new locator first and commits `bound` with expected
generation second; a crash leaves an unreachable orphan. Active delete removes
the locator first and commits `missing` second; either crash point fails closed.
A binding-changing update commits the new credential identity plus an immutable
delete-only tombstone for the old locator. Cleanup can only call delete on the
exact tombstoned locator and cannot read, test, list, export, copy, or rebind it.
The locator is one bounded canonical kind/service/username transcript and the
tombstone is one domain-separated 14-field transcript bound to the finalized
origin transition's historical-before account, credential, and binding. All v1
tombstones are transition-bound, including legacy locators. Claim consumes one
grant and returns an opaque apply-lock-owning delete permit. A combined service
consumes the permit, calls only the low-level delete function, and commits deletion;
it exposes neither a standalone terminal marker nor a deleted-versus-absent
result. A007 creates the unpublished lower-level credential crate, opaque
locator, store-only direct dependency, store-private fake deletion hook,
store-owned permit, and combined store contract. A008 adds the real low-level
keyring delete, exact private adapter method, and exhaustive production-source
AST allowlist. T204 migrates/removes legacy
runtime `SecretStore` paths, wires runtime/CLI only to the high-level store API,
and proves end-to-end crash recovery. No schema or core transcript changes are
part of this architecture decision.

Cleanup challenge creation begins with a pure `authority.rs` manifest preflight:
`transition_id=None` is `authorization_malformed` before apply lock, file,
database, or entropy work, with zero I/O, mutation, or entropy and no core
change. Complete request-independent global authority validation then may stream
all private cleanup, origin, locator, and tombstone graphs. After the request-
independent global validation pass, no request-directed pending/private lookup
or request-dependent private branch may occur before the closed public pair
classification. Absent store/account or persisted
pair mismatch returns `credential_cleanup_invalid`; a matched recovery store
returns `owner_recovery_required`; matched blocked store or blocked account
returns `account_update_conflict`. An unrelated existing matched blocked pair
independently returns `account_update_conflict`. An unrelated existing matched
recovery-store pair independently returns `owner_recovery_required`. A finalized-origin proposed account is corruption;
an unrelated matched proposed pair returns `account_update_conflict`. Active
store plus active/removed account proceeds to request-directed private target
validation. The public-pair matrix contains independent absent-store, absent-
account, pair-mismatch, matched-recovery, matched-blocked, unrelated-proposed,
unrelated-blocked, unrelated-recovery, active/active, and active/removed rows.
Each row is crossed independently with wrong origin, locator kind, locator
digest, tombstone, lifecycle, and descriptor. Every public-ineligible
class returns its closed public result without target distinction, while the
two active classes proceed and return `credential_cleanup_invalid` for each
private-invalid cell. A same-context expired pending challenge followed by a
later matched blocked state returns `account_update_conflict`; a later matched
recovery-store state returns `owner_recovery_required`. Both return without a
pending-row lookup-dependent interaction: predecessor state/event and both
clock fields remain unchanged, and entropy/successor/grant/nonce/cleanup deltas
are zero. For an active eligible pair and valid private target, deterministic
faults `OldChallengeExpiredState` and `OldChallengeExpiredEvent` prove rollback
of all tentative predecessor/event/clock work and zero entropy/successor/cleanup.
A different-context invalid target has zero predecessor interaction; persisted
corruption is step-2 `owner_recovery_required`. The exact issuance phases are
pure preflight, lock/transaction, global validation, checked effective time/time
shape without pending access, public classification, private validation, pending
lookup, reuse/replacement, and successor commit. No pending expiry is durable
before public eligibility; ordinary claim/delete proof-expiry order is unchanged. Generic
locator length gates use one private numeric classifier with numeric-only
`#[cfg(test)]` unit tests; closed-form bytes remain in the registry integration
test. First/reuse/response-loss/valid-replacement/both-fault/restart/concurrent-
winner/every-loser paths each prove zero delta in all six effect/external tables,
zero external calls, and unchanged cleanup; origin grant uses may preexist, so
`grant_uses` is asserted by delta.

The A006 F011 delivery lifecycle leaves the substantive F006 cleanup contract
unchanged and keeps bespoke authority auditors retired. Governance evidence is
review and traceability material inside a trusted local execution boundary, not
a security credential, lock service, or malicious-repository-administrator
defense. The procedural trace is immutable reviewed P11, standalone A11
authorization/dispatch, one exact-scope C11 worker candidate, three reviews of
C11, and I11 review-complete evidence. Unexpected Git environment, rewritten
history mechanisms, or dirty/conflicting state stops the operation. The F011
packet is the canonical execution and evidence contract.

### D-009 Unified Same-Handle Bounded Input

One `kirje-local-io` service backs attachment, send, draft, operation,
authorization, and config file reads. It opens the final component exactly once
relative to an opened parent using no-follow and nonblocking options, validates
the returned handle as regular, applies metadata as an early rejection only,
and consumes at most limit plus one from that handle. Streams use the same
limit-plus-one rule and require EOF at the exact limit.

Constants are:

- account config: 1 MiB
- general operation JSON: 1 MiB
- send/draft JSON: 24 MiB
- authorization proof: 4 KiB
- authorization manifest/transcript: 4 MiB
- one imported attachment: existing 1 MiB decoded limit
- all imported send attachments: existing 8 MiB decoded limit

Typed serde visitors enforce collection, string, Base64, and nesting limits
during deserialization. Allocation failure and every over-limit condition map
to a stable non-secret `resource_limit` result before persistence.

Windows performs lexical namespace/reserved-device rejection before opening
the parent. Config replacement is Unix same-parent atomic rename or Windows
locked journaled two-rename recovery; no delete-then-rename or path-based
fallback weakens the opened-parent boundary.

### D-010 Bounded MCP Stdio

`kirje-mcp` supplies a custom `rmcp::Transport<RoleServer>` rather than the
unbounded async-read adapter. The transport reads newline-delimited frames into
a pre-sized buffer and never retains more than 24 MiB plus 4 KiB plus one byte. A
limit-plus-one frame emits one bounded ID-null invalid-request response, writes
one redacted stderr diagnostic, closes, and exits nonzero without draining the
remaining stream.

The 24 MiB service-document budget covers the largest valid shared send
request. A distinct 4 KiB transport allowance covers the 128-byte request ID,
method name, and JSON-RPC syntax before the newline. Generated tests recompute both
inequalities from core constants. A 16 MiB shared result likewise uses a
separate 4 KiB output-envelope allowance before its one-byte line feed.

The transport permits four request handlers plus one control task. Request
admission reserves a handler slot, active ID, and maximum output allowance.
Handler completion releases only the handler slot; the active ID and output
reservation survive until the matching response is actually sent, cancellation
reaches the worker-aware `TerminalNoResponse` state, or disconnect cleanup
runs. Cancellation after response claim completes the send path. The control lane accepts one
`notifications/initialized` and cancellation for a known active request. A
normal fifth request receives a bounded busy result. Other notifications fail
closed. Writer work and transport queues are bounded by item, actual byte, and
outstanding reservation budgets. Before rmcp builds `serde_json::Value`, a
method-aware lexical preflight enforces the same shared field/count/depth and
decoded-byte limits. Backpressure stops stdin reads before another frame.
Raw request/result tracing is disabled; logs contain method, bounded ID digest,
size, duration, and result category only.

### D-011 Bounded Remote Values And Complete Capabilities

Core exposes byte-first bounded untrusted types with `complete`, `truncated`,
`omitted`, or `rejected` disposition. Presentation character truncation is a
second step. Security-relevant IMAP/SMTP capabilities use a closed typed set and
a completeness flag; an incomplete set cannot authorize extension-dependent
behavior.

Initial contract budgets are:

- one complete IMAP response fragment: 12 MiB, including initial connection,
  greeting, capability, and authentication responses
- capability set: 128 items, 256 bytes per item, 16 KiB total
- one remote identifier/header/attribute: 4 KiB wire bytes
- SMTP transport: lettre's 1,000-byte line and 100,000-byte aggregate response
  bounds, with a 256-byte Kirje receipt display after control stripping
- one adapter diagnostic: 1 KiB
- one structured machine result: 16 MiB serialized
- untrusted values within one result: 8 MiB total
- existing list counts remain at or below 100, except the existing mailbox
  inventory ceiling of 1,000 with the same total-result budget

The IMAP adapter supplies a Kirje-owned bounded connection pump around public
session-open and stream primitives so io-imap's 100 MiB initial default is
never the effective boundary. Replacing only the post-connect fragmentizer is
insufficient. Invalid UTF-8 uses deterministic lossy display only after
security parsing of raw bytes. NUL and non-tab controls become visible replacement categories;
discarded data is never echoed. If an upstream protocol library cannot enforce
the wire boundary before allocation, the affected feature is reported
unsupported until its adapter is replaced or constrained; display truncation is
not accepted as a substitute.

### D-012 Stable Errors And Output Privacy

Core adds stable error codes for account/store identity conflicts, quarantined
or invalid credential binding, owner trust absence/recovery, authorization
required/expired/stale/replayed, effect already claimed, authority projection
conflict, unsupported secure file semantics, MCP overload, and bounded remote
response rejection. Errors remain versioned and carry retryability without
including paths beyond bounded operator diagnostics, mailbox content, raw
provider strings, secrets, signatures, locators, or complete manifests.

### D-013 Portability And Dependency Policy

New production dependencies are narrowly scoped:

- `ed25519-dalek = 3.0` for strict public-key verification
- `getrandom = 0.4` for realm, nonce, and identity entropy
- `cap-std = 4.0` and `cap-fs-ext = 4.0` for safe capability-relative file I/O
- `fs4 = 1.1` for cross-platform advisory coordination
- Tokio `io-util`, `sync`, and `time` features for the bounded MCP transport

All are pinned through `Cargo.lock`, pass `cargo deny`, and receive license,
MSRV, feature, and advisory review. The project keeps `unsafe_code = "forbid"`;
platform unsafe remains encapsulated in reviewed dependencies. macOS, Linux,
and Windows run equivalent no-link, migration, authorization, and framing tests.

### D-014 Release And Live Verification

The slice updates canonical product, architecture, security, operations,
provider, conformance, release, and Agent Skill documentation. Claims state only
IMAP/SMTP password or app-password support. OAuth2, provider APIs, Graph, and
JMAP runtime are unsupported.

Controlled real-account verification is read-only by default and receives the
credential through the OS keyring or hidden local prompt only. A separately
owner-authorized packet is required for any remote effect. Evidence records
aggregate pass/fail categories and capability counts only; it contains no
address, endpoint, UID, subject, body, attachment, credential, signature, or raw
provider response.

## State Models

### Account Readiness

```text
store: unregistered | registered | identity_conflict | recovery_required
owner: absent | ready | recovery_required
binding: quarantined | proposed | authorized | invalidated | mismatch
credential: legacy_quarantined | reentry_required | missing | ready | invalidated | store_unavailable
```

Remote authentication is ready only for
`registered + ready + authorized + ready` from one matching generation.

### Authorization

```text
challenge: pending -> authorized | expired | invalidated
receipt:   unclaimed -> claimed | used | expired | invalidated
effect:    registered -> claimed -> invoked -> observed
```

All transitions are monotonic in supported application paths. Exact proof
replay is idempotent; no transition returns to `pending` or `unclaimed`.

### Operation Projection

```text
planned -> authorization_required -> authorized -> applying
applying -> succeeded | failed | ambiguous
authorization_required|authorized -> expired
```

`authorized` is a projection of a valid authority receipt, not a ledger-local
approval. Terminal states remain immutable. `applying` recovery without a
matching resolved authority claim becomes `ambiguous`.

## Implementation Sequence

1. Core security contracts, byte transcripts, limits, and error catalog.
2. Minimal core owner-public-key boundary, authority schema transaction body,
   fixed home, bootstrap, fail-closed staged classification, anchor matching, and
   CSPRNG boundary (T202A).
3. Typed core payload projection, challenges, proofs, receipts, nonce use, and
   replay (T202B).
4. Grant use and exact store enrollment (T202C1).
5. Pre-release Authority SQLite v1 immutable registry-version correction and
   initial store-version enrollment (T202C1S).
6. Account-create challenge and transition lifecycle (T202C2).
7. Remaining account/credential transitions and delete-only cleanup (T202C3).
8. Registry-bound remote challenge effects and T202C aggregate acceptance
   (T202C4/T202C).
9. Remote-effect claim, invocation permit, and observation (T202D).
10. Verified staged-finalize classification, rotation, recovery, audit, and T202
   umbrella acceptance gates (T202E).
11. Same-handle bounded local I/O and cross-platform recoverable replacement.
12. Config v2, conservative migration, account identity, and bound keyring
   lifecycle.
13. Operation-ledger v3 migration and authorization/effect integration.
14. Shared authorization and crash-recovery runtime.
15. CLI owner, store, account, credential, and operation workflow.
16. Bounded MCP transport and lifecycle budgets.
17. Bounded protocol responses and complete capability model.
18. Canonical documentation, cross-platform QA, controlled live verification,
   release commit, PR, CI, merge, tag, and post-merge evidence.

Each numbered implementation task has its own packet and RED/GREEN evidence.
Only independent read-only review may run in parallel; production tasks that
share core, runtime, store, or adapter files remain serial.

## Validation Strategy

Task-scoped tests are followed by:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --locked
cargo deny check
cargo run -p kirje-cli -- schema --pretty
cargo run -p kirje-cli -- doctor --pretty
```

Additional security gates include:

- config v1/v2 migration and every invalid-state fixture
- deterministic transcript and Ed25519 positive/negative vectors
- nonce, expiry, epoch, rotation, replay, concurrent proof, and effect-claim
  fault tests
- copied and rolled-back ledger replay tests
- keyring locator and credential crash-window tests with a fake secret store
- link, reparse point, special file, growth, replacement, exact-limit, and
  limit-plus-one input tests
- oversized, duplicate-ID, blocked-handler, blocked-writer, cancellation, EOF,
  and stdout-purity MCP tests
- protocol capability/response count, item, total, UTF-8, control, and
  completeness tests
- golden CLI JSON, MCP tool/schema, action policy, error catalog, config, and
  SQLite migration snapshots
- supported-target CI and a repository/evidence secret scan

## Migration And Rollback

- Migration never probes legacy keyring entries and never invokes the network.
- Config migration writes one complete v2 generation using platform atomic
  overwrite or the documented locked journaled recovery protocol. Interrupted
  temp/backup/journal files are resolved by the fixed recovery matrix.
- Authority schema creation and ledger v3 migration use SQLite transactions and
  reject newer versions.
- A binary rollback may inspect exported sanitized data but must not apply
  Security-Alpha-governed work with a v0.3 binary. The release runbook requires backup
  before migration and documents that owner receipts/effect claims must remain
  paired with their authority journal.
- Restoring only a caller-selected ledger cannot restore authority. Restoring
  the owner anchor and authority journal out of band is governed by the stated
  OS/local-tampering boundary and recovery runbook.

## Risks And Mitigations

- Cross-store crash windows could imply a replay. Mitigation: authority owns the
  irreversible effect claim; ledger state is only a recoverable projection.
- An owner could sign an agent summary without reviewing the exact action.
  Mitigation: signer contract parses the exact typed manifest and recomputes its
  digest; summaries are explicitly non-authoritative.
- Config locking could be mistaken for a hostile-writer boundary. Mitigation:
  advisory lock coordinates Kirje processes, while CAS and the documented OS
  trust boundary define the guarantee.
- A no-follow implementation could differ across platforms. Mitigation:
  capability-relative APIs, platform fixtures, and fail-closed unsupported
  results rather than fallback.
- rmcp may spawn one task per delivered message. Mitigation: transport-level
  request/control permits bound delivered tasks, while active-ID and output
  reservations remain registered through the actual transport send.
- Upstream protocol codecs may allocate before Kirje sees a line. Mitigation:
  verify/configure upstream limits or declare the affected capability
  unsupported; never claim that post-parse truncation is a wire bound.
- Stronger migration may temporarily make existing accounts unusable.
  Mitigation: deterministic quarantine/status output and a documented signed
  enrollment plus credential re-entry workflow.

## Supporting Artifacts

- Requirement contract: `spec.md`
- Requirement quality gate: `checklists/requirements.md`
- Research and dependency decisions: `research.md`
- Persistent model and invariants: `data-model.md`
- Authorization contract: `contracts/authorization.md`
- Pinned authority-store contract: `contracts/authority-store.md`
- Account/config contract: `contracts/account-config-v2.md`
- Input and transport contract: `contracts/bounded-input.md`
- Work graph: `tasks.md`
- Consistency analysis: `analysis.md`

## User Review Gate

The security product and architecture contract remains Confirmed. T202A,
T202B, T202C1, and T202C1S are Accepted at their recorded commits and evidence.
T202C2 is Accepted: T109 recovered the interrupted attempt, resolved three
review findings with RED/GREEN tests, produced validated commit `94f3495`, and
received explicit user acceptance on 2026-08-30. The v1 program work graph owns remaining
executable batches and maps all T202C3-T212 acceptance coverage into T110-T112.
Execution still requires one self-contained packet per risky batch, verified
RED evidence, and all required reviews. On 2026-08-31 the orchestrator exercised
the user's standing delegated acceptance authority to approve the material
`kirje-credential` workspace/dependency architecture needed to make the cleanup
capability implementable. That decision specifies one unpublished low-level
crate with `kirje-store` as its only direct dependent and supersedes any shared
store/runtime or pluggable deletion formulation. This is an architecture decision, not an
implementation claim and not a claim that the user personally reviewed the
resulting artifact. `T202C3_A006_PACKET_REVIEW_PASS` authorized only A006's exact
candidate scopes at governance HEAD `3533054`. Candidate `2241a946` later failed
spec and QA review and is Returned/Needs Fix with no current write permission.
The user explicitly resumed A006 repair on 2026-08-31. F001 through F006 packet
reviews failed. The user then authorized the orchestrator to approve existing-
boundary clarifications without requesting approval at each node. F008 review
failed/refused with exact counts spec C0/H2/M2/L0, engineering/security
C0/H4/M1/L0, and QA C0/H4/M2/L0. Under that authority, the orchestrator approved
F009's append-only Git authority clarification, whose review then failed with
spec C0/H1/M0/L0, engineering/security C0/H1/M2/L0, and QA C0/H1/M1/L0. The
F010 review returned spec PASS C0/H0/M0/L0, engineering/security BLOCK
C0/H3/M3/L0, and QA BLOCK C0/H1/M2/L0. The orchestrator approved F011's
trusted-local procedural clarification; this does not claim user review of the
resulting artifact. F011 leaves F006's substantive cleanup contract unchanged.
Three independent packet reviews under F011's substantive review rule must pass
before A11 may dispatch the exact
production/test/fixture scope. Later A007/A008 attempts remain closed.
