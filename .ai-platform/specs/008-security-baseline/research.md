# Research: Security Baseline

## Metadata

- Feature ID: `008-security-baseline`
- Status: Complete
- Updated: 2026-08-27
- Scope: cryptographic verification, authority persistence, account/config
  migration, safe local I/O, bounded MCP transport, and remote response bounds

## Method

Research combined:

- direct inspection of the accepted v0.3 code and tests
- source inspection of locked dependencies in the Cargo registry
- current official crate documentation and release metadata
- three independent read-only design audits covering authority/ledger,
  account/keyring migration, and input/MCP/protocol boundaries

No mailbox content, credential, account address, UID, endpoint, signature, or
provider response is recorded in this artifact.

## Current Baseline Findings

### Account And Credential

- `TomlAccountRepository` uses config version 1, unbounded
  `fs::read_to_string`, and path-based atomic replacement without a lock or
  generation check.
- `upsert` replaces an existing account with the same display ID.
- `KeyringSecretStore` addresses entries as `dev.kirje.mail/<display-id>`.
  Different custom config files therefore share the same credential namespace.
- Authenticated runtime calls load the account and credential by display ID;
  they do not validate an immutable account snapshot or endpoint binding.
- Existing account tests cover basic validation, sorting, credential presence,
  and config secret exclusion, not migration, copied configs, endpoint
  redirection, concurrent mutation, or keyring crash windows.

### Authorization And Ledger

- Operation-ledger schema v2 stores local approval and apply claim in the
  caller-selected outbox.
- `approve_operation` is only `planned -> approved`; it has no owner identity or
  cryptographic proof.
- `claim_operation` is only an outbox-local transition to `applying`.
- Runtime reads credentials and invokes the adapter after that local claim.
  Copying or rolling back the outbox can therefore copy local authority.
- MCP has no approval-named tool, but the contract test uses a substring check
  rather than an exact allowlist and recursive schema deny rule.

### Local Input

- Attachment import calls `symlink_metadata` and later `fs::read`; selected JSON
  files call `metadata` and later `fs::read`. The validation and consumed bytes
  can refer to different objects.
- Explicit JSON stdin already uses `take(max + 1)`, so the remaining defects are
  exact-limit EOF behavior, file-handle identity, special-file blocking, and
  typed allocation limits.
- Account config uses an unbounded path-based string read.
- Derived serde models allocate `String` and `Vec` values before later
  `validate` methods enforce business limits. Attachment validation and summary
  can decode the same content more than once.

### MCP

- rmcp 3.1.4's standard async-read transport retains a `Vec<u8>` and uses
  newline `read_until` without the required exact limit-plus-one policy.
- rmcp exposes a codec max length, but standard stdio does not use it and its
  write side does not provide the required full output/queue contract.
- rmcp's service loop spawns a task for each delivered request and notification.
  It has an internal 64-item sink proxy but no application-selected bound on
  active handler tasks or request IDs.
- rmcp emits tracing events containing debug forms of requests, results, and
  notifications. Kirje must not install a raw subscriber for these targets and
  must provide redacted transport telemetry.
- An MCP serve failure currently reaches the normal CLI JSON envelope path,
  which can place non-MCP JSON on stdout after a transport error.

### Protocol Responses

- io-imap 0.6 uses a 100 MiB initial fragment bound across connect, greeting,
  capability, and authentication before Kirje can replace the normal session
  fragmentizer.
- IMAP capability output uses `Debug` strings with no count, item, or total byte
  limit. Some special-mailbox paths do not share the normal mailbox count
  boundary.
- lettre already limits SMTP response lines to 1,000 bytes and aggregate
  response data to 100,000 bytes. Kirje's receipt sanitization truncates by
  characters and lacks byte-bound, untrusted, truncated, and completeness
  metadata.
- CI runs Ubuntu only, so it cannot establish Windows reparse/junction or macOS
  behavior.

## Dependency Decisions

### Ed25519 Verification

Selected: `ed25519-dalek 3.0.0` with strict verification and without signing-key
generation in production.

Reasons:

- MSRV 1.85 fits Kirje's Rust 1.88 contract.
- `VerifyingKey::verify_strict` rejects scalar and point malleability cases that
  permissive verification can accept.
- Ed25519 provides fixed-size public keys and signatures and is portable across
  supported targets.
- Kirje needs only detached verification; private-key parsing, generation,
  batch, hazmat, legacy compatibility, serde key material, and PEM features are
  unnecessary.

References:

- [ed25519-dalek 3.0.0 crate metadata](https://docs.rs/crate/ed25519-dalek/3.0.0)
- [VerifyingKey strict verification API](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html)

Rejected:

- terminal ID retyping: it proves neither owner identity nor an independent
  security principal and is automatable through a PTY
- HMAC: it would require Kirje and the owner to share signing authority and
  store verifier-capable secret material
- WebAuthn or platform biometrics: valuable future transports, but they add
  hosted/browser/platform ceremony outside the v0.3.1 local verifier boundary
- generic canonical JSON signing: serializer and map-order behavior is a larger
  attack surface than a fixed typed binary transcript

### Randomness

Selected: `getrandom 0.4.3::fill` for realm, nonce, journal, identity, and
temporary-name entropy. MSRV 1.85 fits the project, and the API fills directly
from the operating-system source.

Reference: [getrandom fill](https://docs.rs/getrandom/latest/getrandom/fn.fill.html)

### Safe Local Files

Selected: a new `kirje-local-io` crate using `cap-std 4.0.2` and
`cap-fs-ext 4.0.2`, with `fs4 1.1.0` for cooperative locks.

Reasons:

- `cap_std::fs::Dir` keeps reads, temp creation, and rename relative to one open
  parent directory. Unix may replace through one rename; Windows uses a locked,
  journaled final-to-backup then temp-to-final protocol because cap-std 4.0.2
  delegates to `std::fs::rename` and does not overwrite an existing target.
- `OpenOptionsFollowExt` exposes final-component `FollowSymlinks::No`.
- `OpenOptionsSyncExt` exposes nonblocking mode on supported targets; dependency
  source maps no-follow to Unix `O_NOFOLLOW` and Windows
  `FILE_FLAG_OPEN_REPARSE_POINT` behavior. Windows namespace/device preflight
  runs before parent open; any target lacking the required nonblocking/special
  object guarantee returns unsupported.
- cap-std exposes Unix device/inode and Windows volume/file-index metadata needed
  for a stable config-location identity.
- platform unsafe remains inside reviewed dependencies while Kirje keeps
  `unsafe_code = "forbid"`.
- fs4 is cross-platform, pure Rust at the Kirje call boundary, defaults to the
  synchronous API, and has MSRV 1.75.

References:

- [cap-std directory API](https://docs.rs/cap-std/latest/cap_std/fs/struct.Dir.html)
- [cap-fs-ext extension traits](https://docs.rs/cap-fs-ext/latest/cap_fs_ext/)
- [fs4 crate metadata](https://docs.rs/crate/fs4/latest)

Rejected:

- `symlink_metadata` followed by `fs::read`: classic object-substitution window
- direct `rustix` plus `windows-sys` calls in Kirje: exact but would require
  project-owned unsafe Windows FFI or an exception to the workspace lint
- path canonicalization alone: it does not bind the opened parent object and
  makes aliases and directory replacement ambiguous
- file size metadata as the limit: a file can grow or shrink after metadata is
  read
- tempfile path persistence alone: it cannot prove all reads and writes remain
  relative to the same parent handle

### SQLite Authority

Selected: a separate pinned rusqlite database with `application_id`, schema
version 1, foreign keys, trusted schema disabled, WAL, and `synchronous=FULL`.

Reasons:

- Kirje already depends on bundled SQLite and has migration/test patterns.
- uniqueness constraints provide durable nonce, grant, effect-claim, and
  invocation single-use boundaries.
- `BEGIN IMMEDIATE` provides a clear serialization point for proof consumption
  and claims.
- a separate fixed journal prevents caller-selected outbox rollback from
  becoming authority rollback.

Rejected:

- storing receipts only in outbox: copied/rolled-back outboxes replay authority
- one TOML trust file for all events: lacks transactional unique constraints,
  history queries, and cross-process claims
- a cryptographic transparency-log claim: the local database is not protected
  against an out-of-bound same-user writer and the product must say so

## Canonical Transcript Decision

Authorization and action manifests use strict field-tag transcripts:

```text
domain-bytes || field-count:u16be ||
  repeated(tag:u16be || length:u32be || value-bytes)
```

Rules:

- field tags are action-specific, known, and strictly increasing
- UUID values are 16 bytes; realm and SHA-256 values are 32 bytes
- integers have one fixed width and big-endian byte order
- timestamps are signed Unix milliseconds
- options have explicit presence fields; lists have explicit count and ordinal
- duplicate, unknown, missing, out-of-order, non-minimal, or over-budget fields
  fail before signature verification
- Ed25519 signs the complete authorization transcript directly; SHA-256 is the
  challenge identifier and display digest, not an undocumented prehash mode
- JSON is a bounded review projection and proof envelope, never the signed
  authority

This representation is deterministic across locale, whitespace, JSON map
order, terminal rendering, and serializer implementation.

## Config Location Decision

Config enrollment binds the opened parent object and final component:

The digest is SHA-256 of the exact `KIRJE-CONFIG-LOCATION-V1\0` TLV transcript
defined by the account-config contract. Unix uses u64 big-endian device/inode
and exact `OsStrExt::as_bytes`. Windows uses zero-extended u64 volume serial,
u64 parent file index, and exact native final-component units encoded as
UTF-16LE. Unsafe Windows namespaces fail before the parent open. Missing
platform identity data returns
`secure_file_semantics_unsupported`. Relative and absolute aliases to the same
opened parent and final component match. Recreated parent directories, copied
configs, renamed hard links, and other locations require explicit
owner-authorized enrollment rather than silently sharing credentials.

Parent links may resolve before the parent handle opens; this is intentionally
not a filesystem containment guarantee.

## Input And Transport Budgets

Selected constants:

```text
MAX_CONFIG_BYTES                  = 1 MiB
MAX_OPERATION_INPUT_BYTES         = 1 MiB
MAX_SEND_OR_DRAFT_INPUT_BYTES     = 24 MiB
MAX_AUTHORIZATION_PROOF_BYTES     = 4 KiB
MAX_AUTHORIZATION_MANIFEST_BYTES  = 4 MiB
MAX_READ_SCRATCH_BYTES            = 64 KiB
MAX_JSON_NESTING_DEPTH            = 32
MAX_JSON_RPC_ID_BYTES             = 128
MAX_JSON_RPC_METHOD_BYTES         = 128
MAX_MCP_ENVELOPE_OVERHEAD_BYTES   = 4 KiB
MAX_MCP_FRAME_BYTES               = 24 MiB + 4 KiB
MAX_MCP_OUTPUT_FRAME_BYTES        = 16 MiB + 4 KiB
MAX_MCP_OUTPUT_WIRE_BYTES         = 16 MiB + 4 KiB + 1
MAX_MCP_HANDLER_IN_FLIGHT         = 4
MAX_MCP_CONTROL_IN_FLIGHT         = 1
MAX_MCP_ACTIVE_IDS                = 4
MAX_MCP_DELIVERED_TASKS           = 5
MAX_MCP_QUEUE_ITEMS               = 5
MAX_MCP_QUEUED_OUTPUT_BYTES       = 2 * MAX_MCP_OUTPUT_WIRE_BYTES
MAX_MCP_RESERVED_OUTPUT_BYTES     = 4 * MAX_MCP_OUTPUT_FRAME_BYTES
MAX_MCP_SESSION_TASKS             = 16
MAX_MCP_RESPONSE_HANDOFF_MILLIS   = 1000
MAX_IMAP_RESPONSE_BYTES           = 12 MiB
MAX_IMAP_CAPABILITIES             = 128
MAX_IMAP_CAPABILITY_BYTES         = 256
MAX_IMAP_CAPABILITIES_TOTAL_BYTES = 16 KiB
MAX_SMTP_RECEIPT_BYTES            = 256
MAX_MACHINE_RESULT_BYTES          = 16 MiB
MAX_UNTRUSTED_RESULT_BYTES        = 8 MiB
```

The 24 MiB service-document budget is intentionally larger than the initial 16
MiB audit suggestion. A maximum valid send can contain 8 MiB decoded
attachments, about 10.7 MiB of Base64, and two 262,144-character bodies.
Worst-case JSON surrogate escaping can add about 6 MiB for the bodies before
recipient metadata. The transport adds a separate 4 KiB envelope allowance;
generated tests prove both the domain-document bound and the JSON-RPC wrapper
inequality. The 16 MiB machine result similarly has a separate 4 KiB output
envelope allowance.

## MCP Design Decision

Kirje implements `Transport<RoleServer>` directly:

- fixed-size chunk reads and one retained frame buffer bounded to `N + 1`
- exact-limit input waits for newline, EOF, or one additional byte
- first overflow writes one fixed ID-null invalid-request frame, then closes
  without draining attacker data
- no normal CLI JSON envelope after MCP mode starts
- four request-handler permits and one control permit bound delivered rmcp
  tasks; the control lane accepts only initialization and cancellation
- an active-ID/output-reservation registration rejects duplicates and survives
  handler completion until the response transport send is terminal
- cancelled IDs release through worker-aware `TerminalNoResponse` because rmcp
  drops their later handler result without calling transport send
- only one initialized notification and cancellation for a known active ID are
  allowed; a normal fifth request receives a bounded busy result
- one combined response/writer queue has five-item and total-byte budgets
- backpressure obtains capacity before reading another frame
- method-aware lexical preflight enforces tool field/count/depth/Base64 limits
  before rmcp constructs its `serde_json::Value`
- no raw rmcp request/result tracing subscriber; Kirje emits redacted metrics

The `Transport::receive` API returns `Option` rather than `Result`, so the custom
transport must write its single framing error itself and retain a bounded
termination reason for the CLI exit path.

## Protocol Decision

The IMAP adapter cannot meet the boundary by replacing only a connected
session's fragmentizer because io-imap's initial pump has already accepted the
larger limit. Kirje therefore builds a bounded connection pump from the public
session-open and Pimalaya stream primitives and supplies a 12 MiB fragmentizer
from the first server byte. An upstream `connect_with_max_message_size` proposal
is desirable but not a release dependency.

Capabilities are parsed from raw bounded bytes into a complete closed enum,
sorted and deduplicated for display, and rejected on any item/count/total
overflow. Unknown bounded capabilities may be retained as non-authoritative
display metadata, but incomplete input cannot decide MOVE, authentication, or
write safety.

SMTP retains lettre's stricter transport line limit and adds a 256-byte,
UTF-8-boundary-safe, control-cleaned receipt with `untrusted`, `truncated`, and
`complete` metadata.

## Delivery Consequences

- v0.3.1 needs a new workspace crate and a three-platform CI matrix.
- The authority/effect work and account/config work share the authority schema
  and must be sequenced, not merged as independent competing designs.
- MCP frame and protocol changes are security tasks, not documentation-only
  cleanup.
- Existing accounts intentionally become non-ready until store enrollment,
  binding authorization, and credential re-entry complete.
- Controlled mailbox verification remains read-only unless a separate signed
  execution packet authorizes an exact remote effect.
