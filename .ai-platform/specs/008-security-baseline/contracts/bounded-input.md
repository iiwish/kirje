# Contract: Bounded Input, MCP, And Untrusted Responses

## Metadata

- Feature ID: `008-security-baseline`
- Status: Confirmed
- Contract name: `kirje.bounded-boundary.v1`
- Updated: 2026-08-27

## Boundary Rule

Every untrusted byte source receives a count, item, and total budget at its
first Kirje-controlled boundary. Kirje never accumulates an unbounded source and
checks length afterward. File object validation and consumed bytes come from
the same opened handle. Display truncation is not a security parser and cannot
decide capability or remote-write behavior.

## Constants

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
MAX_REMOTE_VALUE_BYTES            = 4 KiB
MAX_ADAPTER_DIAGNOSTIC_BYTES      = 1 KiB
MAX_SMTP_RECEIPT_BYTES            = 256
MAX_MACHINE_RESULT_BYTES          = 16 MiB
MAX_UNTRUSTED_RESULT_BYTES        = 8 MiB
```

Existing lower domain limits still apply: one decoded imported attachment is 1
MiB, all send attachments are 8 MiB, send recipient/attachment counts remain
50/25, message/read/sync/list counts retain their documented maxima, and config
accounts remain limited to 100.

## `kirje-local-io` API

```rust
pub struct OpenedRegularFile {
    file: cap_std::fs::File,
    metadata: cap_std::fs::Metadata,
    object: FileObjectIdentity,
}

pub struct OpenedParent {
    dir: cap_std::fs::Dir,
    final_component: OsString,
    identity: DirectoryIdentity,
}

pub fn open_parent(path: &Path) -> Result<OpenedParent, BoundaryError>;
pub fn open_existing_regular(parent: &OpenedParent) -> Result<OpenedRegularFile, BoundaryError>;
pub fn read_bounded(file: &mut OpenedRegularFile, limit: usize) -> Result<Vec<u8>, BoundaryError>;
pub fn read_stream_bounded<R: Read>(reader: R, limit: usize) -> Result<Vec<u8>, BoundaryError>;
pub fn replace_private(parent: &OpenedParent, bytes: &[u8], cas: ReplaceCas) -> Result<(), BoundaryError>;
```

The crate contains only filesystem/reader behavior and opaque identities. It
does not parse JSON/TOML, know mail models, map application error codes, inspect
credentials, or implement authorization.

## Final-Component Open

1. Split path into parent and final component. Empty/`.`/`..` final components
   are invalid.
2. Before opening any component on Windows, inspect the complete lexical path.
   Reject `DeviceNS`, every `Verbatim*` form, drive-relative paths, alternate data
   streams, components ending in dot/space, and case-insensitive DOS device
   stems (`CON`, `PRN`, `AUX`, `NUL`, `CLOCK$`, `CONIN$`, `CONOUT$`,
   `COM1`-`COM9`, `LPT1`-`LPT9`, and the superscript 1-3 aliases). Normal
   relative, rooted disk, and UNC forms are eligible only when every component
   passes the same rule; a UNC share named `PIPE` is always rejected before any
   I/O. Final-component identity retains exact UTF-16 units;
   case aliases are allowed to conflict rather than being unsafely merged.
3. Open the parent directory once. Parent links may resolve normally.
4. Build `cap_std::fs::OpenOptions` with read, no create, final-component
   `FollowSymlinks::No`, and nonblocking mode.
5. Open the final component once relative to that parent.
6. Validate metadata from the returned handle as regular.
7. On Windows, reject reparse-point handles; namespace/device rejection has
   already occurred before the parent open. On Unix, nonblocking open plus
   regular-file validation rejects FIFO, socket, device, and directory before
   a read can block.
8. If equivalent secure semantics are unavailable, return unsupported; never
   retry with normal `std::fs::read`.

Only final-component `NotFound` has missing semantics. A symlink, junction,
reparse point, directory, special file, permission failure, malformed path, or
other I/O error never becomes an empty file.

Hard links are allowed and are not represented as containment. A path rename,
replacement, or unlink after open cannot change the object held by
`OpenedRegularFile`.

## Limit-Plus-One Reader

The reader:

- allocates at most a bounded initial capacity with `try_reserve`
- uses a fixed scratch buffer no larger than 64 KiB
- asks for at most the remaining `limit + 1 - retained` bytes
- retains at most `limit + 1`
- returns `resource_limit` immediately when byte `limit + 1` exists
- requires an EOF read when exactly `limit` bytes have been retained
- maps reserve/allocation failure to `resource_limit`
- returns no partial accepted document on any error

File metadata size may reject an already oversized regular file early. It never
accepts a file, controls allocation above the configured cap, or substitutes
for the reader. Growth, shrink, sparse allocation, or metadata mismatch cannot
bypass the retained-byte rule.

## Structured Parsing

### JSON

JSON is parsed directly into typed request structs. It is not first parsed into
`serde_json::Value`.

Bounded visitors:

- reject nesting deeper than 32
- cap every map and sequence while visiting; size hints preallocate only up to
  the field's maximum
- reject item `N + 1` before constructing it when the format permits
- cap UTF-8 bytes and characters according to the field contract
- reject unknown/duplicate fields for security documents
- decode Base64 through a bounded streaming visitor, checking encoded and
  decoded limits before full allocation
- enforce a running total decoded-attachment budget
- reject trailing data after one document

Large mail structs use bounded newtypes or manual `Deserialize` rather than
derived `String`/`Vec` followed by validation. Validation still checks semantic
rules but is not the first memory boundary.

`kirje-core` owns bounded typed deserialization for shared mail and
authorization request types. CLI calls it directly. Before rmcp constructs a
`serde_json::Value`, `kirje-mcp` runs a method-aware, allocation-bounded lexical
preflight over the raw frame. The preflight enforces the same depth, field,
collection, string, Base64, and decoded-total contracts for the selected tool,
then the shared typed parser enforces them again. A whole-frame byte cap alone
is not a substitute for this preflight.

Rust/serde allocation is fallible only where the selected API exposes a
fallible reserve or visitor boundary. Kirje maps every recoverable allocation
failure to `resource_limit` and never claims to recover from a process-level
allocator abort.

### TOML

Config bytes are bounded before UTF-8 conversion and TOML parsing. A lightweight
version discriminator selects strict `ConfigDocumentV1` or
`ConfigDocumentV2`; no untagged fallback attempts multiple large parses.
Unknown fields and invalid state combinations fail.

### Authorization Binary

Transcript decoders check domain, field count, field length, strict tag order,
per-field budget, total budget, and exact end-of-input before constructing the
typed manifest or invoking Ed25519.

## CLI File And Stdin Inputs

The same reader and parser path backs:

- attachment import
- send request
- draft create/update
- mailbox operation plan
- authorization key/proof documents
- config load/migration

File and stdin differ only in open/object validation; their byte and parser
limits are identical for one document type. A file path is not retained as an
attachment authority after import; immutable bounded bytes and digest are
stored.

Credentials never use stdin, file JSON, environment, or command arguments.
They continue to use hidden local terminal input after authorization.

## MCP Frame Contract

### Input Framing

MCP stdio accepts one newline-terminated JSON-RPC document per frame.

- Up to `MAX_MCP_FRAME_BYTES` before `\n` is accepted for parsing.
- `\r\n` is accepted as one line ending; `\r` is excluded from JSON bytes.
- An exact-limit stream without a newline waits for newline, EOF, or one more
  byte.
- EOF with no retained bytes closes normally.
- EOF with a retained incomplete frame is one terminal invalid-request error.
- Byte `limit + 1` is one terminal frame-overflow error.
- The transport writes at most one fixed, bounded JSON-RPC error with null ID,
  never echoes rejected bytes, records one bounded stderr category, stops
  reading immediately, closes, and produces a nonzero MCP exit status.
- MCP mode never emits the normal CLI JSON envelope to stdout.

### Derived Frame Budget

A generated test computes a conservative upper bound:

```text
Base64(max total decoded attachments)
+ worst-case escaped text body
+ worst-case escaped HTML body
+ recipients, subject, attachment metadata, and service IDs
<= MAX_SEND_OR_DRAFT_INPUT_BYTES

MAX_SEND_OR_DRAFT_INPUT_BYTES
+ JSON-RPC method, ID, params, and object syntax
<= MAX_MCP_FRAME_BYTES
```

The test uses 12 bytes per worst-case Unicode scalar for JSON surrogate escape.
If a domain limit increases, the frame constant or service model must change in
the same reviewed contract update.

### Session Capacity

- Before reading a frame, reserve writer item capacity and either one of four
  request-handler slots or the single control-preflight slot. No more than five
  delivered rmcp tasks exist: four request handlers and one control task.
- Parse and validate request ID at no more than 128 UTF-8 bytes and method at no
  more than 128 ASCII bytes.
- A request acquires a handler slot, one of four active-ID registrations, and a
  maximum-output reservation before delivery. Duplicate active IDs receive a
  stable invalid-request result without replacing the first request.
- Handler completion releases only the handler slot. Active ID and output
  reservation remain until the matching response is actually written by the
  transport, cancellation reaches `TerminalNoResponse`, or disconnect
  finalization drops all session state. Parse rejection before
  registration releases all provisional capacity. Service error and panic use
  the same terminal response path.
- The registry state machine is `Admitted -> Handling -> HandlerEnded ->
  ResponseClaimed -> Queued -> Writing -> Terminal`, with
  `CancelPendingWorker`, `TerminalNoResponse`, and `HandoffTimeout ->
  SessionClosing` branches. A fixed lifecycle manager closes the session if
  `Transport::send` has not claimed a non-cancelled handler-ended lease within
  1,000 ms. For cancellation, `cancel_requested && handler_ended &&
  worker_count == 0` transitions directly to `TerminalNoResponse` because rmcp
  removes the ID and drops the later handler result without calling
  `Transport::send`. A running counted worker enters `CancelPendingWorker` and
  transitions to `TerminalNoResponse` only when it exits. Cancellation after
  `ResponseClaimed` is too late and completes the send path. Cancellation never
  waits for the handoff timeout.
- The control lane accepts the one `notifications/initialized` allowed per
  session and cancellation for a known active ID. At four active handlers, a
  normal fifth request receives one bounded busy response and is never
  registered; unknown/duplicate control notifications are rejected. Control
  admission never creates a fifth active request ID.
- The single combined response/writer queue holds at most five entries and
  `MAX_MCP_QUEUED_OUTPUT_BYTES` actual serialized bytes. Outstanding request
  output reservations total at most `MAX_MCP_RESERVED_OUTPUT_BYTES`, including
  responses waiting to enter the writer queue.
- rmcp loop, writer, lifecycle manager, four handlers, one control task, four
  response-send tasks, and four counted service workers total at most 16 tasks.
- Obtain writer capacity before reading another input frame. A blocked writer
  therefore backpressures stdin rather than accumulating responses/tasks.
- Capacity exhaustion returns one stable bounded busy error when a response can
  be written; otherwise it closes the session.

### Output

- Serialize one response into a limit-aware writer with
  `MAX_MCP_OUTPUT_FRAME_BYTES` maximum.
- Reject a shared-service result above the 16 MiB machine-result contract before
  MCP transport serialization.
- The generated envelope test proves
  `MAX_MACHINE_RESULT_BYTES + MAX_MCP_ENVELOPE_OVERHEAD_BYTES <=
  MAX_MCP_OUTPUT_FRAME_BYTES`, including JSON-RPC syntax, the bounded ID, and
  result/error wrapper but excluding the line feed. The wire bound separately
  proves `MAX_MCP_OUTPUT_FRAME_BYTES + 1 <= MAX_MCP_OUTPUT_WIRE_BYTES`.
- A tool result carries the structured result once. Any companion text content
  is a fixed message of at most 64 bytes; it never duplicates serialized data.
- Append exactly one newline.
- Use a single stdout writer task and bounded queue; no direct diagnostics,
  banners, panics, or CLI envelopes write to stdout.
- Raw request, params, result, and notification tracing is disabled. Redacted
  telemetry may include method category, byte count, hashed bounded request ID,
  duration, and result/error category.

## Untrusted Remote Values

```rust
enum ValueDisposition {
    Complete,
    Truncated,
    Omitted,
    Rejected,
}

struct BoundedUntrustedText {
    text: String,
    disposition: ValueDisposition,
    untrusted: bool,
    original_bytes: Option<u64>,
}
```

`original_bytes` is present only when known without consuming discarded data.
No rejected value includes discarded content.

Security-relevant capabilities use a different type:

```rust
struct ProtocolCapabilities {
    known: BoundedSet<KnownCapability>,
    unknown_display: BoundedList<BoundedUntrustedText>,
    complete: bool,
    source_sha256: Sha256Digest,
}
```

An extension-dependent operation requires `complete == true` and the exact
known enum member. A missing member in an incomplete set means unknown, not
unsupported. Truncated display values never feed a security decision.

## IMAP Boundary

- The first network byte enters a Kirje-owned connection pump with a 12 MiB
  response-fragment limit. io-imap's 100 MiB default is not used for initial
  greeting, capability, or authentication.
- Message literal reads retain their existing 10 MiB raw-message business limit
  within the 12 MiB fragment envelope.
- Capability parsing accepts at most 128 items, 256 bytes each, and 16 KiB total.
- Capabilities are parsed from bounded raw bytes into a closed enum, sorted, and
  deduplicated. Debug formatting is not a public representation.
- Unknown capability display is bounded and untrusted. Any capability count,
  item, total, or parse overflow makes the security set incomplete/rejected and
  prevents extension-dependent writes.
- Mailbox inventory remains at most 1,000 and every normal/special-use path
  shares item, per-value, and total-result budgets.
- Invalid UTF-8, NUL, controls, line breaks, and overlong identifiers have
  deterministic rejected or lossy-display behavior after raw-byte parsing.

## SMTP Boundary

- lettre's 1,000-byte response-line and 100,000-byte aggregate response bounds
  remain required and are locked by dependency/source assertions.
- Kirje emits at most 256 UTF-8 bytes of one control-cleaned receipt display,
  truncating only at a valid code-point boundary.
- Receipt fields include `untrusted: true`, `truncated`, and `complete`.
- Operation ledger, CLI/MCP, logs, and evidence receive only the bounded Kirje
  receipt, never the raw provider response.

## Machine Result And Audit Bounds

- One serialized CLI/MCP result is at most 16 MiB.
- Untrusted text/binary-derived display retained in one result is at most 8 MiB.
- Audit/status/list methods retain their existing maximum row counts and apply
  one total-byte budget while constructing results.
- Event/detail strings are typed and capped at the store boundary.
- Errors and diagnostics cap their own generated text and do not interpolate
  rejected provider values.
- Evidence records counts, state, disposition, and digests only; it cannot
  become a raw response overflow path.

## Stable Failure Codes

```text
resource_limit
secure_file_semantics_unsupported
input_not_regular_file
input_link_rejected
input_document_incomplete
input_nesting_limit
mcp_frame_too_large
mcp_request_id_invalid
mcp_duplicate_request_id
mcp_session_busy
mcp_output_too_large
remote_response_too_large
remote_capability_incomplete
```

None includes rejected bytes, raw path content beyond a bounded operator-selected
display, remote response text, mailbox content, credential, proof, or signature.

## Required Tests

### Local I/O

- zero, exact limit, exact plus one, no EOF, short reads, interrupted reads
- metadata over/under-report, growth, shrink, rename, replace, unlink
- final symlink, directory, hard link, allocation failure
- Unix FIFO nonblocking rejection, Unix socket, and device
- Windows file symlink, junction/reparse point, pre-open namespace/device-name
  rejection, local/UNC named pipe, and UNC `PIPE` share rejection
- same opened object retained after path replacement
- private temp permissions, Unix same-parent replacement, and Windows
  journaled two-rename recovery

### Structured Input

- max and max-plus-one string, list, map, nesting, Base64, decoded bytes, and
  total attachment bytes
- duplicate/unknown fields, trailing document, malformed UTF-8/JSON/TOML
- allocation failure mapping with no partial persistence
- one-pass attachment decode/hash/summary memory bound
- direct typed CLI parsing and method-aware MCP preflight parity

### MCP

- frame N and N+1 with newline, exact N without newline, oversized no-newline
  stream, incomplete EOF
- one null-ID error, nonzero exit, bounded stderr, no input echo, stdout purity
- four blocked requests plus one bounded control task; fifth normal request busy
- duplicate active ID, oversized/string ID, notification flood, cancellation
- handler completion retains active-ID/output state until transport send
- cancellation before/after response claim, counted worker completion,
  `TerminalNoResponse`, and no handoff-timeout wait on cancelled IDs
- blocked output, output overflow, disconnect, handler error/panic, state release
- generated service-payload/input-envelope/output-envelope inequalities
- exact tool allowlist and recursive prohibited-field schema snapshot

### Protocol

- first IMAP response 12 MiB and plus one
- capability 128/129, 256/257 bytes, 16 KiB/plus one, unknown/duplicate/order
- complete/incomplete capability decision behavior including MOVE
- mailbox 1,000/1,001 and special-use duplicate/overflow
- SMTP 256/257 display bytes, multibyte boundary, controls, line/aggregate source
  limits, and completeness metadata

### CI

- Linux, macOS, and Windows test/build matrix
- platform-specific tests cannot silently skip on their target
- Rust 1.88 compatibility check for new dependencies
- full format, Clippy, test, build, and cargo-deny gates
