# Spec: Stable 1.0 Program

## Metadata

- Feature ID: `007-stable-v1-program`
- Status: Confirmed
- Target release: `v1.0.0`
- Delivery checkpoints: `alpha.1`, `alpha.2`, `beta.1`, `beta.2`, `rc.1`,
  `rc.2`, and stable
- Product: Kirje
- Updated: 2026-08-31
- Source: User-confirmed direct delivery of the narrow, reliability-first 1.0
  product through incremental, usable checkpoints.

## Goal

Kirje 1.0 is a reliable, local-first IMAP/SMTP mail runtime for AI agents. It
can converge mailbox state, represent threads, submit and file sent messages,
reconcile uncertain operations without automatic replay, enforce account-level
policy, preserve stable machine contracts, and ship as verifiable binaries on
supported desktop operating systems.

## Product Boundary

The 1.0 support promise is deliberately narrower than the long-term protocol
architecture:

- IMAP and SMTP with password or provider-issued app-password authentication are
  the production protocol and authentication boundary in 1.0.
- OAuth2, Gmail-specific APIs, Microsoft Graph, and JMAP runtime operations are
  post-1.0 capabilities. Provider-neutral ports and reference-only registry
  metadata may remain, but user-facing documentation cannot claim runtime
  support for unavailable protocols or authentication methods.
- Synchronization remains explicit and agent-invoked. A resident background
  daemon is not required for 1.0.
- Permanent deletion, unrestricted bulk mutation, automatic resend, automatic
  ambiguous-state replay, semantic search, and embedded LLM behavior remain
  outside 1.0.

## Users And Outcomes

### US-001: Trustworthy mailbox state

An agent can explicitly synchronize a bounded portion or all of a mailbox and
can tell whether local state is current, partial, stale, or invalidated.

### US-002: Thread-aware work

An agent can inspect deterministic thread groupings and compose replies without
inventing relationships that are absent from message headers.

### US-003: Reconciled sending

A user can approve one immutable send operation, observe SMTP acceptance and
Sent-folder filing as separate recorded outcomes, and resolve uncertainty
without causing an automatic duplicate send.

### US-004: Enforced local policy

An account owner can restrict mailbox scopes, remote operation kinds,
recipients, and resource ceilings independently of agent-provided requests.

### US-005: Stable automation contract

CLI and MCP clients can upgrade within 1.x without silent schema, error,
operation-state, or database incompatibility.

### US-006: Verifiable installation

Users can install a versioned Kirje binary for a supported platform and verify
its checksum, provenance, dependency inventory, and release notes.

## Functional Requirements

### Security Alpha

- SFR-001: A credential is addressed by a random immutable credential identity
  and is cryptographically or canonically bound to the account username,
  authentication kind, and normalized IMAP/SMTP endpoint fingerprint. Reusing
  an account display ID cannot make Kirje submit an existing credential to a
  different endpoint or identity. Every legacy credential that lacks a provable
  binding is quarantined and unusable; it is never automatically bound to the
  current account configuration and must be entered again through the trusted
  owner setup flow.
- SFR-002: Creating an account cannot silently replace an existing account.
  Endpoint, username, or authentication changes use an explicit owner-signed
  update flow, invalidate the old credential binding, and require trusted
  credential re-entry before any authenticated operation.
- SFR-003: Terminal presence is never sufficient authorization for a remote
  effect or security-sensitive control-plane change. Approval requires a
  detached owner signature over the action kind, immutable operation or config
  digest, unique challenge nonce, and expiry. Kirje stores only the owner trust
  root; the private signing key remains outside Kirje and outside the agent
  execution environment. The signature requirement covers send and mailbox
  approval, account endpoint/username/authentication changes, policy or
  assurance changes, owner-key rotation, and ambiguous-outcome closure. TTY may
  display and review a challenge but cannot create an approved state. Initial
  trust-root enrollment and recovery use a documented trusted bootstrap outside
  an agent-controlled session; later rotation requires the current owner key or
  the documented offline recovery procedure. Before a challenge is persisted,
  caller-supplied common subject IDs remain untrusted typed request values.
  Complete request-independent global authority validation may already stream
  all private graphs. After the request-independent global validation pass, no
  request-directed private lookup or request-dependent private branch may occur
  before the closed public pair
  classification, so absent/mismatched or blocked/recovery public subjects
  cannot reveal whether a private target exists or is valid. Credential cleanup
  with `transition_id=None` fails a pure `authority.rs` manifest preflight as
  `authorization_malformed` before apply lock, file, database, or entropy work,
  with no core type or transcript change.
- SFR-004: Local attachment and JSON file import opens one bounded regular-file
  handle without following a symlink, reads no more than the declared maximum
  plus one byte, and validates metadata on that same handle. A path replacement
  between checks cannot change the bytes or file type imported. Stdin input is
  also read through a limiting reader that stops at the declared maximum plus
  one byte rather than accumulating an unbounded stream.
- SFR-005: The security model accurately states that the SQLite event trail is
  application-level append-only, not cryptographically tamper-proof, and that
  local databases are private but not encrypted at rest. Retention, backup,
  restore, and erasure boundaries are explicit.
- SFR-006: Remote capability strings and provider responses remain bounded and
  untrusted at every CLI, MCP, log, audit, and evidence boundary.
- SFR-007: The Security Alpha runtime capability report, README, product definition,
  Skill, architecture, and security documentation state the actual IMAP/SMTP
  password or app-password boundary and mark OAuth2, Gmail/Outlook APIs, and
  JMAP runtime operations unsupported. No later prerelease may carry the known
  broader claim.

### Mailbox Alpha

- FR-001: Historical backfill is explicit, bounded per invocation, ordered,
  resumable from a transactional cursor, and safe to interrupt. It never turns
  an omitted limit into an unbounded allocation or response, and the protocol
  adapter cannot materialize an entire remote UID set before applying the
  requested bound.
- FR-002: Reconciliation updates changed flags and envelope metadata, records
  remote disappearance as a scoped tombstone or equivalent auditable state,
  and never interprets a missing message outside the synchronized coverage as a
  deletion.
- FR-003: UIDVALIDITY changes invalidate the affected mailbox scope and rebuild
  it transactionally. A stale message reference remains unusable for reads or
  writes.
- FR-004: Thread reconstruction uses normalized Message-ID, References, and
  In-Reply-To relationships with deterministic cycle, duplicate, missing-parent,
  and truncated-header handling. Subject-only grouping is not authoritative;
  threads derived from incomplete historical coverage are marked provisional.
- FR-005: CLI and MCP expose the same task-level backfill, reconciliation,
  coverage, and thread-query services with bounded versioned output.

### Delivery Beta

- FR-006: A send plan binds a Sent-copy policy and the complete immutable MIME
  snapshot before approval. Reply-derived plans include their normalized
  In-Reply-To and References headers. Kirje prepares one canonical RFC822 byte
  artifact with stable Date, Message-ID, MIME boundaries, and digest; SMTP DATA
  and client-managed IMAP filing use those same bytes. Bcc remains in the SMTP
  envelope and approved ledger snapshot but not the RFC822 header. Changing any
  covered field requires a new plan.
- FR-007: SMTP submission and Sent-folder filing are separately persisted steps
  with separate timestamps, receipts, certainty, and audit events. SMTP
  acceptance is never described as proof of recipient delivery. A top-level
  success means the approved Sent-copy policy is also satisfied; an accepted
  message whose copy needs operator work has a distinct `needs_attention`
  outcome rather than being relabeled failed or delivered.
- FR-008: Sent filing uses a server-declared `\\Sent` mailbox or an explicit
  approved destination. Kirje never guesses a localized Sent folder. Policy
  explicitly selects client-managed APPEND or server-managed bounded
  verification so Kirje does not create duplicate provider copies.
- FR-009: Failure or process loss after SMTP invocation can never trigger an
  automatic resend. Filing may be resumed only when the ledger proves SMTP was
  accepted and filing has not begun; uncertain filing is not replayed. A durable
  claim precedes each remote effect, and each effect has an independent attempt
  count and certainty state.
- FR-010: An operator can close an ambiguous operation as externally reconciled
  using an explicit owner-signed CLI-only action that records an assertion,
  timestamp, and immutable audit event. Reconciliation never rewrites prior
  events or claims remote facts Kirje did not observe. A separate bounded
  read-only inspection
  may search the approved Sent mailbox for candidates; closing an outcome never
  sends, files, or otherwise invokes a remote write.
- FR-011: MCP can inspect reconciliation state and apply already approved safe
  work, but it cannot approve, assert or close an external outcome, retry an
  uncertain effect, or alter credentials.

### Policy Beta

- FR-012: Each account can define a local policy for allowed remote operation
  kinds, readable and writable mailbox scopes, recipient addresses or domains,
  and bounded message, attachment, recipient, and synchronization ceilings.
  Creating or changing policy requires owner-signed authorization.
- FR-013: Policy is evaluated both when planning and immediately before remote
  invocation. Plans bind the policy revision or digest; a stricter policy
  change invalidates incompatible approved work.
- FR-014: Default policy remains read-only for remote writes until the owner
  explicitly enables governed send or mailbox mutation capabilities. Legacy
  pre-policy plans remain readable for audit but cannot invoke remote work; the
  owner must enable policy and create a new immutable plan.
- FR-015: Provider entries distinguish reference configuration, fixture-tested
  compatibility, and credentialed live verification. Preset presence alone is
  never presented as a support guarantee.
- FR-016: The conformance harness stores only sanitized capabilities and
  aggregate outcomes. Credentials, addresses, UIDs, subjects, message bodies,
  and provider-assigned identifiers are excluded from committed evidence.
- FR-017: Runtime and documentation reject or clearly defer OAuth2 and JMAP
  operations in 1.0 rather than advertising unavailable support.

### Stable Contracts

- FR-018: Release, binary, JSON envelope, schema, MCP server, error catalog,
  operation state, and SQLite schema versions have one documented compatibility
  policy and are tested against checked-in golden contracts.
- FR-019: All persisted schemas migrate transactionally from every supported
  pre-1.0 version, reject newer incompatible schemas, and provide a documented
  backup and restore procedure before destructive migration.
- FR-020: Within 1.x, additive fields remain backward compatible, stable error
  codes retain meaning, and removals require a documented deprecation period.
- FR-021: Capability discovery lets clients distinguish unsupported, disabled by
  policy, unavailable from the provider, and temporarily failed operations.

### Distribution And Platform Support

- FR-022: Release automation builds versioned binaries for macOS arm64 and
  x86_64, Linux x86_64 and arm64, and Windows x86_64, runs target-appropriate
  tests, and publishes checksums, an SBOM, and verifiable build provenance.
  Buildable, preview, and supported target tiers are distinct; a target becomes
  supported only after its keyring, access-control, locking, path, installation,
  and upgrade behavior has passing platform evidence.
- FR-023: Platform keyring, config, index, ledger, locking, file-permission, and
  path behavior have target-specific tests and documented limitations. Kirje
  never falls back to plaintext credential storage.
- FR-024: `kirje doctor` reports actionable platform and installation readiness
  without exposing secrets or treating advisory detection as proof of keyring
  access.
- FR-025: Release archives contain the binary, license, concise installation
  instructions, and generated shell completions without bundling account data.

### Release Candidate

- FR-026: Protocol parsing, MIME construction, contract decoding, migration,
  and operation-state transitions receive fuzz, property, or fault-injection
  coverage appropriate to their risk.
- FR-027: Crash tests cover every persisted remote-operation transition and
  prove that no uncertain SMTP or IMAP action is automatically replayed.
- FR-028: A release-candidate conformance report covers at least two independent
  server families: a deterministic standards-based local test server and at
  least one credentialed real provider. Every additional available dedicated
  provider account is included, with sanitized blockers for unavailable
  external environments.
- FR-029: Security, privacy, dependency, migration, performance, documentation,
  and disaster-recovery reviews have no unresolved P0 or P1 finding.

### v1.0 Stable Release

- FR-030: All 1.0 required contracts are implemented, documented, and accepted;
  full local and CI gates pass on the release commit; the worktree is clean.
- FR-031: The release commit receives an annotated `v1.0.0` tag and a published
  GitHub Release whose artifacts, checksums, SBOM, provenance, and release notes
  match that exact commit.
- FR-032: The final release report records supported platforms, verified
  provider tiers, known limitations, migration path, security boundary, and
  post-1.0 roadmap without overstating recipient delivery or protocol support.

## Non-Functional Requirements

- NFR-001 Security: Existing immutable approval, CLI-only approval, keyring,
  verified TLS, untrusted-content, UIDVALIDITY, and no-automatic-replay
  invariants remain non-negotiable.
- NFR-002 Privacy: Indexes, ledgers, fixtures, logs, CI, release artifacts, and
  evidence contain no credentials or unrestricted mailbox content.
- NFR-003 Reliability: Every network or process-loss boundary maps to a stable,
  persisted certainty state and has deterministic recovery behavior.
- NFR-004 Boundedness: Network batches, local queries, output arrays, body and
  attachment bytes, audit histories, and migrations remain explicitly bounded.
- NFR-005 Portability: Supported targets build without disabling security
  checks; platform limitations are explicit rather than silently bypassed.
- NFR-006 Compatibility: CLI and MCP remain adapters over the same runtime, and
  all stable external contracts have regression fixtures.
- NFR-007 Observability: Diagnostics go to stderr, MCP stdout stays protocol
  clean, and audit output is structured, bounded, and secret-free.
- NFR-008 Delivery discipline: Protocol, auth, sync, persistence, policy, and
  remote-write behavior starts with a verified failing test and ends with fresh
  local and CI evidence.

## Non-Requirements

- Graphical UI, Tauri, hosted control plane, hosted relay, and embedded LLM.
- OAuth2, Gmail API, Microsoft Graph, and JMAP runtime support before 1.0.
- Resident background synchronization daemon or mandatory IMAP IDLE.
- Permanent deletion, unrestricted bulk mutation, or automatic ambiguous-state
  retry.
- Recipient-delivery tracking or claims beyond the SMTP and mailbox facts Kirje
  directly observes.
- Body indexing, semantic search, attachment execution, or autonomous approval.

## Delivery Checkpoints

1. Current branch checkpoint: preserve, review, and merge the accepted security
   foundation plus the account-create transition already under test.
2. `v1.0.0-alpha.1`: complete owner-authorized account, credential, local-input,
   runtime, CLI, MCP-deny, and capability boundaries.
3. `v1.0.0-alpha.2`: deliver resumable mailbox convergence and deterministic
   thread queries through shared CLI/MCP services.
4. `v1.0.0-beta.1`: deliver separate SMTP/Sent progress and explicit uncertain
   outcome reconciliation without automatic replay.
5. `v1.0.0-beta.2`: enforce local account policy and publish honest provider
   compatibility tiers.
6. `v1.0.0-rc.1`: freeze stable machine/persistence contracts and publish
   verifiable preview artifacts for every buildable target.
7. `v1.0.0-rc.2`: complete fuzz, fault, migration, conformance, security,
   privacy, performance, and disaster-recovery acceptance.
8. `v1.0.0`: publish the exact accepted release commit and artifacts.

This spec, one program plan, one program work graph, and checkpoint evidence are
the v1 governance SSOT. A checkpoint may use executor-sized packets for risky
implementation batches, but it does not create an independent release program,
duplicate product spec, or repeated approval chain. Focused tests run per code
batch; the complete local gate runs once at each tagged checkpoint and once on
the final release commit.

## Success Criteria

1. A fresh user can install and verify a supported binary, configure a
   password-based IMAP/SMTP account through the OS keyring, and inspect an
   honest capability and policy report without exposing a secret.
2. Replacing an account display ID, endpoint, username, or authentication kind
   cannot reuse an old credential, and strong approval evidence cannot be
   produced by terminal presence alone.
3. An interrupted full-mailbox synchronization resumes without duplicate local
   rows, skipped covered ranges, false deletion claims, or stale UID references.
4. A governed send produces independently inspectable SMTP and Sent-filing
   outcomes and cannot be submitted twice after any crash or uncertain result.
5. Policy tests prove that a disallowed mailbox, recipient, operation kind, or
   resource request is rejected before network mutation through both CLI and
   MCP paths.
6. Golden-contract and migration tests prove the documented 1.0 compatibility
   policy from supported pre-1.0 state.
7. Release artifacts for every supported target are generated from the tagged
   commit and pass checksum, SBOM, and provenance verification.
8. Full local gates, target CI, sanitized conformance, security review, release
   dry run, final tag, and GitHub Release are recorded as evidence.

## Acceptance Criteria

1. Every `FR-*` and `NFR-*` maps to at least one release task and validation
   command before implementation begins.
2. Every `SFR-*` is completed before the mailbox-alpha checkpoint merges.
3. No phase weakens the confirmed constitution or the v0.3 remote-write safety
   invariants.
4. Documentation and runtime capability reporting match the narrow IMAP/SMTP
   1.0 boundary at `alpha.1` and remain consistent through release.
5. A failed or unavailable real-provider check is recorded as a sanitized
   blocker and cannot be converted into a compatibility claim.
6. The final `v1.0.0` release is created only after `rc.2` acceptance and a
   clean, green release commit.

## Clarifications

- The 1.0 product boundary is the narrow IMAP/SMTP runtime defined in this spec.
- Delivery targets `v1.0.0` directly through incremental usable checkpoints.
- Every checkpoint produces a reviewed commit, PR/merge decision, prerelease
  tag, or stable release rather than planning-only progress.
- The confirmed product boundary does not waive failed security, privacy,
  migration, remote-write, CI, or release gates.
- The detailed technical plan and work graph require explicit user approval
  before new production execution begins.

## User Review Gate

Confirmed on 2026-08-30. The narrow 1.0 product boundary and incremental
checkpoint model, technical plan, and work graph are approved. T109 was
explicitly accepted by the user on 2026-08-30 at production commit `94f3495`.
