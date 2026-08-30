# Spec: Security Baseline

## Metadata

- Feature ID: `008-security-baseline`
- Status: Confirmed
- Target checkpoint: `v1.0.0-alpha.1`
- Product: Kirje
- Updated: 2026-08-30
- Source: `007-stable-v1-program`, the accepted v0.3 baseline, and the
  credential, approval, input-boundary, and capability-claim audits performed
  before Mailbox Alpha planning.
- Depends on: Confirmed `007-stable-v1-program` spec, plan, and work graph.
- Review: The base contract was confirmed on 2026-08-27 after three independent
  security reviews. The user approved the T202C3 cleanup contract revision on
  2026-08-30 and delegated later evidence-based acceptance; this record does
  not claim personal review of the resulting unseen artifact. The A006 packet
  remains pending independent review before production permission.

## Goal

Kirje Security Alpha closes the security gaps that would otherwise make later mailbox
convergence and delivery work unsafe. A stored credential cannot be redirected
by reusing an account display ID, terminal automation cannot create owner
authorization, local imports cannot bypass their file-type or byte bounds, and
the runtime and documentation state the actual local trust, storage, protocol,
and authentication boundaries.

## Users And Outcomes

### US-001: Bound account credentials

An account owner can create an account and enter its credential knowing that
Kirje will use that credential only with the identity and encrypted endpoints
the owner authorized.

Scenario:

1. The CLI prepares a proposed account and Kirje assigns an immutable
   credential identity without persisting an active account.
2. Kirje presents the complete account binding for owner authorization.
3. The owner authorizes creation, Kirje persists the account, and the owner
   separately authorizes and enters the credential through a hidden local
   prompt.
4. Reads and remote writes can retrieve the credential only while the current
   account binding still matches the authorized binding.

### US-002: Safe upgrade from v0.3

An existing user can upgrade without an unbound legacy credential or terminal
approval silently becoming trusted under the stronger Security Alpha model.

Scenario:

1. Kirje opens a v0.3 account configuration and operation ledger.
2. Accounts and terminal records remain inspectable, but every credential whose
   binding cannot be proven is quarantined.
3. Pending work with only legacy TTY approval cannot invoke a remote effect.
4. The owner establishes trust, authorizes the intended account binding, and
   re-enters the credential before authenticated work resumes.

### US-003: External owner authorization

An owner can review a bounded challenge and authorize exactly one immutable
remote action or sensitive control-plane change using a signing key that Kirje
and the agent cannot access.

Scenario:

1. The CLI creates a persisted, expiring challenge for one immutable object.
2. The external owner signer parses the exact action manifest, recomputes its
   digest, renders every covered effect field outside the agent-controlled
   session, signs the versioned signing payload, and returns a detached
   signature.
3. Kirje verifies the pinned owner key, action, digest, nonce, expiry, and
   one-time use before recording authorization.
4. Replaying the signature, changing any covered field, or presenting it
   through MCP cannot authorize another action.

### US-004: Bounded local import

An operator can provide an attachment or JSON document without a symlink race,
special file, or oversized stream causing Kirje to import unintended or
unbounded bytes.

Scenario:

1. Kirje opens the selected path once without following a link or reparse
   point.
2. Kirje validates the opened handle as a regular file and reads through a
   limiting reader.
3. Kirje imports at most the declared limit and rejects any limit-plus-one
   input without retaining partial application state.

### US-005: Honest security and capability reporting

An operator can understand what Kirje protects, what it does not protect, and
which protocol and authentication paths are actually implemented before
granting mailbox access.

## Security Model

### Protected Assets

- Passwords and provider-issued app passwords in the operating-system
  credential store.
- Account identity, endpoint, transport, and authentication bindings.
- Owner trust roots and accepted authorization evidence.
- Immutable send and mailbox-operation payloads and their state transitions.
- Private drafts, imported attachment bytes, local message metadata, and audit
  records.
- The integrity of the decision to invoke an authenticated remote effect.

### Untrusted Inputs And Actors

- Agent prompts, tool arguments, stdin, local input paths, and MCP clients.
- Mailbox bodies, headers, addresses, filenames, MIME metadata, and attachment
  bytes.
- IMAP and SMTP capabilities, status text, identifiers, and error responses.
- Provider presets and endpoint metadata until validated by Kirje policy.
- A caller that can allocate a pseudo-terminal and answer interactive prompts.
- Process interruption or a crash at any local or network boundary.

### Trusted Components And Deployment Assumptions

- The installed Kirje binary, operating system, TLS implementation, and OS
  credential store are inside the trusted computing base.
- The owner public trust root is provisioned through a trusted bootstrap and is
  writable only through the defined bootstrap, rotation, or recovery process.
- The owner private signing key remains outside Kirje state, the OS credential
  entry used for mailbox credentials, and the agent execution environment.
- The authorization guarantee assumes OS permissions or sandboxing prevent the
  agent from replacing the Kirje binary, modifying the pinned trust root or
  private databases out of band, debugging the owner signer, or directly
  reading the owner's signing key.
- An agent with unrestricted same-user filesystem, process, credential-store,
  and binary replacement access is outside this security boundary. Kirje must
  state this limitation directly; a detached signature does not turn local
  application state into a tamper-proof security boundary.

### Required Assurance

- Terminal presence and knowledge of an operation ID are convenience signals,
  not identity proof.
- Every authorization is asymmetric, detached, object-bound, short-lived, and
  single-use.
- Failure to establish or verify owner authorization fails closed before
  credential lookup or remote protocol invocation.
- Application audit events are append-only through supported Kirje operations,
  but the local databases are neither encrypted at rest nor cryptographically
  tamper-proof against an out-of-bound local writer.

## Functional Requirements

### Credential Identity And Account Binding

- FR-001: Every configuration document receives a cryptographically random,
  immutable store identity, and every account receives separate immutable
  random account and credential identities. These identities are non-secret and
  may be generated while an upgraded account is quarantined before owner trust
  exists. The account identity, not the display ID, is the durable reference
  used by operations, authorization, policy, and compare-and-swap checks.
- FR-002: Kirje derives a deterministic account binding from the validated
  exact email and authentication username bytes, credential kind, and incoming
  and outgoing protocol, host, port, and transport-security fields. DNS hosts
  use lowercase ASCII, IP addresses use canonical text, and protocol, security,
  port, and SMTP presence use explicit tags; email and username case is not
  silently folded. The format is versioned, length-prefixed, and
  domain-separated so a representation change cannot reinterpret an old
  digest.
- FR-003: Credential set, active presence check, retrieval, and active deletion
  require the pinned owner realm's authoritative mapping of canonical config
  location, store identity, account identity, credential identity, and current
  authorized binding. The credential-store locator binds the owner realm, store
  identity, credential identity, and binding digest. A caller-selected config
  cannot declare those identities authoritatively, and a copied store identity
  at a different path produces a stable conflict rather than credential access.
  A missing, mismatched, quarantined, or invalidated mapping fails before any
  network connection and never probes a legacy display-ID locator. Retired and
  legacy cleanup follows only the delete-only path in FR-008 and cannot be used
  for active lookup or deletion semantics.
- FR-004: Account creation is insert-only. Creating an account with an existing
  display ID returns a stable non-retryable conflict and leaves the stored
  account and credential untouched. The display ID is immutable in 1.0.
  Removing and later recreating the same display ID produces a new account and
  credential identity, so stale operation references cannot resolve to the new
  account.
- FR-005: Changing email identity, username, authentication kind, IMAP endpoint,
  SMTP endpoint, or transport security is an explicit owner-authorized account
  update against an expected account generation. It preserves the account
  identity, assigns a new credential identity, invalidates access to the old
  credential, and requires credential re-entry. An authenticated call uses the
  account, binding, credential identity, and endpoints from one validated
  snapshot; it cannot retrieve a secret and then reload different endpoints.
- FR-006: Account creation, any account update, account removal, and credential
  set or deletion are sensitive CLI-only control-plane actions and require
  owner authorization. Credential bytes are still entered through a hidden
  local prompt and never become part of the signing payload, command arguments,
  configuration, JSON output, logs, audit details, or MCP data. Credential set
  writes the new bound locator before an expected-generation account update;
  a failed update leaves only an unreachable orphan. Delete treats an absent
  locator as idempotent, removes the locator before marking the account unbound,
  and fails closed after either crash window. Binding-changing update commits
  the new identity and re-entry state plus an immutable delete-only cleanup
  tombstone before owner-authorized cleanup of the old locator.

### Legacy Migration And Quarantine

- FR-007: Opening a supported v0.3 configuration performs a transactional,
  restart-safe migration to the new account representation under an exclusive
  lock or equivalent compare-and-swap boundary. The document gets one stable
  store identity and each account gets stable account and credential identities,
  but every credential whose binding was not recorded and authorized before
  migration is unconditionally marked quarantined and unusable. Migration may
  complete before owner bootstrap for read-only inspection, but it cannot
  construct or use a new credential locator until the owner enrolls the store
  and authorizes the account binding.
  Concurrent create, update, or migration processes cannot silently lose or
  replace one another's account state. Every write checks the loaded
  configuration generation or content digest and performs same-directory atomic
  replacement through a stable opened parent-directory context; a path swap
  cannot redirect the write or overwrite a newer generation.
- FR-008: Migration never reads an account-ID credential and writes it under a
  newly bound identity. Legacy credential entries are ignored for authenticated
  work and may be removed only by an explicit owner-authorized delete-only
  cleanup path. The authority store records an immutable cleanup tombstone with
  only the realm, service version, store/account/credential/binding identities,
  or legacy account locator material needed to address the retired entry. That
  path can invoke only idempotent delete and then close the tombstone; it can
  never get, contains, list, copy, export, rebind, or fall back. Normal runtime,
  status, doctor, and migration code never probes the legacy service namespace;
  v0.3 accounts report quarantine from migration metadata whether or not an old
  entry exists. Every v1 tombstone is owned by one finalized account update or
  removal and binds that transition's immutable historical-before account,
  credential, binding, and locator transcript; later account state cannot
  redirect it. Challenge is effect-free. Claim atomically consumes one grant
  and yields only an opaque lock-owning delete permit. One combined consuming
  boundary performs the idempotent janitor call and terminal authority update,
  while delete and already-absent outcomes remain indistinguishable. Crashes or
  backend failure leave a safely retryable claimed tombstone, and an exact
  deleted retry performs no second janitor call.
- FR-009: Account status and doctor output expose orthogonal bounded
  `store_state`, `owner_state`, `binding_state`, and `credential_state` fields
  with deterministic combinations, including unregistered, not configured,
  valid, invalidated, missing, quarantined, and ready states. Stable reason
  codes include at least `account_already_exists`, `account_update_conflict`,
  `credential_reentry_required`, `credential_binding_invalid`,
  `config_store_identity_conflict`, and `config_migration`; they reveal no
  credential or store identity, locator, binding digest, endpoint, backend
  detail, or cross-account keyring presence. The non-secret stable account
  identity may be returned where a durable operation reference requires it.
- FR-010: Completed and terminal legacy ledger records remain readable for
  audit. A pending operation with only legacy TTY approval cannot be applied
  after upgrade. It must acquire valid owner authorization for its existing
  immutable digest and migrated stable account identity, or be re-planned when
  its payload or authorization policy is incompatible. A claimed legacy
  operation is never reset for replay; existing crash-recovery and ambiguous
  state rules continue to apply.
- FR-011: Configuration and ledger migration reject newer unsupported schema
  versions, preserve private permissions, commit with one atomic replacement
  where the platform provides it or a locked journaled recovery protocol that
  never exposes a partial document to Kirje, and produce no
  credential, account address, endpoint, operation content, or signature bytes
  in diagnostics. Account configuration is itself opened as a bounded,
  same-handle, non-link regular file; migration cannot allocate an unbounded
  TOML document or follow a substituted configuration path. A genuinely absent
  final component may initialize an empty configuration; permission failures,
  links, directories, special files, malformed content, and other I/O failures
  never degrade to an empty configuration. v1 migration rejects duplicate
  display IDs rather than choosing or merging; every v2 load rejects duplicate
  or malformed store, account, or credential identities and invalid state
  combinations. Random identities become stable only in the committed
  migration and are not regenerated by deserialization defaults after failure.

### Owner Trust And Authorization

- FR-012: Before owner trust is configured, Kirje permits bounded local and
  read-only inspection but rejects remote writes and sensitive control-plane
  changes. Initial trust-root enrollment is a documented trusted bootstrap
  outside the agent-controlled session. It is create-once and installs a random
  immutable owner realm of at least 256 CSPRNG bits, the owner public key, a
  separate offline recovery public key, and a pinned authority-store location
  that ordinary CLI flags, environment variables, custom config/index/outbox
  paths, and MCP requests cannot redirect or replace. Re-running bootstrap
  against an existing anchor always fails. A config store becomes eligible for
  credentials or governed work only after owner-authorized enrollment of its
  store identity and canonical location in that realm.
- FR-013: A persisted authorization challenge includes a versioned signing
  domain, owner realm, applicable account and store identities, action kind,
  immutable target identifier, digest of the complete immutable action manifest,
  current account binding and policy digest when applicable, owner key identity
  and epoch, a cryptographically random nonce of at least 128 bits, issuance
  time, authorization expiry no more than 15 minutes after issuance, a unique
  authorization-grant identity, and one or more unique remote-effect identities
  when the action can invoke a remote effect. The manifest covers every field
  that can affect the result. Human-readable review fields are derived from
  that stored manifest and cannot substitute for the signing payload.
- FR-014: The CLI emits one unambiguous, bounded signing payload and a digest of
  that payload together with the exact bounded action manifest an owner signer
  must independently parse and review. The signed representation is specified
  byte-for-byte and is independent of locale, whitespace, map ordering,
  terminal rendering, and JSON serializer implementation. A signer cannot rely
  only on an agent-provided or terminal-rendered summary. The action coverage
  matrix is explicit: a send manifest covers account binding, to/cc/bcc,
  subject, exact bounded text and HTML, attachment
  names/types/sizes/content digests and bounded summaries, Message-ID, reply
  headers, and applicable delivery policy; a mailbox manifest covers account
  binding, operation kind, mailbox, UIDVALIDITY, UID, requested value, and
  destination; a control-plane manifest covers action kind and the complete
  canonical old and proposed new snapshots. The external signer independently
  parses the manifest, recomputes its digest, and verifies that matrix before
  signing.
- FR-015: Authorization accepts only a detached signature by the currently
  trusted owner key for the exact challenge. Verification rejects an unrecognized or
  retired key, unsupported signing format, malformed signature, action or
  digest mismatch, expired challenge, reused nonce, consumed challenge, or
  clock value outside the documented tolerance. Submitting the exact same proof
  after a response-loss crash may return the same immutable authorization
  receipt but cannot create another grant or extend its expiry; reusing the
  nonce with any changed proof or target is rejected.
- FR-016: The pinned realm authority store is the source of truth for immutable
  authorization receipts, grant expiry, nonce consumption, trust epoch, every
  remote-effect identity, and each effect's global apply-claim state. Proof
  verification and receipt creation are one idempotent durable transition.
  Before credential lookup or network access, apply atomically claims the
  remote-effect identity in the authority store and records the claim in the
  operation ledger through a persisted crash-recovery protocol. Copying or
  rolling back an outbox before or after approval or execution cannot obtain a
  second global claim. A partial local outcome fails closed and can reconcile
  to the same receipt or claim, never repeat a sensitive or remote effect. A
  custom store not enrolled in the realm is read-only for governed work.
- FR-017: Owner authorization is required for send approval, mailbox-operation
  approval, account creation or binding changes, credential set or deletion,
  policy or assurance changes, owner-key rotation, and external closure of an
  ambiguous outcome. Adding another sensitive action later requires an explicit
  authorization-policy mapping and contract test; absence from the map fails
  closed. Apply revalidates the unexpired grant, current trust epoch and key
  status, trust-bundle digest, store/account registration, account binding,
  policy digest, target manifest, and unclaimed remote-effect identity
  immediately before its global claim. An expired or context-stale approval
  returns to an authorization-required state and cannot invoke the effect.
- FR-018: The private authority store retains the exact canonical signing
  payload, bounded manifest, complete detached signature, immutable receipt,
  historical public key and trust metadata, verification time, and effect-claim
  history needed to re-verify evidence after rotation. It stores no owner
  private key or mailbox credential. Normal CLI/MCP status and audit output
  exposes only bounded review metadata, digests, key fingerprints, state, and
  timestamps rather than the full proof or unrestricted manifest content.
- FR-019: Key rotation requires valid authorization by the current owner key
  and proof of possession by the proposed new key over the same canonical
  new-trust manifest, action, role, permissions, trust-bundle digest, and epoch
  transition. Rotation or revocation increments the trust epoch, rejects new
  authorization by retired keys, invalidates all old-epoch grants whose remote
  effects have not been claimed, and preserves historical evidence. Recovery
  requires the bootstrap-pinned offline recovery key or an explicitly documented
  independent OS-administrator boundary, installs a new owner and recovery
  epoch, and invalidates every pending challenge, unclaimed grant, account
  credential binding, and remote-write readiness. A missing authority journal
  or one whose instance/epoch does not match the pinned anchor also fails closed
  into recovery; restoring both anchor and journal out of band remains within
  the stated local-tampering limitation.
- FR-020: CLI may create, inspect, submit, and audit the bounded authorization
  artifacts needed by the trusted owner workflow. MCP may inspect whether an
  operation is awaiting authorization, but exposes no challenge creation,
  signature submission, approval, owner-key management, credential operation,
  account mutation, policy mutation, or ambiguous-closure tool. MCP tool names
  and request schemas use a reviewed allowlist and golden snapshot; status and
  apply schemas accept no inline signature, proof, nonce, key, trust override,
  policy override, or authorization material.

### Same-Handle Bounded Input

- FR-021: Attachment import, user-supplied JSON, authorization documents, and
  account configuration open the selected final path component exactly once
  without following a symbolic link, junction, or platform reparse point.
  Kirje validates the opened handle as a regular file before consuming bytes.
  The open operation itself cannot block on or activate a FIFO, socket, named
  pipe, device namespace, or other special object before validation; platforms
  use no-follow and nonblocking/open-reparse semantics or report the operation
  unsupported. Parent-directory links may resolve normally and are not a
  containment guarantee.
- FR-022: File and stdin readers consume at most the declared limit plus one
  byte. A limit-plus-one input returns `resource_limit` before parsing or
  persisting an operation, draft, attachment, authorization, or configuration
  change. No code path first accumulates an unbounded stream and checks its
  length afterward. At exactly the limit, a stream waits for EOF or the next
  byte and never accepts a possibly truncated document. Bounded parsers also
  enforce nesting depth, collection counts, and field limits before large
  in-memory structures are built, and allocation failure maps to
  `resource_limit` without partial state.
- FR-023: File size metadata is an optimization, not the security boundary.
  Shrinking, growing, replacing, renaming, or unlinking a path after open cannot
  change which file object is read or bypass the byte limit. A zero-length
  permitted input is handled by the consuming parser's normal validation.
- FR-024: The same bounded-input service and error mapping back attachment,
  send, draft, mailbox-operation, authorization-document, and account-config
  reads. Platform implementations have equivalent regular-file and no-link
  semantics, or the affected operation is reported unsupported rather than
  weakened. Parent-directory links and normal hard links are not claimed as a
  containment boundary; the requirement protects the final opened object and
  its byte limit.

### Bounded MCP Transport

- FR-025: MCP stdio enforces a documented maximum newline-terminated JSON-RPC
  frame before unbounded buffer growth. A frame with at most the maximum bytes
  before its newline is accepted for parsing; an exact-limit stream without a
  terminator waits for the terminator, EOF, or one additional byte. EOF without
  a complete frame is invalid. On the first limit-plus-one byte, Kirje stops
  reading that frame, emits at most one bounded JSON-RPC invalid-request error
  with a null identifier and no input echo, records a bounded stderr diagnostic,
  closes the transport, and exits nonzero. It never drains an attacker-sized
  remainder in order to continue the session.
- FR-026: The MCP frame budget is derived from the largest valid bounded tool
  request plus worst-case JSON escaping, Base64 expansion, bounded request ID,
  method name, and JSON-RPC envelope overhead. Every request that is valid under
  a shared runtime service's documented input budget has a valid MCP
  representation within the transport budget; CLI and MCP cannot disagree only
  because the transport limit is smaller than a maximum valid service request.
  The transport also bounds concurrent and in-flight requests and its input,
  response, task, and request-ID queues, and applies backpressure before reading
  another frame. Capacity exhaustion returns one stable bounded busy error or
  closes the transport; completion, cancellation, failure, and disconnect
  release state, while duplicate in-flight IDs are rejected. Raw request/result
  tracing is disabled or bounded and redacted. Both adapters still enforce the
  same service-level nesting, collection, field, and decoded-byte limits.

### Bounded Untrusted Responses

- FR-027: IMAP and SMTP capability names, response text, folder attributes,
  identifiers, and adapter diagnostics are bounded by documented maximum item
  counts, per-item wire-byte limits, and total parser and serialized-output
  limits at the protocol read boundary, before an oversized value reaches core
  objects, the operation ledger, CLI JSON, MCP results, logs, or evidence.
  Invalid UTF-8, NUL, control characters, line breaks, and byte-boundary
  truncation have deterministic handling; character limits are presentation
  constraints rather than memory or wire-security bounds.
- FR-028: Capability values used for authentication, extension support,
  destination resolution, or remote-write safety are parsed into a bounded
  typed set and fail closed when the set or any item exceeds its security
  budget. A truncated display list is never used for a security decision, and
  an omitted capability is not inferred to be unsupported when completeness is
  indeterminate.
- FR-029: Display truncation is deterministic and explicit. A caller can
  distinguish complete, truncated, omitted, and rejected untrusted values
  without receiving discarded content. Untrusted and completeness metadata
  survive core, ledger, CLI/MCP, receipt, log, and evidence boundaries for
  capability values, SMTP receipts, folder attributes, identifiers, and adapter
  diagnostics. Resource-limit failures are stable and do not include the
  rejected provider string.
- FR-030: Audit list, capability report, account status, authorization status,
  and migration diagnostics remain versioned, structured, bounded, stdout-clean,
  and free of credentials, owner private material, unrestricted mailbox
  content, and raw remote responses.

### Honest Product And Storage Boundary

- FR-031: Runtime capability reporting, README, product definition, Agent Skill,
  architecture, security, provider, conformance, and operator documentation
  state that Security Alpha supports IMAP and SMTP with password or provider-issued
  app-password authentication. OAuth2, Gmail API, Microsoft Graph, and JMAP
  runtime operations are explicitly unsupported rather than implied by
  provider-neutral type names or registry metadata.
- FR-032: Security and operations documentation state that local SQLite and
  configuration files rely on OS permissions, are not encrypted at rest, and
  are not tamper-proof against an out-of-bound local writer. The operation event
  trail is append-only through supported application paths, not a
  cryptographic transparency log.
- FR-033: Documentation defines the locations, permissions, backup and restore
  behavior, retention, and erasure procedure for account configuration, message
  index, operation ledger, drafts and imported bytes, authorization state,
  trust roots, quarantined legacy credentials, and OS credential entries.
- FR-034: Documentation distinguishes SMTP acceptance, mailbox mutation
  receipts, owner authorization, and local audit evidence from recipient
  delivery, provider-side finality, and cryptographic proof of local database
  history.

## Non-Functional Requirements

- NFR-001 Security: Credential lookup and every covered authorization check fail
  closed before network connection or mutation. TLS verification remains
  mandatory and no plaintext or opportunistic downgrade path is introduced.
- NFR-002 Privacy: A mailbox credential is never persisted outside its OS
  credential-store entry and is never serialized, output, logged, or recorded.
  It may exist only briefly in secret-wrapping runtime and authentication-adapter
  memory after binding validation and may be submitted only through verified TLS
  authentication to the bound endpoint. The owner private key remains solely in
  the external signer. Committed tests, fixtures, logs, audit summaries,
  migration messages, documentation examples, CI artifacts, and evidence use no
  real mailbox address, UID, subject, body, attachment content, signature, or
  unsanitized provider response. Bounded owner-review or mailbox-operation
  output may contain the exact non-secret content its function requires, but
  marks it untrusted, never emits it through MCP approval tooling, and does not
  persist it outside the documented private stores.
- NFR-003 Reliability: Configuration, authorization, and ledger transitions are
  atomic and restart-safe. A crash cannot reactivate a quarantined credential,
  reuse a consumed challenge, restore retired owner authority, or replay a
  claimed remote operation. Custom data-path flags and database rollback cannot
  replace the pinned realm authority store for a remote or sensitive action.
  Credential-store and config-file partial writes have defined unreachable or
  fail-closed outcomes rather than implicit retry.
- NFR-004 Boundedness: Every local input, external signature artifact, remote
  capability, response, audit history, list, diagnostic, and serialized machine
  result has an enforced bound at its first trust-boundary crossing.
- NFR-005 Portability: macOS, Linux, and Windows implement equivalent credential
  binding, signature verification, private-state, and no-link file-import
  guarantees. A platform-specific inability is explicit and cannot silently
  fall back to weaker behavior.
- NFR-006 Compatibility: CLI and MCP remain adapters over shared runtime
  services. New public fields and states are versioned, and supported v0.3
  configuration and ledger states have deterministic migration fixtures.
- NFR-007 Observability: Security decisions expose stable reason codes and
  retryability metadata while diagnostics use stderr and MCP stdout remains
  protocol-clean. Secret and untrusted values are represented by bounded
  metadata, digests, or redacted categories.
- NFR-008 Delivery discipline: Credential, authorization, migration, import,
  protocol-boundary, and documentation behavior starts with a verified failing
  test where executable behavior exists and ends with fresh full-gate, review,
  PR, CI, merge, and post-merge evidence.

## Non-Requirements

- No OAuth2, Gmail API, Microsoft Graph, JMAP runtime, hosted signer, hosted
  control plane, graphical approval UI, or mobile approval application.
- No claim to protect against an attacker that can replace the trusted Kirje
  binary, directly rewrite protected local state, control the owner signer, or
  bypass the configured OS principal or sandbox boundary.
- No migration that automatically trusts an account-ID keyring entry.
- No terminal-only, biometric-prompt-only, typed-ID-only, or agent-prompt-based
  substitute for detached owner authorization.
- No encryption-at-rest or cryptographic transparency-log claim for the local
  configuration, index, operation ledger, or drafts in Security Alpha.
- No new remote mailbox behavior, background daemon, permanent deletion,
  automatic resend, or automatic ambiguous-state reconciliation.
- No exposure of credential or authorization mutation through MCP.

## Edge Cases

- Two processes create the same account display ID concurrently.
- A caller selects a different `--config`, `--index`, or `--outbox`, copies an
  account or signed operation before or after approval or execution, or restores
  an older operation database in an attempt to retrieve a credential or repeat
  an owner-authorized remote effect.
- A copied configuration presents the same store, account, and credential
  identities at another path, or a config contains duplicate display, account,
  credential, or store identities.
- An account update changes only hostname letter case, email or username case,
  port, TLS mode, SMTP absence/presence, or another normalized authority field.
  Canonically equivalent host text preserves the binding; a semantic authority
  change invalidates it.
- Credential set or delete loses the process between keyring mutation and
  expected-generation config update, or an account update loses the process
  before old-locator cleanup.
- A legacy keyring contains an entry for an account missing from configuration,
  or one display ID has been reused for a different endpoint before migration.
- Upgrade stops after configuration replacement but before credential re-entry,
  or after challenge creation but before authorization consumption.
- A legacy operation is planned, TTY-approved, applying, ambiguous, failed, or
  terminal when migration begins.
- The system clock moves backward or forward across challenge issuance and
  expiry; the documented tolerance is applied without extending the signed
  expiry.
- The same valid signature is submitted concurrently, after restart, after key
  rotation, or for a different action with the same target digest.
- An authorization expires after receipt creation but before apply, the trust
  epoch rotates after approval, or an approved outbox is copied before its
  remote-effect identity is claimed.
- The owner loses the signing key, a proposed rotation key equals the current
  key, the pinned authority journal is missing or mismatched, recovery is
  interrupted, or an old anchor and journal backup are restored out of band.
- A selected path is a symbolic link, junction, reparse point, FIFO, device,
  sparse file, growing file, replaced path, deleted path, or file larger than
  its initial metadata reports.
- Stdin never reaches EOF, reaches exactly the limit, or sends one extra byte.
- MCP stdio receives one oversized JSON-RPC line without a newline, an exact
  limit line, or many bounded lines while handlers or stdout are blocked; task,
  request-ID, input, and response queues remain bounded and recover after
  completion, cancellation, error, or disconnect.
- A provider sends excessive capability items, invalid UTF-8 bytes, control
  characters, very long response lines, or repeated nested error text.
- A migration or security error occurs while stdout is carrying CLI JSON or MCP
  protocol frames.

## Constraints And Assumptions

- The owner can maintain an asymmetric signing key outside the agent execution
  environment and can transfer a detached signature through a bounded local
  channel.
- The operating environment can enforce the documented trust boundary around
  the installed binary, trust root, Kirje private state, and owner signer.
- Existing OS keyring integrations remain the mailbox credential storage
  mechanism; Kirje does not export credentials to perform migration.
- v0.3 terminal records and account-ID credential entries exist in the field
  and must be handled conservatively rather than assumed absent.
- Every remote or sensitive control-plane action uses the same authorization
  policy service; CLI handlers do not implement independent checks.
- Provider-specific response cleanup remains inside adapters, while bounds and
  stable errors are enforced by Kirje-owned contracts.

## Data And Integration Needs

- Versioned account configuration with credential identity, binding digest,
  credential readiness, generation, store/account identities, and migration
  state.
- A pinned owner-realm registry of canonical config-store locations, stable
  account identities, credential identities, and authorized bindings.
- OS credential-store addressing that binds realm, store, credential, and
  account-binding identities and cannot resolve by display ID alone.
- Pinned owner and recovery public-key metadata, realm and authority-store
  identity, key epoch, bootstrap and recovery state.
- Persisted single-use authorization challenges, immutable receipts, unexpired
  grants, globally unique remote-effect apply claims, and re-verifiable evidence.
- Existing operation-ledger migration and shared send/mailbox approval service.
- Shared bounded reader with platform-specific no-link regular-file opening.
- Stable capability, truncation, migration, authorization, and binding error
  codes for CLI and MCP contracts.

## Success Criteria

- SC-001: Tests demonstrate that reusing a display ID or changing canonical
  binding material, including exact email or username bytes, authentication
  kind, endpoint authority, port, SMTP presence, or transport, cannot retrieve
  or submit a previously stored credential to the changed identity, while
  canonical-equivalent DNS or IP host text has one stable binding.
- SC-002: Every migrated account-ID credential is unusable until the owner
  authorizes the intended binding and re-enters the credential; no migration
  test copies or probes legacy secret bytes as a fallback.
- SC-003: A pseudo-terminal can display a challenge but cannot produce an
  authorized send, mailbox mutation, credential change, account binding change,
  key rotation, or ambiguous closure without a valid external owner signature.
- SC-004: Signature tests reject action substitution, target substitution,
  malformed payloads, wrong keys, retired keys, expiry, clock-boundary misuse,
  replay, concurrent reuse, restart reuse, old-epoch approval, copied approved
  outboxes, copied executed outboxes, and rolled-back outboxes before any
  duplicate remote invocation. An exact proof retry returns at most its existing
  receipt, and a remote-effect identity receives at most one global apply claim.
- SC-005: Cross-platform tests reject links and special files, prove path
  replacement cannot change the opened object, and prove file and stdin readers
  consume no more than the configured limit plus one byte. MCP transport tests
  prove an oversized line cannot grow without bound or contaminate stdout and
  prove a stream of individually valid frames cannot exceed the configured
  handler, task, ID, or queue budgets while handlers or output are blocked.
- SC-006: Capability and response fixtures cannot create unbounded memory,
  output, logs, audit details, or evidence; truncation and resource-limit states
  are visible through stable machine contracts.
- SC-007: Runtime capability output and every canonical user or operator
  document agree on the IMAP/SMTP password or app-password boundary and the
  local storage and attacker limitations.
- SC-008: Full workspace gates, supported-target tests, secret scanning,
  controlled read-only account verification, security review, PR CI, merge, and
  post-merge CI pass with credential-free evidence before Mailbox Alpha work.

## Acceptance Criteria

1. FR-001 through FR-034 and NFR-001 through NFR-008 map to confirmed child
   tasks, validation commands, and evidence before implementation begins.
2. RED tests reproduce account replacement, copied-config credential access,
   credential redirection, legacy auto-trust, TTY automation, blind-signing
   substitution, expired and old-epoch apply, approved/executed outbox copy or
   rollback replay, unsafe file import, oversized MCP framing, and unbounded
   MCP concurrency/queue growth and provider-response behavior on the v0.3
   baseline.
3. Both CLI and MCP contract tests prove they use shared runtime services and
   that MCP exposes no owner-authorization or sensitive control-plane mutation.
4. Migration tests cover every non-terminal and terminal legacy operation
   state, interrupted configuration migration, newer-schema rejection, private
   permissions, duplicates and invalid identities, concurrent create/update,
   credential set/delete crash windows, bounded config loading, and
   deterministic restart.
5. Security review confirms that documentation claims do not exceed the
   explicit trusted-computing-base and same-user attacker assumptions.
6. A controlled real-account check may confirm only read-only authentication
   and capability behavior in Security Alpha unless a separately authorized test action
   is part of an approved execution packet. Its evidence contains no account
   address, credential, UID, subject, body, endpoint identifier, or signature.
7. The Security Alpha checkpoint is merged, tagged, and green before Mailbox
   Alpha production work begins.

## Clarifications

- Security Alpha precedes Mailbox Alpha and requires random credential identity,
  legacy quarantine, external owner signatures, same-handle bounded import,
  honest storage claims, bounded remote responses, and correction of
  unsupported protocol claims.
- 2026-08-27: External signatures protect supported Kirje state transitions
  within an enforced local trust boundary. They do not claim to withstand an
  agent that can replace the trusted binary or directly rewrite protected local
  state as the same unrestricted OS principal.
- 2026-08-27: Legacy TTY approval is preserved as historical audit metadata but
  is not sufficient to invoke pending remote work after upgrade.
- The security requirements contract is confirmed. Executable batching follows
  the user-reviewed `007-stable-v1-program` plan and cannot weaken these design
  decisions.

## Open Questions

- The technical plan must select the signing algorithm and byte-level signing
  envelope after dependency, portability, canonicalization, and supply-chain
  review. The selected design cannot weaken FR-013 through FR-019.
- The technical plan must define the trusted bootstrap and offline recovery
  runbook for each supported operating system and state which OS permission or
  sandbox boundary enforces the deployment assumptions.
- The technical plan must select a cross-platform no-link file-opening API and
  provide equivalent macOS, Linux, and Windows evidence or explicitly narrow
  support before implementation readiness.
- The technical plan must define a bounded MCP stdio transport compatible with
  the selected `rmcp` version, calculate the frame budget from valid tool input
  limits and worst-case serialization expansion, select in-flight/task/queue
  budgets, disable or redact raw transport tracing, and verify the FR-025 and
  FR-026 failure states remain bounded and stdout-clean.

## User Review Gate

- Approval: Confirmed on 2026-08-27
- Reviewer notes: The user delegated project-owner authority for autonomous
  delivery. Planning may proceed, but production execution still requires a
  completed technical plan, work graph, consistency analysis, execution packets,
  RED evidence, and review.
