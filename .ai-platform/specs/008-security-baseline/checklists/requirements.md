# Requirements Checklist: Security Baseline

## Metadata

- Version: `v0.1`
- Status: Completed
- Source spec: `.ai-platform/specs/008-security-baseline/spec.md`
- Updated: 2026-08-27

## Checklist Scope

- Feature: `008-security-baseline`, targeting `v0.3.1`
- Reviewed artifacts:
  - `.ai-platform/specs/008-security-baseline/spec.md`
  - `.ai-platform/specs/007-stable-v1-program/spec.md`
  - `.ai-platform/specs/007-stable-v1-program/plan.md`
  - `.ai-platform/specs/007-stable-v1-program/tasks.md`
  - `.ai-platform/memory/constitution.md`
- Review inputs: Read-only credential-binding, owner-authorization, and bounded
  input/response audits of the accepted v0.3 codebase.

## Requirement Quality Checks

### Scope And Outcomes

- [x] Each user story identifies an actor, trigger, and observable security
  outcome. [Completeness]
- [x] The feature is limited to the pre-v0.4 security baseline and does not add
  new remote mailbox behavior. [Scope]
- [x] OAuth2, provider APIs, JMAP runtime, GUI approval, hosted signing,
  encryption at rest, and tamper-proof local history are explicit non-goals.
  [Scope]
- [x] The requirements distinguish owner authorization from terminal presence,
  operation-ID knowledge, and agent prompt confirmation. [Clarity]
- [x] The product guarantee and the out-of-scope unrestricted same-user attacker
  are stated without implying that application-level signatures protect a
  replaced binary or directly rewritten database. [Security boundary]

### Credential And Migration Contract

- [x] Store, account, and credential identities are distinct from the immutable
  display ID; the pinned realm registry and credential locator bind their
  authoritative relationship to the canonical config store and account
  binding. [Coverage]
- [x] Every identity and endpoint field covered by the binding is enumerated,
  including SMTP absence/presence and transport security. [Clarity]
- [x] Duplicate account creation, immutable display IDs, explicit authority
  update, credential rotation, account removal, and same-display-ID recreation
  have defined owner-authorized behavior and stable account identity. [Coverage]
- [x] A copied config-store identity at another path conflicts rather than
  sharing credentials, and caller-selected configuration cannot declare realm
  registry identities authoritatively. [Security]
- [x] Concurrent configuration mutation and migration require a lock or
  compare-and-swap boundary; atomic rename alone is not treated as concurrency
  control. [Reliability]
- [x] Credential set/delete and account-update crash windows have ordered,
  expected-generation, unreachable-orphan or fail-closed outcomes, and one
  authenticated call uses one validated account snapshot. [Reliability]
- [x] Legacy account-ID keyring entries are quarantined, never probed or copied
  as migration fallback, and removable only through owner-authorized cleanup.
  [Security]
- [x] Active credential deletion is distinct from retired/legacy purge; cleanup
  uses immutable delete-only tombstones and can never read, test, list, copy,
  export, or rebind the old entry. [Security]
- [x] Migration behavior covers legacy planned, TTY-approved, applying,
  ambiguous, failed, and completed operation records. [Edge cases]
- [x] Migration is transactional, restart-safe, permission-preserving,
  bounded, idempotent, and rejects newer unsupported schemas. [Reliability]
- [x] Migration and every v2 load reject duplicate or malformed display, store,
  account, and credential identities and invalid state combinations. [Integrity]
- [x] Account status uses orthogonal store, owner, binding, and credential
  states without probing legacy entries or exposing credential locators,
  bindings, store/credential identities, or cross-account keyring presence.
  [Privacy]

### Owner Authorization Contract

- [x] The challenge binds domain/version, owner realm, store/account context,
  action, object, immutable digest, current binding/policy, key epoch, random
  nonce, issuance, and bounded expiry. [Completeness]
- [x] The immutable action manifest covers generated and derived effect fields,
  is stored exactly, and must be parsed independently by the external signer
  rather than trusted from an agent-rendered summary. [Security]
- [x] The signed byte representation must be deterministic across locale,
  whitespace, map order, terminal rendering, and serializer implementation.
  [Testability]
- [x] Verification failure cases include key, epoch, realm, action, object,
  digest, expiry, clock boundary, malformed proof, replay, concurrent reuse,
  restart, copied approved/executed outbox, and rolled-back outbox. [Coverage]
- [x] The pinned authority store issues idempotent immutable receipts and owns
  grant expiry plus a global apply claim for every remote-effect identity before
  credential or network access. [Reliability]
- [x] Historical remote effects reference immutable store/account version
  parents, so advancing a current registry projection cannot rewrite or
  foreign-key-block accepted history. [Integrity]
- [x] The authority store and trust root cannot be redirected through ordinary
  config, index, outbox, environment, or MCP inputs. [Security]
- [x] Apply rechecks grant expiry, trust epoch/key status, trust bundle,
  store/account registration, binding, policy, manifest, and effect claim, so
  rotation and expiry invalidate unclaimed work. [Security]
- [x] Every current sensitive action is enumerated and future unmapped actions
  fail closed. [Completeness]
- [x] Bootstrap, normal rotation, loss recovery, proof of possession, key epoch,
  pending-grant invalidation, pinned recovery key, authority-journal mismatch,
  and historical evidence behavior are defined at the requirements level.
  [Coverage]
- [x] Historical authorization evidence remains privately re-verifiable from
  the canonical payload, manifest, signature, and historical public trust
  metadata while normal machine output remains digest-only. [Auditability]
- [x] The private signing key is excluded from Kirje, mailbox credential
  storage, CLI arguments, environment configuration, agent state, MCP, and
  persisted authorization data. [Privacy]
- [x] MCP's permitted inspection surface and prohibited challenge, signature,
  approval, owner, credential, account, policy, and reconciliation mutations are
  explicit, and request schemas cannot smuggle proof or trust overrides.
  [Interface]

### Input And Untrusted Response Boundaries

- [x] Attachment, JSON, authorization-document, and account-config file reads
  use a single no-link regular-file handle. [Security]
- [x] Files and streams consume at most the limit plus one byte before parsing
  or persistence, including never-ending stdin. [Boundedness]
- [x] Exact-limit streams wait for EOF or another byte, and deserialization
  enforces nesting, collection, field, decoded-byte, and allocation bounds before
  large object construction. [Boundedness]
- [x] Path replacement, growth, shrink, rename, unlink, special files, final
  symlinks, and platform reparse points have defined safe outcomes. [Edge cases]
- [x] Parent-directory links and hard links are not misrepresented as a full
  filesystem containment guarantee. [Clarity]
- [x] Config writeback uses generation/content CAS and a stable parent-directory
  context, and only a genuinely missing final component initializes empty
  state. [Integrity]
- [x] MCP stdio has a pre-allocation frame or line bound, oversized-input
  behavior, no rejected-content echo, one terminal error state, and stdout
  protocol-purity requirement. [Coverage]
- [x] The MCP transport budget is derived from the maximum valid shared-service
  request, so a legal CLI/MCP request cannot fail only because MCP framing is
  smaller. [Consistency]
- [x] MCP bounds in-flight handlers, tasks, request IDs, and input/response
  queues; applies backpressure; releases state on every terminal path; rejects
  duplicate active IDs; and disables or redacts raw transport tracing.
  [Boundedness]
- [x] Remote capabilities, response text, folder attributes, identifiers,
  diagnostics, serialized outputs, logs, ledger receipts, and evidence have
  count, item, and total-bound requirements. [Boundedness]
- [x] Security-relevant capabilities use a complete bounded typed set and fail
  closed on overflow; truncated display data cannot authorize or deny remote
  behavior. [Security]
- [x] Truncation and rejection are deterministic and visible without returning
  discarded untrusted content, and untrusted/completeness metadata survives
  structured boundaries. [Observability]

### Documentation, NFRs, And Acceptance

- [x] Runtime and documentation must agree on the actual IMAP/SMTP password or
  app-password boundary and unsupported OAuth2/API/JMAP behavior. [Consistency]
- [x] Storage permissions, encryption-at-rest absence, application-level
  append-only history, backup, restore, retention, and erasure are required.
  [Operations]
- [x] Mailbox credentials may exist outside keyring only as short-lived wrapped
  runtime/authentication memory after binding validation and may be submitted
  only to the bound verified-TLS endpoint; they are never persisted, serialized,
  output, or logged. [Privacy]
- [x] Security, privacy, reliability, boundedness, portability, compatibility,
  observability, and TDD/release discipline are all covered by stable NFR IDs.
  [NFR]
- [x] Success criteria cover credential redirection, legacy quarantine, PTY
  automation, signature substitution/replay, path races, MCP framing, remote
  response bounds, documentation accuracy, and release evidence. [Testability]
- [x] Controlled mailbox validation is read-only by default and cannot commit
  account, credential, UID, content, endpoint, or signature evidence.
  [Privacy]
- [x] Every functional and non-functional requirement must map to confirmed
  tasks, commands, and evidence before execution. [Traceability]

## Findings Summary

- Critical: 0 requirement-quality findings.
- High: 0 unresolved requirement-quality or governance findings. The parent
  program and this requirements contract were confirmed under the user's
  delegated project-owner authority on 2026-08-27.
- Medium: 0 unresolved requirement-quality findings. Signing algorithm,
  byte-level envelope, OS bootstrap/recovery mechanics, no-link API, and bounded
  `rmcp` transport are deliberately constrained technical-plan decisions rather
  than unspecified user outcomes.
- Low: 1 planning note. Exact per-field and total capability/response constants
  and the derived MCP frame constant must be selected and exposed as contract
  values in the plan and fixtures.

## Resolution Notes

- The credential audit added owner-realm scoping, strict insert semantics,
  stable store/account/credential identities, concurrent configuration and
  credential-state protection, legacy quarantine, stateful readiness, and
  copied-config/keyring isolation requirements.
- The authorization audit added immutable manifest context, pinned realm and
  authority-store receipts and global remote-effect claims, path and rollback
  replay cases, expiry and epoch rechecks, re-verifiable evidence, key rotation
  and recovery invalidation, and an explicit MCP deny surface.
- The input audit corrected the parent analysis: explicit CLI JSON stdin already
  uses a limit-plus-one reader. The remaining gaps are same-handle file reads,
  bounded account configuration, unified allocation behavior, and unbounded
  `rmcp` stdio framing.
- Three scope-specific independent final reviews found no unresolved requirement
  Critical or High after the credential lifecycle, authority/effect-claim, and
  bounded file/MCP transport corrections. Remaining signing, recovery, platform
  API, cross-store projection, and numeric-budget choices are constrained
  technical-plan decisions.
- The feature spec is confirmed. Implementation readiness is not inferred until
  plan, task graph, analysis, packets, and RED evidence are complete.

## User Review Gate

- Approval: Confirmed on 2026-08-27
- Reviewer notes: The user delegated project-owner authority for autonomous
  delivery; technical planning may proceed without another conversational gate.
