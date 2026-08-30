# T202C3-A006 Cleanup Contract Fix A002

## Scope

This governance-only attempt fixes the three High findings returned by the
first independent A006 spec, engineering, and QA review. It changes no
production code, test, schema, dependency, core transcript, runtime, keyring,
protocol, CLI, MCP, network, or external provider behavior.

## Findings Addressed

1. The authorization action matrix and FR-013 make cleanup the explicit
   historical-origin-before binding exception. Account removal and credential
   deletion retain their current signed-before binding rule.
2. Exact pending challenge reuse and exact claimed recovery may advance only the
   paired authority clock high-water. They change no lifecycle/event timestamp
   and append no event. A006 owns discriminating pending-reuse tests; A007 owns
   the claimed-recovery equivalent.
3. A lower `crates/kirje-credential` boundary was proposed to avoid a
   store/runtime dependency cycle. Repeat review found that its shared public
   constructor and pluggable deletion surface still allowed a runtime bypass.
   The focused A003 governance attempt supersedes that formulation.

## Additional Packet Hardening

- A006 parses canonical locator bytes in `CredentialCleanupReservation::new`
  and rederives exact kind/service/username/digest from realm plus signed
  historical-before origin before cleanup insertion. It changes no transition
  state-machine behavior.
- RED matrices cover malformed active-v2/legacy-v1 reservation and prepare,
  expired-pending replacement, concurrent exact issuance and restart, exact
  entropy/event cardinality, invalid-target rollback, and clock-only reuse.
- Deterministic non-real locator bytes are allowed only in Rust test source for
  byte goldens. Signature fixtures and evidence contain none; evidence records
  vector IDs, digests, counts, and results. Real/private locators remain
  prohibited in every committed file.
- Worker paths contain only production/test/fixture files. SSOT, packet, status,
  and evidence remain orchestrator-owned.

## Architecture Decision

On 2026-08-31 the orchestrator exercised the user's standing delegated
acceptance authority to approve the material `kirje-credential` workspace and
dependency direction. This does not claim the user personally reviewed the
artifact and does not claim implementation. A007 remains non-executable.

## Validation

- YAML parse: passed.
- 007 and 008 delivery artifact validators: passed.
- `git diff --check`: passed.

## Result

The revised A006 packet remains `ready_for_review` with production and test
permissions closed. Repeat independent review accepted the binding and
clock-only repairs but returned one High on the low-level capability boundary.
That finding is carried by A003; A007 and A008 remain non-executable outlines.
