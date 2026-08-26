# T007 Evidence

- Result: complete
- Scope: runtime sync cursor, refresh, status, and local search services
- RED: runtime compilation failed after the required sync port was added and the
  concrete protocol adapter did not yet implement it.
- GREEN: runtime tests prove repeated sync passes the persisted high-water UID,
  refresh supplies no cursor and replaces the mailbox window, and local search
  succeeds without a credential.
- Review: account configuration is checked for local operations, but the keyring
  and network are not consulted by index status or search.
- Residual risk: account deletion and orphaned-index cleanup are not yet product
  operations.
