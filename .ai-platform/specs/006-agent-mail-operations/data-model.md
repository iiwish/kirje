# Data Model: Agent Mail Operations

## Core Records

- `Draft`: local id, account id, mode, optional source reference, recipients,
  subject, text/HTML bodies, imported attachments, timestamps, and state.
- `AttachmentInput`: filename, MIME type, bounded bytes, byte size, SHA-256,
  and deterministic summary. A source path is an import instruction only and
  is not persisted as the delivery authority.
- `RemoteOperation`: operation id, kind, account id, source reference,
  destination, exact payload JSON, payload SHA-256, state, expiry, approval
  timestamp, claim timestamp, attempt count, bounded error, and receipt.
- `OperationEvent`: monotonic local event id, operation id, state/event name,
  timestamp, payload digest, and bounded non-secret detail.

## Operation Kinds

`send`, `set_read`, `set_starred`, `move`, `archive`, and `delete` are remote
operation kinds. `draft` is local-only and does not enter the approval state
machine.

## Scope Binding

Every IMAP operation binds account id, source mailbox, UIDVALIDITY when known,
UID, and destination mailbox when applicable. The adapter rechecks the selected
mailbox UIDVALIDITY immediately before issuing a mutation.

## Bounds

- At most 50 recipients and 25 imported attachments per send.
- At most 1 MiB per attachment and 8 MiB total attachment bytes.
- At most 256 KiB per plain/HTML body, 12 MiB serialized draft/send input, and
  600 KiB serialized mailbox-operation input.
- At most 4 KiB per mailbox name, 1 KiB per search/filter value, and 4 KiB per
  summary preview.
- Audit details and provider responses are bounded and control-character safe.
