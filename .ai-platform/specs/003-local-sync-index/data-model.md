# Data Model: Local Sync Index

## `mailbox_sync_state`

- Identity: `account_id`, `mailbox`
- Cursor: `uid_validity`, nullable `highest_uid`
- Coverage: `indexed_messages`, `initial_window_complete`
- Observation: nullable `remote_total`, `last_synced_at`

One row represents the current UID namespace for one mailbox. A UIDVALIDITY
change replaces the namespace and its message rows transactionally.

## `messages`

- Identity: `account_id`, `mailbox`, `uid_validity`, `uid`
- Envelope: `message_id`, `in_reply_to_json`, `subject`, `from_json`, `to_json`,
  `sent_at`, `size`, `is_read`, `is_starred`, `has_attachment`, `truncated`
- Observation: `indexed_at`

Rows contain only bounded envelope metadata. Bodies, raw MIME, attachment
contents, credentials, and provider diagnostics are excluded.

## State Transitions

```text
absent -> initial sync -> current cursor
current cursor -> incremental sync -> advanced cursor
current cursor -> no new mail -> timestamp refreshed
current cursor -> UIDVALIDITY mismatch -> atomic scoped reset -> current cursor
current cursor -> explicit refresh -> atomic scoped reset -> current cursor
```

Unrecognized schema versions fail closed. Version 1 is created in a transaction.
