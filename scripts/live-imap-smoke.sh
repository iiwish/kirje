#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <configured-account-id>" >&2
  exit 2
fi

account_id=$1
kirje_bin=${KIRJE_BIN:-./target/debug/kirje}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

"$kirje_bin" account check "$account_id" >"$work_dir/check.json"
"$kirje_bin" mailbox list --account "$account_id" >"$work_dir/mailboxes.json"
"$kirje_bin" message search \
  --account "$account_id" \
  --mailbox INBOX \
  --limit 1 >"$work_dir/search.json"
"$kirje_bin" --index "$work_dir/index.sqlite3" sync run \
  --account "$account_id" \
  --mailbox INBOX \
  --limit 10 >"$work_dir/sync.json"
"$kirje_bin" --index "$work_dir/index.sqlite3" message search-local \
  --account "$account_id" \
  --mailbox INBOX \
  --limit 1 >"$work_dir/local-search.json"

uid=$(jq -r '.data.messages[0].reference.uid // empty' "$work_dir/search.json")
uid_validity=$(jq -r '.data.messages[0].reference.uid_validity // empty' "$work_dir/search.json")

if [[ -n "$uid" ]]; then
  read_args=(
    message read
    --account "$account_id"
    --mailbox INBOX
    --uid "$uid"
    --max-body-chars 4096
  )
  if [[ -n "$uid_validity" ]]; then
    read_args+=(--uid-validity "$uid_validity")
  fi
  "$kirje_bin" "${read_args[@]}" >"$work_dir/read.json"
  jq -e '.ok == true and .data.untrusted == true' "$work_dir/read.json" >/dev/null
fi

jq -n \
  --arg account_id "$account_id" \
  --argjson mailboxes "$(jq '.data.returned' "$work_dir/mailboxes.json")" \
  --argjson messages "$(jq '.data.returned' "$work_dir/search.json")" \
  --argjson synced "$(jq '.data.stored' "$work_dir/sync.json")" \
  --argjson local_messages "$(jq '.data.returned' "$work_dir/local-search.json")" \
  '{ok: true, account_id: $account_id, mailboxes: $mailboxes, sampled_messages: $messages, synced: $synced, local_messages: $local_messages}'
