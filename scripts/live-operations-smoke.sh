#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <configured-dedicated-test-account-id>" >&2
  exit 2
fi

if [[ "${KIRJE_ALLOW_REMOTE_MUTATION:-}" != "1" ]]; then
  echo "set KIRJE_ALLOW_REMOTE_MUTATION=1 for the explicit live mutation check" >&2
  exit 2
fi

if [[ ! -t 0 || ! -t 2 ]]; then
  echo "live operation approval requires an interactive human terminal" >&2
  exit 2
fi

account_id=$1
mailbox=${KIRJE_LIVE_MAILBOX:-}
uid=${KIRJE_LIVE_UID:-}
uid_validity=${KIRJE_LIVE_UID_VALIDITY:-}
kirje_bin=${KIRJE_BIN:-./target/debug/kirje}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

if [[ -z "$mailbox" || -z "$uid" || -z "$uid_validity" ]]; then
  echo "KIRJE_LIVE_MAILBOX, KIRJE_LIVE_UID, and KIRJE_LIVE_UID_VALIDITY are required" >&2
  exit 2
fi

"$kirje_bin" account status "$account_id" >"$work_dir/account.json"
secret_present=$(jq -r '.data.secret_present // false' "$work_dir/account.json")
if [[ "$secret_present" != true ]]; then
  echo "dedicated account and OS-stored credential are required" >&2
  exit 1
fi

jq -n \
  --arg account_id "$account_id" \
  --arg mailbox "$mailbox" \
  --argjson uid "$uid" \
  --argjson uid_validity "$uid_validity" \
  '{account_id: $account_id, kind: "set_starred", reference: {account_id: $account_id, mailbox: $mailbox, uid: $uid, uid_validity: $uid_validity}, value: true}' \
  >"$work_dir/star.json"

"$kirje_bin" --outbox "$work_dir/outbox.sqlite3" operation plan \
  --input "$work_dir/star.json" >"$work_dir/plan.json"
operation_id=$(jq -r '.data.id' "$work_dir/plan.json")
"$kirje_bin" --outbox "$work_dir/outbox.sqlite3" operation approve "$operation_id" \
  >"$work_dir/approved.json"
"$kirje_bin" --outbox "$work_dir/outbox.sqlite3" operation apply "$operation_id" \
  >"$work_dir/applied.json"

state=$(jq -r '.data.status' "$work_dir/applied.json")
if [[ "$state" != succeeded ]]; then
  jq -n --arg account_id "$account_id" --arg state "$state" \
    '{ok: false, account_id: $account_id, operation_state: $state}'
  exit 1
fi

jq '.value = false' "$work_dir/star.json" >"$work_dir/unstar.json"
"$kirje_bin" --outbox "$work_dir/outbox.sqlite3" operation plan \
  --input "$work_dir/unstar.json" >"$work_dir/unstar-plan.json"
operation_id=$(jq -r '.data.id' "$work_dir/unstar-plan.json")
"$kirje_bin" --outbox "$work_dir/outbox.sqlite3" operation approve "$operation_id" \
  >"$work_dir/unstar-approved.json"
"$kirje_bin" --outbox "$work_dir/outbox.sqlite3" operation apply "$operation_id" \
  >"$work_dir/unstar-applied.json"

restore_state=$(jq -r '.data.status' "$work_dir/unstar-applied.json")
jq -n \
  --arg account_id "$account_id" \
  --arg state "$state" \
  --arg restore_state "$restore_state" \
  '{ok: ($state == "succeeded" and $restore_state == "succeeded"), account_id: $account_id, operation_state: $state, restore_state: $restore_state}'
