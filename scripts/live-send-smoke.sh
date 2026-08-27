#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <configured-dedicated-test-account-id>" >&2
  exit 2
fi

if [[ ! -t 0 || ! -t 2 ]]; then
  echo "live send approval requires an interactive human terminal" >&2
  exit 2
fi

account_id=$1
kirje_bin=${KIRJE_BIN:-./target/debug/kirje}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

"$kirje_bin" account status "$account_id" >"$work_dir/account.json"
email=$(jq -r '.data.account.email // empty' "$work_dir/account.json")
secret_present=$(jq -r '.data.secret_present // false' "$work_dir/account.json")
if [[ -z "$email" || "$secret_present" != true ]]; then
  echo "dedicated account and OS-stored credential are required" >&2
  exit 1
fi

subject="Kirje governed send smoke $(date -u +%Y%m%dT%H%M%SZ)"
jq -n \
  --arg account_id "$account_id" \
  --arg email "$email" \
  --arg subject "$subject" \
  '{account_id: $account_id, to: [{name: null, email: $email}], cc: [], bcc: [], subject: $subject, text: "Automated Kirje governed-send conformance message for this dedicated mailbox.", html: null}' \
  >"$work_dir/request.json"

"$kirje_bin" --outbox "$work_dir/outbox.sqlite3" send plan \
  --input "$work_dir/request.json" >"$work_dir/plan.json"
plan_id=$(jq -r '.data.id' "$work_dir/plan.json")

"$kirje_bin" --outbox "$work_dir/outbox.sqlite3" send approve "$plan_id" \
  >"$work_dir/approved.json"
"$kirje_bin" --outbox "$work_dir/outbox.sqlite3" send apply "$plan_id" \
  >"$work_dir/applied.json"

state=$(jq -r '.data.status' "$work_dir/applied.json")
accepted=$(jq -r '.data.receipt.accepted // false' "$work_dir/applied.json")
if [[ "$state" != sent || "$accepted" != true ]]; then
  jq -n --arg account_id "$account_id" --arg state "$state" \
    --argjson accepted "$accepted" \
    '{ok: false, account_id: $account_id, delivery_state: $state, smtp_accepted: $accepted}'
  exit 1
fi

matches=0
for _ in 1 2 3 4 5; do
  "$kirje_bin" message search --account "$account_id" --mailbox INBOX \
    --subject "$subject" --limit 1 >"$work_dir/search.json"
  matches=$(jq '.data.returned' "$work_dir/search.json")
  [[ "$matches" -gt 0 ]] && break
  sleep 3
done

jq -n --arg account_id "$account_id" --arg state "$state" \
  --argjson accepted "$accepted" --argjson matches "$matches" \
  '{ok: ($state == "sent" and $accepted), account_id: $account_id, delivery_state: $state, smtp_accepted: $accepted, inbox_visible: ($matches > 0), inbox_matches: $matches}'
