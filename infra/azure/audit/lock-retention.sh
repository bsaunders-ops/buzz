#!/usr/bin/env bash
set -euo pipefail

confirm_lock=false
resource_group=
account_name=
container_name=signed-audit
rehearsal_evidence=

while (($#)); do
  case "$1" in
    --resource-group) resource_group=$2; shift 2 ;;
    --account-name) account_name=$2; shift 2 ;;
    --container-name) container_name=$2; shift 2 ;;
    --rehearsal-evidence) rehearsal_evidence=$2; shift 2 ;;
    --confirm-lock) confirm_lock=true; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ ! $resource_group =~ ^[-A-Za-z0-9._()]{1,90}$ ]]; then
  echo "a valid --resource-group is required" >&2
  exit 2
fi
if [[ ! $account_name =~ ^[a-z0-9]{3,24}$ ]]; then
  echo "a valid --account-name is required" >&2
  exit 2
fi
if [[ ! $container_name =~ ^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])$ ]]; then
  echo "a valid --container-name is required" >&2
  exit 2
fi

if [[ $confirm_lock != true ]]; then
  printf 'NO MUTATION: would lock the 2,555-day policy on %s/%s after rehearsal approval.\n' \
    "$account_name" "$container_name"
  exit 0
fi

if [[ -z $rehearsal_evidence || ! -s $rehearsal_evidence ]]; then
  echo "--confirm-lock requires a non-empty --rehearsal-evidence file" >&2
  exit 2
fi

policy=$(az storage container immutability-policy show \
  --resource-group "$resource_group" \
  --account-name "$account_name" \
  --container-name "$container_name" \
  --output json)

state=$(jq -r '.state' <<<"$policy")
period=$(jq -r '.immutabilityPeriodSinceCreationInDays' <<<"$policy")
etag=$(jq -r '.etag' <<<"$policy")
if [[ $state != Unlocked || $period != 2555 || -z $etag || $etag == null ]]; then
  echo "policy must be Unlocked at exactly 2,555 days with an ETag" >&2
  exit 1
fi

az storage container immutability-policy lock \
  --resource-group "$resource_group" \
  --account-name "$account_name" \
  --container-name "$container_name" \
  --if-match "$etag" \
  --output none
