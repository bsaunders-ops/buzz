#!/usr/bin/env bash
set -euo pipefail

umask 077

# shellcheck disable=SC1091
. /etc/buzz/core.env

install -d -m 0700 /run/buzz/secrets /run/buzz/caddy
work_dir=$(mktemp -d /run/buzz/secrets.refresh.XXXXXX)
trap 'rm -rf "$work_dir"' EXIT

az login --identity --allow-no-subscriptions --output none >/dev/null
az acr login --name "$ACR_NAME" --output none >/dev/null

read_secret() {
  az keyvault secret show \
    --vault-name "$KEY_VAULT_NAME" \
    --name "$1" \
    --query value \
    --output tsv
}

require_single_line() {
  local name=$1
  local value=$2
  if [[ -z $value || $value == *$'\n'* || $value == *$'\r'* ]]; then
    echo "Key Vault secret $name must be a non-empty single line" >&2
    exit 1
  fi
}

require_dotenv_safe() {
  local name=$1
  local value=$2
  require_single_line "$name" "$value"
  if [[ ! $value =~ ^[A-Za-z0-9._~+/=-]+$ ]]; then
    echo "Key Vault secret $name contains characters unsafe for a Compose env file" >&2
    exit 1
  fi
}

postgres_password=$(read_secret "$POSTGRES_PASSWORD_SECRET_NAME")
redis_password=$(read_secret "$REDIS_PASSWORD_SECRET_NAME")
minio_access_key=$(read_secret "$MINIO_ACCESS_KEY_SECRET_NAME")
minio_secret_key=$(read_secret "$MINIO_SECRET_KEY_SECRET_NAME")
relay_private_key=$(read_secret "$RELAY_PRIVATE_KEY_SECRET_NAME")
git_hook_secret=$(read_secret "$GIT_HOOK_SECRET_NAME")
origin_secret=$(read_secret "$ORIGIN_SECRET_NAME")

for pair in \
  "$POSTGRES_PASSWORD_SECRET_NAME:$postgres_password" \
  "$REDIS_PASSWORD_SECRET_NAME:$redis_password" \
  "$MINIO_ACCESS_KEY_SECRET_NAME:$minio_access_key" \
  "$MINIO_SECRET_KEY_SECRET_NAME:$minio_secret_key" \
  "$RELAY_PRIVATE_KEY_SECRET_NAME:$relay_private_key" \
  "$GIT_HOOK_SECRET_NAME:$git_hook_secret" \
  "$ORIGIN_SECRET_NAME:$origin_secret"; do
  require_dotenv_safe "${pair%%:*}" "${pair#*:}"
done

database_password_uri=$(printf '%s' "$postgres_password" | python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""))')
redis_password_uri=$(printf '%s' "$redis_password" | python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""))')

cat >"$work_dir/relay.env" <<EOF
DATABASE_URL=postgres://buzz:${database_password_uri}@postgres:5432/buzz
REDIS_URL=redis://:${redis_password_uri}@redis:6379
BUZZ_S3_ACCESS_KEY=$minio_access_key
BUZZ_S3_SECRET_KEY=$minio_secret_key
BUZZ_RELAY_PRIVATE_KEY=$relay_private_key
BUZZ_GIT_HOOK_HMAC_SECRET=$git_hook_secret
EOF
printf 'POSTGRES_PASSWORD=%s\n' "$postgres_password" >"$work_dir/postgres.env"
printf 'REDIS_PASSWORD=%s\n' "$redis_password" >"$work_dir/redis.env"
printf 'MINIO_ROOT_USER=%s\nMINIO_ROOT_PASSWORD=%s\n' "$minio_access_key" "$minio_secret_key" >"$work_dir/minio.env"
printf 'BUZZ_S3_ACCESS_KEY=%s\nBUZZ_S3_SECRET_KEY=%s\n' "$minio_access_key" "$minio_secret_key" >"$work_dir/minio-init.env"
printf 'BUZZ_ORIGIN_SECRET=%s\n' "$origin_secret" >"$work_dir/caddy.env"

cat /etc/buzz/core.env >"$work_dir/compose.env"
cat >>"$work_dir/compose.env" <<EOF
POSTGRES_PASSWORD=$postgres_password
REDIS_PASSWORD=$redis_password
BUZZ_S3_ACCESS_KEY=$minio_access_key
BUZZ_S3_SECRET_KEY=$minio_secret_key
EOF

install -m 0400 "$work_dir/relay.env" /run/buzz/secrets/relay.env
install -m 0400 "$work_dir/postgres.env" /run/buzz/secrets/postgres.env
install -m 0400 "$work_dir/redis.env" /run/buzz/secrets/redis.env
install -m 0400 "$work_dir/minio.env" /run/buzz/secrets/minio.env
install -m 0400 "$work_dir/minio-init.env" /run/buzz/secrets/minio-init.env
install -m 0400 "$work_dir/caddy.env" /run/buzz/secrets/caddy.env
install -m 0400 "$work_dir/compose.env" /run/buzz/compose.env

read_secret "$ORIGIN_TLS_CERT_SECRET_NAME" >"$work_dir/origin.crt"
read_secret "$ORIGIN_TLS_KEY_SECRET_NAME" >"$work_dir/origin.key"
install -o 1000 -g 1000 -m 0400 "$work_dir/origin.crt" /run/buzz/caddy/origin.crt
install -o 1000 -g 1000 -m 0400 "$work_dir/origin.key" /run/buzz/caddy/origin.key
