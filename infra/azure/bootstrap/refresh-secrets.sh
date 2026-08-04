#!/usr/bin/env bash
set -euo pipefail

umask 077

# shellcheck disable=SC1091
. /etc/buzz/core.env

if [[ ${DOCKER_CONFIG:-} != /run/buzz/docker ]]; then
  echo "DOCKER_CONFIG must be the volatile /run/buzz/docker directory" >&2
  exit 1
fi
export DOCKER_CONFIG

install -d -o 0 -g 0 -m 0700 /run/buzz /run/buzz/secrets /run/buzz/docker
install -d -o 0 -g 1000 -m 0750 /run/buzz/caddy
work_dir=$(mktemp -d /run/buzz/secrets.refresh.XXXXXX)
azure_config_dir=$(mktemp -d /run/buzz/azure-cli.refresh.XXXXXX)
export AZURE_CONFIG_DIR=$azure_config_dir

cleanup_refresh() {
  if [[ $work_dir == /run/buzz/secrets.refresh.* ]]; then
    rm -rf -- "$work_dir"
  fi
  if [[ $azure_config_dir == /run/buzz/azure-cli.refresh.* ]]; then
    rm -rf -- "$azure_config_dir"
  fi
}
trap cleanup_refresh EXIT

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

openai_api_key=''
acp_signing_key=''
crm_connector_credential_b64=''
microsoft_connector_credential_b64=''
google_connector_credential_b64=''
audit_blob_credential_b64=''
connector_worker_db_password=''
sanitizer_indexer_db_password=''
signal_runner_db_password=''
action_executor_db_password=''
learning_worker_db_password=''
audit_exporter_db_password=''

if [[ ${ENABLE_MONTH1_WORKERS:-false} == true ]]; then
  openai_api_key=$(read_secret "$OPENAI_API_KEY_SECRET_NAME")
  acp_signing_key=$(read_secret "$ACP_SIGNING_KEY_SECRET_NAME")
  crm_connector_credential_b64=$(read_secret "$CRM_CONNECTOR_CREDENTIAL_B64_SECRET_NAME")
  microsoft_connector_credential_b64=$(read_secret "$MICROSOFT_CONNECTOR_CREDENTIAL_B64_SECRET_NAME")
  google_connector_credential_b64=$(read_secret "$GOOGLE_CONNECTOR_CREDENTIAL_B64_SECRET_NAME")
  audit_blob_credential_b64=$(read_secret "$AUDIT_BLOB_CREDENTIAL_B64_SECRET_NAME")
  connector_worker_db_password=$(read_secret "$CONNECTOR_WORKER_DB_PASSWORD_SECRET_NAME")
  sanitizer_indexer_db_password=$(read_secret "$SANITIZER_INDEXER_DB_PASSWORD_SECRET_NAME")
  signal_runner_db_password=$(read_secret "$SIGNAL_RUNNER_DB_PASSWORD_SECRET_NAME")
  action_executor_db_password=$(read_secret "$ACTION_EXECUTOR_DB_PASSWORD_SECRET_NAME")
  learning_worker_db_password=$(read_secret "$LEARNING_WORKER_DB_PASSWORD_SECRET_NAME")
  audit_exporter_db_password=$(read_secret "$AUDIT_EXPORTER_DB_PASSWORD_SECRET_NAME")
fi

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
for pair in \
  "$OPENAI_API_KEY_SECRET_NAME:$openai_api_key" \
  "$ACP_SIGNING_KEY_SECRET_NAME:$acp_signing_key" \
  "$CRM_CONNECTOR_CREDENTIAL_B64_SECRET_NAME:$crm_connector_credential_b64" \
  "$MICROSOFT_CONNECTOR_CREDENTIAL_B64_SECRET_NAME:$microsoft_connector_credential_b64" \
  "$GOOGLE_CONNECTOR_CREDENTIAL_B64_SECRET_NAME:$google_connector_credential_b64" \
  "$AUDIT_BLOB_CREDENTIAL_B64_SECRET_NAME:$audit_blob_credential_b64" \
  "$CONNECTOR_WORKER_DB_PASSWORD_SECRET_NAME:$connector_worker_db_password" \
  "$SANITIZER_INDEXER_DB_PASSWORD_SECRET_NAME:$sanitizer_indexer_db_password" \
  "$SIGNAL_RUNNER_DB_PASSWORD_SECRET_NAME:$signal_runner_db_password" \
  "$ACTION_EXECUTOR_DB_PASSWORD_SECRET_NAME:$action_executor_db_password" \
  "$LEARNING_WORKER_DB_PASSWORD_SECRET_NAME:$learning_worker_db_password" \
  "$AUDIT_EXPORTER_DB_PASSWORD_SECRET_NAME:$audit_exporter_db_password"; do
  if [[ -n ${pair#*:} ]]; then
    require_dotenv_safe "${pair%%:*}" "${pair#*:}"
  fi
done

database_password_uri=$(printf '%s' "$postgres_password" | python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""))')
redis_password_uri=$(printf '%s' "$redis_password" | python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""))')
connector_worker_db_password_uri=$(printf '%s' "$connector_worker_db_password" | python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""))')
sanitizer_indexer_db_password_uri=$(printf '%s' "$sanitizer_indexer_db_password" | python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""))')
signal_runner_db_password_uri=$(printf '%s' "$signal_runner_db_password" | python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""))')
action_executor_db_password_uri=$(printf '%s' "$action_executor_db_password" | python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""))')
learning_worker_db_password_uri=$(printf '%s' "$learning_worker_db_password" | python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""))')
audit_exporter_db_password_uri=$(printf '%s' "$audit_exporter_db_password" | python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""))')

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

write_optional_env() {
  local path=$1
  local key=$2
  local value=$3
  if [[ -n $value ]]; then
    printf '%s=%s\n' "$key" "$value" >>"$path"
  fi
}

printf 'BUZZ_RELAY_URL=wss://%s\n' "$BUZZ_PUBLIC_HOST" >"$work_dir/agent-supervisor.env"
write_optional_env "$work_dir/agent-supervisor.env" OPENAI_COMPAT_API_KEY "$openai_api_key"
write_optional_env "$work_dir/agent-supervisor.env" BUZZ_ACP_SIGNING_KEY "$acp_signing_key"

printf 'DATABASE_URL=postgres://buzz_connector_worker:%s@postgres:5432/buzz\n' \
  "$connector_worker_db_password_uri" >"$work_dir/connector-worker.env"
write_optional_env "$work_dir/connector-worker.env" CORE_CRM_CREDENTIAL_B64 "$crm_connector_credential_b64"
write_optional_env "$work_dir/connector-worker.env" MICROSOFT_CONNECTOR_CREDENTIAL_B64 "$microsoft_connector_credential_b64"
write_optional_env "$work_dir/connector-worker.env" GOOGLE_CONNECTOR_CREDENTIAL_B64 "$google_connector_credential_b64"

printf 'DATABASE_URL=postgres://buzz_sanitizer_indexer:%s@postgres:5432/buzz\n' \
  "$sanitizer_indexer_db_password_uri" >"$work_dir/sanitizer-indexer.env"

printf 'DATABASE_URL=postgres://buzz_signal_runner:%s@postgres:5432/buzz\n' \
  "$signal_runner_db_password_uri" >"$work_dir/signal-runner.env"

printf 'DATABASE_URL=postgres://buzz_action_executor:%s@postgres:5432/buzz\n' \
  "$action_executor_db_password_uri" >"$work_dir/action-executor.env"
write_optional_env "$work_dir/action-executor.env" CORE_CRM_CREDENTIAL_B64 "$crm_connector_credential_b64"
write_optional_env "$work_dir/action-executor.env" MICROSOFT_CONNECTOR_CREDENTIAL_B64 "$microsoft_connector_credential_b64"
write_optional_env "$work_dir/action-executor.env" GOOGLE_CONNECTOR_CREDENTIAL_B64 "$google_connector_credential_b64"
write_optional_env "$work_dir/action-executor.env" BUZZ_ACP_SIGNING_KEY "$acp_signing_key"

printf 'DATABASE_URL=postgres://buzz_learning_worker:%s@postgres:5432/buzz\n' \
  "$learning_worker_db_password_uri" >"$work_dir/learning-worker.env"

printf 'DATABASE_URL=postgres://buzz_audit_exporter:%s@postgres:5432/buzz\n' \
  "$audit_exporter_db_password_uri" >"$work_dir/audit-exporter.env"
write_optional_env "$work_dir/audit-exporter.env" AUDIT_BLOB_CREDENTIAL_B64 "$audit_blob_credential_b64"

cat >"$work_dir/worker-db-roles.env" <<EOF
CONNECTOR_WORKER_DB_PASSWORD=$connector_worker_db_password
SANITIZER_INDEXER_DB_PASSWORD=$sanitizer_indexer_db_password
SIGNAL_RUNNER_DB_PASSWORD=$signal_runner_db_password
ACTION_EXECUTOR_DB_PASSWORD=$action_executor_db_password
LEARNING_WORKER_DB_PASSWORD=$learning_worker_db_password
AUDIT_EXPORTER_DB_PASSWORD=$audit_exporter_db_password
EOF

cat >"$work_dir/squid-audit.conf" <<EOF
visible_hostname core-buzz-audit-egress
http_port 3128
access_log none
cache_log /dev/null
cache_store_log none
cache deny all
acl SSL_ports port 443
acl CONNECT method CONNECT
acl approved_audit_host dstdomain ${AUDIT_STORAGE_ACCOUNT_NAME}.blob.core.windows.net
http_access deny !CONNECT
http_access deny !SSL_ports
http_access allow approved_audit_host
http_access deny all
EOF

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
for worker_env in agent-supervisor connector-worker sanitizer-indexer signal-runner action-executor learning-worker audit-exporter; do
  install -m 0400 "$work_dir/$worker_env.env" "/run/buzz/secrets/$worker_env.env"
done
install -m 0400 "$work_dir/worker-db-roles.env" /run/buzz/secrets/worker-db-roles.env
install -m 0444 "$work_dir/squid-audit.conf" /run/buzz/squid-audit.conf
install -m 0400 "$work_dir/compose.env" /run/buzz/compose.env

read_secret "$ORIGIN_TLS_CERT_SECRET_NAME" >"$work_dir/origin.crt"
read_secret "$ORIGIN_TLS_KEY_SECRET_NAME" >"$work_dir/origin.key"
install -o 1000 -g 1000 -m 0400 "$work_dir/origin.crt" /run/buzz/caddy/origin.crt
install -o 1000 -g 1000 -m 0400 "$work_dir/origin.key" /run/buzz/caddy/origin.key
