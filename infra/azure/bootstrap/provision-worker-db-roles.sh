#!/usr/bin/env bash
set -euo pipefail

# Login roles are host-provisioned because their passwords live in Key Vault;
# migrations create only fixed NOLOGIN privilege groups.

# shellcheck disable=SC1091
. /etc/buzz/core.env

if [[ ${ENABLE_MONTH1_WORKERS:-false} != true ]]; then
  exit 0
fi

# shellcheck disable=SC1091
. /run/buzz/secrets/worker-db-roles.env
# shellcheck disable=SC1091
. /run/buzz/secrets/postgres.env

docker_bin=${DOCKER_BIN:-/usr/bin/docker}
compose=(
  "$docker_bin" compose
  --env-file /run/buzz/compose.env
  -f /opt/buzz/deploy/compose/compose.yml
  -f /opt/buzz/infra/azure/compose/compose.azure.yml
)

roles=(
  buzz_connector_worker:core_connector_worker:CONNECTOR_WORKER_DB_PASSWORD
  buzz_sanitizer_indexer:core_sanitizer_indexer:SANITIZER_INDEXER_DB_PASSWORD
  buzz_signal_runner:core_signal_runner:SIGNAL_RUNNER_DB_PASSWORD
  buzz_action_executor:core_action_executor:ACTION_EXECUTOR_DB_PASSWORD
  buzz_learning_worker:core_learning_worker:LEARNING_WORKER_DB_PASSWORD
  buzz_audit_exporter:core_audit_exporter:AUDIT_EXPORTER_DB_PASSWORD
)

sql_file=$(mktemp /run/buzz/provision-worker-roles.XXXXXX.sql)
trap 'rm -f -- "$sql_file"' EXIT
chmod 0600 "$sql_file"

for binding in "${roles[@]}"; do
  login_role=${binding%%:*}
  remainder=${binding#*:}
  group_role=${remainder%%:*}
  password_name=${remainder#*:}
  password=${!password_name:-}
  if [[ -z $password || ! $password =~ ^[A-Za-z0-9._~+/=-]+$ ]]; then
    echo "worker database password $password_name is missing or unsafe" >&2
    exit 1
  fi
  cat >>"$sql_file" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$login_role') THEN
    CREATE ROLE $login_role LOGIN;
  END IF;
END
\$\$;
ALTER ROLE $login_role WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$password';
ALTER ROLE $login_role SET search_path = public;
GRANT $group_role TO $login_role;
SQL
done

"${compose[@]}" exec -T \
  -e PGPASSWORD="$POSTGRES_PASSWORD" \
  postgres psql --no-psqlrc --set ON_ERROR_STOP=1 --username buzz --dbname buzz \
  <"$sql_file" >/dev/null
