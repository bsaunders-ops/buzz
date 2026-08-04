#!/usr/bin/env bash
set -euo pipefail

action=${1:-}
docker_bin=${DOCKER_BIN:-/usr/bin/docker}
provision_worker_db_roles_bin=${PROVISION_WORKER_DB_ROLES_BIN:-/usr/local/sbin/buzz-core-provision-worker-db-roles}
compose=(
  "$docker_bin" compose
  --env-file /run/buzz/compose.env
  -f /opt/buzz/deploy/compose/compose.yml
  -f /opt/buzz/infra/azure/compose/compose.azure.yml
)

worker_services=(
  connector-egress-proxy
  model-egress-proxy
  audit-egress-proxy
  agent-supervisor
  connector-worker
  sanitizer-indexer
  signal-runner
  action-executor
  learning-worker
  audit-exporter
)

if [[ ${ENABLE_MONTH1_WORKERS:-false} == true ]]; then
  compose+=(--profile month1-workers)
fi

case "$action" in
  prepare)
    "${compose[@]}" up --detach --wait postgres redis minio
    "${compose[@]}" run --rm --no-deps minio-init >/dev/null
    "${compose[@]}" up --detach --no-deps --wait relay
    if [[ ${ENABLE_MONTH1_WORKERS:-false} == true ]]; then
      "$provision_worker_db_roles_bin"
      "${compose[@]}" up --detach --wait "${worker_services[@]}"
    fi
    ;;
  supervise)
    services=(postgres redis minio relay caddy)
    if [[ ${ENABLE_MONTH1_WORKERS:-false} == true ]]; then
      services+=("${worker_services[@]}")
    fi
    set +e
    "${compose[@]}" up \
      --no-color \
      --no-deps \
      --remove-orphans \
      --abort-on-container-exit \
      --no-attach postgres \
      --no-attach redis \
      --no-attach minio \
      --no-attach relay \
      --no-attach caddy \
      "${services[@]}"
    status=$?
    set -e
    if ((status == 0)); then
      echo "A long-running Core container exited cleanly; requesting bounded stack recovery." >&2
      exit 1
    fi
    exit "$status"
    ;;
  down)
    "${compose[@]}" down
    ;;
  *)
    echo "usage: $0 <prepare|supervise|down>" >&2
    exit 2
    ;;
esac
