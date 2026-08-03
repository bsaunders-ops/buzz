#!/usr/bin/env bash
set -euo pipefail

action=${1:-}
docker_bin=${DOCKER_BIN:-/usr/bin/docker}
compose=(
  "$docker_bin" compose
  --env-file /run/buzz/compose.env
  -f /opt/buzz/deploy/compose/compose.yml
  -f /opt/buzz/infra/azure/compose/compose.azure.yml
)

case "$action" in
  prepare)
    "${compose[@]}" up --detach --wait postgres redis minio
    "${compose[@]}" run --rm --no-deps minio-init >/dev/null
    "${compose[@]}" up --detach --no-deps --wait relay
    ;;
  supervise)
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
      postgres redis minio relay caddy
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
