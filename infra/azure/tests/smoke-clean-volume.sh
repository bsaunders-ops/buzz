#!/usr/bin/env bash
set -euo pipefail

if (($# != 1)); then
  echo "usage: $0 <locally-built-relay-image>" >&2
  exit 2
fi

relay_image=$1
image_pattern='^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$'
required_images=(
  SMOKE_POSTGRES_IMAGE
  SMOKE_REDIS_IMAGE
  SMOKE_MINIO_IMAGE
  SMOKE_MINIO_MC_IMAGE
  SMOKE_CADDY_IMAGE
)
for variable in "${required_images[@]}"; do
  image=${!variable:-}
  if [[ -z $image ]]; then
    echo "$variable is required" >&2
    exit 2
  fi
  if [[ ! $image =~ $image_pattern ]]; then
    echo "$variable must be digest-pinned" >&2
    exit 2
  fi
done

if ! docker image inspect "$relay_image" >/dev/null 2>&1; then
  echo "relay smoke image must already exist locally: $relay_image" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
base_compose=$repo_root/deploy/compose/compose.yml
azure_compose=$repo_root/infra/azure/compose/compose.azure.yml
project="core-buzz-blank-$RANDOM-$$"
smoke_root=$(mktemp -d /tmp/core-buzz-blank.XXXXXX)
override=$smoke_root/smoke.compose.yml
compose_env=$smoke_root/compose.env

compose() {
  docker compose \
    --project-name "$project" \
    --env-file "$compose_env" \
    -f "$base_compose" \
    -f "$azure_compose" \
    -f "$override" \
    "$@"
}

cleanup() {
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  case "$smoke_root" in
    /tmp/core-buzz-blank.*)
      # The database containers create files owned by their container UIDs.
      # Reclaim only this verified test root before removing it on the host.
      docker run --rm \
        --volume "$smoke_root:/cleanup" \
        --entrypoint chown \
        "$SMOKE_REDIS_IMAGE" \
        -R "$(id -u):$(id -g)" /cleanup >/dev/null 2>&1 || true
      rm -rf -- "$smoke_root"
      ;;
    *) echo "refusing to remove unexpected smoke path: $smoke_root" >&2 ;;
  esac
}
trap cleanup EXIT

install -d -m 0777 \
  "$smoke_root/git" \
  "$smoke_root/postgres" \
  "$smoke_root/redis" \
  "$smoke_root/minio"

cat >"$smoke_root/relay.env" <<'EOF'
DATABASE_URL=postgres://buzz:blank-postgres@postgres:5432/buzz
REDIS_URL=redis://:blank-redis@redis:6379
BUZZ_S3_ACCESS_KEY=blank-access
BUZZ_S3_SECRET_KEY=blank-secret
BUZZ_RELAY_PRIVATE_KEY=1111111111111111111111111111111111111111111111111111111111111111
BUZZ_GIT_HOOK_HMAC_SECRET=2222222222222222222222222222222222222222222222222222222222222222
EOF
printf 'POSTGRES_PASSWORD=blank-postgres\n' >"$smoke_root/postgres.env"
printf 'REDIS_PASSWORD=blank-redis\n' >"$smoke_root/redis.env"
printf 'MINIO_ROOT_USER=blank-access\nMINIO_ROOT_PASSWORD=blank-secret\n' >"$smoke_root/minio.env"
printf 'BUZZ_S3_ACCESS_KEY=blank-access\nBUZZ_S3_SECRET_KEY=blank-secret\n' >"$smoke_root/minio-init.env"
printf 'BUZZ_ORIGIN_SECRET=blank-origin-secret\n' >"$smoke_root/caddy.env"

cat >"$compose_env" <<EOF
BUZZ_RELAY_IMAGE=$relay_image
POSTGRES_IMAGE=$SMOKE_POSTGRES_IMAGE
REDIS_IMAGE=$SMOKE_REDIS_IMAGE
MINIO_IMAGE=$SMOKE_MINIO_IMAGE
MINIO_MC_IMAGE=$SMOKE_MINIO_MC_IMAGE
CADDY_IMAGE=$SMOKE_CADDY_IMAGE
POSTGRES_PASSWORD=blank-postgres
REDIS_PASSWORD=blank-redis
BUZZ_S3_ACCESS_KEY=blank-access
BUZZ_S3_SECRET_KEY=blank-secret
BUZZ_ORIGIN_FQDN=origin.blank.invalid
AZURE_FRONT_DOOR_ID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
BUZZ_PUBLIC_HOST=buzz.blank.invalid
RELAY_OWNER_PUBKEY=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
EOF

cat >"$override" <<EOF
services:
  relay:
    pull_policy: never
    env_file: !override
      - path: $smoke_root/relay.env
        required: true
    volumes: !override
      - $smoke_root/git:/data/git
  postgres:
    env_file: !override
      - path: $smoke_root/postgres.env
        required: true
    volumes: !override
      - $smoke_root/postgres:/var/lib/postgresql/data
  redis:
    env_file: !override
      - path: $smoke_root/redis.env
        required: true
    volumes: !override
      - $smoke_root/redis:/data
  minio:
    env_file: !override
      - path: $smoke_root/minio.env
        required: true
    volumes: !override
      - $smoke_root/minio:/data
  minio-init:
    env_file: !override
      - path: $smoke_root/minio-init.env
        required: true
  caddy:
    env_file: !override
      - path: $smoke_root/caddy.env
        required: true
EOF

compose config --quiet
compose up --detach --wait relay

events_table=$(compose exec -T postgres \
  psql -U buzz -d buzz -Atc "select to_regclass('public.events')::text")
if [[ $events_table != events ]]; then
  echo "blank database was not migrated: expected events table, got '$events_table'" >&2
  exit 1
fi

relay_environment=$(compose exec -T relay /usr/bin/env)
for expected in \
  'BUZZ_AUTO_MIGRATE=true' \
  'BUZZ_REQUIRE_RELAY_MEMBERSHIP=true' \
  'BUZZ_REQUIRE_AUTH_TOKEN=true' \
  'BUZZ_ALLOW_NIP_OA_AUTH=false' \
  'BUZZ_PUSH_GATEWAY_DELIVERY_URL=' \
  'BUZZ_WEB_DIR=' \
  'BUZZ_ADMIN_WEB_DIR=' \
  'BUZZ_GIT_ENABLED=false' \
  'BUZZ_SERVE_GIT_WEB_GUI=false' \
  'BUZZ_HUDDLE_AUDIO_AVAILABLE=false'; do
  if ! grep -Fxq "$expected" <<<"$relay_environment"; then
    echo "relay smoke environment is missing: $expected" >&2
    exit 1
  fi
done

echo "isolated blank-volume migration smoke passed for project $project"
