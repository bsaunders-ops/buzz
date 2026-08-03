#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
run_id="${RANDOM}-$$"
network="core-buzz-caddy-policy-${run_id}"
upstream="core-buzz-caddy-upstream-${run_id}"
proxy="core-buzz-caddy-proxy-${run_id}"
data_volume="core-buzz-caddy-data-${run_id}"
config_volume="core-buzz-caddy-config-${run_id}"
test_root=$(mktemp -d /tmp/core-buzz-caddy.XXXXXX)
fdid=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
origin_secret=origin-secret-for-policy-test
caddy_image=${CADDY_TEST_IMAGE:?set CADDY_TEST_IMAGE to a digest-pinned Caddy test image}
openssl_image=${OPENSSL_TEST_IMAGE:?set OPENSSL_TEST_IMAGE to a digest-pinned OpenSSL test image}
image_pattern='^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$'
for image in "$caddy_image" "$openssl_image"; do
  if [[ ! $image =~ $image_pattern ]]; then
    echo "Caddy runtime test images must be pinned by sha256 digest" >&2
    exit 2
  fi
done

cleanup() {
  docker rm --force "$proxy" "$upstream" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$data_volume" "$config_volume" >/dev/null 2>&1 || true
  case "$test_root" in
    /tmp/core-buzz-caddy.*) rm -rf -- "$test_root" ;;
    *) echo "refusing to remove unexpected Caddy test path: $test_root" >&2 ;;
  esac
}
trap cleanup EXIT

docker network create "$network" >/dev/null
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --volume "$test_root:/out" \
  "$openssl_image" \
  req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
  -keyout /out/origin.key \
  -out /out/origin.crt \
  -subj /CN=proxy \
  -addext subjectAltName=DNS:proxy >/dev/null 2>&1
chmod 0444 "$test_root/origin.crt" "$test_root/origin.key"

docker run --detach \
  --name "$upstream" \
  --network "$network" \
  --network-alias relay \
  "$caddy_image" \
  caddy respond --listen :3000 --status 200 --body ok >/dev/null

docker run --detach \
  --name "$proxy" \
  --network "$network" \
  --network-alias proxy \
  --publish 127.0.0.1::8443 \
  --user 1000:1000 \
  --read-only \
  --volume "$data_volume:/data" \
  --volume "$config_volume:/config" \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m,uid=1000,gid=1000,mode=0700 \
  --env "AZURE_FRONT_DOOR_ID=$fdid" \
  --env "BUZZ_ORIGIN_SECRET=$origin_secret" \
  --volume "$repo_root/infra/azure/compose/Caddyfile.azure:/etc/caddy/Caddyfile:ro" \
  --volume "$test_root/origin.crt:/run/buzz/caddy/origin.crt:ro" \
  --volume "$test_root/origin.key:/run/buzz/caddy/origin.key:ro" \
  "$caddy_image" >/dev/null

published_endpoint=$(docker port "$proxy" 8443/tcp | head -n1)
if [[ ! $published_endpoint =~ ^127\.0\.0\.1:[0-9]+$ ]]; then
  echo "Caddy did not publish TLS ingress on the host loopback" >&2
  exit 1
fi

request_status() {
  local method=$1
  local path=$2
  shift 2
  local -a request=(
    curl
    --insecure
    --silent
    --show-error
    --output /dev/null
    --write-out '%{http_code}'
    --connect-timeout 5
    --max-time 5
  )
  if [[ $method == HEAD ]]; then
    request+=(--head)
  else
    request+=(--request "$method")
  fi
  local header
  for header in "$@"; do
    request+=(--header "$header")
  done
  request+=("https://$published_endpoint$path")
  "${request[@]}" || true
}

assert_status() {
  local expected=$1
  local description=$2
  local method=$3
  local path=$4
  shift 4

  local actual=
  actual=$(request_status "$method" "$path" "$@")
  if [[ $actual != "$expected" ]]; then
    echo "$description: expected HTTP $expected, got '${actual:-no response}'" >&2
    docker logs "$proxy" >&2 || true
    exit 1
  fi
}

for _ in $(seq 1 30); do
  if [[ $(request_status GET / "X-Azure-FDID: $fdid") == 403 ]]; then
    break
  fi
  sleep 0.2
done

assert_status 403 "wrong Front Door ID" GET / \
  "X-Azure-FDID: wrong-front-door" \
  "X-Buzz-Origin-Secret: $origin_secret"
assert_status 403 "missing origin secret" GET / \
  "X-Azure-FDID: $fdid"
assert_status 200 "valid Front Door request" GET / \
  "X-Azure-FDID: $fdid" \
  "X-Buzz-Origin-Secret: $origin_secret"
assert_status 403 "health path without marker" GET /origin-healthz \
  "X-Azure-FDID: $fdid"
assert_status 403 "POST cannot use health exception" POST /origin-healthz \
  "X-FD-HealthProbe: 1"
assert_status 200 "GET health probe needs no route headers" GET /origin-healthz \
  "X-FD-HealthProbe: 1"
assert_status 200 "HEAD health probe needs no route headers" HEAD /origin-healthz \
  "X-FD-HealthProbe: 1"

echo "Caddy origin-policy runtime matrix passed"
