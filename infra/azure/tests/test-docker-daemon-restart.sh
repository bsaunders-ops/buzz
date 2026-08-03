#!/usr/bin/env bash
set -euo pipefail

dind_image=${DIND_TEST_IMAGE:?set DIND_TEST_IMAGE to a digest-pinned Docker-in-Docker image}
workload_image=${DIND_WORKLOAD_IMAGE:?set DIND_WORKLOAD_IMAGE to a digest-pinned workload image}
image_pattern='^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$'
for image in "$dind_image" "$workload_image"; do
  if [[ ! $image =~ $image_pattern ]]; then
    echo "Docker restart runtime images must be digest-pinned" >&2
    exit 2
  fi
done

name="buzz-dind-restart-${RANDOM}-$$"
cleanup() {
  docker rm --force "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --detach --privileged --name "$name" "$dind_image" --tls=false >/dev/null
for _ in $(seq 1 60); do
  docker exec "$name" docker info >/dev/null 2>&1 && break
  sleep 0.25
done
docker exec "$name" docker info >/dev/null
docker exec "$name" docker pull "$workload_image" >/dev/null
docker exec "$name" docker run --detach --restart no --name guarded "$workload_image" sleep 300 >/dev/null
docker restart "$name" >/dev/null
for _ in $(seq 1 60); do
  docker exec "$name" docker info >/dev/null 2>&1 && break
  sleep 0.25
done
docker exec "$name" docker info >/dev/null

state=$(docker exec "$name" docker inspect guarded --format '{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}')
if [[ $state != "false no" ]]; then
  echo "Docker revived a systemd-owned container after daemon restart: $state" >&2
  exit 1
fi

echo "Docker daemon restart policy runtime passed"
