#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
python3 "$repo_root/infra/azure/tests/test_contracts.py"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "Docker is required for the Caddy origin-policy runtime gate" >&2
  exit 1
fi

: "${CADDY_TEST_IMAGE:?set CADDY_TEST_IMAGE to a digest-pinned test image}"
: "${OPENSSL_TEST_IMAGE:?set OPENSSL_TEST_IMAGE to a digest-pinned test image}"
: "${FIREWALL_TEST_IMAGE:?set FIREWALL_TEST_IMAGE to a digest-pinned test image}"
: "${DIND_TEST_IMAGE:?set DIND_TEST_IMAGE to a digest-pinned test image}"
: "${DIND_WORKLOAD_IMAGE:?set DIND_WORKLOAD_IMAGE to a digest-pinned test image}"
bash "$repo_root/infra/azure/tests/test-caddy-origin-policy.sh"
bash "$repo_root/infra/azure/tests/test-container-firewall-runtime.sh"
bash "$repo_root/infra/azure/tests/test-docker-first-start.sh"
bash "$repo_root/infra/azure/tests/test-docker-daemon-restart.sh"
bash "$repo_root/infra/azure/tests/test-systemd-boot-order.sh"
