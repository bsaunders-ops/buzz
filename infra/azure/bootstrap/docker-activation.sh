#!/usr/bin/env bash
set -euo pipefail

systemctl_bin=${SYSTEMCTL_BIN:-systemctl}
firewall_bin=${FIREWALL_BIN:-/usr/local/sbin/buzz-core-container-firewall}
docker_bin=${DOCKER_BIN:-docker}
docker_service=${DOCKER_SERVICE:-docker.service}
docker_socket=${DOCKER_SOCKET-docker.socket}
docker_units=("$docker_service")
if [[ -n $docker_socket ]]; then
  docker_units+=("$docker_socket")
fi

case ${1:-} in
  prepare)
    # Fail closed across package installation. Package maintainer scripts cannot
    # activate Docker or its socket while either unit remains masked.
    "$systemctl_bin" mask --now "${docker_units[@]}"
    ;;
  start)
    # The host-level baseline exists before dockerd can restore any retained
    # restart-policy containers. The unit drop-in repeats it in ExecStartPre.
    "$systemctl_bin" daemon-reload
    "$firewall_bin" --baseline
    "$systemctl_bin" unmask "${docker_units[@]}"
    "$systemctl_bin" enable "$docker_service"
    "$systemctl_bin" start "$docker_service"
    "$docker_bin" info >/dev/null
    ;;
  *)
    echo "usage: $0 prepare|start" >&2
    exit 2
    ;;
esac
