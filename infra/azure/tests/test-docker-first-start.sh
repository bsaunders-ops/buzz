#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
activation=$repo_root/infra/azure/bootstrap/docker-activation.sh
firewall=$repo_root/infra/azure/bootstrap/container-firewall.sh
[[ -x $activation ]] || {
  echo "missing executable Docker activation guard: $activation" >&2
  exit 1
}
dind_image=${DIND_TEST_IMAGE:?set DIND_TEST_IMAGE to a digest-pinned Docker-in-Docker image}
workload_image=${DIND_WORKLOAD_IMAGE:?set DIND_WORKLOAD_IMAGE to a digest-pinned workload image}
image_pattern='^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$'
for image in "$dind_image" "$workload_image"; do
  if [[ ! $image =~ $image_pattern ]]; then
    echo "Docker first-start runtime images must be digest-pinned" >&2
    exit 2
  fi
done

if ((EUID != 0)); then
  exec sudo -n --preserve-env=DIND_TEST_IMAGE,DIND_WORKLOAD_IMAGE bash "$0"
fi

run_root=$(mktemp -d /run/buzz-docker-first-start.XXXXXX)
suffix="${RANDOM}-$$"
dind_name="buzz-dind-first-${suffix}"
docker_unit="buzz-first-docker-${suffix}.service"
events=$run_root/events
iptables_fake=$run_root/iptables
firewall_wrapper=$run_root/firewall
docker_wrapper=$run_root/docker
daemon_wrapper=$run_root/start-daemon

cleanup() {
  systemctl stop "$docker_unit" >/dev/null 2>&1 || true
  systemctl unmask "$docker_unit" >/dev/null 2>&1 || true
  rm -f -- "/run/systemd/system/$docker_unit"
  systemctl daemon-reload >/dev/null 2>&1 || true
  docker rm --force "$dind_name" >/dev/null 2>&1 || true
  case "$run_root" in
    /run/buzz-docker-first-start.*) rm -rf -- "$run_root" ;;
    *) echo "refusing to remove unexpected runtime-test root: $run_root" >&2 ;;
  esac
}
trap cleanup EXIT

docker create --privileged --name "$dind_name" "$dind_image" --tls=false >/dev/null
docker start "$dind_name" >/dev/null
for _ in $(seq 1 60); do
  docker exec "$dind_name" docker info >/dev/null 2>&1 && break
  sleep 0.25
done
docker exec "$dind_name" docker info >/dev/null
docker exec "$dind_name" docker pull "$workload_image" >/dev/null
docker exec "$dind_name" docker run --detach --restart always --name legacy "$workload_image" sleep 300 >/dev/null
docker stop "$dind_name" >/dev/null

cat >"$iptables_fake" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ! -e ${FIRST_START_FIREWALL_MARKER:?} ]]; then
  printf '%s\n' firewall >>"${FIRST_START_EVENTS:?}"
  : >"$FIRST_START_FIREWALL_MARKER"
fi
args=("$@")
if [[ ${args[0]:-} == -w ]]; then args=("${args[@]:1}"); fi
[[ ${args[0]:-} == -C ]] && exit 1
exit 0
EOF
cat >"$firewall_wrapper" <<EOF
#!/usr/bin/env bash
export IPTABLES_BIN='$iptables_fake'
export FIRST_START_EVENTS='$events'
export FIRST_START_FIREWALL_MARKER='$run_root/firewall-applied'
exec '$firewall' "\$@"
EOF
cat >"$docker_wrapper" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ \${1:-} == info ]]; then
  for _ in \$(seq 1 80); do
    docker exec '$dind_name' docker info >/dev/null 2>&1 && exit 0
    sleep 0.25
  done
  exit 1
fi
exec docker "\$@"
EOF
cat >"$daemon_wrapper" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' daemon-start >>'$events'
exec docker start --attach '$dind_name'
EOF
chmod 0755 "$iptables_fake" "$firewall_wrapper" "$docker_wrapper" "$daemon_wrapper"

cat >"/run/systemd/system/$docker_unit" <<EOF
[Unit]
Description=Buzz first Docker activation runtime test
[Service]
Type=simple
ExecStartPre=$firewall_wrapper --baseline
ExecStart=$daemon_wrapper
ExecStop=/usr/bin/docker stop $dind_name
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

env \
  DOCKER_SERVICE="$docker_unit" \
  DOCKER_SOCKET= \
  SYSTEMCTL_BIN=systemctl \
  FIREWALL_BIN="$firewall_wrapper" \
  DOCKER_BIN="$docker_wrapper" \
  bash "$activation" prepare

if systemctl start "$docker_unit" >/dev/null 2>&1; then
  echo "masked Docker test unit started during the package-install window" >&2
  exit 1
fi
[[ $(docker inspect "$dind_name" --format '{{.State.Running}}') == false ]]

env \
  DOCKER_SERVICE="$docker_unit" \
  DOCKER_SOCKET= \
  SYSTEMCTL_BIN=systemctl \
  FIREWALL_BIN="$firewall_wrapper" \
  DOCKER_BIN="$docker_wrapper" \
  bash "$activation" start

state=$(docker exec "$dind_name" docker inspect legacy --format '{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}')
[[ $state == "true always" ]]
printf '%s\n' legacy-active >>"$events"
mapfile -t observed <"$events"
expected=(firewall daemon-start legacy-active)
[[ ${observed[*]} == "${expected[*]}" ]]

echo "Docker first-start legacy restart ordering passed"
