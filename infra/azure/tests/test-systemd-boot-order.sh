#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
unit=$repo_root/infra/azure/bootstrap/buzz-core.service

grep -Fxq 'PartOf=docker.service' "$unit"
grep -Eq '^After=.*docker\.service' "$unit"
grep -Fxq 'ExecStartPre=/usr/local/sbin/buzz-core-container-firewall' "$unit"
grep -Fxq 'ExecStart=/usr/local/sbin/buzz-core-compose-supervisor supervise' "$unit"

if ((EUID != 0)); then
  exec sudo -n bash "$0"
fi

run_root=$(mktemp -d /run/buzz-systemd-order.XXXXXX)
suffix="${RANDOM}-$$"
docker_unit="buzz-order-docker-${suffix}.service"
core_unit="buzz-order-core-${suffix}.service"
event_log=$run_root/events
logger=$run_root/log-event
docker_post=$run_root/docker-post

cleanup() {
  systemctl stop "$core_unit" "$docker_unit" >/dev/null 2>&1 || true
  rm -f -- "/run/systemd/system/$core_unit" "/run/systemd/system/$docker_unit"
  systemctl daemon-reload >/dev/null 2>&1 || true
  case "$run_root" in
    /run/buzz-systemd-order.*) rm -rf -- "$run_root" ;;
    *) echo "refusing to remove unexpected systemd test root: $run_root" >&2 ;;
  esac
}
trap cleanup EXIT

cat >"$logger" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$1" >>'$event_log'
EOF
chmod 0755 "$logger"
cat >"$docker_post" <<EOF
#!/usr/bin/env bash
set -euo pipefail
'$logger' docker-firewall
systemctl --no-block start '$core_unit'
EOF
chmod 0755 "$docker_post"

cat >"/run/systemd/system/$docker_unit" <<EOF
[Unit]
Description=Buzz order test Docker
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$logger docker-start
ExecStartPost=$docker_post
ExecStop=$logger docker-stop
EOF
cat >"/run/systemd/system/$core_unit" <<EOF
[Unit]
Description=Buzz order test Core
Requires=$docker_unit
After=$docker_unit
PartOf=$docker_unit
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=$logger core-firewall
ExecStart=$logger compose-up
ExecStop=$logger core-stop
EOF

systemctl daemon-reload
systemctl start "$core_unit"
mapfile -t boot_events <"$event_log"
expected_boot=(docker-start docker-firewall core-firewall compose-up)
[[ ${boot_events[*]} == "${expected_boot[*]}" ]]

: >"$event_log"
systemctl restart "$docker_unit"
for _ in $(seq 1 50); do
  systemctl is-active --quiet "$core_unit" && break
  sleep 0.05
done
systemctl is-active --quiet "$core_unit"
mapfile -t restart_events <"$event_log"
expected_restart=(core-stop docker-stop docker-start docker-firewall core-firewall compose-up)
[[ ${restart_events[*]} == "${expected_restart[*]}" ]]

echo "systemd Docker/Core boot and restart ordering passed"
