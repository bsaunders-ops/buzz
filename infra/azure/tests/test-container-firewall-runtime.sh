#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
firewall_image=${FIREWALL_TEST_IMAGE:?set FIREWALL_TEST_IMAGE to a digest-pinned network test image}
image_pattern='^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$'
if [[ ! $firewall_image =~ $image_pattern ]]; then
  echo "Firewall runtime test image must be pinned by sha256 digest" >&2
  exit 2
fi

docker run --rm --interactive --privileged --network none \
  --volume "$repo_root/infra/azure/bootstrap/container-firewall.sh:/test/container-firewall.sh:ro" \
  "$firewall_image" bash -s <<'INNER'
set -euo pipefail

namespace_pids=()
listener_pids=()
cleanup() {
  ((${#listener_pids[@]} == 0)) || kill "${listener_pids[@]}" >/dev/null 2>&1 || true
  ((${#namespace_pids[@]} == 0)) || kill "${namespace_pids[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

spawn_namespace() {
  unshare --net sh -c 'exec sleep 300' >/dev/null 2>&1 &
  local pid=$!
  for _ in $(seq 1 50); do
    if [[ -e /proc/$pid/ns/net ]]; then
      printf '%s\n' "$pid"
      return
    fi
    sleep 0.05
  done
  echo "network namespace did not start" >&2
  return 1
}

client_pid=$(spawn_namespace)
edge_pid=$(spawn_namespace)
data_pid=$(spawn_namespace)
outside_pid=$(spawn_namespace)
namespace_pids+=("$client_pid" "$edge_pid" "$data_pid" "$outside_pid")

configure_peer() {
  local host_interface=$1
  local peer_interface=$2
  local namespace_pid=$3
  local host_address=$4
  local peer_address=$5
  ip link add "$host_interface" type veth peer name "$peer_interface"
  ip link set "$peer_interface" netns "$namespace_pid"
  ip address add "$host_address" dev "$host_interface"
  ip link set "$host_interface" up
  nsenter -t "$namespace_pid" -n ip link set lo up
  nsenter -t "$namespace_pid" -n ip address add "$peer_address" dev "$peer_interface"
  nsenter -t "$namespace_pid" -n ip link set "$peer_interface" up
}

configure_peer buzz-ingress client0 "$client_pid" 10.55.0.1/24 10.55.0.2/24
configure_peer buzz-edge edge0 "$edge_pid" 10.56.0.1/24 10.56.0.2/24
configure_peer buzz-data data0 "$data_pid" 10.57.0.1/24 10.57.0.2/24
configure_peer buzz-out outside0 "$outside_pid" 198.51.100.1/24 198.51.100.2/24
nsenter -t "$client_pid" -n ip route add default via 10.55.0.1
nsenter -t "$edge_pid" -n ip route add default via 10.56.0.1
nsenter -t "$data_pid" -n ip route add default via 10.57.0.1
nsenter -t "$outside_pid" -n ip route add default via 198.51.100.1
nsenter -t "$outside_pid" -n ip address add 169.254.169.254/32 dev lo
ip route add 169.254.169.254/32 via 198.51.100.2 dev buzz-out
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.buzz-out.rp_filter=0
sysctl -q -w net.ipv4.conf.buzz-edge.rp_filter=0

listen_forever() {
  local namespace_pid=$1
  local port=$2
  nsenter -t "$namespace_pid" -n nc -lk -p "$port" >/dev/null &
  listener_pids+=("$!")
}
listen_forever "$client_pid" 8081
listen_forever "$outside_pid" 8082
nc -lk -p 8080 >/dev/null &
listener_pids+=("$!")
sleep 0.2

# Establish that the synthetic routes work before applying the policy.
nsenter -t "$client_pid" -n nc -z -w 2 10.55.0.1 8080
nsenter -t "$client_pid" -n nc -z -w 2 198.51.100.2 8082
nsenter -t "$edge_pid" -n nc -z -w 2 10.56.0.1 8080
nsenter -t "$data_pid" -n nc -z -w 2 10.57.0.1 8080
nsenter -t "$edge_pid" -n nc -z -w 2 169.254.169.254 8082

iptables -N DOCKER-USER
iptables -I FORWARD 1 -j DOCKER-USER
IPTABLES_BIN=/sbin/iptables bash /test/container-firewall.sh
IPTABLES_BIN=/sbin/iptables bash /test/container-firewall.sh

# Host/outside initiated connections and their established replies remain valid.
nc -z -w 2 10.55.0.2 8081
nsenter -t "$outside_pid" -n nc -z -w 2 10.55.0.2 8081

# Containers cannot initiate host-gateway, external, or IMDS connections.
if nsenter -t "$client_pid" -n nc -z -w 2 10.55.0.1 8080; then
  echo "ingress container reached the host gateway" >&2
  exit 1
fi
if nsenter -t "$client_pid" -n nc -z -w 2 198.51.100.2 8082; then
  echo "ingress container initiated external forwarding" >&2
  exit 1
fi
if nsenter -t "$edge_pid" -n nc -z -w 2 10.56.0.1 8080; then
  echo "edge container reached the host gateway" >&2
  exit 1
fi
if nsenter -t "$data_pid" -n nc -z -w 2 10.57.0.1 8080; then
  echo "data container reached the host gateway" >&2
  exit 1
fi
if nsenter -t "$edge_pid" -n nc -z -w 2 169.254.169.254 8082; then
  echo "edge container reached IMDS" >&2
  exit 1
fi

mapfile -t forward_rules < <(iptables -S DOCKER-USER)
[[ ${forward_rules[1]} == '-A DOCKER-USER -d 169.254.169.254/32 -j REJECT'* ]]
[[ ${forward_rules[2]} == '-A DOCKER-USER -i buzz-ingress -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' ]]
[[ ${forward_rules[3]} == '-A DOCKER-USER -i buzz-ingress -j REJECT'* ]]

echo "Container firewall isolated runtime matrix passed"
INNER
