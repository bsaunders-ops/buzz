#!/usr/bin/env bash
set -euo pipefail

# Docker sends container-forwarded traffic through DOCKER-USER before its own
# accept rules. Container traffic addressed to a bridge gateway instead reaches
# INPUT. Host traffic uses OUTPUT, so these rules leave bootstrap access to the
# managed identity endpoint intact.
iptables_bin=${IPTABLES_BIN:-/usr/sbin/iptables}
imds_cidr=169.254.169.254/32
ingress_bridge=buzz-ingress
host_bridges=(buzz-ingress buzz-edge buzz-data buzz-broker buzz-connector buzz-model buzz-audit buzz-egress)
baseline_only=false
if [[ ${1:-} == --baseline ]]; then
  baseline_only=true
  shift
fi
if (($#)); then
  echo "usage: $0 [--baseline]" >&2
  exit 2
fi

delete_all() {
  local chain=$1
  shift
  while "$iptables_bin" -w -C "$chain" "$@" >/dev/null 2>&1; do
    "$iptables_bin" -w -D "$chain" "$@"
  done
}

# These host-owned rules are installed before dockerd starts. Unlike
# DOCKER-USER, FORWARD and INPUT already exist, so retained restart-policy
# containers cannot race the daemon's creation of Docker-managed chains.
delete_all FORWARD -d "$imds_cidr" -j REJECT
delete_all INPUT -i 'buzz-+' -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
delete_all INPUT -i 'buzz-+' -j REJECT
"$iptables_bin" -w -I FORWARD 1 -d "$imds_cidr" -j REJECT
"$iptables_bin" -w -I INPUT 1 -i 'buzz-+' -j REJECT
"$iptables_bin" -w -I INPUT 1 -i 'buzz-+' -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

if [[ $baseline_only == true ]]; then
  exit 0
fi

if ! "$iptables_bin" -w -n -L DOCKER-USER >/dev/null 2>&1; then
  echo "Docker DOCKER-USER chain is unavailable; refusing to start Core services" >&2
  exit 1
fi

# Delete and reinsert only Buzz-owned exact rules. Reverse insertion produces
# the documented order while leaving unrelated operator policy untouched.
delete_all DOCKER-USER -d "$imds_cidr" -j REJECT
delete_all DOCKER-USER -i "$ingress_bridge" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
delete_all DOCKER-USER -i "$ingress_bridge" -j REJECT
"$iptables_bin" -w -I DOCKER-USER 1 -i "$ingress_bridge" -j REJECT
"$iptables_bin" -w -I DOCKER-USER 1 -i "$ingress_bridge" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
"$iptables_bin" -w -I DOCKER-USER 1 -d "$imds_cidr" -j REJECT

for bridge in "${host_bridges[@]}"; do
  delete_all INPUT -i "$bridge" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  delete_all INPUT -i "$bridge" -j REJECT
done
for ((index = ${#host_bridges[@]} - 1; index >= 0; index--)); do
  bridge=${host_bridges[index]}
  "$iptables_bin" -w -I INPUT 1 -i "$bridge" -j REJECT
  "$iptables_bin" -w -I INPUT 1 -i "$bridge" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
done
