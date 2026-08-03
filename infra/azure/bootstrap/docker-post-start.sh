#!/usr/bin/env bash
set -euo pipefail

firewall_bin=${FIREWALL_BIN:-/usr/local/sbin/buzz-core-container-firewall}
systemctl_bin=${SYSTEMCTL_BIN:-systemctl}

"$firewall_bin"
if "$systemctl_bin" is-enabled --quiet buzz-core.service; then
  # Avoid a dependency deadlock: buzz-core is ordered After=docker.service,
  # whose ExecStartPost is still completing here.
  "$systemctl_bin" --no-block start buzz-core.service
fi
