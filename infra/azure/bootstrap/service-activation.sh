#!/usr/bin/env bash
set -euo pipefail

start_services=${1:-}
systemctl_bin=${SYSTEMCTL_BIN:-systemctl}

case "$start_services" in
  true)
    "$systemctl_bin" enable buzz-core.service
    if "$systemctl_bin" is-active --quiet buzz-core.service; then
      "$systemctl_bin" restart buzz-core.service
    else
      "$systemctl_bin" start buzz-core.service
    fi
    ;;
  false)
    "$systemctl_bin" disable --now buzz-core.service
    echo "Core assets installed; service activation remains gated."
    ;;
  *)
    echo "service activation must be true or false" >&2
    exit 2
    ;;
esac
