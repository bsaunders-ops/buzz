#!/usr/bin/env bash
set -euo pipefail

umask 027

validation_only=false
config_payload=${BUZZ_BOOTSTRAP_CONFIG_BASE64:-}

while (($#)); do
  case "$1" in
    --config-base64)
      config_payload=$2
      shift 2
      ;;
    --validate-config-base64)
      config_payload=$2
      validation_only=true
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z $config_payload || ! $config_payload =~ ^[A-Za-z0-9+/=]+$ ]]; then
  echo "bootstrap configuration must be base64 JSON" >&2
  exit 2
fi

config_json=$(printf '%s' "$config_payload" | base64 --decode) || {
  echo "bootstrap configuration is not valid base64" >&2
  exit 2
}
if ! jq -e 'type == "object"' <<<"$config_json" >/dev/null; then
  echo "bootstrap configuration is not a JSON object" >&2
  exit 2
fi

read_config_string() {
  local key=$1
  local value
  value=$(jq -er --arg key "$key" '.[$key] | select(type == "string")' <<<"$config_json") || {
    echo "bootstrap configuration key $key must be a string" >&2
    exit 2
  }
  printf '%s' "$value"
}

acr_name=$(read_config_string acrName)
key_vault_name=$(read_config_string keyVaultName)
origin_fqdn=$(read_config_string originFqdn)
origin_secret_name=$(read_config_string originSecretName)
front_door_id=$(read_config_string frontDoorId)
public_host=$(read_config_string publicHost)
relay_owner_pubkey=$(read_config_string relayOwnerPubkey)
bootstrap_bundle_image=$(read_config_string bootstrapBundleImage)
relay_image=$(read_config_string relayImage)
postgres_image=$(read_config_string postgresImage)
redis_image=$(read_config_string redisImage)
minio_image=$(read_config_string minioImage)
minio_mc_image=$(read_config_string minioMcImage)
caddy_image=$(read_config_string caddyImage)
core_worker_image=$(read_config_string coreWorkerImage)
egress_proxy_image=$(read_config_string egressProxyImage)
audit_storage_account_name=$(read_config_string auditStorageAccountName)
if ! jq -e '.startServices | type == "boolean"' <<<"$config_json" >/dev/null; then
  echo "bootstrap configuration key startServices must be a boolean" >&2
  exit 2
fi
start_services=$(jq -r '.startServices' <<<"$config_json")
if ! jq -e '.enableMonth1Workers | type == "boolean"' <<<"$config_json" >/dev/null; then
  echo "bootstrap configuration key enableMonth1Workers must be a boolean" >&2
  exit 2
fi
enable_month1_workers=$(jq -r '.enableMonth1Workers' <<<"$config_json")
if [[ $enable_month1_workers == true ]]; then
  echo "Month-1 workers remain deployment-gated until role business loops and end-to-end tests are complete" >&2
  exit 2
fi

if [[ ! $acr_name =~ ^[a-z0-9]{5,50}$ ]]; then
  echo "acrName is invalid" >&2
  exit 2
fi
if [[ ! $key_vault_name =~ ^[A-Za-z0-9-]{3,24}$ ]]; then
  echo "keyVaultName is invalid" >&2
  exit 2
fi
if [[ ! $audit_storage_account_name =~ ^[a-z0-9]{3,24}$ ]]; then
  echo "auditStorageAccountName is invalid" >&2
  exit 2
fi
if [[ ! $origin_fqdn =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ || $origin_fqdn != *.* || $origin_fqdn == *..* ]]; then
  echo "originFqdn is invalid" >&2
  exit 2
fi
if [[ ! $origin_secret_name =~ ^[A-Za-z0-9-]{1,127}$ ]]; then
  echo "originSecretName is invalid" >&2
  exit 2
fi
if [[ ! $front_door_id =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]]; then
  echo "frontDoorId is invalid" >&2
  exit 2
fi
if [[ ! $public_host =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ || $public_host != *.* || $public_host == *..* ]]; then
  echo "publicHost is invalid" >&2
  exit 2
fi
if [[ -n $relay_owner_pubkey && ! $relay_owner_pubkey =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "relayOwnerPubkey must be empty or a 64-character hex public key" >&2
  exit 2
fi
relay_owner_pubkey=${relay_owner_pubkey,,}
if [[ $start_services == true && -z $relay_owner_pubkey ]]; then
  echo "relayOwnerPubkey is required when startServices is true" >&2
  exit 2
fi

image_pattern='^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$'
for image in "$bootstrap_bundle_image" "$relay_image" "$postgres_image" "$redis_image" "$minio_image" "$minio_mc_image" "$caddy_image" "$core_worker_image" "$egress_proxy_image"; do
  if [[ ! $image =~ $image_pattern ]]; then
    echo "every image must be pinned by sha256 digest" >&2
    exit 2
  fi
done
if [[ $bootstrap_bundle_image != "$acr_name.azurecr.io/"* ]]; then
  echo "bootstrap bundle must come from the foundation ACR" >&2
  exit 2
fi

if [[ $validation_only == true ]]; then
  exit 0
fi
if [[ ${EUID} -ne 0 ]]; then
  echo "bootstrap must run as root" >&2
  exit 1
fi

for early_guard in /usr/local/sbin/buzz-core-docker-activation /usr/local/sbin/buzz-core-container-firewall; do
  if [[ ! -x $early_guard ]]; then
    echo "bootstrap preload is missing $early_guard" >&2
    exit 1
  fi
done
/usr/local/sbin/buzz-core-docker-activation prepare

azure_config_dir=''
docker_config_dir=''
tmp_config=''
tmp_docker_dropin=''

cleanup_bootstrap() {
  if [[ -n $tmp_config ]]; then
    rm -f -- "$tmp_config"
  fi
  if [[ -n $tmp_docker_dropin ]]; then
    rm -f -- "$tmp_docker_dropin"
  fi
  if [[ -n $azure_config_dir && $azure_config_dir == /run/buzz/azure-cli.bootstrap.* ]]; then
    rm -rf -- "$azure_config_dir"
  fi
  if [[ -n $docker_config_dir && $docker_config_dir == /run/buzz/docker.bootstrap.* ]]; then
    rm -rf -- "$docker_config_dir"
  fi
}
trap cleanup_bootstrap EXIT

install -d -m 0700 /run/buzz
azure_config_dir=$(mktemp -d /run/buzz/azure-cli.bootstrap.XXXXXX)
docker_config_dir=$(mktemp -d /run/buzz/docker.bootstrap.XXXXXX)
export AZURE_CONFIG_DIR=$azure_config_dir
export DOCKER_CONFIG=$docker_config_dir

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl gnupg iptables jq python3 util-linux xfsprogs
}

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    return
  fi
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
  chmod 0644 /etc/apt/keyrings/docker.gpg
  # shellcheck disable=SC1091
  . /etc/os-release
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

ensure_docker_running() {
  install -d -m 0755 /etc/systemd/system/docker.service.d
  tmp_docker_dropin=$(mktemp /etc/systemd/system/docker.service.d/20-buzz-imds-firewall.conf.XXXXXX)
  cat >"$tmp_docker_dropin" <<'EOF'
[Service]
ExecStartPre=/usr/local/sbin/buzz-core-container-firewall --baseline
ExecStartPost=/usr/local/sbin/buzz-core-container-firewall
EOF
  chmod 0644 "$tmp_docker_dropin"
  mv -f "$tmp_docker_dropin" /etc/systemd/system/docker.service.d/20-buzz-imds-firewall.conf
  tmp_docker_dropin=''
  /usr/local/sbin/buzz-core-docker-activation start
}

install_azure_cli() {
  if command -v az >/dev/null 2>&1; then
    return
  fi
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
    | gpg --dearmor --yes -o /etc/apt/keyrings/microsoft.gpg
  chmod 0644 /etc/apt/keyrings/microsoft.gpg
  # shellcheck disable=SC1091
  . /etc/os-release
  printf 'Types: deb\nURIs: https://packages.microsoft.com/repos/azure-cli/\nSuites: %s\nComponents: main\nArchitectures: %s\nSigned-by: /etc/apt/keyrings/microsoft.gpg\n' \
    "$VERSION_CODENAME" "$(dpkg --print-architecture)" > /etc/apt/sources.list.d/azure-cli.sources
  apt-get update
  apt-get install -y --no-install-recommends azure-cli
}

parent_disk() {
  local node
  local parent_name
  node=$(readlink -f "$1")
  parent_name=$(lsblk -ndo PKNAME "$node" | head -n1)
  if [[ -n $parent_name ]]; then
    readlink -f "/dev/$parent_name"
  else
    printf '%s\n' "$node"
  fi
}

mount_data_disk() {
  local device=/dev/disk/azure/scsi1/lun0
  local resolved
  local root_source
  local root_disk
  local resolved_disk
  local existing_mount_source
  local existing_mount_disk
  local device_size
  local expected_min_bytes=$((255 * 1024 * 1024 * 1024))
  local expected_max_bytes=$((257 * 1024 * 1024 * 1024))
  local filesystem_type
  local filesystem_label
  local signatures
  local uuid
  local existing_fstab_source
  local -a topology
  local -a mountpoints

  for _ in {1..60}; do
    [[ -e $device ]] && break
    sleep 2
  done
  if [[ ! -e $device ]]; then
    echo "Azure data disk LUN 0 did not appear" >&2
    exit 1
  fi
  resolved=$(readlink -f "$device")
  if [[ ! -b $resolved ]]; then
    echo "Azure data disk LUN 0 did not resolve to a block device" >&2
    exit 1
  fi

  root_source=$(findmnt -n -o SOURCE /)
  root_disk=$(parent_disk "$root_source")
  resolved_disk=$(parent_disk "$resolved")
  if [[ $resolved == "$root_disk" || $resolved_disk == "$root_disk" ]]; then
    echo "refusing to treat the OS/root disk as the Core data disk" >&2
    exit 1
  fi

  existing_mount_source=$(findmnt -n -o SOURCE --mountpoint /srv/buzz 2>/dev/null || true)
  if [[ -n $existing_mount_source ]]; then
    existing_mount_disk=$(parent_disk "$existing_mount_source")
    if [[ $existing_mount_disk != "$resolved_disk" ]]; then
      echo "refusing to reuse /srv/buzz while it is mounted from another disk" >&2
      exit 1
    fi
  fi

  device_size=$(blockdev --getsize64 "$resolved")
  if ((device_size < expected_min_bytes || device_size > expected_max_bytes)); then
    echo "Core data disk must be the approved 256-GiB disk" >&2
    exit 1
  fi

  mapfile -t topology < <(lsblk -nrpo NAME,TYPE "$resolved")
  if ((${#topology[@]} != 1)) || [[ ${topology[0]} != "$resolved disk" ]]; then
    echo "Core data disk must be a raw disk with no partitions or child devices" >&2
    exit 1
  fi

  mapfile -t mountpoints < <(lsblk -nrpo MOUNTPOINT "$resolved" | sed '/^[[:space:]]*$/d')
  if ((${#mountpoints[@]} > 1)) || ((${#mountpoints[@]} == 1)) && [[ ${mountpoints[0]} != /srv/buzz ]]; then
    echo "Core data disk is mounted at an unexpected location" >&2
    exit 1
  fi

  filesystem_type=$(blkid -s TYPE -o value "$resolved" 2>/dev/null || true)
  filesystem_label=$(blkid -s LABEL -o value "$resolved" 2>/dev/null || true)
  if [[ -z $filesystem_type ]]; then
    if ((${#mountpoints[@]} != 0)); then
      echo "blank Core data disk unexpectedly reports a mount" >&2
      exit 1
    fi
    signatures=$(wipefs --noheadings --output TYPE "$resolved" | tr -d '[:space:]')
    if [[ -n $signatures ]]; then
      echo "refusing to format a Core data disk with an existing signature" >&2
      exit 1
    fi
    mkfs.xfs -L buzz-data "$resolved"
    filesystem_type=xfs
    filesystem_label=buzz-data
  fi
  if [[ $filesystem_type != xfs || $filesystem_label != buzz-data ]]; then
    echo "Core data disk must contain only the expected buzz-data XFS filesystem" >&2
    exit 1
  fi

  uuid=$(blkid -s UUID -o value "$resolved")
  if [[ -z $uuid ]]; then
    echo "Core data disk has no filesystem UUID" >&2
    exit 1
  fi
  install -d -m 0750 /srv/buzz
  existing_fstab_source=$(awk '$2 == "/srv/buzz" { print $1; exit }' /etc/fstab)
  if [[ -n $existing_fstab_source && $existing_fstab_source != "UUID=$uuid" ]]; then
    echo "existing /srv/buzz fstab entry targets a different device" >&2
    exit 1
  fi
  if [[ -z $existing_fstab_source ]]; then
    printf 'UUID=%s /srv/buzz xfs defaults,nofail,nodev,nosuid 0 2\n' "$uuid" >> /etc/fstab
  fi
  if ! mountpoint -q /srv/buzz; then
    mount /srv/buzz
  fi
}

extract_verified_bundle() {
  local expected_digest=${bootstrap_bundle_image##*@}
  local digest_hex=${expected_digest#sha256:}
  local actual_digest
  local container_id=''
  local bundle_root=/opt/buzz/bootstrap-bundles
  local bundle_target="$bundle_root/$digest_hex"
  local staging_dir=''

  cleanup_bundle_extract() {
    if [[ -n $container_id ]]; then
      docker rm -f "$container_id" >/dev/null 2>&1 || true
    fi
    if [[ -n $staging_dir && $staging_dir == "$bundle_root"/.* ]]; then
      rm -rf -- "$staging_dir"
    fi
  }
  trap cleanup_bundle_extract RETURN ERR

  install -d -m 0750 "$bundle_root"
  az login --identity --allow-no-subscriptions --output none >/dev/null
  az acr login --name "$acr_name" --output none >/dev/null
  docker pull "$bootstrap_bundle_image" >/dev/null
  actual_digest=$(docker image inspect "$bootstrap_bundle_image" --format '{{range .RepoDigests}}{{println .}}{{end}}' \
    | awk -F@ -v expected="$expected_digest" '$2 == expected { print $2; exit }')
  if [[ $actual_digest != "$expected_digest" ]]; then
    echo "bootstrap bundle digest verification failed" >&2
    return 1
  fi

  if [[ -f $bundle_target/.bundle-digest ]] && [[ $(<"$bundle_target/.bundle-digest") == "$expected_digest" ]]; then
    asset_dir=$bundle_target
    trap - RETURN ERR
    return
  fi

  staging_dir=$(mktemp -d "$bundle_root/.${digest_hex}.XXXXXX")
  container_id=$(docker create "$bootstrap_bundle_image")
  docker cp "$container_id:/bundle/." "$staging_dir/"
  docker rm -f "$container_id" >/dev/null
  container_id=''
  printf '%s\n' "$expected_digest" >"$staging_dir/.bundle-digest"
  chmod 0440 "$staging_dir/.bundle-digest"
  if ! mv -T "$staging_dir" "$bundle_target" 2>/dev/null; then
    if [[ ! -f $bundle_target/.bundle-digest ]] || [[ $(<"$bundle_target/.bundle-digest") != "$expected_digest" ]]; then
      echo "verified bootstrap bundle target already exists with different contents" >&2
      return 1
    fi
    rm -rf -- "$staging_dir"
  fi
  staging_dir=''
  asset_dir=$bundle_target
  trap - RETURN ERR
}

install_packages
install_docker
ensure_docker_running
install_azure_cli
mount_data_disk
extract_verified_bundle

for asset in compose-supervisor.sh container-firewall.sh docker-activation.sh docker-post-start.sh service-activation.sh refresh-secrets.sh provision-worker-db-roles.sh buzz-core.service compose.yml compose.azure.yml Caddyfile.azure squid-connectors.conf squid-model.conf; do
  if [[ ! -f $asset_dir/$asset ]]; then
    echo "verified bootstrap bundle is missing $asset" >&2
    exit 1
  fi
done

install -d -m 0750 /etc/buzz /opt/buzz/deploy/compose /opt/buzz/infra/azure/compose
install -d -m 0750 -o 1000 -g 1000 /srv/buzz/git /srv/buzz/minio
install -d -m 0750 -o 999 -g 999 /srv/buzz/postgres /srv/buzz/redis

install -m 0755 "$asset_dir/refresh-secrets.sh" /usr/local/sbin/buzz-core-refresh-secrets
install -m 0755 "$asset_dir/provision-worker-db-roles.sh" /usr/local/sbin/buzz-core-provision-worker-db-roles
install -m 0755 "$asset_dir/container-firewall.sh" /usr/local/sbin/buzz-core-container-firewall
install -m 0755 "$asset_dir/service-activation.sh" /usr/local/sbin/buzz-core-service-activation
install -m 0755 "$asset_dir/compose-supervisor.sh" /usr/local/sbin/buzz-core-compose-supervisor
install -m 0755 "$asset_dir/docker-activation.sh" /usr/local/sbin/buzz-core-docker-activation
install -m 0755 "$asset_dir/docker-post-start.sh" /usr/local/sbin/buzz-core-docker-post-start
install -m 0644 "$asset_dir/buzz-core.service" /etc/systemd/system/buzz-core.service
install -m 0644 "$asset_dir/compose.yml" /opt/buzz/deploy/compose/compose.yml
install -m 0644 "$asset_dir/compose.azure.yml" /opt/buzz/infra/azure/compose/compose.azure.yml
install -m 0644 "$asset_dir/Caddyfile.azure" /opt/buzz/infra/azure/compose/Caddyfile.azure
install -m 0644 "$asset_dir/squid-connectors.conf" /opt/buzz/infra/azure/compose/squid-connectors.conf
install -m 0644 "$asset_dir/squid-model.conf" /opt/buzz/infra/azure/compose/squid-model.conf

install -d -m 0755 /etc/systemd/system/docker.service.d
tmp_docker_dropin=$(mktemp /etc/systemd/system/docker.service.d/20-buzz-imds-firewall.conf.XXXXXX)
cat >"$tmp_docker_dropin" <<'EOF'
[Service]
ExecStartPre=/usr/local/sbin/buzz-core-container-firewall --baseline
ExecStartPost=/usr/local/sbin/buzz-core-docker-post-start
EOF
chmod 0644 "$tmp_docker_dropin"
mv -f "$tmp_docker_dropin" /etc/systemd/system/docker.service.d/20-buzz-imds-firewall.conf
tmp_docker_dropin=''

tmp_config=$(mktemp /etc/buzz/core.env.XXXXXX)
cat >"$tmp_config" <<EOF
ACR_NAME=$acr_name
KEY_VAULT_NAME=$key_vault_name
BUZZ_ORIGIN_FQDN=$origin_fqdn
BUZZ_PUBLIC_HOST=$public_host
RELAY_OWNER_PUBKEY=$relay_owner_pubkey
ORIGIN_SECRET_NAME=$origin_secret_name
AZURE_FRONT_DOOR_ID=$front_door_id
ORIGIN_TLS_CERT_SECRET_NAME=origin-tls-certificate
ORIGIN_TLS_KEY_SECRET_NAME=origin-tls-private-key
POSTGRES_PASSWORD_SECRET_NAME=postgres-password
REDIS_PASSWORD_SECRET_NAME=redis-password
MINIO_ACCESS_KEY_SECRET_NAME=minio-access-key
MINIO_SECRET_KEY_SECRET_NAME=minio-secret-key
RELAY_PRIVATE_KEY_SECRET_NAME=relay-private-key
GIT_HOOK_SECRET_NAME=git-hook-hmac-secret
OPENAI_API_KEY_SECRET_NAME=openai-api-key
ACP_SIGNING_KEY_SECRET_NAME=acp-signing-key
CRM_CONNECTOR_CREDENTIAL_B64_SECRET_NAME=crm-connector-credential-b64
MICROSOFT_CONNECTOR_CREDENTIAL_B64_SECRET_NAME=microsoft-connector-credential-b64
GOOGLE_CONNECTOR_CREDENTIAL_B64_SECRET_NAME=google-connector-credential-b64
AUDIT_BLOB_CREDENTIAL_B64_SECRET_NAME=audit-blob-credential-b64
CONNECTOR_WORKER_DB_PASSWORD_SECRET_NAME=connector-worker-db-password
SANITIZER_INDEXER_DB_PASSWORD_SECRET_NAME=sanitizer-indexer-db-password
SIGNAL_RUNNER_DB_PASSWORD_SECRET_NAME=signal-runner-db-password
ACTION_EXECUTOR_DB_PASSWORD_SECRET_NAME=action-executor-db-password
LEARNING_WORKER_DB_PASSWORD_SECRET_NAME=learning-worker-db-password
AUDIT_EXPORTER_DB_PASSWORD_SECRET_NAME=audit-exporter-db-password
AUDIT_STORAGE_ACCOUNT_NAME=$audit_storage_account_name
ENABLE_MONTH1_WORKERS=$enable_month1_workers
COMPOSE_PROFILES=$( [[ $enable_month1_workers == true ]] && printf month1-workers )
BUZZ_RELAY_IMAGE=$relay_image
POSTGRES_IMAGE=$postgres_image
REDIS_IMAGE=$redis_image
MINIO_IMAGE=$minio_image
MINIO_MC_IMAGE=$minio_mc_image
CADDY_IMAGE=$caddy_image
BUZZ_CORE_WORKER_IMAGE=$core_worker_image
EGRESS_PROXY_IMAGE=$egress_proxy_image
BUZZ_AZURE_ASSET_ROOT=/opt/buzz/infra/azure
DOCKER_CONFIG=/run/buzz/docker
EOF
chmod 0640 "$tmp_config"
mv -f "$tmp_config" /etc/buzz/core.env
tmp_config=''

systemctl daemon-reload
/usr/local/sbin/buzz-core-container-firewall
/usr/local/sbin/buzz-core-service-activation "$start_services"
