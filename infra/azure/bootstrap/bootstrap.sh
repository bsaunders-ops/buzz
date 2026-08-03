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
bootstrap_bundle_image=$(read_config_string bootstrapBundleImage)
relay_image=$(read_config_string relayImage)
postgres_image=$(read_config_string postgresImage)
redis_image=$(read_config_string redisImage)
minio_image=$(read_config_string minioImage)
minio_mc_image=$(read_config_string minioMcImage)
caddy_image=$(read_config_string caddyImage)
if ! jq -e '.startServices | type == "boolean"' <<<"$config_json" >/dev/null; then
  echo "bootstrap configuration key startServices must be a boolean" >&2
  exit 2
fi
start_services=$(jq -r '.startServices' <<<"$config_json")

if [[ ! $acr_name =~ ^[a-z0-9]{5,50}$ ]]; then
  echo "acrName is invalid" >&2
  exit 2
fi
if [[ ! $key_vault_name =~ ^[A-Za-z0-9-]{3,24}$ ]]; then
  echo "keyVaultName is invalid" >&2
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

image_pattern='^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$'
for image in "$bootstrap_bundle_image" "$relay_image" "$postgres_image" "$redis_image" "$minio_image" "$minio_mc_image" "$caddy_image"; do
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

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl gnupg jq python3 xfsprogs
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

mount_data_disk() {
  local device=/dev/disk/azure/scsi1/lun0
  local resolved
  for _ in {1..60}; do
    [[ -e $device ]] && break
    sleep 2
  done
  if [[ ! -e $device ]]; then
    echo "Azure data disk LUN 0 did not appear" >&2
    exit 1
  fi
  resolved=$(readlink -f "$device")
  if ! blkid "$resolved" >/dev/null 2>&1; then
    mkfs.xfs -f -L buzz-data "$resolved"
  fi
  local uuid
  uuid=$(blkid -s UUID -o value "$resolved")
  install -d -m 0750 /srv/buzz
  if ! grep -Fq "UUID=$uuid " /etc/fstab; then
    printf 'UUID=%s /srv/buzz xfs defaults,nofail,nodev,nosuid 0 2\n' "$uuid" >> /etc/fstab
  fi
  if ! mountpoint -q /srv/buzz; then
    mount /srv/buzz
  fi
}

extract_verified_bundle() {
  local expected_digest=${bootstrap_bundle_image##*@}
  local actual_digest
  local container_id
  install -d -m 0750 /opt/buzz/bootstrap-bundle
  rm -rf /opt/buzz/bootstrap-bundle/*
  az login --identity --allow-no-subscriptions --output none >/dev/null
  az acr login --name "$acr_name" --output none >/dev/null
  docker pull "$bootstrap_bundle_image" >/dev/null
  actual_digest=$(docker image inspect "$bootstrap_bundle_image" --format '{{range .RepoDigests}}{{println .}}{{end}}' \
    | awk -F@ -v expected="$expected_digest" '$2 == expected { print $2; exit }')
  if [[ $actual_digest != "$expected_digest" ]]; then
    echo "bootstrap bundle digest verification failed" >&2
    exit 1
  fi
  container_id=$(docker create "$bootstrap_bundle_image")
  trap 'docker rm -f "$container_id" >/dev/null 2>&1 || true' RETURN
  docker cp "$container_id:/bundle/." /opt/buzz/bootstrap-bundle/
  docker rm -f "$container_id" >/dev/null
  trap - RETURN
}

install_packages
install_docker
install_azure_cli
mount_data_disk
extract_verified_bundle

asset_dir=/opt/buzz/bootstrap-bundle
for asset in refresh-secrets.sh buzz-core.service compose.yml compose.azure.yml Caddyfile.azure; do
  if [[ ! -f $asset_dir/$asset ]]; then
    echo "verified bootstrap bundle is missing $asset" >&2
    exit 1
  fi
done

install -d -m 0750 /etc/buzz /opt/buzz/deploy/compose /opt/buzz/infra/azure/compose
install -d -m 0750 -o 1000 -g 1000 /srv/buzz/git /srv/buzz/minio
install -d -m 0750 -o 999 -g 999 /srv/buzz/postgres /srv/buzz/redis

install -m 0755 "$asset_dir/refresh-secrets.sh" /usr/local/sbin/buzz-core-refresh-secrets
install -m 0644 "$asset_dir/buzz-core.service" /etc/systemd/system/buzz-core.service
install -m 0644 "$asset_dir/compose.yml" /opt/buzz/deploy/compose/compose.yml
install -m 0644 "$asset_dir/compose.azure.yml" /opt/buzz/infra/azure/compose/compose.azure.yml
install -m 0644 "$asset_dir/Caddyfile.azure" /opt/buzz/infra/azure/compose/Caddyfile.azure

tmp_config=$(mktemp /etc/buzz/core.env.XXXXXX)
trap 'rm -f "$tmp_config"' EXIT
cat >"$tmp_config" <<EOF
ACR_NAME=$acr_name
KEY_VAULT_NAME=$key_vault_name
BUZZ_ORIGIN_FQDN=$origin_fqdn
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
BUZZ_RELAY_IMAGE=$relay_image
POSTGRES_IMAGE=$postgres_image
REDIS_IMAGE=$redis_image
MINIO_IMAGE=$minio_image
MINIO_MC_IMAGE=$minio_mc_image
CADDY_IMAGE=$caddy_image
BUZZ_AZURE_ASSET_ROOT=/opt/buzz/infra/azure
EOF
chmod 0640 "$tmp_config"
mv -f "$tmp_config" /etc/buzz/core.env
trap - EXIT

systemctl daemon-reload
systemctl enable docker.service
if [[ $start_services == true ]]; then
  systemctl enable --now buzz-core.service
else
  systemctl disable buzz-core.service >/dev/null 2>&1 || true
  echo "Core assets installed; service activation remains gated."
fi
