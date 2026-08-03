# Core Buzz Azure foundation runbook

This lane prepares a single-node Azure foundation for Core Buzz. It is disabled
by default: validation and artifact builds are safe to run, the `what-if` job is
manual and environment-gated, and neither workflow deploys resources, publishes
images, changes DNS, activates services, or locks immutable storage.

## Topology and security boundary

The subscription-scoped `infra/azure/main.bicep` creates one East US 2 resource
group and composes focused network, security, compute, Front Door/WAF,
monitoring/backup, audit-storage, and budget modules. The VM is Ubuntu 24.04
Trusted Launch on `Standard_D4as_v5`, with a 256-GiB P15 data disk. Its NSG has
one custom inbound allow: TCP 443 from `AzureFrontDoor.Backend`. There is no
permanent public administration rule; use Entra VM login with JIT or Azure Run
Command.

Front Door adds `X-Buzz-Origin-Secret` and probes `/origin-healthz`. Caddy
requires both that secret and the exact profile GUID in `X-Azure-FDID`, then
presents an operator-provided origin certificate. The service-tag IPs are shared
by Front Door customers, so either header check by itself is insufficient. The
Compose overlay runs only services that exist in the supported single-node
bundle. The reserved `connector-internal` network is intentionally empty until
real connector binaries are delivered; do not add stand-in images.

The approved Standard tier supports custom WAF and rate-limit rules but not the
Microsoft-managed Default/Bot rule sets. Those require Front Door Premium and
its materially higher base cost. This foundation keeps Standard and explicit
custom rules; a Premium upgrade needs a new cost/security review and budget
approval.

The signed-NDJSON audit container starts with a 2,555-day **unlocked**
immutability policy. `infra/azure/audit/lock-retention.sh` is deliberately
outside the main module graph and defaults to no mutation. Daily exporter activation depends on the separately reviewed
signed audit exporter; this foundation only supplies the append-capable
container, managed-identity RBAC, cadence/format metadata, and retention policy.

## External authorization gates

Each gate needs a separate approval; one approval does not imply the next.

1. **Entra/OIDC:** create the least-privilege app or managed identity, federated
   credential, and protected GitHub environments. Store tenant, subscription,
   and client IDs as environment variables—not in Git. No client secret is used.
2. **Cost/resource purchase:** approve the `what-if`, the East US 2 resource
   purchase, and the $350 monthly budget before any `deployment sub create`.
3. **Image publication:** approve an ACR push separately. The delivery workflow
   only builds downloadable OCI archives and never logs in to or pushes to ACR.
   The first foundation deployment leaves `enableHostBootstrap=false`; the
   bootstrap extension cannot be enabled until the reviewed bundle exists in
   the newly created ACR at its approved digest.
4. **Key Vault material:** an authorized operator seeds the service secrets and
   origin certificate after the vault exists. Never paste them into chat, Git,
   command history, or a checked-in parameter file.
5. **DNS:** approve the origin A/AAAA record, Front Door validation record, and
   public cutover independently. Bicep creates no DNS records.
6. **Service activation:** approve `startCoreServices=true` or `systemctl enable
   --now buzz-core` only after restore, origin, secret, and digest checks pass.
7. **Immutability lock:** approve only after a disposable account rehearsal and
   restore evidence. A locked policy is irreversible.
8. **Windows signing:** provision the Artifact Signing account/profile and
   approve the `azure-trusted-signing` environment. Unsigned build approval does
   not authorize signing or Intune distribution.

## Prerequisites

- Azure CLI and Bicep CLI `v0.45.15` for local compile/what-if, or the pinned
  validation workflow when those tools are unavailable.
- Docker Engine with Compose v2.24.4 or newer for overlay rendering.
- An exact Ubuntu marketplace image version. Resolve it without selecting
  `latest`:

  ```bash
  az vm image list \
    --location eastus2 \
    --publisher Canonical \
    --offer ubuntu-24_04-lts \
    --sku 24_04-lts-gen2 \
    --all --query '[-1].version' -o tsv
  ```

- Seven immutable container references in `registry/repository@sha256:<64 hex>`
  form: the foundation-ACR bootstrap bundle, Buzz relay, Postgres/pgvector,
  Redis, MinIO, MinIO client, and Caddy. The bundle is a `FROM scratch` OCI
  artifact containing only reviewed Compose/Caddy/systemd assets. The VM pulls
  it with managed identity, verifies the requested repository digest, and never
  executes it as a container.
- An origin FQDN and a certificate/key whose SAN covers it. DNS changes remain
  gated even when the intended names are known.
- An Entra operator group for Run Command/JIT and alert/budget recipients.

## Offline validation

Activate the repository toolchain first:

```bash
. ./bin/activate-hermit
python3 infra/azure/tests/test_contracts.py
az bicep build --file infra/azure/main.bicep --stdout >/dev/null
bash -n infra/azure/audit/lock-retention.sh
```

Render the merged Compose model with non-secret validation values. Every image
must still be a digest reference:

```bash
export BUZZ_RELAY_IMAGE='registry.invalid/buzz@sha256:<64-hex>'
export POSTGRES_IMAGE='registry.invalid/pgvector@sha256:<64-hex>'
export REDIS_IMAGE='registry.invalid/redis@sha256:<64-hex>'
export MINIO_IMAGE='registry.invalid/minio@sha256:<64-hex>'
export MINIO_MC_IMAGE='registry.invalid/mc@sha256:<64-hex>'
export CADDY_IMAGE='registry.invalid/caddy@sha256:<64-hex>'
export POSTGRES_PASSWORD=validation-only REDIS_PASSWORD=validation-only
export BUZZ_S3_ACCESS_KEY=validation-only BUZZ_S3_SECRET_KEY=validation-only
export BUZZ_ORIGIN_FQDN=origin.invalid
export BUZZ_ORIGIN_SECRET=validation-only
export AZURE_FRONT_DOOR_ID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
docker compose \
  -f deploy/compose/compose.yml \
  -f infra/azure/compose/compose.azure.yml \
  config --quiet
```

If `az`/Bicep or Compose is missing, record the absence and use the
`Azure foundation validation` workflow. Do not replace compiler validation with
a deployment attempt.

## Dry-run and what-if

The preferred path is manual dispatch of `Azure foundation validation` with
`enable_what_if=true`. The `azure-foundation-what-if` environment must contain
OIDC IDs, protected secure inputs, approved image digests, the origin name, and
the exact Ubuntu image version. The job fails closed if an input is unset or an
image is not digest-pinned. It executes only:

```bash
az deployment sub what-if \
  --location eastus2 \
  --template-file infra/azure/main.bicep \
  --parameters enableHostBootstrap=false startCoreServices=false '<approved parameters>'
```

Export the JSON what-if result for review and confirm: no inbound destination
other than 443, no broad source prefix, no VM power-off schedule, no DNS record,
no immutable `Locked` state, and no service activation. Treat replacement of a
VM, disk, vault, Front Door profile, storage account, or public IP as a stop.

Only after the cost/resource gate may an operator translate the reviewed
what-if into `az deployment sub create`. That mutation is intentionally not
implemented in GitHub Actions. Keep the first deployment bootstrap-disabled,
then use the separate image-publication gate to import the `FROM scratch`
bootstrap bundle into the new ACR. Record its registry digest, rerun what-if
with `bootstrapBundleImage=<acr>/...@sha256:<digest>` and
`enableHostBootstrap=true`, and obtain a second deployment approval. Keep
`startCoreServices=false` during that second phase.

## Secret provisioning and activation

Seed these exact Key Vault names through an approved secure operator session:

- `postgres-password`, `redis-password`
- `minio-access-key`, `minio-secret-key`
- `relay-private-key`, `git-hook-hmac-secret`
- `frontdoor-origin-secret`
- `origin-tls-certificate`, `origin-tls-private-key`

The dotenv values must be non-empty, single-line values limited to
letters, digits, `.`, `_`, `~`, `+`, `/`, `=`, and `-`. The PEM certificate and
private key retain their normal multiline form. `refresh-secrets.sh` retrieves
only this allowlist, writes per-service files under `/run/buzz`, authenticates to
ACR with the VM's managed identity, and never prints secret values.

After DNS and certificate verification, activate with Run Command rather than a
permanent administration port:

```bash
az vm run-command invoke \
  --resource-group '<approved-rg>' \
  --name '<approved-vm>' \
  --command-id RunShellScript \
  --scripts 'sudo systemctl enable --now buzz-core.service'
```

Verify `systemctl status buzz-core`, `docker compose ps`, Caddy TLS, and relay
readiness through Run Command. Do not enable Tauri self-update; the Windows
workflow explicitly sets `createUpdaterArtifacts` to false.

## Front Door and WebSocket verification

Before DNS cutover, verify the Front Door endpoint and then the custom domain:

```bash
curl --fail --show-error --silent 'https://<front-door-host>/_liveness'
websocat -n1 'wss://<front-door-host>/' <<'EOF'
["REQ","origin-probe",{"kinds":[39000],"limit":1}]
EOF
```

Repeat after at least one Front Door origin rotation window. Confirm an ordinary
request sent directly to the public origin is blocked by the NSG, while the
Front Door health probe remains healthy. Through VM Run Command, test Caddy's
two independent header controls without printing their values: load
`AZURE_FRONT_DOOR_ID` from `/etc/buzz/core.env` and `BUZZ_ORIGIN_SECRET` from
`/run/buzz/secrets/caddy.env`, then require 403 for missing/wrong FDID with the
correct secret, 403 for missing/wrong secret with the correct FDID, and 200 for
both exact headers at `/origin-healthz`. Review Front Door metrics for origin
health, 4xx/5xx, WAF blocks, and WebSocket disconnects.

Both Front Door routes explicitly disable caching so WebSocket Upgrade headers
reach the relay. Front Door closes idle WebSockets after five minutes and can
force periodic disconnects for maintenance; current service guidance also caps
a connection at roughly two hours. Clients must send protocol traffic or a
ping/pong comfortably inside five minutes (use a 60–120 second interval), use
bounded exponential backoff with jitter after any disconnect, resubscribe
idempotently, and tolerate duplicate delivery. Exercise a controlled reconnect
before 110 minutes as well as a forced connection drop; confirm the client
recovers without user action or message loss.

## Alerts and cost validation

Read-only checks:

```bash
az monitor metrics alert list --resource-group '<approved-rg>' -o table
az monitor action-group list --resource-group '<approved-rg>' -o table
az consumption budget show --budget-name '<approved-budget>' -o jsonc
az consumption usage list --start-date '<yyyy-mm-01>' --end-date '<yyyy-mm-dd>' -o table
```

Sending an action-group test notification or deliberately stopping the VM is a
separate operational mutation. Obtain approval, notify pilot users, run the
test, confirm common-alert-schema delivery, then restore service immediately.
Do not use auto-shutdown for Postgres, Redis, MinIO, or the relay.

## Backup restore rehearsal

Never overwrite the active VM during a rehearsal. Select a recovery point and
restore disks into a disposable restore resource group:

```bash
az backup recoverypoint list \
  --resource-group '<approved-rg>' --vault-name '<vault>' \
  --container-name '<container>' --item-name '<item>' \
  --backup-management-type AzureIaasVM -o table

az backup restore restore-disks \
  --resource-group '<approved-rg>' --vault-name '<vault>' \
  --container-name '<container>' --item-name '<item>' \
  --rp-name '<recovery-point>' --storage-account '<staging-account>' \
  --target-resource-group '<disposable-restore-rg>'
```

Attach restored disks only to an isolated rehearsal VM. Validate Postgres,
Redis, MinIO, git data, audit-chain verification, and the documented 24-hour
RPO/four-hour RTO. Delete the disposable restore resources only under their
separate cleanup approval.

## Disposable immutability rehearsal

Create a disposable resource group and storage account with no production
data. Upload a small signed NDJSON fixture, deploy the unlocked 2,555-day policy,
verify append behavior, and test read/restore. First run the lock helper without
confirmation; it performs no Azure call and prints the intended target:

```bash
infra/azure/audit/lock-retention.sh \
  --resource-group '<disposable-rg>' \
  --account-name '<disposable-account>' \
  --container-name signed-audit
```

Only the disposable rehearsal approval may authorize rerunning with
`--confirm-lock --rehearsal-evidence <non-empty-reviewed-file>`. The helper
re-reads the policy, requires `Unlocked`, exactly 2,555 days, and its current
ETag, then calls the irreversible lock action. After locking, prove that deletion/shortening fails,
append still succeeds, signatures verify, and recovery works. Archive the
evidence. Production lock activation requires a new approval and the same
explicit helper invocation; never add it to `main.bicep` or an automatic workflow.

## Rollback

1. Stop new traffic at Front Door or restore the previous healthy origin under
   the incident change approval.
2. Stop the Compose project with `systemctl stop buzz-core` via Run Command.
3. Preserve disks and logs; do not delete the resource group or storage.
4. Restore the last verified VM/data-disk recovery point into a new VM, validate
   offline, then repoint the Front Door origin after approval.
5. Roll image references back to prior known-good digests in `/etc/buzz/core.env`
   and restart only after `docker compose config` and signature/SBOM review.
6. Re-run WebSocket, health, alert, restore, and cost checks. Record RPO/RTO.

An immutable policy cannot be rolled back after it is locked. Compromise or
misconfiguration therefore requires a new container/account and a governed
migration, never an attempt to weaken retention.
