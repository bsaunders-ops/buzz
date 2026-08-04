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
one custom inbound allow: TCP 443 from `AzureFrontDoor.Backend`. An explicit
priority-200 deny follows it, overriding Azure's default VNet inbound allow for
all other traffic, including future peers. There is no permanent public
administration rule; use Entra VM login with JIT or Azure Run Command.

Front Door adds `X-Buzz-Origin-Secret` to routed client requests and probes
`/origin-healthz`. Only an exact `GET` or `HEAD` to that path carrying Front
Door's reserved `X-FD-HealthProbe: 1` marker bypasses the route headers and is
proxied to relay readiness. Ordinary traffic requires both the exact profile
GUID in `X-Azure-FDID` and the route-added origin secret. Caddy then presents an operator-provided
origin certificate. The service-tag IPs are shared by Front Door customers, so
either ordinary-traffic header check by itself is insufficient. The
Compose overlay runs the supported single-node bundle plus a disabled-by-default
`month1-workers` profile. The source-built worker process host enforces distinct
database identities, secret requirements, and health boundaries; activating the
profile still requires the role-specific connector/scheduler acceptance gates.
Caddy alone
joins the non-internal `ingress` bridge for host-published TLS and the internal
`edge` bridge for relay access; it never joins general `egress`. Stable bridge
names let the persistent `DOCKER-USER`/`INPUT` firewall reject container access
to IMDS, Caddy-initiated external forwarding, and new traffic from every Core bridge to the host
while preserving published ingress replies and host-managed-identity access.

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
   `enableMonth1Workers` is currently compiler- and bootstrap-locked to `false`;
   remove that lock only after all role business loops, credentials, and
   role-specific end-to-end tests are approved.
7. **Immutability lock:** approve only after a disposable account rehearsal and
   restore evidence. A locked policy is irreversible.
8. **Windows signing:** provision the Artifact Signing account/profile and
   approved certificate subject, then configure `AZURE_SIGNING_ENDPOINT`,
   `AZURE_SIGNING_ACCOUNT`, `AZURE_SIGNING_PROFILE`, and
   `AZURE_SIGNING_SUBJECT` in the protected `azure-trusted-signing`
   environment. Unsigned build approval does not authorize signing or Intune
   distribution.

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

- Nine immutable container references in `registry/repository@sha256:<64 hex>`
  form: the foundation-ACR bootstrap bundle, Buzz relay, Postgres/pgvector,
  Redis, MinIO, MinIO client, Caddy, Core worker, and Squid egress proxy. The bundle is a `FROM scratch` OCI
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
az bicep build --file infra/azure/main.bicep --stdout >/dev/null
bash -n infra/azure/audit/lock-retention.sh
export CADDY_TEST_IMAGE='docker.io/library/caddy@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d'
export OPENSSL_TEST_IMAGE='docker.io/alpine/openssl@sha256:42c7389ef077aed0eb4e96d0abbd094083d701bbaff1313073b061c0c9cd8278'
export FIREWALL_TEST_IMAGE='docker.io/nicolaka/netshoot@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b'
bash infra/azure/tests/run.sh
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
export BUZZ_CORE_WORKER_IMAGE='registry.invalid/core-worker@sha256:<64-hex>'
export EGRESS_PROXY_IMAGE='registry.invalid/squid@sha256:<64-hex>'
export POSTGRES_PASSWORD=validation-only REDIS_PASSWORD=validation-only
export BUZZ_S3_ACCESS_KEY=validation-only BUZZ_S3_SECRET_KEY=validation-only
export BUZZ_ORIGIN_FQDN=origin.invalid
export BUZZ_ORIGIN_SECRET=validation-only
export AZURE_FRONT_DOOR_ID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
export BUZZ_PUBLIC_HOST=buzz.validation.invalid
export RELAY_OWNER_PUBKEY=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
docker compose \
  -f deploy/compose/compose.yml \
  -f infra/azure/compose/compose.azure.yml \
  config --quiet
```

Before approving a relay image, exercise the production binary against truly
blank, isolated storage. The smoke script creates a unique Compose project and
temporary bind roots and removes only those resources when it exits. It is a
required job for every pull request; manual dispatches use
`enable_clean_volume_smoke=true`. The Dockerfile frontend, build stages, and
every Compose dependency are supplied by immutable digest:

```bash
docker build --target runtime --tag core-buzz-relay:azure-smoke .
bash infra/azure/tests/smoke-clean-volume.sh core-buzz-relay:azure-smoke
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
  --parameters enableHostBootstrap=false startCoreServices=false enableMonth1Workers=false '<approved parameters>'
```

Export the JSON what-if result for review and confirm: no inbound destination
other than 443, no broad source prefix on an allow rule, no VM power-off schedule, no DNS record,
no immutable `Locked` state, and no service activation. Treat replacement of a
VM, disk, vault, Front Door profile, storage account, or public IP as a stop.

Only after the cost/resource gate may an operator translate the reviewed
what-if into `az deployment sub create`. That mutation is intentionally not
implemented in GitHub Actions. Keep the first deployment bootstrap-disabled,
then use the separate image-publication gate to import the `FROM scratch`
bootstrap bundle into the new ACR. Record its registry digest, rerun what-if
with `bootstrapBundleImage=<acr>/...@sha256:<digest>` and
`enableHostBootstrap=true`, and obtain a second deployment approval. Keep
`startCoreServices=false` during that second phase. The bootstrap derives the
canonical public relay host from the custom domain when configured and from the
Front Door endpoint otherwise. Supply Blake's 64-character x-only public key as
`relayOwnerPubkey` before activation; `startCoreServices=true` fails closed when
that value is empty or malformed. Re-running bootstrap with
`startCoreServices=false` executes `disable --now` and fails if the running
service cannot be stopped; `true` restarts an already-active unit so refreshed
assets and secrets take effect.

Docker never owns Core restart behavior: every Compose service uses
`restart: "no"`. The foreground supervisor runs the initializer as a preflight,
watches only long-running services with `--abort-on-container-exit`, and maps
even an unexpected clean exit to failure. Systemd bounds recovery to five
attempts per ten minutes. Bootstrap masks Docker and its socket before package
installation, preloads the firewall without depending on Docker, and installs
a pre-start baseline before unmasking the daemon. That baseline blocks
forwarded IMDS traffic and new host traffic from every `buzz-*` bridge before
retained restart-policy containers can return. `PartOf=docker.service` stops
Core during a Docker restart; Docker's post-start hook restores the full
firewall before queuing an enabled Core unit. Container logs are not attached to journald, and
`ExecStopPost` removes partial containers even when preflight fails.

## Secret provisioning and activation

Seed these exact Key Vault names through an approved secure operator session:

- `postgres-password`, `redis-password`
- `minio-access-key`, `minio-secret-key`
- `relay-private-key`, `git-hook-hmac-secret`
- `frontdoor-origin-secret`
- `origin-tls-certificate`, `origin-tls-private-key`

Only when the independent worker rollout is approved, also seed:

- `openai-api-key`, `acp-signing-key`
- `crm-connector-credential-b64`, `microsoft-connector-credential-b64`,
  `google-connector-credential-b64`, `audit-blob-credential-b64`
- `connector-worker-db-password`, `sanitizer-indexer-db-password`,
  `signal-runner-db-password`, `action-executor-db-password`,
  `learning-worker-db-password`, `audit-exporter-db-password`

With `enableMonth1Workers=true`, every worker secret is mandatory and any Key
Vault read/RBAC/network failure aborts activation. The bootstrap provisions six
non-superuser login roles into fixed NOLOGIN privilege groups after migrations.
The model-facing supervisor has neither a database credential nor a route to
the data network. Signal and learning workers have no model credential or model
egress. Connector, model, and audit traffic use separate proxies; the audit
proxy permits only the exact deployed storage-account hostname.

`frontdoor-origin-secret` must be the exact generated value supplied as the
deployment's secure `originSecret` parameter; generating a second value causes
a complete origin outage. During the approved activation session, with shell
tracing disabled, compare hashes without printing either value:

```bash
set +x
expected_origin_hash=$(printf %s "$ORIGIN_SECRET" | sha256sum | cut -d' ' -f1)
vault_origin_hash=$(az keyvault secret show \
  --vault-name "$KEY_VAULT_NAME" --name frontdoor-origin-secret \
  --query value --output tsv | sha256sum | cut -d' ' -f1)
[[ $expected_origin_hash == "$vault_origin_hash" ]] || {
  echo 'Front Door and Key Vault origin secrets do not match' >&2
  exit 1
}
unset expected_origin_hash vault_origin_hash ORIGIN_SECRET
```

The dotenv values must be non-empty, single-line values limited to
letters, digits, `.`, `_`, `~`, `+`, `/`, `=`, and `-`. The PEM certificate and
private key retain their normal multiline form. `refresh-secrets.sh` retrieves
only this allowlist, writes per-service files under `/run/buzz`, authenticates to
ACR with the VM's managed identity, and never prints secret values. Azure CLI
tokens use a per-run `AZURE_CONFIG_DIR` under volatile `/run/buzz` and are
deleted when refresh finishes. Docker's short-lived ACR login is retained only
under root-only `/run/buzz/docker` so the immediately following Compose pull can
use it; reboot clears it.

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

On the live VM, also verify `iptables -S DOCKER-USER` begins with the IMDS deny,
followed by the established-reply allow and ingress-originated reject, and that
`iptables -S INPUT` has established-reply allows before rejects for all six
named `buzz-*` bridges. Restart Docker and `buzz-core`, then repeat the
checks; the Docker drop-in and Core `ExecStartPre` must both restore policy.
From a disposable test container, confirm DNS resolution still works while
connections to `169.254.169.254`, either bridge gateway, and an external test
listener fail. Confirm HTTPS through Front Door remains healthy.

## Front Door and WebSocket verification

When no custom domain is configured, the Front Door endpoint is the canonical
public host. Once a custom domain is configured, only that domain is linked to
the route and the `azurefd.net` endpoint alias must not reach the relay. Before
DNS cutover, resolve the validated custom name to Front Door locally and test
the canonical name:

```bash
curl --fail --show-error --silent 'https://<canonical-public-host>/_liveness'
websocat -n1 'wss://<canonical-public-host>/' <<'EOF'
["REQ","origin-probe",{"kinds":[39000],"limit":1}]
EOF
```

Repeat after at least one Front Door origin rotation window. Confirm an ordinary
request sent directly to the public origin is blocked by the NSG, while the
Front Door health probe remains healthy. Through VM Run Command, test Caddy's
two independent header controls without printing their values: load
`AZURE_FRONT_DOOR_ID` from `/etc/buzz/core.env` and `BUZZ_ORIGIN_SECRET` from
`/run/buzz/secrets/caddy.env`, then require 403 for missing/wrong FDID with the
correct secret and 403 for missing/wrong secret with the correct FDID on an
ordinary relay path. For `/origin-healthz`, require 403 without the exact
`X-FD-HealthProbe: 1` marker, require 403 for `POST` even with the marker, and
require 200 for exact `GET` and `HEAD` with only the marker (no FDID or route
secret). Confirm the `azurefd.net` alias is unreachable after custom-domain
activation. Review Front Door metrics for origin health, 4xx/5xx, WAF blocks,
and WebSocket disconnects.

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
az monitor diagnostic-settings list --resource '<front-door-profile-resource-id>' -o jsonc
az consumption budget show --budget-name '<approved-budget>' -o jsonc
az consumption usage list --start-date '<yyyy-mm-01>' --end-date '<yyyy-mm-dd>' -o table
```

Sending an action-group test notification or deliberately stopping the VM is a
separate operational mutation. Obtain approval, notify pilot users, run the
test, confirm common-alert-schema delivery, then restore service immediately.
Do not use auto-shutdown for Postgres, Redis, MinIO, or the relay.

The Front Door diagnostic setting exports only `FrontDoorHealthProbeLog` and
aggregate `AllMetrics`. Access and WAF request logs remain disabled because they
can retain request URLs or matched body content. Inspect WAF blocks through
aggregate metrics; do not enable content-bearing categories for this pilot.

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
