#!/usr/bin/env python3
"""Offline contracts for the disabled-by-default Azure delivery lane."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[3]
AZURE = ROOT / "infra" / "azure"


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        raise AssertionError(f"required Azure foundation artifact is missing: {relative}")
    return path.read_text(encoding="utf-8")


def assert_action_refs_are_pinned(test: unittest.TestCase, workflow: str) -> None:
    refs = re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", workflow, re.MULTILINE)
    test.assertGreater(len(refs), 0, "workflow must use pinned reusable actions")
    for ref in refs:
        if ref.startswith("./"):
            continue
        test.assertRegex(
            ref,
            r"^[^@]+@[0-9a-f]{40}$",
            f"GitHub Action must be pinned by full commit SHA: {ref}",
        )


class BicepContracts(unittest.TestCase):
    def test_main_is_parameterized_and_composes_required_modules(self) -> None:
        main = read("infra/azure/main.bicep")
        self.assertIn("targetScope = 'subscription'", main)
        self.assertRegex(main, r"param\s+location\s+string\s+=\s+'eastus2'")
        for module in (
            "network",
            "compute",
            "edge",
            "security",
            "monitoring-backup",
            "audit-storage",
            "budget",
        ):
            self.assertRegex(main, rf"module\s+\w+\s+'modules/{re.escape(module)}\.bicep'")
        forbidden_literals = (
            "subscriptions/00000000",
            "tenant.onmicrosoft.com",
            "example.com",
        )
        for literal in forbidden_literals:
            self.assertNotIn(literal, main.lower())

    def test_origin_network_exposes_only_front_door_https(self) -> None:
        network = read("infra/azure/modules/network.bicep")
        self.assertIn("AzureFrontDoor.Backend", network)
        self.assertRegex(network, r"destinationPortRange:\s*'443'")
        self.assertNotRegex(network, r"destinationPortRange:\s*'22'")
        self.assertNotRegex(network, r"(?i)(allow|inbound).{0,40}ssh")
        self.assertNotRegex(network, r"sourceAddressPrefix:\s*'\*'")

    def test_compute_is_trusted_launch_with_required_disk(self) -> None:
        compute = read("infra/azure/modules/compute.bicep")
        for expected in (
            "Standard_D4as_v5",
            "TrustedLaunch",
            "secureBootEnabled: true",
            "vTpmEnabled: true",
            "24_04-lts-gen2",
            "diskSizeGB: 256",
            "Premium_LRS",
        ):
            self.assertIn(expected, compute)

    def test_front_door_validates_origin_and_has_waf_rate_limit(self) -> None:
        edge = read("infra/azure/modules/edge.bicep")
        for expected in (
            "Standard_AzureFrontDoor",
            "originHostHeader",
            "X-Buzz-Origin-Secret",
            "healthProbeSettings",
            "WebApplicationFirewall",
            "RateLimitRule",
            "profile.properties.frontDoorId",
        ):
            self.assertIn(expected, edge)
        self.assertRegex(edge, r"enabledState:\s*'Enabled'")
        self.assertRegex(edge, r"certificateType:\s*'ManagedCertificate'")
        self.assertEqual(edge.count("cacheConfiguration: null"), 2)

    def test_front_door_rate_limit_explicitly_covers_all_client_addresses(self) -> None:
        edge = read("infra/azure/modules/edge.bicep")
        rate_rule = edge[edge.index("name: 'RateLimitRule'") : edge.index("resource securityPolicy")]
        self.assertIn("'0.0.0.0/0'", rate_rule)
        self.assertIn("'::/0'", rate_rule)
        self.assertRegex(rate_rule, r"negateCondition:\s*false")
        self.assertNotIn("255.255.255.255/32", rate_rule)

    def test_standard_front_door_waf_uses_only_supported_custom_rules(self) -> None:
        edge = read("infra/azure/modules/edge.bicep")
        self.assertIn("Standard_AzureFrontDoor", edge)
        self.assertNotIn("managedRules", edge)
        self.assertNotIn("DefaultRuleSet", edge)
        self.assertNotIn("BotManager", edge)
        self.assertIn("customRules", edge)

    def test_platform_includes_registry_vault_monitor_backup_dns_and_budget(self) -> None:
        security = read("infra/azure/modules/security.bicep")
        monitoring = read("infra/azure/modules/monitoring-backup.bicep")
        budget = read("infra/azure/modules/budget.bicep")
        main = read("infra/azure/main.bicep")
        dns = read("infra/azure/modules/dns.bicep")
        self.assertIn("Microsoft.ContainerRegistry/registries", security)
        self.assertIn("adminUserEnabled: false", security)
        self.assertIn("Microsoft.ContainerRegistry", read("infra/azure/modules/network.bicep"))
        registry_block = security[security.index("resource registry") : security.index("resource keyVault")]
        self.assertIn("networkRuleSet", registry_block)
        self.assertRegex(registry_block, r"defaultAction:\s*'Deny'")
        self.assertIn("virtualNetworkRules", registry_block)
        self.assertIn("virtualNetworkSubnetResourceId: subnetId", registry_block)
        self.assertIn("enableRbacAuthorization: true", security)
        self.assertRegex(security, r"param\s+subnetId\s+string")
        security_module = main[main.index("module security") : main.index("module compute")]
        self.assertIn("subnetId: network.outputs.subnetId", security_module)
        self.assertIn("Microsoft.OperationalInsights/workspaces", monitoring)
        self.assertIn("Microsoft.RecoveryServices/vaults", monitoring)
        self.assertIn("Microsoft.Insights/metricAlerts", monitoring)
        self.assertIn("Microsoft.Network/dnsZones", dns)
        self.assertRegex(budget, r"param\s+monthlyBudgetUsd\s+int\s+=\s+350")
        for threshold in (70, 85, 100):
            self.assertRegex(
                budget,
                rf"(?s)actual{threshold}:\s*\{{.*?threshold:\s*{threshold}\b.*?thresholdType:\s*'Actual'",
            )
        self.assertNotRegex(main + monitoring, r"(?i)auto.?shutdown")

    def test_audit_retention_is_modeled_but_lock_requires_explicit_opt_in(self) -> None:
        audit = read("infra/azure/modules/audit-storage.bicep")
        lock = read("infra/azure/audit/lock-retention.sh")
        self.assertIn("allowProtectedAppendWrites: true", audit)
        self.assertRegex(audit, r"immutabilityPeriodSinceCreationInDays:\s*2555")
        self.assertIn("output immutabilityState string = 'Unlocked'", audit)
        self.assertIn("confirm_lock=false", lock)
        self.assertIn("--confirm-lock", lock)
        self.assertIn("--rehearsal-evidence", lock)
        self.assertIn("az storage container immutability-policy lock", lock)
        self.assertIn('if [[ $confirm_lock != true ]]', lock)
        self.assertNotIn("lock-retention.sh", read("infra/azure/main.bicep"))
        result = subprocess.run(
            ["bash", "-n", str(AZURE / "audit" / "lock-retention.sh")],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


class ComposeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("docker"):
            raise unittest.SkipTest("docker executable is unavailable")
        env = os.environ.copy()
        digest = "sha256:" + "a" * 64
        env.update(
            {
                "BUZZ_RELAY_IMAGE": f"corebuzz.azurecr.io/buzz-relay@{digest}",
                "POSTGRES_IMAGE": f"docker.io/pgvector/pgvector@{digest}",
                "REDIS_IMAGE": f"docker.io/library/redis@{digest}",
                "MINIO_IMAGE": f"quay.io/minio/minio@{digest}",
                "MINIO_MC_IMAGE": f"quay.io/minio/mc@{digest}",
                "CADDY_IMAGE": f"docker.io/library/caddy@{digest}",
                "POSTGRES_PASSWORD": "contract-postgres",
                "REDIS_PASSWORD": "contract-redis",
                "BUZZ_S3_ACCESS_KEY": "contract-access",
                "BUZZ_S3_SECRET_KEY": "contract-secret",
                "BUZZ_ORIGIN_FQDN": "origin.invalid",
                "BUZZ_ORIGIN_SECRET": "contract-origin-secret",
                "AZURE_FRONT_DOOR_ID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            }
        )
        command = [
            "docker",
            "compose",
            "-f",
            str(ROOT / "deploy" / "compose" / "compose.yml"),
            "-f",
            str(AZURE / "compose" / "compose.azure.yml"),
            "config",
            "--format",
            "json",
        ]
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(f"docker compose config failed:\n{result.stderr}")
        cls.config = json.loads(result.stdout)

    def test_all_images_are_digest_pinned(self) -> None:
        for service, config in self.config["services"].items():
            self.assertRegex(
                config["image"],
                r"^[^\s:@]+(?:[/:][^\s:@]+)+@sha256:[0-9a-f]{64}$",
                f"{service} image must be supplied by immutable digest",
            )

    def test_every_service_has_container_hardening_health_and_limits(self) -> None:
        for service, config in self.config["services"].items():
            self.assertTrue(config.get("read_only"), f"{service} root must be read-only")
            self.assertIn("ALL", config.get("cap_drop", []), f"{service} must drop all capabilities")
            self.assertIn(
                "no-new-privileges:true",
                config.get("security_opt", []),
                f"{service} must disable privilege escalation",
            )
            self.assertTrue(config.get("tmpfs"), f"{service} must use tmpfs for runtime writes")
            self.assertIn("healthcheck", config, f"{service} must define a health check")
            limits = config.get("deploy", {}).get("resources", {}).get("limits", {})
            self.assertIn("cpus", limits, f"{service} must set a CPU limit")
            self.assertIn("memory", limits, f"{service} must set a memory limit")
            self.assertNotIn(config.get("user", "root").split(":", 1)[0], ("", "0", "root"))
            self.assertFalse(config.get("privileged", False), f"{service} must not be privileged")

    def test_networks_separate_edge_data_broker_connector_and_egress(self) -> None:
        expected_active = {"edge", "relay-data", "broker", "egress"}
        self.assertTrue(expected_active.issubset(self.config["networks"]))
        overlay = read("infra/azure/compose/compose.azure.yml")
        self.assertRegex(overlay, r"(?m)^\s{2}connector-internal:\s*$")
        self.assertNotRegex(overlay, r"(?m)^\s{2}(connector|sanitizer|indexer|executor):\s*$")
        self.assertEqual(set(self.config["services"]["caddy"]["networks"]), {"edge", "egress"})
        self.assertEqual(
            set(self.config["services"]["relay"]["networks"]),
            {"edge", "relay-data", "broker", "egress"},
        )
        self.assertEqual(set(self.config["services"]["postgres"]["networks"]), {"relay-data"})
        self.assertEqual(set(self.config["services"]["redis"]["networks"]), {"broker"})
        self.assertRegex(
            overlay,
            r"(?ms)^\s{2}connector-internal:\s*\n(?:\s{4}.+\n)*?\s{4}internal:\s*true\s*$",
        )

    def test_only_caddy_publishes_origin_https(self) -> None:
        for service, config in self.config["services"].items():
            ports = config.get("ports", [])
            if service == "caddy":
                self.assertEqual(len(ports), 1)
                self.assertEqual(ports[0]["target"], 8443)
                self.assertEqual(ports[0]["published"], "443")
            else:
                self.assertEqual(ports, [], f"{service} must not publish a host port")

    def test_caddy_rejects_missing_origin_secret_and_proxies_websockets(self) -> None:
        caddy = read("infra/azure/compose/Caddyfile.azure")
        self.assertIn("X-Buzz-Origin-Secret", caddy)
        self.assertRegex(
            caddy,
            r"@invalid_fdid\s+not\s+header\s+X-Azure-FDID\s+\{\$AZURE_FRONT_DOOR_ID\}",
        )
        self.assertRegex(caddy, r"respond\s+@invalid_fdid\s+403")
        self.assertRegex(
            caddy,
            r"@invalid_origin_secret\s+not\s+header\s+X-Buzz-Origin-Secret\s+\{\$BUZZ_ORIGIN_SECRET\}",
        )
        self.assertRegex(caddy, r"respond\s+@invalid_origin_secret\s+403")
        self.assertIn("/_readiness", caddy)
        self.assertRegex(caddy, r"reverse_proxy\s+relay:3000")


class HostAndDeliveryContracts(unittest.TestCase):
    def test_bootstrap_assets_come_from_digest_pinned_acr_bundle(self) -> None:
        main = read("infra/azure/main.bicep")
        compute = read("infra/azure/modules/compute.bicep")
        host_bootstrap = read("infra/azure/modules/host-bootstrap.bicep")
        bootstrap = read("infra/azure/bootstrap/bootstrap.sh")
        delivery = read(".github/workflows/azure-delivery.yml")
        combined = main + compute + host_bootstrap
        self.assertNotIn("raw.githubusercontent.com", combined)
        self.assertNotIn("block/buzz", combined)
        self.assertNotIn("deploymentSourceRef", combined)
        self.assertRegex(main, r"param\s+bootstrapBundleImage\s+string")
        self.assertRegex(main, r"module\s+\w+\s+'modules/host-bootstrap\.bicep'")
        self.assertIn("loadTextContent('../bootstrap/bootstrap.sh')", host_bootstrap)
        self.assertIn("configPayload = base64(string(", host_bootstrap)
        self.assertIn("protectedSettings", host_bootstrap)
        self.assertIn("script: scriptPayload", host_bootstrap)
        self.assertNotIn("commandToExecute", host_bootstrap)
        self.assertRegex(bootstrap, r"@sha256:\[0-9a-f\]\{64\}")
        self.assertIn('docker pull "$bootstrap_bundle_image"', bootstrap)
        self.assertIn("infra/azure/bootstrap/Dockerfile", delivery)
        self.assertIn("variant: bootstrap", delivery)

    def test_bootstrap_config_rejects_shell_injection_values(self) -> None:
        bootstrap = ROOT / "infra" / "azure" / "bootstrap" / "bootstrap.sh"
        valid = {
            "acrName": "corebuzzacr",
            "keyVaultName": "core-buzz-kv",
            "originFqdn": "origin.core.invalid",
            "originSecretName": "frontdoor-origin-secret",
            "frontDoorId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "bootstrapBundleImage": "corebuzzacr.azurecr.io/bootstrap@sha256:" + "a" * 64,
            "relayImage": "corebuzzacr.azurecr.io/relay@sha256:" + "a" * 64,
            "postgresImage": "docker.io/pgvector/pgvector@sha256:" + "a" * 64,
            "redisImage": "docker.io/library/redis@sha256:" + "a" * 64,
            "minioImage": "quay.io/minio/minio@sha256:" + "a" * 64,
            "minioMcImage": "quay.io/minio/mc@sha256:" + "a" * 64,
            "caddyImage": "docker.io/library/caddy@sha256:" + "a" * 64,
            "startServices": False,
        }

        def validate(config: dict[str, object]) -> subprocess.CompletedProcess[str]:
            import base64

            payload = base64.b64encode(json.dumps(config).encode()).decode()
            return subprocess.run(
                ["bash", str(bootstrap), "--validate-config-base64", payload],
                text=True,
                capture_output=True,
                check=False,
            )

        accepted = validate(valid)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        for field, malicious in (
            ("originFqdn", "origin.invalid; touch /tmp/pwned"),
            ("acrName", "$(id)"),
            ("originSecretName", "secret\nINJECTED=value"),
            ("frontDoorId", "not-a-guid; id"),
            ("relayImage", "registry.invalid/relay:latest"),
            ("bootstrapBundleImage", "registry.invalid/bootstrap@sha256:" + "g" * 64),
        ):
            fixture = dict(valid)
            fixture[field] = malicious
            rejected = validate(fixture)
            self.assertNotEqual(rejected.returncode, 0, f"accepted malicious {field}")

    def test_bootstrap_is_valid_idempotent_shell_and_unit_refreshes_secrets(self) -> None:
        bootstrap = ROOT / "infra" / "azure" / "bootstrap" / "bootstrap.sh"
        refresh = ROOT / "infra" / "azure" / "bootstrap" / "refresh-secrets.sh"
        unit = read("infra/azure/bootstrap/buzz-core.service")
        for script in (bootstrap, refresh):
            self.assertTrue(script.is_file(), f"missing {script.relative_to(ROOT)}")
            result = subprocess.run(
                ["bash", "-n", str(script)], text=True, capture_output=True, check=False
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        bootstrap_text = bootstrap.read_text(encoding="utf-8")
        for expected in ("blkid", "mountpoint", "install -d", "systemctl enable"):
            self.assertIn(expected, bootstrap_text)
        refresh_text = refresh.read_text(encoding="utf-8")
        for expected in ("az login --identity", "az acr login", "az keyvault secret show"):
            self.assertIn(expected, refresh_text)
        self.assertIn("RequiresMountsFor=/srv/buzz", unit)
        self.assertIn("ExecStartPre=/usr/local/sbin/buzz-core-refresh-secrets", unit)
        self.assertIn("docker compose", unit)
        self.assertNotRegex(bootstrap_text + refresh_text + unit, r"(?i)(client_secret|azure_credentials)")

    def test_validation_workflow_is_offline_by_default_and_uses_oidc_for_what_if(self) -> None:
        workflow = read(".github/workflows/azure-foundation-validate.yml")
        assert_action_refs_are_pinned(self, workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("azure/login", workflow)
        self.assertIn("vars.AZURE_CLIENT_ID", workflow)
        self.assertIn("az deployment sub what-if", workflow)
        self.assertIn("enable_what_if", workflow)
        self.assertIn("python3 infra/azure/tests/test_contracts.py", workflow)
        self.assertIn("az bicep build", workflow)
        self.assertIn("docker compose", workflow)
        self.assertNotRegex(workflow, r"(?i)(AZURE_CREDENTIALS|client[_-]?secret|AZURE[_-].*password\s*:)")

    def test_delivery_builds_unsigned_artifacts_and_gates_trusted_signing(self) -> None:
        workflow = read(".github/workflows/azure-delivery.yml")
        assert_action_refs_are_pinned(self, workflow)
        for expected in (
            "push: false",
            "sbom: true",
            "provenance: mode=max",
            "sha256sum",
            "--bundles nsis",
            '"createUpdaterArtifacts": false',
            "enable_signing",
            "environment: azure-trusted-signing",
            "azure/artifact-signing-action",
            "id-token: write",
            "syft_1.44.0_windows_amd64.zip",
            "buzz-windows.spdx.json",
            "version-manifest.json",
            "provenance.json",
            "Get-AuthenticodeSignature",
            "signed = $true",
        ):
            self.assertIn(expected, workflow)
        self.assertNotRegex(workflow, r"(?i)(AZURE_CREDENTIALS|client[_-]?secret|AZURE[_-].*password\s*:)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
