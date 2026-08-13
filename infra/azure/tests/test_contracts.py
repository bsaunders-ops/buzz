#!/usr/bin/env python3
"""Offline contracts for the disabled-by-default Azure delivery lane."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
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
        allow_rule = network[
            network.index("name: 'AllowFrontDoorBackendHttps'") : network.index(
                "name: 'DenyAllInbound'"
            )
        ]
        self.assertNotRegex(allow_rule, r"sourceAddressPrefix:\s*'\*'")
        deny_rule = network[network.index("name: 'DenyAllInbound'") :]
        for expected in (
            "priority: 200",
            "access: 'Deny'",
            "direction: 'Inbound'",
            "protocol: '*'",
            "destinationPortRange: '*'",
            "sourceAddressPrefix: '*'",
        ):
            self.assertIn(expected, deny_rule)

    def test_compute_is_trusted_launch_with_required_disk(self) -> None:
        compute = read("infra/azure/modules/compute.bicep")
        for expected in (
            "Standard_D4as_v7",
            "TrustedLaunch",
            "secureBootEnabled: true",
            "vTpmEnabled: true",
            "sku: 'server'",
            "diskSizeGB: 256",
            "Premium_LRS",
        ):
            self.assertIn(expected, compute)
        entra_login = compute[
            compute.index("resource entraLogin") : compute.index("resource monitorAgent")
        ]
        self.assertIn("autoUpgradeMinorVersion: true", entra_login)
        self.assertNotIn("enableAutomaticUpgrade", entra_login)

    def test_front_door_validates_origin_and_has_waf_rate_limit(self) -> None:
        edge = read("infra/azure/modules/edge.bicep")
        for expected in (
            "Standard_AzureFrontDoor",
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
        self.assertNotRegex(edge, r"originPath:\s*''")
        self.assertIn("name: 'originValidation'", edge)
        self.assertIn("name: 'addOriginSecret'", edge)
        self.assertNotIn(
            "originHostHeader",
            edge,
            "Front Door must preserve the public Host used for tenant and NIP auth binding",
        )
        self.assertIn(
            "linkToDefaultDomain: customDomainEnabled ? 'Disabled' : 'Enabled'",
            edge,
        )
        self.assertRegex(
            edge,
            r"resource\s+route\s+'[^']+'\s*=\s*if\s*\(!customDomainEnabled\)",
            "default and custom-domain routes must be mutually exclusive",
        )
        self.assertRegex(
            edge,
            r"output\s+publicHost\s+string\s*=\s*customDomainEnabled\s*\?\s*customDomainHostName\s*:\s*endpoint\.properties\.hostName",
        )

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
        self.assertNotIn("trustPolicy", registry_block)
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

    def test_trusted_launch_backup_uses_enhanced_v2_policy(self) -> None:
        monitoring = read("infra/azure/modules/monitoring-backup.bicep")
        policy = monitoring[
            monitoring.index("resource dailyPolicy") : monitoring.index(
                "resource protectedVm"
            )
        ]
        self.assertIn("policyType: 'V2'", policy)
        self.assertIn("schedulePolicyType: 'SimpleSchedulePolicyV2'", policy)
        self.assertRegex(policy, r"scheduleRunFrequency:\s*'Daily'")
        self.assertRegex(
            policy,
            r"(?s)schedulePolicy:\s*\{.*?dailySchedule:\s*\{\s*scheduleRunTimes:\s*\[\s*'2026-08-03T02:00:00Z'",
        )
        self.assertNotRegex(policy, r"schedulePolicyType:\s*'SimpleSchedulePolicy'")
        self.assertRegex(policy, r"instantRpRetentionRangeInDays:\s*5\b")
        self.assertRegex(
            policy,
            r"(?s)retentionPolicy:.*?dailySchedule:.*?retentionTimes:\s*\[\s*'2026-08-03T02:00:00Z'.*?count:\s*30\b.*?durationType:\s*'Days'",
        )
        self.assertRegex(policy, r"timeZone:\s*'UTC'")

    def test_front_door_emits_content_free_health_diagnostics_and_alerts(self) -> None:
        monitoring = read("infra/azure/modules/monitoring-backup.bicep")
        main = read("infra/azure/main.bicep")
        edge = read("infra/azure/modules/edge.bicep")
        self.assertRegex(edge, r"output\s+profileName\s+string")
        self.assertIn("frontDoorProfileName: edge.outputs.profileName", main)
        self.assertIn("Microsoft.Cdn/profiles", monitoring)
        self.assertIn("FrontDoorHealthProbeLog", monitoring)
        self.assertIn("OriginHealthPercentage", monitoring)
        self.assertIn("AllMetrics", monitoring)
        self.assertNotIn(
            "FrontDoorAccessLog",
            monitoring,
            "access logs can persist request URLs and are outside the no-content logging boundary",
        )
        self.assertNotIn(
            "FrontDoorWebApplicationFirewallLog",
            monitoring,
            "WAF request logs can persist matched request content; use WAF metrics instead",
        )

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
        cls._fixture_dir = tempfile.TemporaryDirectory(prefix="buzz-compose-contract-")
        fixture_dir = Path(cls._fixture_dir.name)
        secret_values = {
            "relay.env": {
                "DATABASE_URL": "postgres://buzz:file-postgres@postgres:5432/buzz",
                "REDIS_URL": "redis://:file-redis@redis:6379",
                "BUZZ_S3_ACCESS_KEY": "file-access",
                "BUZZ_S3_SECRET_KEY": "file-secret",
                "BUZZ_RELAY_PRIVATE_KEY": "1" * 64,
                "BUZZ_GIT_HOOK_HMAC_SECRET": "2" * 64,
            },
            "postgres.env": {"POSTGRES_PASSWORD": "file-postgres"},
            "redis.env": {"REDIS_PASSWORD": "file-redis"},
            "minio.env": {
                "MINIO_ROOT_USER": "file-access",
                "MINIO_ROOT_PASSWORD": "file-secret",
            },
            "minio-init.env": {
                "BUZZ_S3_ACCESS_KEY": "file-access",
                "BUZZ_S3_SECRET_KEY": "file-secret",
            },
            "caddy.env": {"BUZZ_ORIGIN_SECRET": "file-origin-secret"},
            "agent-supervisor.env": {
                "BUZZ_RELAY_URL": "wss://buzz.contract.invalid",
                "OPENAI_COMPAT_API_KEY": "file-openai",
                "BUZZ_ACP_SIGNING_KEY": "3" * 64,
            },
            "connector-worker.env": {
                "DATABASE_URL": "postgres://buzz_connector_worker:file@postgres:5432/buzz",
                "CORE_CRM_CREDENTIAL_B64": "Y3Jt",
                "MICROSOFT_CONNECTOR_CREDENTIAL_B64": "bXM=",
                "GOOGLE_CONNECTOR_CREDENTIAL_B64": "Z29vZ2xl",
            },
            "sanitizer-indexer.env": {
                "DATABASE_URL": "postgres://buzz_sanitizer_indexer:file@postgres:5432/buzz"
            },
            "signal-runner.env": {
                "DATABASE_URL": "postgres://buzz_signal_runner:file@postgres:5432/buzz"
            },
            "action-executor.env": {
                "DATABASE_URL": "postgres://buzz_action_executor:file@postgres:5432/buzz",
                "CORE_CRM_CREDENTIAL_B64": "Y3Jt",
                "MICROSOFT_CONNECTOR_CREDENTIAL_B64": "bXM=",
                "GOOGLE_CONNECTOR_CREDENTIAL_B64": "Z29vZ2xl",
                "BUZZ_ACP_SIGNING_KEY": "4" * 64,
            },
            "learning-worker.env": {
                "DATABASE_URL": "postgres://buzz_learning_worker:file@postgres:5432/buzz"
            },
            "audit-exporter.env": {
                "DATABASE_URL": "postgres://buzz_audit_exporter:file@postgres:5432/buzz",
                "AUDIT_BLOB_CREDENTIAL_B64": "YXVkaXQ=",
            },
        }
        for name, values in secret_values.items():
            (fixture_dir / name).write_text(
                "".join(f"{key}={value}\n" for key, value in values.items()),
                encoding="utf-8",
            )
        cls.secret_values = secret_values
        env_override = fixture_dir / "secret-files.compose.yml"
        services = {
            "relay": "relay.env",
            "postgres": "postgres.env",
            "redis": "redis.env",
            "minio": "minio.env",
            "minio-init": "minio-init.env",
            "caddy": "caddy.env",
            "agent-supervisor": "agent-supervisor.env",
            "connector-worker": "connector-worker.env",
            "sanitizer-indexer": "sanitizer-indexer.env",
            "signal-runner": "signal-runner.env",
            "action-executor": "action-executor.env",
            "learning-worker": "learning-worker.env",
            "audit-exporter": "audit-exporter.env",
        }
        override_lines = ["services:"]
        for service, env_name in services.items():
            env_path = json.dumps((fixture_dir / env_name).as_posix())
            override_lines.extend(
                (
                    f"  {service}:",
                    "    env_file: !override",
                    f"      - path: {env_path}",
                    "        required: true",
                )
            )
        env_override.write_text("\n".join(override_lines) + "\n", encoding="utf-8")

        env = os.environ.copy()
        digest = "sha256:" + "a" * 64
        env.update(
            {
                "BUZZ_RELAY_IMAGE": f"corebuzz.azurecr.io/buzz-relay@{digest}",
                "BUZZ_CORE_WORKER_IMAGE": f"corebuzz.azurecr.io/buzz-core-worker@{digest}",
                "EGRESS_PROXY_IMAGE": f"docker.io/library/squid@{digest}",
                "POSTGRES_IMAGE": f"docker.io/pgvector/pgvector@{digest}",
                "REDIS_IMAGE": f"docker.io/library/redis@{digest}",
                "MINIO_IMAGE": f"quay.io/minio/minio@{digest}",
                "MINIO_MC_IMAGE": f"quay.io/minio/mc@{digest}",
                "CADDY_IMAGE": f"docker.io/library/caddy@{digest}",
                "POSTGRES_PASSWORD": "interpolation-postgres",
                "REDIS_PASSWORD": "interpolation-redis",
                "BUZZ_S3_ACCESS_KEY": "interpolation-access",
                "BUZZ_S3_SECRET_KEY": "interpolation-secret",
                "BUZZ_ORIGIN_FQDN": "origin.invalid",
                "AZURE_FRONT_DOOR_ID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "BUZZ_PUBLIC_HOST": "buzz.contract.invalid",
                "RELAY_OWNER_PUBKEY": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            }
        )
        command = [
            "docker",
            "compose",
            "-f",
            str(ROOT / "deploy" / "compose" / "compose.yml"),
            "-f",
            str(AZURE / "compose" / "compose.azure.yml"),
            "-f",
            str(env_override),
            "--profile",
            "month1-workers",
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

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "_fixture_dir"):
            cls._fixture_dir.cleanup()

    def test_per_service_secret_files_survive_compose_merge(self) -> None:
        for service, env_file in (
            ("relay", "relay.env"),
            ("postgres", "postgres.env"),
            ("redis", "redis.env"),
            ("minio", "minio.env"),
            ("minio-init", "minio-init.env"),
            ("caddy", "caddy.env"),
        ):
            rendered = self.config["services"][service]["environment"]
            for key, expected in self.secret_values[env_file].items():
                self.assertEqual(
                    rendered.get(key),
                    expected,
                    f"{service} must receive {key} from its least-privilege env file",
                )

    def test_relay_migrates_a_blank_database_before_readiness(self) -> None:
        relay_env = self.config["services"]["relay"]["environment"]
        self.assertEqual(relay_env.get("BUZZ_AUTO_MIGRATE"), "true")

    def test_relay_uses_closed_month1_configuration(self) -> None:
        relay_env = self.config["services"]["relay"]["environment"]
        expected = {
            "RELAY_URL": "wss://buzz.contract.invalid",
            "RELAY_OWNER_PUBKEY": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "BUZZ_REQUIRE_RELAY_MEMBERSHIP": "true",
            "BUZZ_REQUIRE_AUTH_TOKEN": "true",
            "BUZZ_ALLOW_NIP_OA_AUTH": "false",
            "BUZZ_PUSH_GATEWAY_DELIVERY_URL": "",
            "BUZZ_WEB_DIR": "",
            "BUZZ_ADMIN_WEB_DIR": "",
            "BUZZ_GIT_ENABLED": "false",
            "BUZZ_SERVE_GIT_WEB_GUI": "false",
            "BUZZ_HUDDLE_AUDIO_AVAILABLE": "false",
        }
        for key, value in expected.items():
            self.assertEqual(relay_env.get(key), value, f"closed relay setting {key} drifted")

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
        expected_active = {"ingress", "edge", "relay-data", "broker"}
        self.assertTrue(expected_active.issubset(self.config["networks"]))
        overlay = read("infra/azure/compose/compose.azure.yml")
        self.assertRegex(overlay, r"(?m)^\s{2}connector-internal:\s*$")
        self.assertRegex(overlay, r"(?m)^\s{2}egress:\s*$")
        required_workers = {
            "agent-supervisor",
            "connector-worker",
            "sanitizer-indexer",
            "signal-runner",
            "action-executor",
            "learning-worker",
            "audit-exporter",
            "connector-egress-proxy",
            "model-egress-proxy",
            "audit-egress-proxy",
        }
        self.assertTrue(required_workers.issubset(self.config["services"]))
        for service in required_workers:
            self.assertEqual(
                self.config["services"][service].get("profiles"),
                ["month1-workers"],
                f"{service} must stay disabled until its rollout gate is approved",
            )
        self.assertEqual(
            set(self.config["services"]["caddy"]["networks"]),
            {"ingress", "edge"},
        )
        self.assertEqual(
            set(self.config["services"]["relay"]["networks"]),
            {"edge", "relay-data", "broker"},
        )
        self.assertEqual(set(self.config["services"]["postgres"]["networks"]), {"relay-data"})
        self.assertEqual(set(self.config["services"]["redis"]["networks"]), {"broker"})
        self.assertRegex(
            overlay,
            r"(?ms)^\s{2}connector-internal:\s*\n(?:\s{4}.+\n)*?\s{4}internal:\s*true\s*$",
        )
        egress_services = {
            service
            for service, config in self.config["services"].items()
            if "egress" in config.get("networks", [])
        }
        self.assertEqual(
            egress_services,
            {"connector-egress-proxy", "model-egress-proxy", "audit-egress-proxy"},
            "only allowlisting proxies may reach external egress",
        )
        for worker in required_workers - {
            "connector-egress-proxy",
            "model-egress-proxy",
            "audit-egress-proxy",
        }:
            self.assertNotIn("egress", self.config["services"][worker].get("networks", []))
        expected_bridges = {
            "ingress": "buzz-ingress",
            "edge": "buzz-edge",
            "relay-data": "buzz-data",
            "broker": "buzz-broker",
            "connector-internal": "buzz-connector",
            "model-internal": "buzz-model",
            "audit-internal": "buzz-audit",
            "egress": "buzz-egress",
        }
        for network, bridge in expected_bridges.items():
            self.assertLessEqual(len(bridge), 15)
            self.assertRegex(
                overlay,
                rf"(?ms)^\s{{2}}{re.escape(network)}:\s*\n(?:\s{{4}}.+\n)*?\s{{6}}com\.docker\.network\.bridge\.name:\s*{bridge}\s*$",
            )

    def test_model_credential_boundary_has_no_database_path(self) -> None:
        supervisor = self.config["services"]["agent-supervisor"]
        self.assertNotIn("DATABASE_URL", supervisor.get("environment", {}))
        self.assertNotIn("relay-data", supervisor.get("networks", []))
        for worker in (
            "connector-worker",
            "sanitizer-indexer",
            "signal-runner",
            "action-executor",
            "learning-worker",
            "audit-exporter",
        ):
            self.assertNotIn(
                "OPENAI_COMPAT_API_KEY",
                self.config["services"][worker].get("environment", {}),
            )
            self.assertNotIn("model-internal", self.config["services"][worker]["networks"])

    def test_workers_use_distinct_least_privilege_database_logins(self) -> None:
        expected = {
            "connector-worker": "buzz_connector_worker",
            "sanitizer-indexer": "buzz_sanitizer_indexer",
            "signal-runner": "buzz_signal_runner",
            "action-executor": "buzz_action_executor",
            "learning-worker": "buzz_learning_worker",
            "audit-exporter": "buzz_audit_exporter",
        }
        for service, role in expected.items():
            url = self.config["services"][service]["environment"]["DATABASE_URL"]
            self.assertTrue(url.startswith(f"postgres://{role}:"), service)

    def test_connector_proxy_has_no_multitenant_storage_wildcards(self) -> None:
        connector_proxy = read("infra/azure/compose/squid-connectors.conf")
        self.assertNotRegex(connector_proxy, r"(?m)^\s+\.blob\.core\.windows\.net")
        self.assertNotRegex(connector_proxy, r"(?m)^\s+\.googleapis\.com")
        self.assertNotRegex(connector_proxy, r"(?m)^\s+\.google\.com")
        self.assertIn("www.googleapis.com", connector_proxy)
        for host in (
            "docs.googleapis.com",
            "sheets.googleapis.com",
            "slides.googleapis.com",
        ):
            self.assertIn(host, connector_proxy)
        refresh = read("infra/azure/bootstrap/refresh-secrets.sh")
        self.assertIn("${AUDIT_STORAGE_ACCOUNT_NAME}.blob.core.windows.net", refresh)

    def test_only_caddy_publishes_origin_https(self) -> None:
        for service, config in self.config["services"].items():
            ports = config.get("ports", [])
            if service == "caddy":
                self.assertEqual(len(ports), 1)
                self.assertEqual(ports[0]["target"], 8443)
                self.assertEqual(ports[0]["published"], "443")
            else:
                self.assertEqual(ports, [], f"{service} must not publish a host port")

    def test_systemd_exclusively_owns_container_restart_policy(self) -> None:
        for service in ("relay", "postgres", "redis", "minio", "minio-init", "caddy"):
            self.assertEqual(
                self.config["services"][service].get("restart"),
                "no",
                f"{service} must not be revived by Docker before the host firewall",
            )

    def test_caddy_rejects_missing_origin_secret_and_proxies_websockets(self) -> None:
        caddy = read("infra/azure/compose/Caddyfile.azure")
        self.assertRegex(caddy, r"(?m)^:8443\s*\{")
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
        self.assertRegex(
            caddy,
            r"(?s)@front_door_health_probe\s*\{.*?path\s+/origin-healthz.*?method\s+GET\s+HEAD.*?header\s+X-FD-HealthProbe\s+1.*?\}",
        )
        self.assertIn("/_readiness", caddy)
        self.assertRegex(caddy, r"reverse_proxy\s+relay:3000")
        self.assertLess(caddy.index("@front_door_health_probe"), caddy.index("@invalid_fdid"))
        self.assertLess(caddy.index("@invalid_fdid"), caddy.index("@invalid_origin_secret"))


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
        self.assertRegex(main, r"param\s+relayOwnerPubkey\s+string")
        self.assertIn("publicHost: edge.outputs.publicHost", main)
        self.assertIn("relayOwnerPubkey: relayOwnerPubkey", main)
        self.assertRegex(host_bootstrap, r"param\s+publicHost\s+string")
        self.assertRegex(host_bootstrap, r"param\s+relayOwnerPubkey\s+string")
        self.assertIn("protectedSettings", host_bootstrap)
        self.assertIn("script: scriptPayload", host_bootstrap)
        self.assertNotIn("commandToExecute", host_bootstrap)
        self.assertRegex(bootstrap, r"@sha256:\[0-9a-f\]\{64\}")
        self.assertIn('docker pull "$bootstrap_bundle_image"', bootstrap)
        self.assertIn("infra/azure/bootstrap/Dockerfile", delivery)
        self.assertIn("variant: bootstrap", delivery)
        self.assertIn("variant: core-worker", delivery)
        worker_dockerfile = read("infra/azure/worker/Dockerfile")
        self.assertRegex(worker_dockerfile, r"RUST_BUILD_IMAGE=.*@sha256:[0-9a-f]{64}")
        self.assertRegex(worker_dockerfile, r"DEBIAN_RUNTIME_IMAGE=.*@sha256:[0-9a-f]{64}")

    def test_bootstrap_config_rejects_shell_injection_values(self) -> None:
        bootstrap = ROOT / "infra" / "azure" / "bootstrap" / "bootstrap.sh"
        valid = {
            "acrName": "corebuzzacr",
            "keyVaultName": "core-buzz-kv",
            "originFqdn": "origin.core.invalid",
            "originSecretName": "frontdoor-origin-secret",
            "frontDoorId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "publicHost": "buzz.core.invalid",
            "relayOwnerPubkey": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "bootstrapBundleImage": "corebuzzacr.azurecr.io/bootstrap@sha256:" + "a" * 64,
            "relayImage": "corebuzzacr.azurecr.io/relay@sha256:" + "a" * 64,
            "postgresImage": "docker.io/pgvector/pgvector@sha256:" + "a" * 64,
            "redisImage": "docker.io/library/redis@sha256:" + "a" * 64,
            "minioImage": "quay.io/minio/minio@sha256:" + "a" * 64,
            "minioMcImage": "quay.io/minio/mc@sha256:" + "a" * 64,
            "caddyImage": "docker.io/library/caddy@sha256:" + "a" * 64,
            "coreWorkerImage": "corebuzzacr.azurecr.io/core-worker@sha256:" + "a" * 64,
            "egressProxyImage": "docker.io/library/squid@sha256:" + "a" * 64,
            "auditStorageAccountName": "corebuzzaudit",
            "enableMonth1Workers": False,
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
            ("publicHost", "buzz.invalid; id"),
            ("relayOwnerPubkey", "not-a-pubkey"),
            ("relayImage", "registry.invalid/relay:latest"),
            ("bootstrapBundleImage", "registry.invalid/bootstrap@sha256:" + "g" * 64),
        ):
            fixture = dict(valid)
            fixture[field] = malicious
            rejected = validate(fixture)
            self.assertNotEqual(rejected.returncode, 0, f"accepted malicious {field}")

        missing_owner = dict(valid)
        missing_owner["relayOwnerPubkey"] = ""
        missing_owner["startServices"] = True
        rejected = validate(missing_owner)
        self.assertNotEqual(
            rejected.returncode,
            0,
            "service activation must fail closed without a valid relay owner",
        )

        incomplete_workers = dict(valid)
        incomplete_workers["enableMonth1Workers"] = True
        rejected = validate(incomplete_workers)
        self.assertNotEqual(
            rejected.returncode,
            0,
            "health-only worker process hosts must not be production-activatable",
        )

    def test_bootstrap_is_valid_idempotent_shell_and_unit_refreshes_secrets(self) -> None:
        bootstrap = ROOT / "infra" / "azure" / "bootstrap" / "bootstrap.sh"
        refresh = ROOT / "infra" / "azure" / "bootstrap" / "refresh-secrets.sh"
        clean_volume_smoke = (
            ROOT / "infra" / "azure" / "tests" / "smoke-clean-volume.sh"
        )
        caddy_runtime = (
            ROOT / "infra" / "azure" / "tests" / "test-caddy-origin-policy.sh"
        )
        firewall_runtime = (
            ROOT / "infra" / "azure" / "tests" / "test-container-firewall-runtime.sh"
        )
        docker_restart_runtime = (
            ROOT / "infra" / "azure" / "tests" / "test-docker-daemon-restart.sh"
        )
        docker_first_start_runtime = (
            ROOT / "infra" / "azure" / "tests" / "test-docker-first-start.sh"
        )
        systemd_order_runtime = (
            ROOT / "infra" / "azure" / "tests" / "test-systemd-boot-order.sh"
        )
        container_firewall = (
            ROOT / "infra" / "azure" / "bootstrap" / "container-firewall.sh"
        )
        service_activation = (
            ROOT / "infra" / "azure" / "bootstrap" / "service-activation.sh"
        )
        docker_post_start = (
            ROOT / "infra" / "azure" / "bootstrap" / "docker-post-start.sh"
        )
        docker_activation = (
            ROOT / "infra" / "azure" / "bootstrap" / "docker-activation.sh"
        )
        compose_supervisor = (
            ROOT / "infra" / "azure" / "bootstrap" / "compose-supervisor.sh"
        )
        provision_worker_roles = (
            ROOT / "infra" / "azure" / "bootstrap" / "provision-worker-db-roles.sh"
        )
        unit = read("infra/azure/bootstrap/buzz-core.service")
        for script in (
            bootstrap,
            refresh,
            container_firewall,
            service_activation,
            docker_activation,
            docker_post_start,
            compose_supervisor,
            provision_worker_roles,
            clean_volume_smoke,
            caddy_runtime,
            firewall_runtime,
            docker_restart_runtime,
            docker_first_start_runtime,
            systemd_order_runtime,
        ):
            self.assertTrue(script.is_file(), f"missing {script.relative_to(ROOT)}")
            result = subprocess.run(
                ["bash", "-n", str(script)], text=True, capture_output=True, check=False
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        bootstrap_text = bootstrap.read_text(encoding="utf-8")
        for expected in ("blkid", "mountpoint", "install -d"):
            self.assertIn(expected, bootstrap_text)
        refresh_text = refresh.read_text(encoding="utf-8")
        for expected in ("az login --identity", "az acr login", "az keyvault secret show"):
            self.assertIn(expected, refresh_text)
        self.assertIn("RequiresMountsFor=/srv/buzz", unit)
        self.assertIn("ExecStartPre=/usr/local/sbin/buzz-core-container-firewall", unit)
        self.assertIn("PartOf=docker.service", unit)
        self.assertIn("StartLimitBurst=5", unit)
        self.assertIn("StartLimitIntervalSec=10min", unit)
        self.assertIn("ExecStart=/usr/local/sbin/buzz-core-compose-supervisor supervise", unit)
        self.assertIn("ExecStopPost=-/usr/local/sbin/buzz-core-compose-supervisor down", unit)
        self.assertNotIn("up --detach", unit)
        self.assertIn("ExecStartPre=/usr/local/sbin/buzz-core-refresh-secrets", unit)
        self.assertLess(
            unit.index("ExecStartPre=/usr/local/sbin/buzz-core-container-firewall"),
            unit.index("ExecStartPre=/usr/bin/docker compose"),
        )
        self.assertIn("docker compose", unit)
        self.assertIn("buzz-core-docker-activation prepare", bootstrap_text)
        self.assertIn("buzz-core-docker-activation start", bootstrap_text)
        self.assertIn("buzz-core-docker-post-start", bootstrap_text)
        self.assertIn("docker.service.d/20-buzz-imds-firewall.conf", bootstrap_text)
        activation_text = service_activation.read_text(encoding="utf-8")
        self.assertIn('disable --now buzz-core.service', activation_text)
        self.assertIn('restart buzz-core.service', activation_text)
        self.assertNotIn('disable --now buzz-core.service >/dev/null 2>&1 || true', activation_text)
        self.assertLess(
            bootstrap_text.index("buzz-core-docker-activation start"),
            bootstrap_text.rindex("\nextract_verified_bundle\n"),
        )
        self.assertNotIn("rm -rf /opt/buzz/bootstrap-bundle/*", bootstrap_text)
        extract_block = bootstrap_text[
            bootstrap_text.index("extract_verified_bundle()") : bootstrap_text.index(
                "\ninstall_packages\n"
            )
        ]
        self.assertNotIn(
            "exit 1",
            extract_block,
            "bundle extraction must return through its cleanup trap on failure",
        )
        self.assertIn(
            "trap cleanup_bundle_extract RETURN ERR",
            extract_block,
            "unexpected command failures must clean staged bundle data and containers",
        )
        self.assertRegex(
            refresh_text,
            r"install\s+-d\s+-o\s+0\s+-g\s+1000\s+-m\s+0750\s+[^\n]*/caddy",
        )
        self.assertIn("AZURE_CONFIG_DIR", bootstrap_text)
        self.assertIn("AZURE_CONFIG_DIR", refresh_text)
        self.assertIn(
            "export DOCKER_CONFIG",
            refresh_text,
            "ACR login must receive the volatile Docker credential directory",
        )
        self.assertIn("/run/buzz", bootstrap_text + refresh_text)
        self.assertNotRegex(bootstrap_text + refresh_text + unit, r"(?i)(client_secret|azure_credentials)")

    def test_docker_post_start_applies_firewall_before_restarting_enabled_core(self) -> None:
        post_start = ROOT / "infra" / "azure" / "bootstrap" / "docker-post-start.sh"
        with tempfile.TemporaryDirectory(prefix="buzz-docker-post-start-") as directory:
            root = Path(directory)
            calls = root / "calls"
            firewall = root / "firewall"
            systemctl = root / "systemctl"
            firewall.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' firewall >>\"${POST_START_CALLS:?}\"\n",
                encoding="utf-8",
            )
            systemctl.write_text(
                """#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"${POST_START_CALLS:?}"
if [[ ${1:-} == is-enabled ]]; then exit "${IS_ENABLED_RC:-0}"; fi
exit 0
""",
                encoding="utf-8",
            )
            firewall.chmod(0o755)
            systemctl.chmod(0o755)
            env = os.environ | {
                "FIREWALL_BIN": str(firewall),
                "SYSTEMCTL_BIN": str(systemctl),
                "POST_START_CALLS": str(calls),
            }
            enabled = subprocess.run(
                ["bash", str(post_start)], env=env, text=True, capture_output=True, check=False
            )
            self.assertEqual(enabled.returncode, 0, enabled.stderr)
            self.assertEqual(
                calls.read_text(encoding="utf-8").splitlines(),
                [
                    "firewall",
                    "systemctl is-enabled --quiet buzz-core.service",
                    "systemctl --no-block start buzz-core.service",
                ],
            )

            calls.unlink()
            disabled = subprocess.run(
                ["bash", str(post_start)],
                env=env | {"IS_ENABLED_RC": "1"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(disabled.returncode, 0, disabled.stderr)
            self.assertEqual(
                calls.read_text(encoding="utf-8").splitlines(),
                ["firewall", "systemctl is-enabled --quiet buzz-core.service"],
            )

    def test_docker_activation_masks_install_window_and_applies_baseline_before_start(self) -> None:
        activation = ROOT / "infra" / "azure" / "bootstrap" / "docker-activation.sh"
        with tempfile.TemporaryDirectory(prefix="buzz-docker-activation-") as directory:
            root = Path(directory)
            calls = root / "calls"
            systemctl = root / "systemctl"
            firewall = root / "firewall"
            docker = root / "docker"
            systemctl.write_text(
                "#!/usr/bin/env bash\nprintf 'systemctl %s\\n' \"$*\" >>\"${ACTIVATION_CALLS:?}\"\n",
                encoding="utf-8",
            )
            firewall.write_text(
                "#!/usr/bin/env bash\nprintf 'firewall %s\\n' \"$*\" >>\"${ACTIVATION_CALLS:?}\"\n",
                encoding="utf-8",
            )
            docker.write_text(
                "#!/usr/bin/env bash\nprintf 'docker %s\\n' \"$*\" >>\"${ACTIVATION_CALLS:?}\"\n",
                encoding="utf-8",
            )
            for executable in (systemctl, firewall, docker):
                executable.chmod(0o755)
            env = os.environ | {
                "ACTIVATION_CALLS": str(calls),
                "SYSTEMCTL_BIN": str(systemctl),
                "FIREWALL_BIN": str(firewall),
                "DOCKER_BIN": str(docker),
            }

            prepared = subprocess.run(
                ["bash", str(activation), "prepare"],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self.assertEqual(
                calls.read_text(encoding="utf-8").splitlines(),
                ["systemctl mask --now docker.service docker.socket"],
            )

            calls.unlink()
            started = subprocess.run(
                ["bash", str(activation), "start"],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(started.returncode, 0, started.stderr)
            self.assertEqual(
                calls.read_text(encoding="utf-8").splitlines(),
                [
                    "systemctl daemon-reload",
                    "firewall --baseline",
                    "systemctl unmask docker.service docker.socket",
                    "systemctl enable docker.service",
                    "systemctl start docker.service",
                    "docker info",
                ],
            )

    def test_clean_volume_smoke_rejects_missing_or_floating_dependency_images(self) -> None:
        smoke = ROOT / "infra" / "azure" / "tests" / "smoke-clean-volume.sh"
        with tempfile.TemporaryDirectory(prefix="buzz-smoke-validation-") as directory:
            root = Path(directory)
            marker = root / "docker-called"
            fake = root / "docker"
            fake.write_text(
                "#!/usr/bin/env bash\nprintf called >\"${DOCKER_MARKER:?}\"\nexit 99\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            base_env = os.environ | {
                "PATH": f"{root}:{os.environ['PATH']}",
                "DOCKER_MARKER": str(marker),
            }
            missing = subprocess.run(
                ["bash", str(smoke), "local-relay:test"],
                env=base_env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(missing.returncode, 2)
            self.assertIn("SMOKE_POSTGRES_IMAGE", missing.stderr)
            self.assertFalse(marker.exists(), "dependency validation must precede Docker")

            digest = "sha256:" + "a" * 64
            invalid_env = base_env | {
                "SMOKE_POSTGRES_IMAGE": "docker.io/pgvector/pgvector:pg17",
                "SMOKE_REDIS_IMAGE": f"docker.io/library/redis@{digest}",
                "SMOKE_MINIO_IMAGE": f"docker.io/minio/minio@{digest}",
                "SMOKE_MINIO_MC_IMAGE": f"docker.io/minio/mc@{digest}",
                "SMOKE_CADDY_IMAGE": f"docker.io/library/caddy@{digest}",
            }
            floating = subprocess.run(
                ["bash", str(smoke), "local-relay:test"],
                env=invalid_env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(floating.returncode, 2)
            self.assertIn("digest-pinned", floating.stderr)
            self.assertFalse(marker.exists(), "invalid image refs must fail before Docker")

    def test_service_activation_stops_disabled_services_and_propagates_failures(self) -> None:
        activation = ROOT / "infra" / "azure" / "bootstrap" / "service-activation.sh"
        with tempfile.TemporaryDirectory(prefix="buzz-systemctl-") as directory:
            root = Path(directory)
            calls = root / "calls"
            fake = root / "systemctl"
            fake.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SYSTEMCTL_CALLS:?}"
if [[ ${1:-} == disable && ${FAIL_DISABLE:-0} == 1 ]]; then exit 42; fi
if [[ ${1:-} == is-active ]]; then exit "${IS_ACTIVE_RC:-3}"; fi
exit 0
""",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            base_env = os.environ | {
                "SYSTEMCTL_BIN": str(fake),
                "SYSTEMCTL_CALLS": str(calls),
            }

            for _ in range(2):
                stopped = subprocess.run(
                    ["bash", str(activation), "false"],
                    env=base_env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(stopped.returncode, 0, stopped.stderr)
            self.assertEqual(
                calls.read_text(encoding="utf-8").splitlines(),
                ["disable --now buzz-core.service"] * 2,
            )

            calls.unlink()
            failed = subprocess.run(
                ["bash", str(activation), "false"],
                env=base_env | {"FAIL_DISABLE": "1"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(failed.returncode, 42)
            self.assertEqual(calls.read_text(encoding="utf-8").splitlines(), ["disable --now buzz-core.service"])

            calls.unlink()
            restarted = subprocess.run(
                ["bash", str(activation), "true"],
                env=base_env | {"IS_ACTIVE_RC": "0"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(restarted.returncode, 0, restarted.stderr)
            self.assertEqual(
                calls.read_text(encoding="utf-8").splitlines(),
                [
                    "enable buzz-core.service",
                    "is-active --quiet buzz-core.service",
                    "restart buzz-core.service",
                ],
            )

            calls.unlink()
            started = subprocess.run(
                ["bash", str(activation), "true"],
                env=base_env | {"IS_ACTIVE_RC": "3"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(started.returncode, 0, started.stderr)
            self.assertEqual(
                calls.read_text(encoding="utf-8").splitlines(),
                [
                    "enable buzz-core.service",
                    "is-active --quiet buzz-core.service",
                    "start buzz-core.service",
                ],
            )

    def test_compose_supervisor_preflights_init_and_treats_every_long_exit_as_failure(self) -> None:
        supervisor = ROOT / "infra" / "azure" / "bootstrap" / "compose-supervisor.sh"
        with tempfile.TemporaryDirectory(prefix="buzz-compose-supervisor-") as directory:
            root = Path(directory)
            calls = root / "calls"
            fake = root / "docker"
            fake.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DOCKER_CALLS:?}"
if [[ " $* " == *" --abort-on-container-exit "* ]]; then
  exit "${SUPERVISE_RC:-0}"
fi
exit 0
""",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            env = os.environ | {"DOCKER_BIN": str(fake), "DOCKER_CALLS": str(calls)}

            prepared = subprocess.run(
                ["bash", str(supervisor), "prepare"],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            prepare_calls = calls.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(prepare_calls), 3)
            self.assertIn("up --detach --wait postgres redis minio", prepare_calls[0])
            self.assertIn("run --rm --no-deps minio-init", prepare_calls[1])
            self.assertIn("up --detach --no-deps --wait relay", prepare_calls[2])

            provision = root / "provision"
            provision.write_text(
                "#!/usr/bin/env bash\nprintf 'provisioned\\n' >>\"${DOCKER_CALLS:?}\"\n",
                encoding="utf-8",
            )
            provision.chmod(0o755)
            calls.unlink()
            workers_prepared = subprocess.run(
                ["bash", str(supervisor), "prepare"],
                env=env
                | {
                    "ENABLE_MONTH1_WORKERS": "true",
                    "PROVISION_WORKER_DB_ROLES_BIN": str(provision),
                },
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(workers_prepared.returncode, 0, workers_prepared.stderr)
            worker_calls = calls.read_text(encoding="utf-8")
            self.assertIn("--profile month1-workers", worker_calls)
            self.assertIn("provisioned", worker_calls)
            self.assertIn("agent-supervisor", worker_calls)
            self.assertIn("audit-egress-proxy", worker_calls)

            calls.unlink()
            clean_exit = subprocess.run(
                ["bash", str(supervisor), "supervise"],
                env=env | {"SUPERVISE_RC": "0"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(clean_exit.returncode, 1)
            supervise_call = calls.read_text(encoding="utf-8").strip()
            self.assertIn("--abort-on-container-exit", supervise_call)
            for service in ("postgres", "redis", "minio", "relay", "caddy"):
                self.assertIn(f"--no-attach {service}", supervise_call)
            self.assertNotIn("minio-init", supervise_call)

            calls.unlink()
            failed_exit = subprocess.run(
                ["bash", str(supervisor), "supervise"],
                env=env | {"SUPERVISE_RC": "42"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(failed_exit.returncode, 42)

            calls.unlink()
            cleaned = subprocess.run(
                ["bash", str(supervisor), "down"],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
            self.assertIn(" down", f" {calls.read_text(encoding='utf-8').strip()}")

    def test_container_firewall_blocks_imds_idempotently_without_touching_host_output(self) -> None:
        firewall = ROOT / "infra" / "azure" / "bootstrap" / "container-firewall.sh"
        text = firewall.read_text(encoding="utf-8")
        self.assertIn("DOCKER-USER", text)
        self.assertIn("INPUT", text)
        self.assertIn("169.254.169.254/32", text)
        self.assertIn("buzz-ingress", text)
        self.assertIn("buzz-edge", text)
        for bridge in (
            "buzz-data",
            "buzz-broker",
            "buzz-connector",
            "buzz-model",
            "buzz-audit",
            "buzz-egress",
        ):
            self.assertIn(bridge, text)
        self.assertIn("ESTABLISHED,RELATED", text)
        self.assertIn("-C", text)
        self.assertIn("-I", text)
        self.assertNotRegex(
            text,
            r"(?m)^[^#\n]*\bOUTPUT\b",
            "host managed-identity access must remain available",
        )

        with tempfile.TemporaryDirectory(prefix="buzz-iptables-") as directory:
            root = Path(directory)
            state = root / "rules"
            fake = root / "iptables"
            fake.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
state=${IPTABLES_STATE:?}
args=("$@")
if [[ ${args[0]} == -w ]]; then args=("${args[@]:1}"); fi
if [[ ${args[*]} == "-n -L DOCKER-USER" ]]; then exit 0; fi
op=${args[0]}
chain=${args[1]}
case "$op" in
  -C|-D) rule="${args[*]:2}" ;;
  -I)
    [[ ${args[2]} == 1 ]]
    rule="${args[*]:3}"
    ;;
  *) exit 2 ;;
esac
key="$chain|$rule"
case "$op" in
  -C) [[ -f $state ]] && grep -Fxq -- "$key" "$state" ;;
  -D)
    line=$(grep -nFx -- "$key" "$state" | head -n1 | cut -d: -f1)
    sed -i "${line}d" "$state"
    ;;
  -I)
    { printf '%s\n' "$key"; [[ ! -f $state ]] || cat "$state"; } >"$state.tmp"
    mv "$state.tmp" "$state"
    ;;
esac
""",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            env = os.environ | {"IPTABLES_BIN": str(fake), "IPTABLES_STATE": str(state)}
            for _ in range(2):
                result = subprocess.run(
                    ["bash", str(firewall)], env=env, text=True, capture_output=True, check=False
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                state.read_text(encoding="utf-8").splitlines(),
                [
                    "INPUT|-i buzz-ingress -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "INPUT|-i buzz-ingress -j REJECT",
                    "INPUT|-i buzz-edge -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "INPUT|-i buzz-edge -j REJECT",
                    "INPUT|-i buzz-data -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "INPUT|-i buzz-data -j REJECT",
                    "INPUT|-i buzz-broker -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "INPUT|-i buzz-broker -j REJECT",
                    "INPUT|-i buzz-connector -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "INPUT|-i buzz-connector -j REJECT",
                    "INPUT|-i buzz-model -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "INPUT|-i buzz-model -j REJECT",
                    "INPUT|-i buzz-audit -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "INPUT|-i buzz-audit -j REJECT",
                    "INPUT|-i buzz-egress -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "INPUT|-i buzz-egress -j REJECT",
                    "DOCKER-USER|-d 169.254.169.254/32 -j REJECT",
                    "DOCKER-USER|-i buzz-ingress -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "DOCKER-USER|-i buzz-ingress -j REJECT",
                    "INPUT|-i buzz-+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    "INPUT|-i buzz-+ -j REJECT",
                    "FORWARD|-d 169.254.169.254/32 -j REJECT",
                ],
            )

    def test_bootstrap_data_disk_formatting_fails_closed(self) -> None:
        bootstrap = read("infra/azure/bootstrap/bootstrap.sh")
        mount_block = bootstrap[
            bootstrap.index("mount_data_disk()") : bootstrap.index(
                "\nextract_verified_bundle()"
            )
        ]
        for required_guard in (
            "findmnt -n -o SOURCE /",
            "blockdev --getsize64",
            "expected_min_bytes=$((255 * 1024 * 1024 * 1024))",
            "expected_max_bytes=$((257 * 1024 * 1024 * 1024))",
            "lsblk -nrpo NAME,TYPE",
            "lsblk -nrpo MOUNTPOINT",
            "findmnt -n -o SOURCE --mountpoint /srv/buzz",
            "wipefs --noheadings --output TYPE",
            'filesystem_type != xfs',
            'filesystem_label != buzz-data',
        ):
            self.assertIn(required_guard, mount_block)
        self.assertIn('resolved == "$root_disk"', mount_block)
        self.assertIn("mkfs.xfs -L buzz-data", mount_block)
        self.assertNotIn("mkfs.xfs -f", mount_block)
        self.assertRegex(bootstrap, r"apt-get install[^\n]+\butil-linux\b")

    def test_bootstrap_bundle_image_supports_create_and_copy(self) -> None:
        if not shutil.which("docker"):
            self.skipTest("docker executable is unavailable")
        tag = f"core-buzz-bootstrap-contract:{os.getpid()}"
        container_id = ""
        with tempfile.TemporaryDirectory(prefix="buzz-bootstrap-copy-") as destination:
            try:
                built = subprocess.run(
                    [
                        "docker",
                        "build",
                        "--target",
                        "bundle",
                        "--tag",
                        tag,
                        "--file",
                        str(ROOT / "infra" / "azure" / "bootstrap" / "Dockerfile"),
                        str(ROOT),
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(built.returncode, 0, built.stderr)
                created = subprocess.run(
                    ["docker", "create", tag],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(created.returncode, 0, created.stderr)
                container_id = created.stdout.strip()
                copied = subprocess.run(
                    ["docker", "cp", f"{container_id}:/bundle/.", destination],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(copied.returncode, 0, copied.stderr)
                self.assertTrue((Path(destination) / "compose.azure.yml").is_file())
                self.assertTrue((Path(destination) / "buzz-core.service").is_file())
                self.assertTrue((Path(destination) / "docker-activation.sh").is_file())
            finally:
                if container_id:
                    subprocess.run(
                        ["docker", "rm", "--force", container_id],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                subprocess.run(
                    ["docker", "image", "rm", "--force", tag],
                    text=True,
                    capture_output=True,
                    check=False,
                )

    def test_validation_workflow_is_offline_by_default_and_uses_oidc_for_what_if(self) -> None:
        workflow = read(".github/workflows/azure-foundation-validate.yml")
        assert_action_refs_are_pinned(self, workflow)
        pull_request_trigger = workflow[
            workflow.index("  pull_request:") : workflow.index("  workflow_dispatch:")
        ]
        self.assertNotIn(
            "paths:",
            pull_request_trigger,
            "all relay image and migration inputs must trigger the required smoke",
        )
        self.assertIn("id-token: write", workflow)
        self.assertIn("azure/login", workflow)
        self.assertIn("vars.AZURE_CLIENT_ID", workflow)
        self.assertIn("az deployment sub what-if", workflow)
        self.assertIn("enable_what_if", workflow)
        self.assertIn("az bicep build", workflow)
        self.assertIn("docker compose", workflow)
        self.assertIn("bash infra/azure/tests/run.sh", workflow)
        self.assertIn("CADDY_TEST_IMAGE", workflow)
        self.assertIn("OPENSSL_TEST_IMAGE", workflow)
        self.assertIn("FIREWALL_TEST_IMAGE", workflow)
        self.assertIn("DIND_TEST_IMAGE", workflow)
        self.assertIn("DIND_WORKLOAD_IMAGE", workflow)
        self.assertIn("enable_clean_volume_smoke", workflow)
        self.assertIn("bash infra/azure/tests/smoke-clean-volume.sh", workflow)
        self.assertIn("github.event_name == 'pull_request'", workflow)
        dockerfile = read("Dockerfile")
        self.assertRegex(dockerfile.splitlines()[0], r"dockerfile:1\.7@sha256:[0-9a-f]{64}$")
        for image in (
            "SMOKE_RUST_BUILD_IMAGE",
            "SMOKE_NODE_BUILD_IMAGE",
            "SMOKE_DEBIAN_RUNTIME_IMAGE",
        ):
            self.assertRegex(workflow, rf"{image}:\s+[^\s]+@sha256:[0-9a-f]{{64}}")
            self.assertIn(f"--build-arg {image.removeprefix('SMOKE_')}=\"${image}\"", workflow)
        for image in (
            "SMOKE_POSTGRES_IMAGE",
            "SMOKE_REDIS_IMAGE",
            "SMOKE_MINIO_IMAGE",
            "SMOKE_MINIO_MC_IMAGE",
            "SMOKE_CADDY_IMAGE",
        ):
            self.assertRegex(workflow, rf"{image}:\s+[^\s]+@sha256:[0-9a-f]{{64}}")
        self.assertIn("BUZZ_PUBLIC_HOST", workflow)
        self.assertIn("RELAY_OWNER_PUBKEY", workflow)
        self.assertIn('relayOwnerPubkey="$RELAY_OWNER_PUBKEY"', workflow)
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
            "AZURE_SIGNING_SUBJECT",
            "SignerCertificate.Subject",
            "signingProfile",
        ):
            self.assertIn(expected, workflow)
        self.assertNotIn(
            "Swatinem/rust-cache",
            workflow,
            "writable build-output caches must not feed a signed installer",
        )
        self.assertRegex(
            workflow,
            r"SignerCertificate\.Subject\s+-ne\s+\$env:EXPECTED_SIGNING_SUBJECT",
        )
        self.assertNotRegex(workflow, r"(?i)(AZURE_CREDENTIALS|client[_-]?secret|AZURE[_-].*password\s*:)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
