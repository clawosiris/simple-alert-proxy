"""Production-container smoke journeys over real sockets and persistent storage."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import unittest
import uuid
from pathlib import Path
from typing import Any

from tests.system.harness import (
    INBOUND_TOKEN,
    MANAGEMENT_TOKEN,
    ScriptedReceiver,
    TestWorkspace,
    eventually,
    generate_certificate,
    request,
    redact,
    reserve_port,
    synthetic_payload,
    wait_for_container_http,
    write_config,
)


class ContainerEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = shlex.split(os.environ.get("CONTAINER_ENGINE", "podman"))
        cls.image = os.environ.get("CONTAINER_E2E_IMAGE", "simple-alert-proxy:e2e")
        if not cls.engine or shutil.which(cls.engine[0]) is None:
            raise unittest.SkipTest(f"container engine not found: {cls.engine}")
        result = cls.run_engine("image", "exists", cls.image, check=False)
        if result.returncode != 0:
            raise RuntimeError(
                f"container image {cls.image} is missing; build it before running container E2E"
            )

    @classmethod
    def run_engine(
        cls, *arguments: str, check: bool = True, timeout: float = 60
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [*cls.engine, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            command = " ".join([*cls.engine, *arguments])
            raise AssertionError(
                f"container command failed ({result.returncode}): {command}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def setUp(self) -> None:
        self.workspace = TestWorkspace(self.id().rsplit(".", 1)[-1])
        self.receiver = ScriptedReceiver(
            self.workspace.artifact_dir / "receiver-requests.json", host="0.0.0.0"
        ).start()
        suffix = uuid.uuid4().hex[:10]
        self.network = f"sap-e2e-{suffix}"
        self.containers: list[str] = []
        self.run_engine("network", "create", self.network)

    def tearDown(self) -> None:
        for name in reversed(self.containers):
            self.capture_logs(name)
            self.run_engine("rm", "-f", "--time", "3", name, check=False)
        self.run_engine("network", "rm", "-f", self.network, check=False)
        self.receiver.close()
        self.workspace.close()

    def capture_logs(self, name: str) -> None:
        logs = self.run_engine("logs", name, check=False)
        content = logs.stdout + logs.stderr
        for secret in (INBOUND_TOKEN, MANAGEMENT_TOKEN):
            content = content.replace(secret, "[REDACTED]")
        self.workspace.artifact_dir.mkdir(parents=True, exist_ok=True)
        (self.workspace.artifact_dir / f"{name}.log").write_text(content)

    def start_container(
        self,
        name: str,
        host_port: int,
        *,
        container_port: int = 8080,
        tls_mounts: tuple[Path, Path] | None = None,
        health_command: str | None = None,
    ) -> None:
        arguments = [
            "run",
            "--detach",
            "--name",
            name,
            "--network",
            self.network,
            "--add-host",
            "host.containers.internal:host-gateway",
            "--publish",
            f"127.0.0.1:{host_port}:{container_port}",
            "--health-interval",
            "1s",
            "--health-timeout",
            "2s",
            "--health-start-period",
            "1s",
            "--health-retries",
            "10",
            "--volume",
            f"{self.workspace.config}:/etc/simple-alert-proxy/config.yaml:ro,Z",
            "--volume",
            f"{self.workspace.root / 'data'}:/var/lib/simple-alert-proxy/data:Z,U",
        ]
        if tls_mounts:
            certificate, private_key = tls_mounts
            arguments.extend(
                [
                    "--volume",
                    f"{certificate}:/run/simple-alert-proxy/tls/tls.crt:ro,Z",
                    "--volume",
                    f"{private_key}:/run/simple-alert-proxy/tls/tls.key:ro,Z",
                ]
            )
        if health_command:
            arguments.extend(["--health-cmd", health_command])
        arguments.append(self.image)
        self.containers.append(name)
        result = self.run_engine(*arguments)
        self.assertTrue(result.stdout.strip())

    def inspect(self, name: str, template: str) -> str:
        return self.run_engine("inspect", "--format", template, name).stdout.strip()

    def stop_container(self, name: str) -> None:
        self.run_engine("stop", "--time", "10", name, timeout=20)
        self.capture_logs(name)
        self.assertEqual(self.inspect(name, "{{.State.Running}}"), "false")
        self.assertEqual(self.inspect(name, "{{.State.ExitCode}}"), "0")

    def assert_healthy(self, name: str) -> None:
        check = self.run_engine("healthcheck", "run", name, check=False, timeout=10)
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        self.assertEqual(self.inspect(name, "{{.State.Health.Status}}"), "healthy")

    def api_json(self, base_url: str, path: str) -> Any:
        response = request(
            base_url,
            "GET",
            path,
            headers={"authorization": f"Bearer {MANAGEMENT_TOKEN}"},
        )
        self.assertEqual(response.status, 200, response.body)
        return response.json()

    def test_non_root_health_persistence_restart_and_tls_mounts(self) -> None:
        image_user = self.run_engine(
            "image", "inspect", "--format", "{{.Config.User}}", self.image
        ).stdout.strip()
        self.assertEqual(image_user, "simple-alert-proxy")

        host_port = reserve_port()
        write_config(
            self.workspace.config,
            bind="0.0.0.0:8080",
            database="/var/lib/simple-alert-proxy/data/simple-alert-proxy.db",
            receiver_url=f"http://host.containers.internal:{self.receiver.port}/receiver",
            local_users=False,
        )
        first = f"sap-http-{uuid.uuid4().hex[:8]}"
        self.start_container(first, host_port)
        wait_for_container_http("127.0.0.1", host_port)
        self.assert_healthy(first)
        self.assertEqual(self.inspect(first, "{{.Config.User}}"), "simple-alert-proxy")
        base_url = f"http://127.0.0.1:{host_port}"
        intake = request(
            base_url,
            "POST",
            "/webhooks/synthetic",
            payload=synthetic_payload("container-http"),
            headers={"authorization": f"Bearer {INBOUND_TOKEN}"},
        )
        self.assertEqual(intake.status, 202, intake.body)
        self.receiver.wait_for_requests(1)
        events = eventually(
            lambda: self.api_json(base_url, "/api/alert-events"),
            lambda records: len(records) == 1,
            description="container-persisted event",
        )
        self.assertEqual(events[0]["fingerprint"], "container-http")
        self.stop_container(first)

        self.run_engine("rm", first)
        self.containers.remove(first)
        restarted = f"sap-restart-{uuid.uuid4().hex[:8]}"
        self.start_container(restarted, host_port)
        wait_for_container_http("127.0.0.1", host_port)
        persisted = self.api_json(base_url, "/api/alert-events")
        self.assertEqual([event["fingerprint"] for event in persisted], ["container-http"])
        self.stop_container(restarted)

        self.run_engine("rm", restarted)
        self.containers.remove(restarted)
        certificate, private_key, ca_certificate = generate_certificate(self.workspace.root)
        certificate.chmod(0o644)
        private_key.chmod(0o644)
        tls_port = reserve_port()
        write_config(
            self.workspace.config,
            bind="0.0.0.0:8443",
            database="/var/lib/simple-alert-proxy/data/simple-alert-proxy.db",
            receiver_url=f"http://host.containers.internal:{self.receiver.port}/receiver",
            tls={
                "cert_path": "/run/simple-alert-proxy/tls/tls.crt",
                "key_path": "/run/simple-alert-proxy/tls/tls.key",
            },
            local_users=False,
        )
        tls_name = f"sap-tls-{uuid.uuid4().hex[:8]}"
        self.start_container(
            tls_name,
            tls_port,
            container_port=8443,
            tls_mounts=(certificate, private_key),
            health_command="curl -kfsS https://127.0.0.1:8443/healthz || exit 1",
        )
        tls_url = f"https://127.0.0.1:{tls_port}"
        eventually(
            lambda: request(
                tls_url,
                "GET",
                "/healthz",
                timeout=1,
                verify_tls=True,
                ca_file=ca_certificate,
            ).status,
            lambda status: status == 204,
            timeout=20,
            description="TLS container health",
        )
        self.assert_healthy(tls_name)
        self.assertEqual(self.inspect(tls_name, "{{.Config.User}}"), "simple-alert-proxy")
        intake = request(
            tls_url,
            "POST",
            "/webhooks/synthetic",
            payload=synthetic_payload("container-tls"),
            headers={"authorization": f"Bearer {INBOUND_TOKEN}"},
        )
        self.assertEqual(intake.status, 202, intake.body)
        self.receiver.wait_for_requests(2)
        tls_events = self.api_json(tls_url, "/api/alert-events")
        self.assertIn("container-tls", [event["fingerprint"] for event in tls_events])
        self.stop_container(tls_name)
        stopped_health = self.run_engine(
            "healthcheck", "run", tls_name, check=False, timeout=10
        )
        self.assertNotEqual(stopped_health.returncode, 0)

        image_health = self.run_engine(
            "image", "inspect", "--format", "{{json .Config.Healthcheck.Test}}", self.image
        ).stdout
        self.assertIn("healthz", image_health)
        self.assertEqual(self.inspect(tls_name, "{{.State.Running}}"), "false")

        self.run_engine("rm", tls_name)
        self.containers.remove(tls_name)
        invalid = self.workspace.config.read_text().replace(
            'default_receiver: "loopback"', 'default_receiver: "missing"'
        )
        self.workspace.config.write_text(invalid)
        invalid_name = f"sap-invalid-{uuid.uuid4().hex[:8]}"
        result = self.run_engine(
            "run",
            "--rm",
            "--name",
            invalid_name,
            "--volume",
            f"{self.workspace.config}:/etc/simple-alert-proxy/config.yaml:ro,Z",
            self.image,
            check=False,
            timeout=20,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown receiver missing", result.stderr)
        (self.workspace.artifact_dir / "invalid-startup.log").write_text(
            redact(result.stdout + result.stderr)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
