"""Production-binary tests over real HTTP and HTTPS sockets."""

from __future__ import annotations

import os
import shutil
import unittest
from pathlib import Path

from tests.system.harness import (
    ADMIN_PASSWORD,
    INBOUND_TOKEN,
    MANAGEMENT_TOKEN,
    ProxyProcess,
    ScriptedReceiver,
    ScriptedResponse,
    TestWorkspace,
    eventually,
    generate_certificate,
    request,
    reserve_port,
    run_to_exit,
    signoz_payload,
    synthetic_payload,
    write_config,
)


class BinaryEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configured = os.environ.get("SYSTEM_E2E_BIN", "target/release/simple-alert-proxy")
        cls.binary = Path(configured).resolve()
        if not cls.binary.is_file():
            raise RuntimeError(
                f"release binary not found at {cls.binary}; run cargo build --release --locked"
            )
        if shutil.which("openssl") is None:
            raise RuntimeError("openssl is required for TLS system tests")

    def setUp(self) -> None:
        name = self.id().rsplit(".", 1)[-1]
        self.workspace = TestWorkspace(name)
        self.receiver = ScriptedReceiver(
            self.workspace.artifact_dir / "receiver-requests.json"
        ).start()
        self.services: list[ProxyProcess] = []

    def tearDown(self) -> None:
        errors: list[BaseException] = []
        for service in reversed(self.services):
            try:
                service.stop()
            except BaseException as error:
                errors.append(error)
        self.receiver.close()
        self.workspace.close()
        if errors:
            raise errors[0]

    def start_proxy(
        self,
        *,
        batching: bool = False,
        group_wait_millis: int = 100,
        max_attempts: int = 3,
        initial_backoff_millis: int = 50,
        max_backoff_millis: int = 100,
        max_body_bytes: int = 2048,
        tls: dict[str, str] | None = None,
        environment: dict[str, str] | None = None,
        port: int | None = None,
        receiver_kind: str = "generic_webhook",
    ) -> ProxyProcess:
        port = port or reserve_port()
        write_config(
            self.workspace.config,
            bind=f"127.0.0.1:{port}",
            database=str(self.workspace.database),
            receiver_url=self.receiver.url,
            batching=batching,
            group_wait_millis=group_wait_millis,
            max_attempts=max_attempts,
            initial_backoff_millis=initial_backoff_millis,
            max_backoff_millis=max_backoff_millis,
            max_body_bytes=max_body_bytes,
            tls=tls,
            receiver_kind=receiver_kind,
        )
        scheme = "https" if tls else "http"
        service = ProxyProcess(
            self.binary,
            self.workspace.config,
            f"{scheme}://127.0.0.1:{port}",
            self.workspace.artifact_dir,
            environment=environment,
        ).start()
        self.services.append(service)
        return service

    def management_json(self, service: ProxyProcess, path: str):
        response = request(
            service.base_url,
            "GET",
            path,
            headers={"authorization": f"Bearer {MANAGEMENT_TOKEN}"},
        )
        self.assertEqual(response.status, 200, response.body)
        return response.json()

    def post_alert(self, service: ProxyProcess, path: str, payload) -> None:
        response = request(
            service.base_url,
            "POST",
            path,
            payload=payload,
            headers={"authorization": f"Bearer {INBOUND_TOKEN}"},
        )
        self.assertEqual(response.status, 202, response.body)

    def wait_for_deliveries(self, service: ProxyProcess, count: int, status: str):
        return eventually(
            lambda: self.management_json(service, "/api/deliveries"),
            lambda deliveries: len(deliveries) >= count
            and all(delivery["status"] == status for delivery in deliveries[:count]),
            timeout=12,
            description=f"{count} {status} deliveries",
        )

    def test_http_intake_routing_persistence_sessions_and_lifecycle(self) -> None:
        service = self.start_proxy(max_body_bytes=1024)

        health = request(service.base_url, "GET", "/healthz")
        self.assertEqual(health.status, 204)
        unauthorized = request(
            service.base_url, "POST", "/webhooks/synthetic", payload=synthetic_payload("no-auth")
        )
        self.assertEqual(unauthorized.status, 401)
        wrong_token = request(
            service.base_url,
            "POST",
            "/webhooks/synthetic",
            payload=synthetic_payload("wrong-auth"),
            headers={"authorization": "Bearer wrong"},
        )
        self.assertEqual(wrong_token.status, 401)
        oversized = request(
            service.base_url,
            "POST",
            "/webhooks/synthetic",
            body=b"x" * 2048,
            headers={
                "authorization": f"Bearer {INBOUND_TOKEN}",
                "content-type": "application/json",
            },
        )
        self.assertEqual(oversized.status, 413)

        self.post_alert(service, "/webhooks/synthetic", synthetic_payload("generic-1"))
        self.post_alert(service, "/webhooks/signoz", signoz_payload("signoz-1"))
        captures = self.receiver.wait_for_requests(2)
        deliveries = self.wait_for_deliveries(service, 2, "succeeded")

        self.assertEqual({delivery["target"] for delivery in deliveries}, {"loopback"})
        events = self.management_json(service, "/api/alert-events")
        groups = self.management_json(service, "/api/alert-groups")
        routes = self.management_json(service, "/api/routes")
        integrations = self.management_json(service, "/api/integrations")
        self.assertEqual(len(events), 2)
        self.assertEqual(len(groups), 2)
        self.assertEqual(routes[0]["name"], "production")
        self.assertEqual({item["name"] for item in integrations}, {"signoz", "synthetic"})
        generic_capture = next(
            capture for capture in captures if capture["body"]["event"]["integration"] == "synthetic"
        )
        self.assertEqual(generic_capture["method"], "POST")
        self.assertEqual(generic_capture["path"], "/receiver")
        self.assertEqual(generic_capture["body"]["delivery"]["route"], "production")
        self.assertEqual(generic_capture["body"]["event"]["fingerprint"], "generic-1")

        login = request(
            service.base_url,
            "POST",
            "/auth/login",
            payload={"username": "admin", "password": ADMIN_PASSWORD},
        )
        self.assertEqual(login.status, 200, login.body)
        csrf = login.json()["csrf_token"]
        cookie = login.headers["set-cookie"].split(";", 1)[0]
        me = request(service.base_url, "GET", "/api/me", headers={"cookie": cookie})
        self.assertEqual(me.status, 200)
        self.assertEqual(me.json()["user"]["username"], "admin")

        generic_group = next(group for group in groups if group["fingerprint"] == "generic-1")
        missing_csrf = request(
            service.base_url,
            "POST",
            f"/api/alert-groups/{generic_group['id']}/ack",
            headers={"cookie": cookie},
        )
        self.assertEqual(missing_csrf.status, 401)
        acknowledged = request(
            service.base_url,
            "POST",
            f"/api/alert-groups/{generic_group['id']}/ack",
            headers={"cookie": cookie, "x-csrf-token": csrf},
        )
        self.assertEqual(acknowledged.status, 202)

        self.post_alert(
            service,
            "/webhooks/synthetic",
            synthetic_payload("generic-1", status="resolved"),
        )
        self.receiver.wait_for_requests(3)
        resolved = eventually(
            lambda: self.management_json(service, "/api/alert-groups"),
            lambda records: any(
                record["fingerprint"] == "generic-1"
                and record["status"] == "resolved"
                and record["event_count"] == 2
                for record in records
            ),
            description="firing-to-resolved lifecycle state",
        )
        self.assertTrue(resolved)

        self.post_alert(
            service,
            "/webhooks/synthetic",
            synthetic_payload("generic-1", status="firing"),
        )
        self.receiver.wait_for_requests(4)
        reactivated = eventually(
            lambda: self.management_json(service, "/api/alert-groups"),
            lambda records: (
                lambda record: record["status"] == "active"
                and record["acknowledged_at"] is None
                and record["event_count"] == 3
            )(next(record for record in records if record["fingerprint"] == "generic-1")),
            description="resolved-to-firing reactivation",
        )
        self.assertTrue(reactivated)

        self.assertEqual(service.stop(), 0)
        self.services.remove(service)

    def test_grouped_batch_and_pending_restart_recovery(self) -> None:
        port = reserve_port()
        service = self.start_proxy(
            batching=True, group_wait_millis=60_000, port=port
        )
        self.post_alert(
            service, "/webhooks/synthetic", synthetic_payload("batch-1", group="shared")
        )
        self.post_alert(
            service, "/webhooks/synthetic", synthetic_payload("batch-2", group="shared")
        )
        self.assertEqual(service.stop(), 0)
        self.services.remove(service)

        restarted = self.start_proxy(
            batching=True, group_wait_millis=60_000, port=port
        )
        captures = self.receiver.wait_for_requests(1, timeout=8)
        self.assertEqual(captures[0]["body"]["batch"]["count"], 2)
        self.assertEqual(len(captures[0]["body"]["events"]), 2)
        deliveries = self.wait_for_deliveries(restarted, 2, "succeeded")
        self.assertEqual({delivery["attempt_count"] for delivery in deliveries}, {1})

    def test_retry_dead_letter_and_replay(self) -> None:
        self.receiver.script(
            ScriptedResponse(500),
            ScriptedResponse(429),
            ScriptedResponse(200),
            ScriptedResponse(400),
            ScriptedResponse(200),
        )
        service = self.start_proxy(
            max_attempts=3,
            initial_backoff_millis=750,
            max_backoff_millis=750,
        )
        self.post_alert(service, "/webhooks/synthetic", synthetic_payload("retry-success"))
        self.receiver.wait_for_requests(1)
        retrying = eventually(
            lambda: self.management_json(service, "/api/deliveries"),
            lambda records: len(records) == 1 and records[0]["status"] == "retrying",
            timeout=2,
            description="retry backoff state",
        )[0]
        self.assertEqual(retrying["attempt_count"], 1)
        self.assertGreater(retrying["next_retry_at"], retrying["updated_at"])
        self.receiver.wait_for_requests(3)
        first = self.wait_for_deliveries(service, 1, "succeeded")[0]
        self.assertEqual(first["attempt_count"], 3)

        self.post_alert(service, "/webhooks/synthetic", synthetic_payload("dead-letter"))
        self.receiver.wait_for_requests(4)
        deliveries = eventually(
            lambda: self.management_json(service, "/api/deliveries"),
            lambda records: any(record["status"] == "dead_letter" for record in records),
            description="dead-letter state",
        )
        failed = next(record for record in deliveries if record["status"] == "dead_letter")
        self.assertEqual(failed["attempt_count"], 1)
        self.assertIn("400 Bad Request", failed["last_error"])
        self.assertNotIn(INBOUND_TOKEN, failed["last_error"])
        original_event_id = next(
            capture["body"]["event"]["event_id"]
            for capture in self.receiver.requests
            if capture["body"]["event"]["fingerprint"] == "dead-letter"
        )

        replay = request(
            service.base_url,
            "POST",
            f"/api/deliveries/{failed['id']}/replay",
            headers={"authorization": f"Bearer {MANAGEMENT_TOKEN}"},
        )
        self.assertEqual(replay.status, 202, replay.body)
        captures = self.receiver.wait_for_requests(5)
        recovered = eventually(
            lambda: self.management_json(service, "/api/deliveries"),
            lambda records: next(record for record in records if record["id"] == failed["id"])[
                "status"
            ]
            == "succeeded",
            description="successful replay",
        )
        self.assertTrue(recovered)
        self.assertEqual(captures[-1]["body"]["event"]["event_id"], original_event_id)

    def test_matrix_replay_renews_transaction_identity(self) -> None:
        service = self.start_proxy(receiver_kind="matrix")
        self.post_alert(service, "/webhooks/synthetic", synthetic_payload("matrix-replay"))
        captures = self.receiver.wait_for_requests(1)
        delivery = self.wait_for_deliveries(service, 1, "succeeded")[0]
        initial_path = captures[0]["path"]
        self.assertIn(f"/simple-alert-proxy-{delivery['id']}", initial_path)

        replay = request(
            service.base_url,
            "POST",
            f"/api/deliveries/{delivery['id']}/replay",
            headers={"authorization": f"Bearer {MANAGEMENT_TOKEN}"},
        )
        self.assertEqual(replay.status, 202, replay.body)
        replay_path = self.receiver.wait_for_requests(2)[1]["path"]
        self.assertNotEqual(initial_path, replay_path)
        self.assertIn(
            f"/simple-alert-proxy-{delivery['id']}-replay-",
            replay_path,
        )

    def test_in_progress_delivery_recovers_after_process_replacement(self) -> None:
        self.receiver.script(ScriptedResponse(200, delay=4), ScriptedResponse(200))
        port = reserve_port()
        service = self.start_proxy(port=port)
        self.post_alert(service, "/webhooks/synthetic", synthetic_payload("restart"))
        self.receiver.wait_for_requests(1)
        self.assertEqual(service.stop(), 0)
        self.services.remove(service)

        restarted = self.start_proxy(port=port)
        captures = self.receiver.wait_for_requests(2, timeout=8)
        self.assertEqual(
            [capture["body"]["event"]["fingerprint"] for capture in captures],
            ["restart", "restart"],
        )
        deliveries = self.wait_for_deliveries(restarted, 1, "succeeded")
        self.assertEqual(deliveries[0]["attempt_count"], 1)

    def test_tls_sources_graceful_shutdown_and_startup_failures(self) -> None:
        certificate, private_key, ca_certificate = generate_certificate(self.workspace.root)
        service = self.start_proxy(
            tls={"cert_path": str(certificate), "key_path": str(private_key)}
        )
        self.post_alert(service, "/webhooks/synthetic", synthetic_payload("tls-path"))
        verified_health = request(
            service.base_url,
            "GET",
            "/healthz",
            verify_tls=True,
            ca_file=ca_certificate,
        )
        self.assertEqual(verified_health.status, 204)
        self.receiver.wait_for_requests(1)
        tls_events = self.management_json(service, "/api/alert-events")
        self.assertEqual(tls_events[0]["fingerprint"], "tls-path")
        self.assertEqual(service.stop(), 0)
        self.services.remove(service)

        environment = {
            "SYSTEM_TEST_TLS_CERT_PEM": certificate.read_text(),
            "SYSTEM_TEST_TLS_KEY_PEM": private_key.read_text(),
        }
        service = self.start_proxy(
            tls={
                "cert_env": "SYSTEM_TEST_TLS_CERT_PEM",
                "key_env": "SYSTEM_TEST_TLS_KEY_PEM",
            },
            environment=environment,
        )
        self.assertEqual(request(service.base_url, "GET", "/healthz").status, 204)
        self.assertEqual(service.stop(), 0)
        self.services.remove(service)

        invalid_yaml = self.workspace.root / "invalid.yaml"
        invalid_yaml.write_text("server: [\n")
        result = run_to_exit(self.binary, invalid_yaml)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed to parse", result.stderr)

        write_config(
            self.workspace.config,
            bind=f"127.0.0.1:{reserve_port()}",
            database=str(self.workspace.database),
            receiver_url=self.receiver.url,
        )
        invalid_reference = self.workspace.config.read_text().replace(
            'default_receiver: "loopback"', 'default_receiver: "missing"'
        )
        self.workspace.config.write_text(invalid_reference)
        result = run_to_exit(self.binary, self.workspace.config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown receiver missing", result.stderr)

        write_config(
            self.workspace.config,
            bind=f"127.0.0.1:{reserve_port()}",
            database="/proc/simple-alert-proxy/system-e2e.db",
            receiver_url=self.receiver.url,
        )
        result = run_to_exit(self.binary, self.workspace.config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed to create sqlite database directory", result.stderr)

        write_config(
            self.workspace.config,
            bind=f"127.0.0.1:{reserve_port()}",
            database=str(self.workspace.database),
            receiver_url=self.receiver.url,
            tls={"cert_env": "MISSING_TLS_CERT", "key_env": "MISSING_TLS_KEY"},
        )
        result = run_to_exit(self.binary, self.workspace.config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("environment variable MISSING_TLS_CERT is not set", result.stderr)

        broken_certificate = self.workspace.root / "broken.crt"
        broken_private_key = self.workspace.root / "broken.key"
        broken_certificate.write_text("not a certificate\n")
        broken_private_key.write_text("not a private key\n")
        write_config(
            self.workspace.config,
            bind=f"127.0.0.1:{reserve_port()}",
            database=str(self.workspace.database),
            receiver_url=self.receiver.url,
            tls={
                "cert_path": str(broken_certificate),
                "key_path": str(broken_private_key),
            },
        )
        result = run_to_exit(self.binary, self.workspace.config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed to load TLS certificate or key", result.stderr)
        for secret in (INBOUND_TOKEN, MANAGEMENT_TOKEN, ADMIN_PASSWORD):
            self.assertNotIn(secret, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
