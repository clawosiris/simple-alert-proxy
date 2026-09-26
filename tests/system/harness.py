"""Reusable real-process and loopback-receiver harness for system tests."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable


INBOUND_TOKEN = "system-inbound-token"
MANAGEMENT_TOKEN = "system-management-token"
ADMIN_PASSWORD = "system-admin-password"
MATRIX_TOKEN = "system-matrix-token"
REDACTIONS = (INBOUND_TOKEN, MANAGEMENT_TOKEN, ADMIN_PASSWORD, MATRIX_TOKEN)


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def eventually(
    operation: Callable[[], Any],
    predicate: Callable[[Any], bool] = bool,
    *,
    timeout: float = 10.0,
    interval: float = 0.05,
    description: str = "condition",
) -> Any:
    deadline = time.monotonic() + timeout
    last_value: Any = None
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            last_value = operation()
            if predicate(last_value):
                return last_value
        except BaseException as error:  # readiness must preserve the last useful failure
            last_error = error
        time.sleep(interval)
    detail = f"; last value: {last_value!r}"
    if last_error is not None:
        detail += f"; last error: {last_error}"
    raise AssertionError(f"timed out waiting for {description}{detail}")


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


def request(
    base_url: str,
    method: str,
    path: str,
    *,
    payload: Any | None = None,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 2.0,
    verify_tls: bool = False,
    ca_file: Path | None = None,
) -> HttpResponse:
    request_headers = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload).encode()
        request_headers.setdefault("content-type", "application/json")
    context = None
    if base_url.startswith("https://"):
        if ca_file is not None:
            context = ssl.create_default_context(cafile=str(ca_file))
        elif not verify_tls:
            context = ssl._create_unverified_context()  # noqa: SLF001 - readiness probe
    outgoing = urllib.request.Request(
        f"{base_url}{path}", data=body, headers=request_headers, method=method
    )
    try:
        with urllib.request.urlopen(outgoing, timeout=timeout, context=context) as response:
            return HttpResponse(
                response.status,
                {name.lower(): value for name, value in response.headers.items()},
                response.read(),
            )
    except urllib.error.HTTPError as error:
        return HttpResponse(
            error.code,
            {name.lower(): value for name, value in error.headers.items()},
            error.read(),
        )


@dataclass(frozen=True)
class ScriptedResponse:
    status: int = 200
    body: bytes = b"{}"
    delay: float = 0.0
    headers: tuple[tuple[str, str], ...] = (("content-type", "application/json"),)


class ScriptedReceiver:
    def __init__(self, artifact_path: Path | None = None, host: str = "127.0.0.1") -> None:
        self._responses: list[ScriptedResponse] = []
        self._requests: list[dict[str, Any]] = []
        self._condition = threading.Condition()
        self._artifact_path = artifact_path
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                owner._handle(self)

            def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                owner._handle(self)

            def log_message(self, _format: str, *_args: Any) -> None:
                return

        self._server = ThreadingHTTPServer((host, 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/receiver"

    @property
    def requests(self) -> list[dict[str, Any]]:
        with self._condition:
            return list(self._requests)

    def start(self) -> "ScriptedReceiver":
        self._thread.start()
        return self

    def script(self, *responses: ScriptedResponse) -> None:
        with self._condition:
            self._responses.extend(responses)

    def wait_for_requests(self, count: int, timeout: float = 10.0) -> list[dict[str, Any]]:
        deadline = time.monotonic() + timeout
        with self._condition:
            while len(self._requests) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(
                        f"expected {count} receiver requests, got {len(self._requests)}"
                    )
                self._condition.wait(remaining)
            return list(self._requests)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)
        self._write_artifact()

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        length = int(handler.headers.get("content-length", "0"))
        body = handler.rfile.read(length)
        try:
            decoded_body: Any = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            decoded_body = body.decode(errors="replace")
        record = {
            "method": handler.command,
            "path": handler.path,
            "headers": {
                name.lower(): redact(value)
                for name, value in handler.headers.items()
                if name.lower() not in {"authorization", "cookie"}
            },
            "body": sanitize(decoded_body),
        }
        with self._condition:
            self._requests.append(record)
            response = self._responses.pop(0) if self._responses else ScriptedResponse()
            self._condition.notify_all()
        self._write_artifact()
        if response.delay:
            time.sleep(response.delay)
        try:
            handler.send_response(response.status)
            for name, value in response.headers:
                handler.send_header(name, value)
            handler.end_headers()
            handler.wfile.write(response.body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _write_artifact(self) -> None:
        if self._artifact_path is None:
            return
        self._artifact_path.parent.mkdir(parents=True, exist_ok=True)
        self._artifact_path.write_text(
            json.dumps(self.requests, indent=2, sort_keys=True, default=str) + "\n"
        )


class ProxyProcess:
    def __init__(
        self,
        binary: Path,
        config: Path,
        base_url: str,
        artifact_dir: Path,
        *,
        environment: dict[str, str] | None = None,
    ) -> None:
        self.binary = binary
        self.config = config
        self.base_url = base_url
        self.artifact_dir = artifact_dir
        self.environment = environment or {}
        self.process: subprocess.Popen[bytes] | None = None
        self._stdout = None
        self._stderr = None

    def start(self) -> "ProxyProcess":
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self._stdout = (self.artifact_dir / "stdout.log").open("ab")
        self._stderr = (self.artifact_dir / "stderr.log").open("ab")
        environment = os.environ.copy()
        environment.update(
            {
                "RUST_LOG": "simple_alert_proxy=info",
                "SYSTEM_E2E_BOOTSTRAP_PASSWORD": ADMIN_PASSWORD,
            }
        )
        environment.update(self.environment)
        self.process = subprocess.Popen(
            [str(self.binary), "--config", str(self.config)],
            env=environment,
            stdout=self._stdout,
            stderr=self._stderr,
            start_new_session=True,
        )
        try:
            eventually(
                self._health,
                lambda response: response.status == 204,
                timeout=12,
                description=f"{self.base_url}/healthz readiness",
            )
        except BaseException:
            self._close_logs()
            raise AssertionError(self.failure_context())
        return self

    def stop(self, *, expect_success: bool = True, timeout: float = 12.0) -> int:
        if self.process is None:
            return 0
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
                raise AssertionError(f"proxy did not stop after SIGTERM\n{self.failure_context()}")
        return_code = int(self.process.returncode or 0)
        self._close_logs()
        self._redact_logs()
        if expect_success and return_code != 0:
            raise AssertionError(
                f"proxy exited with status {return_code}\n{self.failure_context()}"
            )
        return return_code

    def failure_context(self) -> str:
        status = self.process.poll() if self.process is not None else "not started"
        self._close_logs()
        self._redact_logs()
        stderr = _tail(self.artifact_dir / "stderr.log")
        stdout = _tail(self.artifact_dir / "stdout.log")
        return f"process status: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"

    def _health(self) -> HttpResponse:
        if self.process is not None and self.process.poll() is not None:
            raise RuntimeError(f"proxy exited with {self.process.returncode}")
        return request(self.base_url, "GET", "/healthz", timeout=0.5)

    def _close_logs(self) -> None:
        for stream in (self._stdout, self._stderr):
            if stream is not None and not stream.closed:
                stream.flush()
                stream.close()

    def _redact_logs(self) -> None:
        for path in (self.artifact_dir / "stdout.log", self.artifact_dir / "stderr.log"):
            if path.exists():
                content = path.read_text(errors="replace")
                redacted = redact(content)
                if redacted != content:
                    path.write_text(redacted)


class TestWorkspace:
    def __init__(self, name: str) -> None:
        root = Path(tempfile.mkdtemp(prefix=f"simple-alert-proxy-{name}-"))
        artifact_root = Path(
            os.environ.get("SYSTEM_E2E_ARTIFACT_DIR", "target/system-e2e-artifacts")
        )
        self.root = root
        self.artifact_dir = artifact_root / name
        if self.artifact_dir.exists():
            shutil.rmtree(self.artifact_dir)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.database = root / "data" / "simple-alert-proxy.db"
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.config = root / "config.yaml"

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def write_config(
    path: Path,
    *,
    bind: str,
    database: str,
    receiver_url: str,
    batching: bool = False,
    group_wait_millis: int = 100,
    max_attempts: int = 3,
    initial_backoff_millis: int = 50,
    max_backoff_millis: int = 100,
    max_body_bytes: int = 2048,
    tls: dict[str, str] | None = None,
    local_users: bool = True,
    receiver_kind: str = "generic_webhook",
) -> None:
    def quoted(value: str) -> str:
        return json.dumps(value)

    tls_block = ""
    if tls:
        tls_lines = "\n".join(f"    {name}: {quoted(value)}" for name, value in tls.items())
        tls_block = f"\n  tls:\n{tls_lines}"
    if receiver_kind == "generic_webhook":
        receiver_block = f"""type: "generic_webhook"
    webhook_url: {quoted(receiver_url)}
    timeout_secs: 10"""
    elif receiver_kind == "matrix":
        receiver_block = f"""type: "matrix"
    homeserver_url: {quoted(receiver_url.rstrip('/'))}
    room_id: "!system:example.test"
    access_token: {quoted(MATRIX_TOKEN)}
    timeout_secs: 10"""
    else:
        raise ValueError(f"unsupported test receiver kind {receiver_kind}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"""server:
  bind: {quoted(bind)}
  webhook_path: "/webhooks/signoz"
  max_body_bytes: {max_body_bytes}
  auth:
    bearer_token: {quoted(INBOUND_TOKEN)}{tls_block}

management:
  auth:
    bearer_token: {quoted(MANAGEMENT_TOKEN)}
  local_users: {str(local_users).lower()}
  bootstrap_admin_password_env: "SYSTEM_E2E_BOOTSTRAP_PASSWORD"
  secure_cookies: false
  allow_unauthenticated: false

debug:
  log_alerts: false
  log_full_payloads: false

integrations:
  signoz:
    type: "builtin"
    preset: "signoz"
    path: "/webhooks/signoz"
    auth:
      bearer_token: {quoted(INBOUND_TOKEN)}
  synthetic:
    type: "generic_json"
    path: "/webhooks/synthetic"
    auth:
      bearer_token: {quoted(INBOUND_TOKEN)}
    source: "system-test"
    status: "state"
    severity: "severity"
    title: "title"
    body: "message"
    fingerprint: "id"
    notification_group_key: "group"
    labels:
      environment: "environment"

storage:
  type: "sqlite"
  path: {quoted(database)}
  retention_days: 90

delivery:
  max_attempts: {max_attempts}
  initial_backoff_millis: {initial_backoff_millis}
  max_backoff_millis: {max_backoff_millis}

notification_batching:
  enabled: {str(batching).lower()}
  group_wait_millis: {group_wait_millis}
  max_events: 10
  max_payload_bytes: 262144

routing:
  default_receiver: "loopback"
  routes:
    - name: "production"
      receiver: "loopback"
      matchers:
        - field: "label.environment"
          equals: "production"

receivers:
  loopback:
    {receiver_block}
"""
    )


def synthetic_payload(
    fingerprint: str,
    *,
    status: str = "firing",
    severity: str = "critical",
    group: str | None = None,
) -> dict[str, Any]:
    return {
        "state": status,
        "severity": severity,
        "title": f"Synthetic {fingerprint}",
        "message": f"system test event {fingerprint}",
        "id": fingerprint,
        "group": group or fingerprint,
        "environment": "production",
    }


def signoz_payload(fingerprint: str) -> dict[str, Any]:
    return {
        "status": "firing",
        "commonLabels": {
            "alertname": "System test SigNoz",
            "severity": "warning",
            "environment": "production",
        },
        "commonAnnotations": {"description": "black-box SigNoz event"},
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "System test SigNoz", "instance": fingerprint},
                "annotations": {"description": "black-box SigNoz event"},
                "fingerprint": fingerprint,
            }
        ],
    }


def generate_certificate(directory: Path) -> tuple[Path, Path, Path]:
    ca_certificate = directory / "ca.crt"
    ca_private_key = directory / "ca.key"
    certificate = directory / "server.crt"
    private_key = directory / "server.key"
    signing_request = directory / "server.csr"
    extensions = directory / "server.ext"
    extensions.write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"
    )
    commands = [
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=Simple Alert System Test CA",
            "-keyout",
            str(ca_private_key),
            "-out",
            str(ca_certificate),
        ],
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(private_key),
            "-out",
            str(signing_request),
        ],
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(signing_request),
            "-CA",
            str(ca_certificate),
            "-CAkey",
            str(ca_private_key),
            "-CAcreateserial",
            "-days",
            "1",
            "-sha256",
            "-extfile",
            str(extensions),
            "-out",
            str(certificate),
        ],
    ]
    for command in commands:
        subprocess.run(command, check=True, capture_output=True, timeout=15)
    return certificate, private_key, ca_certificate


def run_to_exit(
    binary: Path,
    config: Path,
    *,
    environment: dict[str, str] | None = None,
    timeout: float = 8.0,
) -> subprocess.CompletedProcess[str]:
    merged_environment = os.environ.copy()
    merged_environment.update(environment or {})
    return subprocess.run(
        [str(binary), "--config", str(config)],
        env=merged_environment,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def redact(value: str) -> str:
    for secret in REDACTIONS:
        value = value.replace(secret, "[REDACTED]")
    return value


def sanitize(value: Any, key: str = "") -> Any:
    normalized_key = key.lower().replace("-", "_")
    if any(marker in normalized_key for marker in ("token", "secret", "password", "cookie")):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {name: sanitize(item, str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return redact(value)
    return value


def _tail(path: Path, limit: int = 8_000) -> str:
    if not path.exists():
        return ""
    content = path.read_text(errors="replace")
    return content[-limit:]


def wait_for_container_http(host: str, port: int, timeout: float = 20.0) -> None:
    def health() -> int:
        connection = http.client.HTTPConnection(host, port, timeout=0.5)
        try:
            connection.request("GET", "/healthz")
            return connection.getresponse().status
        finally:
            connection.close()

    eventually(health, lambda status: status == 204, timeout=timeout, description="container health")
