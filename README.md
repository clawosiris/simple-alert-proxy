# simple-alert-proxy

A small Rust service that accepts SigNoz alert webhooks, evaluates configurable routing rules, and forwards matching notifications to Google Chat webhooks.

This repo starts as a spec-backed scaffold: the application shape, config schema, routing behavior, TLS handling, and receiver contract are defined in code and docs, with enough implementation to compile and guide the MVP.

## Feature Set

- Accept SigNoz alert webhook payloads at `POST /webhooks/signoz`
- Optional HTTPS listener with certificate/key paths
- Optional bearer-token authentication for inbound webhooks
- Request body size limits and outbound receiver timeouts
- Parse Alertmanager-style SigNoz alert payloads
- Route alerts by status, labels, annotations, or JSON payload fields
- Send routed alerts to Google Chat incoming webhooks
- Optional debug mode that logs incoming and outgoing alert payloads to stderr
- Configure the service from a YAML file

## Quick Start

```bash
cargo run -- --config examples/config.yaml
```

```bash
curl -X POST http://127.0.0.1:8080/webhooks/signoz \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer replace-me' \
  --data @examples/signoz-webhook.json
```

## Container Build

```bash
podman build -t simple-alert-proxy:local .
podman run --rm -p 8080:8080 \
  -v ./examples/config.yaml:/etc/simple-alert-proxy/config.yaml:ro,Z \
  simple-alert-proxy:local
```

Release images are published to GitHub Container Registry:

```bash
podman pull ghcr.io/clawosiris/simple-alert-proxy:0.0.3
podman pull ghcr.io/clawosiris/simple-alert-proxy:latest
```

## Quadlet Deployment

The repo includes a Quadlet unit at `deploy/systemd/simple-alert-proxy.container`.

It mounts the config and TLS files from fixed host paths:

```bash
sudo install -D -m 0644 deploy/systemd/simple-alert-proxy.container \
  /etc/containers/systemd/simple-alert-proxy.container
sudo install -D -m 0644 examples/config.yaml \
  /etc/simple-alert-proxy/config.yaml
sudo install -D -m 0600 /path/to/tls.crt \
  /etc/simple-alert-proxy/tls.crt
sudo install -D -m 0600 /path/to/tls.key \
  /etc/simple-alert-proxy/tls.key
```

Then point the app config at the mounted in-container paths:

```yaml
server:
  tls:
    cert_path: "/run/simple-alert-proxy/tls/tls.crt"
    key_path: "/run/simple-alert-proxy/tls/tls.key"
```

Build or pull the `localhost/simple-alert-proxy:latest` image, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now simple-alert-proxy.service
```

## Configuration

See [examples/config.yaml](examples/config.yaml) for a working example and [docs/SPEC.md](docs/SPEC.md) for the full contract.

To log incoming webhook payloads and outgoing receiver payloads to stderr:

```yaml
debug:
  log_alerts: true
```

Only enable this while debugging. Alert payloads can contain sensitive labels, annotations, and incident context.

## Current Status

Implemented:

- Rust service scaffold with Axum
- YAML config loading and validation
- SigNoz webhook payload parsing
- Routing engine with exact, contains, and regex matchers
- Google Chat webhook client
- TLS config loading path
- Bearer auth, body limits, and receiver timeouts
- Debug alert payload logging
- Unit/integration-style tests with a local mock Google Chat endpoint
- GitHub Actions CI
- Dockerfile

Still expected before production use:

- More exact SigNoz payload fixtures from a real deployment
- Structured Google Chat cards instead of plain text only
- Delivery retry policy and dead-letter handling
- HMAC request signing if SigNoz can support it

## License

simple-alert-proxy is licensed under the GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).

## Security

Security issues should be reported privately as described in [SECURITY.md](SECURITY.md).
