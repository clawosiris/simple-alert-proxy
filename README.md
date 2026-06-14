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

## Quadlet Deployment

The repo includes a Quadlet unit at `deploy/systemd/simple-alert-proxy.container`.

It reads TLS PEM content variables from `/etc/defaults/simple-aleert-proxy`:

```bash
sudo install -D -m 0644 deploy/systemd/simple-alert-proxy.container \
  /etc/containers/systemd/simple-alert-proxy.container
sudo install -D -m 0600 deploy/systemd/simple-aleert-proxy.default \
  /etc/defaults/simple-aleert-proxy
sudo install -D -m 0644 examples/config.yaml \
  /etc/simple-alert-proxy/config.yaml
```

Set `SIMPLE_ALERT_PROXY_TLS_CERT_PEM` and `SIMPLE_ALERT_PROXY_TLS_KEY_PEM` in `/etc/defaults/simple-aleert-proxy`. PEM newlines can be escaped as `\n`, which is friendlier for environment files. Build or pull the `localhost/simple-alert-proxy:latest` image, then run:

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
