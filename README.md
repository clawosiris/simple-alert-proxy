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
podman pull ghcr.io/clawosiris/simple-alert-proxy:0.0.4
podman pull ghcr.io/clawosiris/simple-alert-proxy:latest
```

## Quadlet Deployment

The repo includes a Quadlet unit at `deploy/systemd/simple-alert-proxy.container`.

It uses an environment file to point at the source certificate/key, then a pre-start helper copies them into fixed host paths that the container mounts:

```bash
sudo install -D -m 0644 deploy/systemd/simple-alert-proxy.container \
  /etc/containers/systemd/simple-alert-proxy.container
sudo install -D -m 0755 deploy/systemd/prepare-simple-alert-proxy-tls.sh \
  /usr/local/libexec/simple-alert-proxy/prepare-simple-alert-proxy-tls.sh
sudo install -D -m 0600 deploy/systemd/simple-alert-proxy.default \
  /etc/default/simple-alert-proxy
sudo install -D -m 0644 examples/config.yaml \
  /etc/simple-alert-proxy/config.yaml
```

Set `SIMPLE_ALERT_PROXY_TLS_CERT_FILE` and `SIMPLE_ALERT_PROXY_TLS_KEY_FILE` in `/etc/default/simple-alert-proxy` to the real host-side source paths. On startup, the helper copies them into `/etc/simple-alert-proxy/tls.crt` and `/etc/simple-alert-proxy/tls.key` with ownership and permissions that allow the containerized service to read them.

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

## Set Up SigNoz Notification Channel

SigNoz's current docs route webhook setup through `Settings -> Account Settings -> Notification Channels`, then `New Channel`, then `Webhook`.

For this proxy:

1. Deploy `simple-alert-proxy` somewhere SigNoz can reach it.
2. Decide whether the proxy will listen on plain HTTP or HTTPS.
3. Note the full webhook URL for SigNoz:

```text
https://your-proxy.example.com/webhooks/signoz
```

Or, if you changed the path in config:

```text
https://your-proxy.example.com/<your-webhook-path>
```

4. In SigNoz, go to `Settings -> Account Settings -> Notification Channels`.
5. Click `New Channel`.
6. Enter a name like `simple-alert-proxy`.
7. Select `Webhook` as the channel type.
8. Paste the proxy URL into the `Webhook URL` field.
9. Use SigNoz's `Test` button to send a sample payload to the proxy.
10. Attach that notification channel to the alert rule or alert policy you want to forward.

Auth note:

- SigNoz's webhook-channel docs describe a webhook URL and optional username/password fields.
- This proxy's built-in auth expects `Authorization: Bearer ...` when `server.auth.bearer_token` is set.
- The simplest setup is to leave `server.auth` unset for the SigNoz-facing endpoint, or put a reverse proxy in front that adds the bearer header before forwarding to `simple-alert-proxy`.

Routing note:

- SigNoz sends Alertmanager-style webhook payloads.
- `simple-alert-proxy` routes those alerts using `routing.default_receiver` and `routing.routes` from `config.yaml`.
- You do not need a separate SigNoz notification channel per Google Chat space unless you want different SigNoz rules to target different proxy instances.

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
- Delivery retry policy and dead-letter handling
- HMAC request signing if SigNoz can support it

## License

simple-alert-proxy is licensed under the GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).

## Security

Security issues should be reported privately as described in [SECURITY.md](SECURITY.md).
