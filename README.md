# simple-alert-proxy

`simple-alert-proxy` is a compact Rust alert webhook gateway. It accepts SigNoz
and generic JSON alert webhooks, normalizes them into canonical alert events,
routes them to chat or webhook targets, persists delivery state in SQLite, and
serves a small operator UI for inspecting and acting on alerts.

The v2 branch keeps the original SigNoz-to-Google-Chat behavior as a
compatibility path while adding source-agnostic integrations, durable delivery,
alert lifecycle APIs, additional targets, escalation scheduling, and optional
advisory intelligence scaffolding.

## Feature Set

- SigNoz compatibility endpoint at `POST /webhooks/signoz`
- Generic JSON integrations at `POST /webhooks/{integration}`
- Config-only mapping into canonical alert events
- Routing by status, labels, annotations, or JSON payload fields
- Google Chat, generic webhook, Slack, Mattermost, and Discord receivers
- SQLite persistence for alert events, alert groups, deliveries, audit entries,
  escalation tasks, and advisory enrichment
- Durable delivery queue with bounded retry and dead-letter handling
- Alert groups keyed by normalized fingerprint
- Operator APIs for alert groups, events, deliveries, integrations, and routes
- Lifecycle actions for acknowledge, resolve, silence, and delivery replay
- Static operator UI at `/` and `/ui`
- Optional HTTPS listener with certificate/key paths
- Optional bearer-token authentication for inbound webhooks and APIs
- Request body size limits, receiver timeouts, and redacted stored summaries
- Config-defined escalation policies with ack/resolve stop conditions
- Optional intelligence config that is disabled by default and advisory only

## Quick Start

```bash
cargo run -- --config examples/config.yaml
```

To run the published container image, copy the example config first and adjust
it for container networking and persistent storage:

```bash
mkdir -p .local/simple-alert-proxy/data
cp examples/config.yaml .local/simple-alert-proxy/config.yaml
```

In `.local/simple-alert-proxy/config.yaml`, set:

```yaml
server:
  bind: "0.0.0.0:8080"
storage:
  path: "/var/lib/simple-alert-proxy/simple-alert-proxy.db"
```

Run with Podman:

```bash
podman run --rm --name simple-alert-proxy \
  --pull=always \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/.local/simple-alert-proxy/config.yaml:/etc/simple-alert-proxy/config.yaml:ro,Z" \
  -v "$PWD/.local/simple-alert-proxy/data:/var/lib/simple-alert-proxy:Z" \
  ghcr.io/clawosiris/simple-alert-proxy:latest
```

Run with Docker:

```bash
docker run --rm --name simple-alert-proxy \
  --pull=always \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/.local/simple-alert-proxy/config.yaml:/etc/simple-alert-proxy/config.yaml:ro" \
  -v "$PWD/.local/simple-alert-proxy/data:/var/lib/simple-alert-proxy" \
  ghcr.io/clawosiris/simple-alert-proxy:latest
```

Send the bundled SigNoz-compatible fixture:

```bash
curl -X POST http://127.0.0.1:8080/webhooks/signoz \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer replace-me' \
  --data @examples/signoz-webhook.json
```

Send the bundled generic JSON fixture:

```bash
curl -X POST http://127.0.0.1:8080/webhooks/openvas-example \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer replace-me' \
  --data @examples/generic-json-webhook.json
```

Open the operator UI:

```text
http://127.0.0.1:8080/ui
```

## HTTP API

### Health

- `GET /healthz`

### Webhooks

- `POST /webhooks/signoz`
- `POST /webhooks/{integration}`
- `POST /debug/webhook`

`/webhooks/signoz` is the compatibility integration for existing SigNoz
deployments. Generic integrations are configured under `integrations` and can
map arbitrary JSON payloads into canonical alert events without Rust changes.

Accepted webhooks are persisted and queued before the service returns
`202 Accepted`; outbound target delivery happens through the delivery worker.

`/debug/webhook` is an authenticated diagnostic intake that pretty-prints the
incoming JSON payload to stderr and returns `202 Accepted` without persisting,
routing, or delivering it. This endpoint always requires
`server.auth.bearer_token`; it returns `401 Unauthorized` if auth is missing
from the request or not configured on the server.

### Read APIs

- `GET /api/alert-groups`
- `GET /api/alert-events`
- `GET /api/deliveries`
- `GET /api/advisories`
- `GET /api/integrations`
- `GET /api/routes`

### Lifecycle APIs

- `POST /api/alert-groups/{id}/ack`
- `POST /api/alert-groups/{id}/resolve`
- `POST /api/alert-groups/{id}/silence`
- `POST /api/deliveries/{id}/replay`

Lifecycle actions update persistent state and write audit entries. Acknowledge
and resolve actions also cancel scheduled escalation tasks for the alert group.

If `server.auth.bearer_token` is configured, these APIs require the same
`Authorization: Bearer ...` header as inbound webhooks.

## Configuration

See [examples/config.yaml](examples/config.yaml) for a complete working
configuration and [docs/ALERT_WEBHOOK_GATEWAY_OPENSPEC.md](docs/ALERT_WEBHOOK_GATEWAY_OPENSPEC.md)
for the v2 implementation plan. [docs/SPEC.md](docs/SPEC.md) still contains
lower-level API and compatibility notes.

The original SigNoz path remains configurable:

```yaml
server:
  bind: "127.0.0.1:8080"
  webhook_path: "/webhooks/signoz"
  max_body_bytes: 1048576
  auth:
    bearer_token: "replace-me"
```

Generic JSON integrations use dotted paths or JSON pointers to map payload
fields:

```yaml
integrations:
  openvas-example:
    type: "generic_json"
    preset: "openvas_scan"
    path: "/webhooks/openvas-example"
    auth:
      bearer_token: "replace-me"
    source: "openvas"
    status: "state"
    severity: "risk.level"
    title: "finding.title"
    body: "finding.description"
    fingerprint: "finding.id"
    labels:
      asset: "asset.host"
    annotations:
      plugin: "finding.plugin"
```

Supported generic JSON presets are:

- `alertmanager`
- `grafana`
- `openobserve`
- `openvas_scan`

SQLite persistence and retry policy:

```yaml
storage:
  type: "sqlite"
  path: "simple-alert-proxy.db"

delivery:
  max_attempts: 3
  initial_backoff_millis: 250
  max_backoff_millis: 30000
```

Receiver types:

```yaml
receivers:
  default-chat:
    type: "google_chat"
    webhook_url: "https://chat.googleapis.com/v1/spaces/example/messages?key=example&token=example"

  generic-webhook:
    type: "generic_webhook"
    webhook_url: "https://alerts.example.test/webhook"

  slack-alerts:
    type: "slack"
    webhook_url: "https://hooks.slack.com/services/example"

  mattermost-alerts:
    type: "mattermost"
    webhook_url: "https://mattermost.example.test/hooks/example"

  discord-alerts:
    type: "discord"
    webhook_url: "https://discord.com/api/webhooks/example"
```

Escalation policies can be attached to routes:

```yaml
escalation:
  policies:
    primary-on-duty:
      steps:
        - receiver: "critical-chat"
          delay_millis: 300000
          stop_on_ack: true
          stop_on_resolve: true

routing:
  routes:
    - name: "critical-production"
      receiver: "critical-chat"
      escalation_policy: "primary-on-duty"
```

Optional intelligence is disabled by default. Advisory output is stored
separately from canonical alert and lifecycle state:

```yaml
intelligence:
  enabled: false
  allow_lifecycle_mutation: false
```

## SigNoz Setup

SigNoz's current docs route webhook setup through
`Settings -> Account Settings -> Notification Channels`, then `New Channel`,
then `Webhook`.

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
10. Attach that notification channel to the alert rule or alert policy you want
    to forward.

Auth note:

- SigNoz's webhook-channel docs describe a webhook URL and optional
  username/password fields.
- This proxy's built-in auth expects `Authorization: Bearer ...` when
  `server.auth.bearer_token` is set.
- The simplest setup is to leave `server.auth` unset for the SigNoz-facing
  endpoint, or put a reverse proxy in front that adds the bearer header before
  forwarding to `simple-alert-proxy`.

## Alert Grouping

Alert grouping is enabled by default. The proxy accepts matching webhook
requests, waits briefly before sending outbound notifications, and combines
multiple SigNoz webhook calls for the same `ruleId` into one Google Chat card
with multiple instances:

```yaml
alert_grouping:
  enabled: true
  debounce_millis: 1000
```

Gateway v2 also persists normalized alert groups keyed by fingerprint. Repeated
active events increment the group count and update timestamps; resolved events
mark the group resolved.

## Debug Logging

To log incoming webhook payloads and outgoing receiver payloads to stderr:

```yaml
debug:
  log_alerts: true
```

Only enable this while debugging. Alert payloads can contain sensitive labels,
annotations, and incident context.

For source-side webhook troubleshooting without routing an alert, send JSON to
`POST /debug/webhook` with `Authorization: Bearer ...`. The endpoint logs the
payload and returns `{"logged":true}`.

## TLS

TLS is optional.

```yaml
server:
  tls:
    cert_path: "/run/simple-alert-proxy/tls/tls.crt"
    key_path: "/run/simple-alert-proxy/tls/tls.key"
```

If `server.tls` is omitted, the service listens over plain HTTP. In production,
either enable native TLS or run behind a TLS-terminating reverse proxy.

TLS supports PEM files on disk, whole-value environment references in `$VAR` or
`${VAR}` form, and PEM content read directly from environment variables. See
[docs/SPEC.md](docs/SPEC.md) for the exact TLS contract.

## Container Build

After creating the container-ready `.local/simple-alert-proxy/config.yaml` from
the Quick Start, build and run a local image:

```bash
podman build -t simple-alert-proxy:local .
podman run --rm -p 8080:8080 \
  -v "$PWD/.local/simple-alert-proxy/config.yaml:/etc/simple-alert-proxy/config.yaml:ro,Z" \
  -v "$PWD/.local/simple-alert-proxy/data:/var/lib/simple-alert-proxy:Z" \
  simple-alert-proxy:local
```

Release images are published to GitHub Container Registry:

```bash
podman pull ghcr.io/clawosiris/simple-alert-proxy:0.0.5
podman pull ghcr.io/clawosiris/simple-alert-proxy:latest
```

## Quadlet Deployment

The repo includes a Quadlet unit at
[deploy/systemd/simple-alert-proxy.container](deploy/systemd/simple-alert-proxy.container).

It uses an environment file to point at the source certificate/key, then a
pre-start helper copies them into fixed host paths that the container mounts:

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

Set `SIMPLE_ALERT_PROXY_TLS_CERT_FILE` and
`SIMPLE_ALERT_PROXY_TLS_KEY_FILE` in `/etc/default/simple-alert-proxy` to the
real host-side source paths. On startup, the helper copies them into
`/etc/simple-alert-proxy/tls.crt` and `/etc/simple-alert-proxy/tls.key` with
ownership and permissions that allow the containerized service to read them.

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

The image includes a default HTTP health check for `GET /healthz` on
`127.0.0.1:8080`. The bundled Quadlet unit overrides it for the native TLS
deployment path and checks `https://127.0.0.1:8443/healthz` every 30 seconds
with a 3-second timeout, 3 retries, and a 30-second startup grace period. If the
health check fails repeatedly, Podman kills the container and systemd restarts
it through the unit's `Restart=on-failure` policy.

## Development

```bash
cargo fmt --check
cargo test
```

Current gateway planning and compatibility docs:

- [docs/ALERT_WEBHOOK_GATEWAY_PRD.md](docs/ALERT_WEBHOOK_GATEWAY_PRD.md)
- [docs/ALERT_WEBHOOK_GATEWAY_OPENSPEC.md](docs/ALERT_WEBHOOK_GATEWAY_OPENSPEC.md)
- [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)
- [docs/SPEC.md](docs/SPEC.md)

## License

simple-alert-proxy is licensed under the GNU Affero General Public License v3.0
or later. See [LICENSE](LICENSE).

## Security

Security issues should be reported privately as described in
[SECURITY.md](SECURITY.md).
