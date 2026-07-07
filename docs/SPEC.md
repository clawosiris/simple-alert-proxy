# Simple Alert Proxy Spec

## Goal

Build a small Rust notification proxy that receives SigNoz alert webhooks, normalizes the alert payload, evaluates routing rules, and sends the alert to one or more Google Chat spaces through incoming webhooks.

## Non-Goals

- Replacing SigNoz alert rules
- Owning incident lifecycle state
- Providing a UI
- Storing alert history beyond logs and optional future metrics

## Runtime

The service is a single Rust binary.

- HTTP framework: Axum
- Async runtime: Tokio
- Config format: YAML
- Outbound HTTP: Reqwest using Rustls
- TLS serving: Rustls with PEM certificate and private key files
- Inbound authentication: optional bearer token

## HTTP API

### `GET /healthz`

Returns `204 No Content` when the process is alive.

### Read APIs

The gateway exposes compact JSON read APIs for operator and later UI use:

- `GET /api/alert-groups`
- `GET /api/alert-events`
- `GET /api/deliveries`
- `GET /api/integrations`
- `GET /api/routes`

If server bearer authentication is configured, these endpoints require the same
`Authorization: Bearer ...` header as inbound webhooks.

### Lifecycle APIs

Alert groups and delivery records support explicit operator actions:

- `POST /api/alert-groups/{id}/ack`
- `POST /api/alert-groups/{id}/resolve`
- `POST /api/alert-groups/{id}/silence`
- `POST /api/deliveries/{id}/replay`

Lifecycle actions update persisted state and write audit entries. Silence uses
a one-hour default window until configurable policies are added.

### `POST /webhooks/signoz`

This is the current SigNoz compatibility integration path. Gateway v2 work must
keep accepting this path by default unless the operator explicitly changes
`server.webhook_path`.

Accepts SigNoz alert webhook JSON. The parser expects Alertmanager-style fields:

- `status`
- `commonLabels`
- `commonAnnotations`
- `alerts[]`

The raw payload is retained for routing rules that need JSON pointer access.

The proxy groups alerts by `ruleId` before delivery. When one webhook payload contains alerts for multiple `ruleId` values, the proxy splits the payload by `ruleId`. When SigNoz emits separate webhook requests for instances of the same rule, the proxy accepts each request, holds grouped alerts for the configured debounce window, and then sends one outgoing notification with the instances combined.

Success returns `202 Accepted` with an accepted delivery summary:

```json
{
  "delivered": 1,
  "receivers": ["critical-chat"]
}
```

Invalid payloads return `400`. Ungrouped receiver failures return `502`. Grouped delivery failures happen after the webhook response and are logged.

If bearer authentication is enabled, missing or invalid credentials return `401`.

### `POST /webhooks/{integration}`

Generic JSON integrations can be configured under `integrations`. Each
integration maps fields from an arbitrary JSON payload into the canonical alert
event model with config only.

```yaml
integrations:
  openvas-example:
    type: generic_json
    path: "/webhooks/openvas-example"
    auth:
      bearer_token: "replace-me"
    source: "openvas"
    status: "state"
    severity: "risk.level"
    title: "finding.title"
    body: "finding.description"
    fingerprint: "finding.id"
    starts_at: "observed_at"
    labels:
      asset: "asset.host"
    annotations:
      plugin: "finding.plugin"
    links:
      source: "finding.url"
```

Field mappings accept either dotted paths such as `finding.title` or JSON
pointers such as `/finding/title`. Required mappings are `source`, `status`,
`title`, and `fingerprint`; invalid integration config fails at startup with a
clear validation error. A missing configured integration returns `404`, while a
payload missing a required mapped field returns `400`.

Integration-specific bearer auth overrides the server-level bearer token for
that integration. If no integration auth is configured, the server auth setting
applies.

## SigNoz Integration

SigNoz's webhook notification channel posts Alertmanager-style webhook payloads to the proxy. In current SigNoz docs, the setup flow is:

1. `Settings -> Account Settings -> Notification Channels`
2. `New Channel`
3. choose `Webhook`
4. set the proxy URL, for example `https://proxy.example.com/webhooks/signoz`
5. use `Test` to send a sample alert

The webhook-channel docs describe a webhook URL and optional username/password fields. This proxy's native inbound auth uses a bearer token, so deployments that enable `server.auth.bearer_token` may need a reverse proxy or another hop that injects `Authorization: Bearer ...` before forwarding to `simple-alert-proxy`.

## TLS

TLS is optional.

```yaml
server:
  bind: "0.0.0.0:8443"
  tls:
    cert_path: "/run/simple-alert-proxy/tls/tls.crt"
    key_path: "/run/simple-alert-proxy/tls/tls.key"
```

If `server.tls` is omitted, the service listens over plain HTTP. In production, either enable native TLS or run behind a TLS-terminating reverse proxy.

TLS supports two source modes:

- `cert_path` and `key_path`: read PEM files from disk. Values can be literal paths or whole-value environment references in `$VAR` or `${VAR}` form.
- `cert_env` and `key_env`: read PEM content directly from environment variables. Literal `\n` sequences are converted into real newlines before parsing.

The bundled Quadlet deployment uses the file-path mode. A pre-start helper reads the real certificate and key paths from `/etc/default/simple-alert-proxy`, copies them into `/etc/simple-alert-proxy/tls.crt` and `/etc/simple-alert-proxy/tls.key` with container-readable ownership and permissions, and the unit mounts those prepared copies into `/run/simple-alert-proxy/tls/tls.crt` and `/run/simple-alert-proxy/tls/tls.key`.

Do not mix file path and environment-content sources for the same TLS config.

## Inbound Authentication

Bearer authentication is optional but recommended for every exposed deployment.

```yaml
server:
  auth:
    bearer_token: "replace-me"
```

SigNoz should send:

```http
Authorization: Bearer replace-me
```

The current implementation uses a shared secret. If SigNoz can emit signed webhooks in the target deployment, HMAC verification should replace or complement this.

## Limits And Timeouts

The service rejects request bodies larger than `server.max_body_bytes`.

```yaml
server:
  max_body_bytes: 1048576
```

Google Chat receivers use `timeout_secs` to bound outbound delivery time.

```yaml
receivers:
  default-chat:
    type: google_chat
    timeout_secs: 10
```

Accepted alert events and delivery records are persisted in SQLite before
outbound delivery is attempted. The default database path is
`simple-alert-proxy.db`.

```yaml
storage:
  type: sqlite
  path: "simple-alert-proxy.db"

delivery:
  max_attempts: 3
  initial_backoff_millis: 250
  max_backoff_millis: 30000
```

Delivery records store target name, status, attempt count, next retry time,
last redacted error, request summary, and response summary. Delivery failures
retry with bounded exponential backoff and move to `dead_letter` after retry
exhaustion. Request summaries store route and receiver names, not receiver
webhook URLs.

Alert groups are keyed by normalized event fingerprint. Repeated active events
increment `event_count` and update `last_event_at`; resolved events mark the
group `resolved`.

Alert grouping uses a short debounce window so separate SigNoz webhook calls for the same rule can be combined before delivery. Grouped alerts are enqueued before the webhook response returns, then flushed in the background after the debounce window.

```yaml
alert_grouping:
  enabled: true
  debounce_millis: 1000
```

The grouping key includes receiver, route, status, and `ruleId`, so unrelated routes and firing/resolved transitions are not merged into the same outgoing notification.

## Debug Logging

Debug alert logging is disabled by default.

```yaml
debug:
  log_alerts: true
```

When enabled, the service writes the raw incoming webhook payload and each outgoing receiver payload to stderr as pretty-printed JSON. Outgoing logs include the route and receiver names but do not include receiver webhook URLs.

Only enable this for debugging. Alert payloads can contain sensitive labels, annotations, and incident context.

## Routing

Routes are evaluated in order. Every matcher on a route must match. A route can stop evaluation or allow later routes with `continue_matching`.

Supported matcher operators:

- `equals`
- `contains`
- `regex`

Supported matcher fields:

- `integration`
- `source`
- `status`
- `severity`
- `title`
- `fingerprint`
- `label.<name>`
- `annotation.<name>`
- `payload.<json-pointer-or-path>`

Example:

```yaml
routing:
  default_receiver: "default-chat"
  routes:
    - name: "critical-prod"
      receiver: "critical-chat"
      matchers:
        - field: "label.severity"
          equals: "critical"
        - field: "label.environment"
          regex: "prod|production"
```

## Receivers

Initial receiver support is Google Chat incoming webhooks.

```yaml
receivers:
  critical-chat:
    type: google_chat
    webhook_url: "https://chat.googleapis.com/v1/spaces/..."
    title_template: "[{{status}}] {{alertname}}"
    timeout_secs: 10
```

The current implementation sends a compact Google Chat card payload with status, per-severity counts, grouped host/resource rows, and a labeled source link when present.

## Security

Required before production:

- Configure bearer authentication for inbound SigNoz webhooks
- Prefer HMAC verification if the deployed SigNoz webhook path supports it
- Redact webhook URLs in logs
- Avoid logging full alert payloads by default
- Add receiver retry limits and optional dead-letter handling

## Observability

The service should emit structured logs for:

- Webhook accepted/rejected
- Matched route
- Receiver delivery success/failure
- Config load/validation errors

Future metrics:

- `webhooks_total`
- `routing_matches_total`
- `deliveries_total`
- `delivery_failures_total`
- `delivery_latency_seconds`

## MVP Milestones

1. Compile and run with YAML config
2. Accept real SigNoz webhook payloads
3. Deliver compact Google Chat card messages
4. Add route tests and config validation tests
5. Add inbound auth and request limits
6. Package as a container image
