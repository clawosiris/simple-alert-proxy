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

### `POST /webhooks/signoz`

Accepts SigNoz alert webhook JSON. The parser expects Alertmanager-style fields:

- `status`
- `commonLabels`
- `commonAnnotations`
- `alerts[]`

The raw payload is retained for routing rules that need JSON pointer access.

Success returns `202 Accepted` with a delivery summary:

```json
{
  "delivered": 1,
  "receivers": ["critical-chat"]
}
```

Invalid payloads return `400`. Receiver failures return `502`.

If bearer authentication is enabled, missing or invalid credentials return `401`.

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

The bundled Quadlet deployment uses the file-path mode. Its environment file stores absolute host paths for the certificate and key, and the unit mounts those files into the container at `/run/simple-alert-proxy/tls/tls.crt` and `/run/simple-alert-proxy/tls/tls.key`.

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

- `status`
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

The first implementation sends plain text messages. A later iteration should support Google Chat cards with sections for labels, annotations, and instance links.

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
3. Deliver plain text Google Chat messages
4. Add route tests and config validation tests
5. Add inbound auth and request limits
6. Package as a container image
