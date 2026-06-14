# SigNoz Alert Proxy Spec

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

## TLS

TLS is optional.

```yaml
server:
  bind: "0.0.0.0:8443"
  tls:
    cert_path: "/etc/signoz-alert-proxy/tls.crt"
    key_path: "/etc/signoz-alert-proxy/tls.key"
```

If `server.tls` is omitted, the service listens over plain HTTP. In production, either enable native TLS or run behind a TLS-terminating reverse proxy.

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
```

The first implementation sends plain text messages. A later iteration should support Google Chat cards with sections for labels, annotations, and instance links.

## Security

Required before production:

- Add shared-secret or HMAC verification for inbound SigNoz webhooks
- Redact webhook URLs in logs
- Avoid logging full alert payloads by default
- Set request body size limits
- Add receiver timeout and retry limits

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
