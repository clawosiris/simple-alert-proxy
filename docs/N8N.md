# n8n Integration

`simple-alert-proxy` supports n8n in both directions:

- an n8n HTTP Request node can submit one canonical alert or an explicit
  `events[]` batch to a built-in `n8n` integration; and
- an `n8n_webhook` receiver can trigger an active n8n Webhook workflow with a
  versioned JSON payload, environment-backed Header Auth, and a stable delivery
  idempotency key.

The proxy remains authoritative for normalization, lifecycle state, routing,
notification batching, retries, dead letters, and replay. It does not infer
alert semantics from arbitrary n8n execution output.

## Receive alerts from n8n

Configure a built-in integration and use a distinct bearer token for the n8n
workflow:

```yaml
integrations:
  n8n-alerts:
    type: builtin
    preset: n8n
    path: /webhooks/n8n
    auth:
      bearer_token: replace-with-a-secret
```

The single-event request body is the contract in
[`examples/n8n-webhook.json`](../examples/n8n-webhook.json). `status`, `title`,
and `fingerprint` are required non-empty strings. `severity` defaults to
`unknown`; all other fields are optional. `labels`, `annotations`, and `links`
are arbitrary string maps. `group_key` is the source hint used by durable
notification batching when a route does not define `group_by`.

Send the example directly:

```bash
curl -X POST https://proxy.example.com/webhooks/n8n \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer replace-with-a-secret' \
  --data @examples/n8n-webhook.json
```

Multiple events must use the explicit envelope shown in
[`examples/n8n-webhook-batch.json`](../examples/n8n-webhook-batch.json):

```json
{"events":[{"status":"firing","title":"Queue high","fingerprint":"queue-high"}]}
```

Each member is normalized, persisted, routed, and delivered independently.
Empty batches, a non-array `events` value, malformed maps, missing required
fields, and empty required strings return `400 Bad Request`. Valid requests are
persisted before `202 Accepted` is returned. Per-integration bearer auth,
request-size limits, concurrency limits, debug redaction, and lifecycle
namespacing work exactly as they do for other built-in integrations.

Import
[`send-alert-to-simple-alert-proxy.json`](../examples/n8n/send-alert-to-simple-alert-proxy.json)
into n8n for a ready-to-edit workflow. It expects `SIMPLE_ALERT_PROXY_URL` and
`N8N_TO_ALERT_PROXY_TOKEN` in the n8n process environment. A managed n8n
deployment that blocks `$env` expressions can replace those expressions with
an n8n Header Auth credential and a literal proxy URL.

## Send alerts to n8n

Create an n8n Webhook node, configure Header Auth, publish/activate the workflow,
and copy its **Production URL**. The Test URL only exists while n8n is listening
for a manual test execution and must not be used by a persistent receiver.

Store the header value in the proxy process environment and reference only the
variable name from YAML:

```yaml
receivers:
  n8n-automation:
    type: n8n_webhook
    webhook_url: https://n8n.example.com/webhook/alert-automation
    auth:
      type: header
      header_name: X-N8N-Webhook-Token
      value_env: SIMPLE_ALERT_PROXY_N8N_TOKEN
    timeout_secs: 10
```

The URL must be an absolute HTTP(S) URL without embedded credentials, query
parameters, or a fragment. The configured header name cannot replace transport
headers such as `Content-Type` or `Idempotency-Key`. Missing, empty, or invalid
environment-backed header values fail safely as a permanent target
configuration error; their values are never included in delivery summaries,
APIs, UI records, or debug payload logs.

The receiver sends one POST request for each queued delivery. Any 2xx response
is success. Timeouts, 408, 425, 429, and 5xx responses use the normal retry and
dead-letter policy; other 4xx responses are permanent failures. Durable
notification batches remain one queued delivery, one HTTP request, and one
retry/dead-letter unit.

The default JSON body has `contract: "simple-alert-proxy.n8n.v1"` and one of:

- `kind: "event"`, with `event` and `delivery`; or
- `kind: "notification_batch"`, with `batch`, `events`, and `delivery`.

The normalized event objects deliberately omit raw source payloads. `delivery`
contains `route`, `receiver`, optional `owner_team`, and `idempotency_key`. The
same key is also sent in the `Idempotency-Key` header. It remains stable across
automatic retries and restart recovery, and a manual replay creates a new key.
Use that value in n8n before performing non-idempotent side effects.

Import
[`receive-alert-from-simple-alert-proxy.json`](../examples/n8n/receive-alert-from-simple-alert-proxy.json)
for a Webhook plus Code-node deduplication example. The workflow's static-data
map is illustrative; choose durable storage appropriate to the side effect and
retention window in production.

`template.payload` can replace the complete JSON body when an existing n8n
workflow requires another shape. The normal safe template context is available,
but raw payloads, receiver URLs, environment variables, and secrets are not.
The `Idempotency-Key` HTTP header is still added when a payload template is used.

## Troubleshooting and loop avoidance

- `401` from the proxy means the n8n HTTP Request bearer token is missing or
  wrong. A `400` response includes the malformed contract reason.
- A delivery stuck in retry/dead-letter usually means the production Webhook
  URL is inactive, unreachable, timed out, or returned a non-2xx response.
- Keep request bodies under `server.max_body_bytes`; rendered outbound bodies
  are limited to 256 KiB, and notification batches also obey configured event
  and payload bounds.
- If one workflow receives proxy alerts and also emits alerts back to the proxy,
  add an origin label or a workflow filter. Otherwise it can create an alert
  loop even though delivery idempotency prevents duplicate retries of one unit.
