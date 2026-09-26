# simple-alert-proxy

`simple-alert-proxy` is a compact Rust alert webhook gateway. It accepts SigNoz,
Grafana, CloudEvents 1.0, and generic JSON alert webhooks, normalizes them into
canonical alert events, routes them to chat or webhook targets, persists
delivery state in SQLite, and serves a small operator UI for inspecting and
acting on alerts.

The current mainline implementation keeps the original SigNoz-to-Google-Chat
behavior as a compatibility path while adding source-agnostic integrations,
durable delivery, alert lifecycle APIs, additional targets, escalation
scheduling, and optional advisory intelligence scaffolding.

## Feature Set

- SigNoz compatibility endpoint at `POST /webhooks/signoz`
- First-class Grafana webhook endpoint support through configured integrations
- CloudEvents 1.0 structured and binary JSON input
- Generic JSON integrations at `POST /webhooks/{integration}`
- Config-only mapping into canonical alert events
- Routing by status, labels, annotations, or JSON payload fields
- Google Chat, generic webhook, Slack, Mattermost, Discord, and Matrix receivers
- SQLite persistence for alert events, alert groups, deliveries, audit entries,
  escalation tasks, and advisory enrichment
- Durable delivery queue with bounded retry and dead-letter handling
- Alert groups keyed by integration/tenant namespace plus normalized fingerprint
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

To run the published container image, copy the example config first. It already
uses the container data path for SQLite storage:

```bash
image=ghcr.io/clawosiris/simple-alert-proxy:latest
mkdir -p .local/simple-alert-proxy/data
cp examples/config.yaml .local/simple-alert-proxy/config.yaml
```

In `.local/simple-alert-proxy/config.yaml`, keep:

```yaml
server:
  bind: "0.0.0.0:8080"
storage:
  path: "/var/lib/simple-alert-proxy/data/simple-alert-proxy.db"
  retention_days: 90
```

The image runs as the non-root `simple-alert-proxy` user. Make the mounted data
directory writable by that in-container user before starting the service. The
host data directory and the in-container storage path must line up: the examples
below mount `.local/simple-alert-proxy/data` at
`/var/lib/simple-alert-proxy/data`, so the SQLite path also uses that directory.

Run with Podman:

```bash
uid="$(podman run --rm --entrypoint /usr/bin/id "$image" -u simple-alert-proxy)"
gid="$(podman run --rm --entrypoint /usr/bin/id "$image" -g simple-alert-proxy)"
podman unshare chown -R "$uid:$gid" .local/simple-alert-proxy/data

podman run --rm --name simple-alert-proxy \
  --pull=always \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/.local/simple-alert-proxy/config.yaml:/etc/simple-alert-proxy/config.yaml:ro,Z" \
  -v "$PWD/.local/simple-alert-proxy/data:/var/lib/simple-alert-proxy/data:Z" \
  "$image"
```

Run with Docker:

```bash
uid="$(docker run --rm --entrypoint /usr/bin/id "$image" -u simple-alert-proxy)"
gid="$(docker run --rm --entrypoint /usr/bin/id "$image" -g simple-alert-proxy)"
sudo chown -R "$uid:$gid" .local/simple-alert-proxy/data

docker run --rm --name simple-alert-proxy \
  --pull=always \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/.local/simple-alert-proxy/config.yaml:/etc/simple-alert-proxy/config.yaml:ro" \
  -v "$PWD/.local/simple-alert-proxy/data:/var/lib/simple-alert-proxy/data" \
  "$image"
```

For a disposable local test, you can skip the data volume and ownership commands;
SQLite will write inside the temporary container filesystem.

If SQLite reports `Unable to open the database file`, confirm that the configured
`storage.path` is inside the mounted container directory and that the mounted
host directory is writable by the image's `simple-alert-proxy` UID/GID.
For older configs that still use the relative example path
`simple-alert-proxy.db`, the published image uses `/var/lib/simple-alert-proxy/data`
as its working directory so the database lands in the mounted data directory.

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

`/debug/webhook` is an authenticated diagnostic intake that logs the incoming
JSON payload to stderr and returns `202 Accepted` without persisting, routing,
or delivering it. Debug payload logging is redacted by default. This endpoint
uses `management.auth.bearer_token` when configured, falls back to
`server.auth.bearer_token` when management auth is not set, and accepts
unauthenticated requests only when `management.allow_unauthenticated: true` is
set deliberately. It returns `401 Unauthorized` if auth is required and missing
from the request.

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

Management APIs use `management.auth.bearer_token` when configured. If that is
not set, they fall back to `server.auth.bearer_token` for compatibility. Exposed
non-loopback binds require effective management auth unless
`management.allow_unauthenticated: true` is set deliberately.

## Configuration

See [examples/config.yaml](examples/config.yaml) for a complete working
configuration and [docs/ALERT_WEBHOOK_GATEWAY_OPENSPEC.md](docs/ALERT_WEBHOOK_GATEWAY_OPENSPEC.md)
for the current implementation plan. [docs/SPEC.md](docs/SPEC.md) still contains
lower-level API and compatibility notes.

The default SigNoz compatibility path remains `/webhooks/signoz`. Older configs
can still use `server.webhook_path`; new configs should model SigNoz as a
configured built-in integration alongside other inputs:

```yaml
server:
  bind: "127.0.0.1:8080"
  webhook_path: "/webhooks/signoz"
  max_body_bytes: 1048576
  limits:
    webhook_concurrency: 64
    management_concurrency: 16
  auth:
    bearer_token: "replace-me"

management:
  auth:
    bearer_token: "replace-me"
  local_users: true
  bootstrap_admin_password_env: "SIMPLE_ALERT_PROXY_BOOTSTRAP_ADMIN_PASSWORD"
  session_ttl_secs: 28800
  secure_cookies: true
  allow_unauthenticated: false

integrations:
  signoz:
    type: "builtin"
    preset: "signoz"
    path: "/webhooks/signoz"
    auth:
      bearer_token: "replace-me"

  grafana:
    type: "builtin"
    preset: "grafana"
    path: "/webhooks/grafana"
    auth:
      bearer_token: "replace-me"
```

The built-in operator UI supports local user login backed by SQLite sessions.
On first startup, if no users exist and `management.local_users: true`, the app
creates an `admin` user from the password stored in the environment variable
named by `management.bootstrap_admin_password_env`. The default variable name is
`SIMPLE_ALERT_PROXY_BOOTSTRAP_ADMIN_PASSWORD`.

The bootstrap password is only used to initialize the first admin user. Once a
user password exists in the database, the database password hash takes
precedence; changing the environment variable does not overwrite it. Admins can
rotate user passwords in the WebUI. The legacy management bearer token remains
supported as an admin-equivalent bootstrap/emergency path and is still accepted
as `Authorization: Bearer ...`. `/healthz` remains public.

Session cookies are `HttpOnly` and `SameSite=Lax`. They use the `Secure`
attribute automatically when native `server.tls` is configured. Set
`management.secure_cookies: true` when TLS terminates at a trusted reverse proxy
or ingress in front of the app.

`server.limits.webhook_concurrency` bounds concurrent webhook intake requests.
`server.limits.management_concurrency` bounds concurrent API, UI, and debug
requests. Saturated route classes return `503 Service Unavailable` with a small
JSON error body; `/healthz` is not behind those route-class limits. Use a
trusted reverse proxy or ingress for per-client/IP rate limiting.

Built-in integrations preserve source-specific parsing behavior while using the
same configured path/auth model as generic inputs. Supported built-in presets
are:

- `signoz`
- `alertmanager`
- `grafana`

Generic JSON integrations use dotted paths or JSON pointers to map payload
fields. Supported generic JSON presets are:

- `alertmanager`
- `grafana`
- `openobserve`
- `openvas_scan`

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
    notification_group_key: "group.id"
    labels:
      asset: "asset.host"
    annotations:
      plugin: "finding.plugin"
```

SQLite persistence and retry policy:

```yaml
storage:
  type: "sqlite"
  path: "simple-alert-proxy.db"
  retention_days: 90

delivery:
  max_attempts: 3
  initial_backoff_millis: 250
  max_backoff_millis: 30000
```

`storage.retention_days` is measured in days and defaults to `90` when unset.
Alert events older than the retention window are dropped from SQLite along with
their dependent delivery and alert-group records.

Receiver types:

```yaml
receivers:
  default-chat:
    type: "google_chat"
    owner_team: "platform"
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

  matrix-alerts:
    type: "matrix"
    homeserver_url: "https://matrix.example.com"
    room_id: "!roomid:example.com"
    access_token_env: "SIMPLE_ALERT_PROXY_MATRIX_TOKEN"
    title_template: "[{{status}}] {{title}}"
```

Matrix receivers send `m.notice` messages through the Matrix Client-Server API.
The access token must belong to a user or bot account that has joined the room
and can send messages there. Prefer `access_token_env` over inline
`access_token` so Matrix credentials stay out of config files. `room_id` must
use the canonical `!room:server` form; room aliases such as `#alerts:server`
are not resolved.

### Notification templates

All receivers support guarded MiniJinja 2.x templates. Google Chat, Slack,
Mattermost, Discord, and Matrix accept a standard `template.title` /
`template.body` mode. Generic webhooks accept `template.payload`; every other
receiver can also use payload mode when its complete platform JSON body must be
controlled.

```yaml
receivers:
  platform-slack:
    type: slack
    webhook_url: "https://hooks.slack.com/services/example"
    template:
      title: "[{{ alert.severity | upper }}] {{ alert.title }}"
      body: |-
        {% if alert.body %}{{ alert.body }}{% endif %}
        {% for name, value in alert.labels | items %}
        {{ name }}={{ value }}
        {% endfor %}

  custom-webhook:
    type: generic_webhook
    webhook_url: "https://alerts.example.test/webhook"
    template:
      payload: |-
        {
          "summary": {{ alert.title | tojson }},
          "severity": {{ alert.severity | tojson }},
          "route": {{ delivery.route | tojson }}
        }
```

The allow-listed context is:

- `alert`: `integration`, `source`, `status`, `severity`, `title`, `body`,
  `fingerprint`, `starts_at`, `ends_at`, `labels`, `annotations`, and `links`.
- `delivery`: `route`, `receiver`, and optional `owner_team`.
- `group`: `count`, `status`, `severity_counts`, and `instances` for batched
  delivery. Each instance contains canonical alert fields but no raw payload.
- Legacy aliases: `status`, `severity`, `title`, and `alertname`.

Undefined variables are errors. Optional values should be checked with `{% if
... %}` or handled with MiniJinja's `default` filter. Maps can be iterated with
`{% for name, value in alert.labels | items %}` and JSON string values should
use `| tojson` in payload templates. The context deliberately excludes
`raw_payload`, receiver URLs, tokens, server/management config, environment
variables, and all credentials.

The `template` block is mutually exclusive with legacy `title_template`.
Without `template`, existing receiver payloads and the legacy automatic Google
Chat ` via <route>` title suffix remain unchanged. Replays use the currently
configured template.

Templates are compiled once at startup with strict undefined values, a 64 KiB
source limit, a fixed recursion limit, and a per-render instruction budget.
Rendered titles are limited to 4 KiB. Final payload limits are 32 KiB for
Google Chat, 40 KiB for Slack/Mattermost, 16 KiB for Discord, 64 KiB for
Matrix, and 256 KiB for generic webhooks. Standard Google Chat and Matrix modes
escape alert-controlled text before placing it in HTML-bearing fields.

Payload templates must render a JSON object. Minimal target-shape validation
requires `text` or `cardsV2` for Google Chat, `text` or `blocks` for
Slack/Mattermost, `content` or `embeds` for Discord, and string `msgtype` plus
`body` for Matrix. Templates cannot change the destination URL, method,
headers, authentication, timeout, routing, lifecycle, or retry policy. Syntax
and configuration errors stop startup. Data-dependent rendering, fuel,
recursion, size, JSON, and shape errors make the delivery a permanent
single-attempt dead letter without issuing an HTTP request; stored errors only
contain the receiver, template field, error class, and safe line information.

Escalation policies can be attached to routes:

```yaml
escalation:
  policies:
    primary-on-duty:
      steps:
        - schedule: "primary"
          delay_millis: 300000
          stop_on_ack: true
          stop_on_resolve: true
        - receiver: "critical-chat"
          delay_millis: 600000
          stop_on_ack: true
          stop_on_resolve: true

schedules:
  on_call:
    primary:
      entries:
        - receiver: "critical-chat"

routing:
  routes:
    - name: "critical-production"
      receiver: "critical-chat"
      owner_team: "platform"
      escalation_policy: "primary-on-duty"
```

Each escalation step waits `delay_millis`, then targets exactly one `receiver`,
`webhook`, `schedule`, `user`, or `team`. Receiver, webhook, and schedule
receiver entries create delivery records; user and team entries are recorded as
deferred until personal notification policies are configured.

Routes and receivers can declare `owner_team` to scope alert groups to a team.
Route ownership wins; receiver ownership is used as the fallback for default or
otherwise unowned routes. The named team must exist in the management database
before matching alerts are stored as team-owned.

Optional intelligence is disabled by default. Advisory output is stored
separately from canonical alert and lifecycle state:

```yaml
intelligence:
  enabled: false
  allow_lifecycle_mutation: false
```

## Input Setup

`simple-alert-proxy` supports three intake styles:

- Built-in source presets such as SigNoz and Grafana through configured
  `POST /webhooks/{integration}` paths
- Configured generic JSON integrations through `POST /webhooks/{integration}`
- CloudEvents 1.0 structured or binary JSON through configured
  `POST /webhooks/{integration}` paths

Built-in integrations are configured under `integrations` and keep parser logic
for payload shapes that need source-specific handling. SigNoz,
Alertmanager-compatible, and Grafana payloads use this path so `alerts[]`,
common labels/annotations, rule metadata, links, and source-specific event
cardinality keep their documented behavior.

Generic JSON integrations do not require Rust changes for simple payload shapes.
Each integration maps fields from an incoming JSON document into the canonical
alert event model used by routing, persistence, lifecycle actions, and delivery.
Mappings accept dotted object paths such as `finding.title`; JSON pointer syntax
is also supported by the integration mapper for keys that are easier to address
that way.

For generic JSON integrations, the optional `preset` field is validation and
operator metadata for the source family. The current supported generic preset
names are:

- `alertmanager`
- `grafana`
- `openobserve`
- `openvas_scan`

The bundled example uses the `openvas_scan` preset:

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
    notification_group_key: "group.id"
    starts_at: "observed_at"
    labels:
      asset: "asset.host"
    annotations:
      plugin: "finding.plugin"
    links:
      source: "finding.url"
```

Send a matching generic JSON alert with:

```bash
curl -X POST http://127.0.0.1:8080/webhooks/openvas-example \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer replace-me' \
  --data @examples/generic-json-webhook.json
```

### CloudEvents 1.0

CloudEvents integrations accept one event per request in either JSON structured
content mode or HTTP binary content mode. They validate the CloudEvents envelope
and then apply the same declarative alert mapping used by generic JSON inputs.
Core context attributes and extensions are top-level mapping values (`source`,
`type`, `subject`, `time`, `tenant`, and so on); event data is under `data`.

```yaml
integrations:
  platform-events:
    type: "cloudevents"
    path: "/webhooks/cloudevents/platform"
    auth:
      bearer_token: "replace-me"
    mapping:
      status: "data.status"
      severity: "data.severity"
      title: "data.title"
      body: "data.message"
      fingerprint: "subject"
      notification_group_key: "data.group"
      starts_at: "time"
      labels:
        tenant: "tenant"
        event_type: "type"
      links:
        runbook: "data.runbook"
```

Send the bundled structured event:

```bash
curl -X POST http://127.0.0.1:8080/webhooks/cloudevents/platform \
  -H 'content-type: application/cloudevents+json' \
  -H 'authorization: Bearer replace-me' \
  --data @examples/cloudevents-webhook.json
```

Send the equivalent data in binary content mode, where CloudEvents context is
carried in `ce-*` headers:

```bash
curl -X POST http://127.0.0.1:8080/webhooks/cloudevents/platform \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer replace-me' \
  -H 'ce-specversion: 1.0' \
  -H 'ce-id: incident-42-firing-1' \
  -H 'ce-source: urn:example:monitoring' \
  -H 'ce-type: com.example.alert.status.v1' \
  -H 'ce-subject: service/api' \
  -H 'ce-time: 2026-09-25T12:00:00Z' \
  -H 'ce-tenant: platform' \
  --data '{"status":"firing","severity":"critical","title":"API availability is low","message":"Availability dropped below the SLO","group":"platform-api"}'
```

The normalized raw payload has the same structured envelope in both modes, so
routing can match context with fields such as `source`, `payload.type`, or
`payload.tenant`. CloudEvents `source` plus `id` identifies this occurrence and
is stored as the canonical event ID. It is deliberately separate from the
configured alert `fingerprint`: firing and resolved occurrences should use new
CloudEvents IDs while mapping to the same lifecycle fingerprint (often
`subject`, an extension, or `data.fingerprint`).

Malformed CloudEvents return `400 Bad Request`. Batch mode, non-JSON event data,
and unsupported encodings return `415 Unsupported Media Type`. JSON batch mode,
duplicate suppression, and the separate CloudEvents HTTP Webhook profile
(OPTIONS consent, rate negotiation, and query-token behavior) are not included.

Use `POST /debug/webhook` while integrating a new source if you need to inspect
the redacted inbound payload before committing a mapping.

## Grafana Setup

Grafana unified alerting can send webhook contact-point payloads directly to a
configured built-in Grafana integration:

```yaml
integrations:
  grafana:
    type: "builtin"
    preset: "grafana"
    path: "/webhooks/grafana"
    auth:
      bearer_token: "replace-me"
```

Point the Grafana webhook contact point at:

```text
https://your-proxy.example.com/webhooks/grafana
```

The Grafana parser emits one canonical alert event per item in Grafana's
`alerts[]` array. If Grafana sends an empty test payload, the proxy emits one
group-level event using `groupKey`, `title`, `message`, and common labels.
Instance links such as `generatorURL`, `silenceURL`, `dashboardURL`, and
`panelURL` are exposed as structured event links. Each per-instance event keeps
the top-level Grafana context but scopes its raw `alerts[]` payload to that
instance so independently routed receivers do not receive sibling alerts.
Grafana group identity preserves the source `fingerprint` or `groupKey` while
namespacing lifecycle state by the configured integration and `orgId` when
present. The contact-point `receiver` is routing metadata, not an isolation
boundary, so duplicate notifications from contact points in the same Grafana
organization still converge on one group.

If you need a highly customized Grafana payload transform, the generic JSON
integration still accepts `preset: "grafana"` with explicit field mappings.

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
  endpoint, configure `management.auth.bearer_token` for the API/UI, or put a
  reverse proxy in front that adds the inbound bearer header before forwarding
  to `simple-alert-proxy`.

## Notification Batching

Notification batching is enabled by default. After normalization and routing,
the proxy persists matching events, waits briefly, then sends one bounded batch
to the selected receiver:

```yaml
notification_batching:
  enabled: true
  group_wait_millis: 1000
  max_events: 100
  max_payload_bytes: 262144
```

SigNoz supplies `ruleId` as its source group hint and Grafana supplies
`groupKey`. A generic JSON integration can map its own hint with
`notification_group_key`. A route can override the source hint with canonical
selectors; every selector must resolve or that event is delivered separately:

```yaml
routing:
  routes:
    - name: "production-alerts"
      receiver: "critical-chat"
      group_by: ["integration", "label.alertname", "label.environment"]
```

Supported selectors are `event_id`, `integration`, `group_namespace`, `source`,
`status`, `severity`, `title`, `fingerprint`, `label.<name>`, and
`annotation.<name>`. Batch identity also isolates receiver, route, owner team,
escalation policy, group namespace, and lifecycle status. Pending batches and
their delivery records survive restarts; attempts, retries, successes, and dead
letters are applied to every member.

`alert_grouping` and `debounce_millis` remain accepted as legacy aliases. A
generic-webhook batch with one event keeps the existing `{event, delivery}`
schema; multi-event batches use `{batch, events, delivery}`.

Notification batches are separate from lifecycle `AlertGroup` records. The
latter remain keyed by canonical group namespace plus source fingerprint and
drive deduplication, acknowledgement, resolution, silence, and escalation state.

## Debug Logging

To log incoming webhook payloads and outgoing receiver payloads to stderr:

```yaml
debug:
  log_alerts: true
  log_full_payloads: false
```

With `log_full_payloads: false`, debug output recursively redacts obvious
sensitive keys such as tokens, passwords, secrets, authorization material,
API keys, credentials, and webhook URLs. Only enable `log_full_payloads: true`
for trusted local diagnostics; raw alert payloads can contain sensitive labels,
annotations, hostnames, URLs, and incident context.

For source-side webhook troubleshooting without routing an alert, send JSON to
`POST /debug/webhook` with `Authorization: Bearer ...`. The endpoint logs the
redacted payload by default and returns `{"logged":true}`.

Webhook failures, including authorization failures, also log request context such
as method, path, source IP, forwarded IP headers, user agent, and a redacted
header map. Header values that commonly carry credentials, cookies, tokens, API
keys, or secrets are logged as `[redacted]`.

Example:

```bash
curl -X POST http://127.0.0.1:8080/debug/webhook \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer replace-me' \
  --data @examples/generic-json-webhook.json
```

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
podman build --format docker -t simple-alert-proxy:local .
podman run --rm -p 8080:8080 \
  -v "$PWD/.local/simple-alert-proxy/config.yaml:/etc/simple-alert-proxy/config.yaml:ro,Z" \
  -v "$PWD/.local/simple-alert-proxy/data:/var/lib/simple-alert-proxy/data:Z" \
  simple-alert-proxy:local
```

Release images are published to GitHub Container Registry:

```bash
podman pull ghcr.io/clawosiris/simple-alert-proxy:0.0.12
podman pull ghcr.io/clawosiris/simple-alert-proxy:latest
```

Nightly builds run from the `Nightly` GitHub Actions workflow. They verify the
Rust project, build the container image, and publish these GHCR tags from
`main`:

```bash
podman pull ghcr.io/clawosiris/simple-alert-proxy:nightly
podman pull ghcr.io/clawosiris/simple-alert-proxy:nightly-YYYYMMDD
podman pull ghcr.io/clawosiris/simple-alert-proxy:nightly-<short-sha>
```

The `nightly` tag moves with the latest successful nightly build. Date and
short-SHA nightly tags are retained in GHCR until package cleanup removes them.
Manual `Nightly` workflow runs on non-`main` branches build the image for
validation but do not publish package tags.

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
Set `SIMPLE_ALERT_PROXY_BOOTSTRAP_ADMIN_PASSWORD` there as well for first-run
WebUI admin creation:

```ini
SIMPLE_ALERT_PROXY_BOOTSTRAP_ADMIN_PASSWORD=change-this-long-password
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

The image includes a default HTTP health check for `GET /healthz` on
`127.0.0.1:8080`. The bundled Quadlet unit overrides it for the native TLS
deployment path and checks `https://127.0.0.1:8443/healthz` every 30 seconds
with a 3-second timeout, 3 retries, and a 30-second startup grace period. If the
health check fails repeatedly, Podman kills the container and systemd restarts
it through the unit's `Restart=on-failure` policy.

## Development

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

Black-box tests also exercise the compiled production process and container over
real HTTP/HTTPS sockets. Run the binary suite with:

```bash
cargo build --release --locked
SYSTEM_E2E_BIN=target/release/simple-alert-proxy \
  python3 -m unittest -v tests.system.test_binary_e2e
```

Run the production-like non-root Podman suite with:

```bash
sudo podman build --format docker -t simple-alert-proxy:e2e .
CONTAINER_ENGINE="sudo podman" \
CONTAINER_E2E_IMAGE=simple-alert-proxy:e2e \
  python3 -m unittest -v tests.container.test_container_e2e
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the test-layer boundaries, hermetic
test guarantees, and failure-artifact behavior.

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
