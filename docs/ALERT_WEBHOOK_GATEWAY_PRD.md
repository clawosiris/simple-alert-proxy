# Alert Webhook Gateway PRD

## Summary

Expand `simple-alert-proxy` from a SigNoz-to-Google-Chat proxy into a small,
self-hosted alert webhook gateway.

The product should solve the operational gap between alert-producing tools and
notification or ticketing backends. Many monitoring and security tools can emit
webhooks, but they differ widely in payload shape, routing capability, delivery
reliability, acknowledgement support, and notification targets. The gateway
should normalize those webhooks, provide durable state and delivery handling,
deduplicate noisy alerts, route them to the right targets, and expose a simple
acknowledgement-oriented UI/API.

The closest product shape is the original self-hosted Grafana OnCall OSS plus
its mapping support, but smaller, source-agnostic, config-first, and easier to
operate. It should avoid becoming a broad AIOps workbench like Keep.

## Problem

Teams use multiple systems that can generate alerts through webhooks, for
example:

- SigNoz
- OpenObserve
- OpenVAS SCAN, once webhook support exists there
- Grafana
- Prometheus Alertmanager-compatible sources
- Custom scripts and internal tools

Those tools do not consistently support the same notification targets. Some can
notify Slack but not Google Chat, some can create tickets but not send rich chat
cards, and many lack robust queueing, retries, deduplication, delivery history,
and acknowledgement tracking.

Adding every needed alerting target separately to every alert-producing tool is
inefficient and makes each source carry integration complexity that belongs in a
shared notification hub.

The result is a fragmented alert flow:

- each source needs separate notification configuration
- payload formats are inconsistent
- routing rules are duplicated across systems
- delivery failures are hard to inspect or replay
- duplicate alerts create noise
- acknowledgement state is missing or scattered across chat, tickets, and source
  systems
- on-duty routing and escalation are hard to centralize

## Goals

- Accept alert webhooks from multiple source systems.
- Normalize source-specific payloads into one internal alert model.
- Provide mapping and templating at the integration boundary.
- Queue outbound deliveries and preserve delivery attempt history.
- Retry failed deliveries with bounded policies.
- Deduplicate alerts into stateful alert groups using configurable fingerprints.
- Provide first-class acknowledgement and resolution state.
- Route alerts by source, severity, labels, annotations, payload fields, status,
  and alert group state.
- Fan out alerts and lifecycle changes to multiple notification and ticketing
  targets.
- Provide a compact web UI and API for alert inspection, acknowledgement,
  resolution, silencing, and replay.
- Keep deployment small: one Rust service, minimal external dependencies, and
  config-as-code by default.

## Non-Goals

- Replacing monitoring, vulnerability scanning, or alert rule engines.
- Building a full AIOps platform.
- Owning broad incident management, retrospectives, status pages, or runbooks in
  the first phases.
- Building full PagerDuty/Opsgenie replacement features in the MVP.
- Making LLM-based deduplication or triage required for core operation.
- Making a large low-code workflow builder.
- Supporting every notification backend before the core lifecycle is reliable.

## Product Positioning

`simple-alert-proxy` should be positioned as an alert webhook gateway, not a
generic alert management suite.

Adjacent projects:

- Keep / KeepHQ: broad open-source AIOps and alert management platform with
  integrations, correlation, workflows, AI features, and dashboards. Useful
  benchmark, but too broad and complex for this target.
- Grafana OnCall OSS: closest historical mental model for integrations, mapping,
  grouping, routing, escalation chains, schedules, and acknowledgement. No
  longer a good base because the OSS version was discontinued/archived.
- Alerta: mature compact alert consolidation system with API, UI,
  deduplication, correlation, suppression, and plugins. Good reference for alert
  lifecycle and plugin boundaries.
- Prometheus Alertmanager: excellent dedupe/group/routing/silence/inhibition
  primitive, but not a source-agnostic webhook gateway with rich mapping,
  delivery history, UI, or acknowledgement workflows.
- GoAlert: strong on-call scheduling and escalation. Potential future
  integration or design reference, not the core gateway.
- Convoy/Svix/Hook0 style webhook gateways: useful references for reliable
  webhook delivery, retries, rate limits, signatures, and replay, but they do
  not own alert semantics.

The intended niche:

> A small, predictable, self-hosted alert webhook gateway with durable state,
> mapping, dedupe, ack-aware routing, and reliable delivery to chat and ticketing
> systems.

## Primary Users

- Operators who run several observability or security tools and want one place
  to manage outgoing alert delivery.
- Small infrastructure or security teams that want self-hosted alert routing
  without adopting a large AIOps suite.

## Core Concepts

### Integration

A named inbound endpoint and parser/mapping configuration for one source.

Examples:

- `signoz-prod`
- `openobserve-prod`
- `grafana-lab`
- `openvas-scan`
- `generic-json`
- `alertmanager-compatible`

Responsibilities:

- endpoint path and authentication
- request size and rate limits
- source-specific parser or declarative mapping
- normalization into alert events
- optional source-specific signature verification

### Alert Event

An immutable normalized event derived from an inbound webhook.

Expected fields:

- `event_id`
- `integration`
- `source`
- `received_at`
- `status`
- `severity`
- `title`
- `body`
- `labels`
- `annotations`
- `links`
- `starts_at`
- `ends_at`
- `fingerprint`
- `raw_payload`

### Alert Group

A stateful deduplicated alert object that humans interact with.

Expected fields:

- `group_id`
- `fingerprint`
- `source`
- `severity`
- `title`
- `status`
- `created_at`
- `updated_at`
- `last_event_at`
- `event_count`
- `acknowledged_at`
- `acknowledged_by`
- `resolved_at`
- `resolved_by`
- `silenced_until`
- `labels`
- `annotations`

Alert groups are the primary objects shown in the UI and used for
acknowledgement, resolution, silencing, and escalation.

### Route

A rule that matches alert events or alert groups and chooses one or more
targets, escalation policies, or processing actions.

Routes should support matching on:

- integration
- source
- status
- severity
- labels
- annotations
- raw payload fields
- alert group state
- time windows
- future user/group/on-duty state

### Target

An outbound destination adapter.

Initial targets:

- Google Chat
- Slack
- Mattermost
- Discord
- generic webhook

Later targets:

- Jira
- ServiceNow
- Otobo
- Keep
- GoAlert
- email/SMTP
- ntfy/Pushover

### Delivery

A durable outbound attempt to one target.

Expected fields:

- `delivery_id`
- `group_id`
- `event_id`
- `target`
- `status`
- `attempt`
- `next_retry_at`
- `last_error`
- `request_summary`
- `response_summary`
- `created_at`
- `updated_at`

### Escalation Policy

A future ordered set of notification steps with delays and stop conditions.

Example concepts:

- notify primary chat channel immediately
- if unacknowledged after 10 minutes, notify on-duty user
- if still unacknowledged after 20 minutes, create or update ticket
- stop escalation when acknowledged or resolved

### Schedule

A future user/group availability source.

The first implementation should prefer external calendars or existing schedule
systems rather than owning a complete scheduling product. Possible sources:

- iCalendar feeds
- Google Calendar
- CalDAV
- GoAlert
- static YAML schedule for development and small teams

## Alert Lifecycle

The lifecycle should be explicit and first-class.

Recommended states:

- `received`: raw webhook accepted and persisted
- `normalized`: payload mapped into the canonical event model
- `open`: active alert group exists
- `delivered`: at least one target notification succeeded
- `acknowledged`: human, API, or external system accepted ownership
- `resolved`: source or user closed the alert group
- `silenced`: matching route or user action suppresses notifications
- `failed`: processing or delivery exhausted retry policy

Acknowledgement should update canonical alert group state. It should not be only
a chat reaction or a ticket comment.

Ack sources:

- web UI
- REST API
- signed action links
- chat callbacks where supported
- ticket state sync from Jira, ServiceNow, or Otobo
- external systems such as GoAlert

Ack side effects:

- stop or pause escalation
- update routed chat notifications when supported
- add history entry
- optionally notify selected targets of the state change
- optionally call back to source systems if the integration supports it

## Mapping And Normalization

Mapping support is a core feature and should be available before adding many
hardcoded source integrations.

The first mapping implementation should be declarative and config-driven.
Templates can be based on a small, well-supported expression/template engine.
Avoid making users write Rust for simple payload transformations.

Example:

```yaml
integrations:
  openobserve-prod:
    type: webhook
    path: /webhooks/openobserve/prod
    auth:
      bearer_token: ${OPENOBSERVE_WEBHOOK_TOKEN}
    mapping:
      source: openobserve
      title: "{{ body.alert_name }}"
      body: "{{ body.message }}"
      severity: "{{ body.severity | lower }}"
      status: "{{ body.status | lower }}"
      starts_at: "{{ body.starts_at }}"
      fingerprint: "{{ body.org }}/{{ body.stream }}/{{ body.alert_name }}/{{ body.labels.instance }}"
      labels:
        service: "{{ body.labels.service }}"
        environment: "{{ body.labels.env }}"
        instance: "{{ body.labels.instance }}"
      annotations:
        runbook_url: "{{ body.annotations.runbook_url }}"
```

Later, add plugin mappers for complex cases:

- Rust-native source adapters
- WASM plugins
- JSONata/JQ-like transforms, if a safe embedded option is chosen
- CEL-based expressions, if already used for routing

## Routing And Escalation

Routing should be deterministic before it becomes smart.

MVP routing:

- ordered routes
- match all conditions on a route
- default target
- optional continue matching
- send to one or more targets
- route by normalized fields and raw payload fields

Future routing:

- route to escalation policy
- route based on group state, such as unacknowledged duration
- route based on user/group ownership
- route based on schedule or external calendar
- route based on maintenance windows
- route state-change events, not only new alerts

## Queueing And Delivery

The gateway should persist incoming events before attempting outbound delivery.
This makes webhook acceptance independent from target availability.

Requirements:

- return success to source after the event is accepted and queued
- store delivery attempts
- support bounded retries with backoff
- support manual replay from UI/API
- support dead-letter state after retry exhaustion
- avoid logging full secrets or webhook URLs
- keep target-specific response summaries for troubleshooting

SQLite is acceptable for an early single-node deployment. Postgres should be
available before positioning this as production-ready for teams.

## Dedupe

The first dedupe mechanism should be fingerprint-based.

Fingerprint inputs may include:

- source/integration
- alert name
- rule ID
- service
- environment
- instance or resource
- vulnerability ID/CVE, for OpenVAS SCAN
- severity, optionally
- custom labels

Dedupe behavior:

- same active fingerprint maps to the same alert group
- repeated firing events increment count and update last seen time
- resolved events close or update the active group
- status transitions are recorded in history
- route configuration can choose whether resolved notifications are emitted

LLM-based dedupe can be explored later as advisory enrichment, not as the
default correctness mechanism.

## UI Requirements

The UI should be operational, not decorative.

MVP views:

- alert group list
- alert detail
- raw payload view
- normalized event view
- delivery attempts and errors
- ack button
- resolve button
- silence button
- replay delivery button
- route/debug explanation for why a target was selected

Later views:

- integrations
- targets
- routes
- escalation policies
- schedules
- user/group management
- audit log

## API Requirements

Initial API:

- `GET /healthz`
- `POST /webhooks/{integration}`
- `GET /api/alerts`
- `GET /api/alerts/{group_id}`
- `POST /api/alerts/{group_id}/ack`
- `POST /api/alerts/{group_id}/resolve`
- `POST /api/alerts/{group_id}/silence`
- `POST /api/deliveries/{delivery_id}/replay`
- `GET /api/deliveries`
- `GET /api/integrations`
- `GET /api/routes`

Administrative write APIs can come after config-file workflows are stable.

## Security Requirements

- Per-integration authentication.
- Optional bearer tokens for simple integrations.
- HMAC signature verification where sources support it.
- Request body limits.
- Rate limits per integration.
- Secret redaction in logs and UI.
- Config validation that rejects missing target secrets.
- Signed one-click action URLs, if supported, with short expiration.
- Audit log for ack, resolve, silence, replay, and config reload.

## LLM Requirements

LLM features should be optional and isolated.

Potential later uses:

- summarize raw alert payloads
- suggest dedupe fingerprints
- suggest routing labels
- cluster similar alerts for operator review
- draft ticket descriptions
- explain why an alert may be related to another

Non-requirements:

- LLMs must not be required for ingestion, routing, dedupe, delivery, ack, or
  recovery.
- LLM output should not silently change alert lifecycle state without explicit
  rules or human approval.

## Roadmap

### Phase 0: Current Product

Current `simple-alert-proxy` behavior:

- accepts SigNoz alert webhooks
- routes by configured matchers
- groups SigNoz alerts by `ruleId`
- sends Google Chat cards
- supports YAML config, TLS, bearer auth, body limits, and debug logging

### Phase 1: Gateway Foundation

- Introduce integration abstraction.
- Preserve existing SigNoz path as a compatibility integration.
- Add canonical alert event model.
- Add generic webhook integration with declarative mapping.
- Add durable event storage with SQLite.
- Add delivery queue and delivery attempt table.
- Add retry policy and dead-letter state.
- Add generic webhook output target.
- Keep Google Chat target working.

### Phase 2: Alert Groups And Acknowledgement

- Add fingerprint-based alert groups.
- Add alert group lifecycle state.
- Add ack, resolve, silence, and replay APIs.
- Add delivery history API.
- Add a minimal web UI for alert list/detail/action flows.
- Add audit/history entries for lifecycle changes.

### Phase 3: More Sources And Targets

Sources:

- Alertmanager-compatible endpoint
- Grafana webhook mapping preset
- OpenObserve mapping preset
- OpenVAS SCAN mapping preset once its webhook shape exists
- generic JSON examples

Targets:

- Slack
- Mattermost
- Discord
- Google Chat improvements
- Jira
- ServiceNow
- Otobo

### Phase 4: Escalation And On-Duty Routing

- Add users and groups.
- Add ownership metadata on routes and alert groups.
- Add external schedule support, starting with iCalendar.
- Add escalation policies with delayed steps.
- Stop escalation on acknowledgement or resolution.
- Add schedule-aware routing expressions.

### Phase 5: Optional Intelligence

- Add optional LLM provider abstraction.
- Add alert summarization.
- Add suggested fingerprints and route labels.
- Add operator-reviewed correlation suggestions.

## Open Questions

- Should SQLite remain supported indefinitely, or should Postgres become the
  only production datastore?
- Which template/expression language should be used for mapping?
- Should routes and mappings share one expression language?
- Should the UI be served by the Rust binary or built as a separate static app?
- Should WASM plugins be part of the first plugin design, or postponed until
  declarative mapping hits real limits?
- How much bidirectional sync should be attempted with source systems?
- Should acknowledgement links be supported for all targets through signed URLs,
  even when the target has no native button/callback support?
- Should on-duty schedules be internal eventually, or should the project stay
  calendar/external-schedule backed?

## Success Criteria

- A new alert source can be added with config-only mapping in under 30 minutes.
- A failed chat or ticketing backend does not lose accepted alerts.
- Operators can inspect and replay failed deliveries from the UI/API.
- Duplicate alert events collapse into an understandable alert group.
- Acknowledgement is visible in one canonical place and can stop routing or
  escalation.
- The service remains understandable to run as a small self-hosted binary.
