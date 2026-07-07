# OpenSpec: Alert Webhook Gateway

## Metadata

- id: `alert-webhook-gateway`
- repo: `clawosiris/simple-alert-proxy`
- status: `proposed`
- owner: `Simple Alert`
- source_prd: `docs/ALERT_WEBHOOK_GATEWAY_PRD.md`
- scope: evolve the current SigNoz-to-Google-Chat proxy into a compact,
  source-agnostic alert webhook gateway.

## Principles

- Preserve current SigNoz webhook and Google Chat behavior while adding gateway
  abstractions behind it.
- Persist accepted alerts before outbound delivery is attempted.
- Keep config-as-code as the primary administrative interface until read APIs
  and the minimal UI are stable.
- Prefer deterministic mapping, routing, and fingerprinting before optional
  intelligence.
- Keep the service operable as one Rust binary with minimal required
  dependencies.

## Phase 0: Baseline Compatibility

### Objective

Make the current product explicit as the compatibility baseline for all gateway
work.

### Requirements

- REQ-0.1: The service SHALL continue to accept existing SigNoz webhook payloads
  on the existing path.
- REQ-0.2: Existing YAML route and Google Chat receiver configuration SHALL keep
  working without migration.
- REQ-0.3: Existing bearer-token auth, body limits, TLS configuration, debug
  payload logging, and health checks SHALL keep their current behavior.
- REQ-0.4: Grouped SigNoz notifications by `ruleId` SHALL keep producing one
  outbound notification with separate instances.

### Deliverables

- Compatibility test matrix for current webhook, routing, grouping, and Google
  Chat behavior in `docs/COMPATIBILITY.md`.
- Baseline docs that name the current SigNoz path as a compatibility
  integration in `docs/SPEC.md` and `docs/COMPATIBILITY.md`.

### Acceptance

- `cargo test` passes.
- Existing example payloads still produce the same routed Google Chat outcome.
- No configuration migration is required for current users.

## Phase 1: Gateway Foundation

### Objective

Introduce source-agnostic integration and alert-event foundations while keeping
the current SigNoz flow intact.

### Requirements

- REQ-1.1: The service SHALL define a canonical `AlertEvent` model with
  integration, source, status, severity, title, body, labels, annotations,
  links, timestamps, fingerprint, and raw payload metadata.
- REQ-1.2: The service SHALL define an `Integration` abstraction that can map an
  inbound request into one or more canonical alert events.
- REQ-1.3: The existing SigNoz parser SHALL become or wrap a `signoz`
  compatibility integration.
- REQ-1.4: The service SHALL add a generic webhook integration path of the form
  `POST /webhooks/{integration}`.
- REQ-1.5: Generic webhook integrations SHALL support declarative config for
  path, auth, source name, severity/status/title/body fields, labels,
  annotations, and fingerprint.
- REQ-1.6: The service SHALL validate integration config at startup and fail
  clearly for missing required fields.
- REQ-1.7: The service SHALL keep Google Chat as an outbound target.

### Deliverables

- Canonical alert model module.
- Integration config schema.
- SigNoz compatibility adapter.
- Generic JSON webhook example config and fixture.
- Tests for SigNoz compatibility and generic webhook normalization.

### Acceptance

- Existing SigNoz tests pass without weakening assertions.
- A generic JSON payload can be normalized into a canonical alert event using
  config only.
- A missing integration or invalid mapping returns a clear client or startup
  error, as appropriate.

## Phase 2: Durable Event And Delivery Queue

### Objective

Decouple webhook acceptance from outbound target availability.

### Requirements

- REQ-2.1: The service SHALL persist accepted alert events before outbound
  delivery is attempted.
- REQ-2.2: SQLite SHALL be supported as the first durable store.
- REQ-2.3: The service SHALL store delivery records with target, status,
  attempt count, next retry time, last error, request summary, and response
  summary.
- REQ-2.4: The service SHALL retry failed deliveries with bounded backoff.
- REQ-2.5: The service SHALL mark deliveries dead-lettered after retry
  exhaustion.
- REQ-2.6: Webhook responses SHALL indicate acceptance after persistence and
  queueing, not after target delivery.
- REQ-2.7: Logs and persisted summaries SHALL redact secrets and full webhook
  URLs.

### Deliverables

- Storage trait and SQLite implementation.
- Schema migrations or startup schema creation.
- Delivery worker loop.
- Retry policy config.
- Tests for persistence-before-delivery and retry/dead-letter behavior.

### Acceptance

- A failing target does not cause an accepted webhook event to be lost.
- Delivery attempt history can be queried internally for later API exposure.
- `cargo test` covers at least one retry and one dead-letter path.

## Phase 3: Alert Groups And Lifecycle API

### Objective

Promote deduplicated alert groups to the primary operator-facing object.

### Requirements

- REQ-3.1: The service SHALL create or update an `AlertGroup` based on a
  configurable fingerprint.
- REQ-3.2: Repeated active events with the same fingerprint SHALL increment
  event count and update last-event timestamps.
- REQ-3.3: Resolved events SHALL update or close the active group based on
  integration and route config.
- REQ-3.4: The service SHALL expose read APIs for alert groups, alert events,
  deliveries, integrations, and routes.
- REQ-3.5: The service SHALL expose action APIs to acknowledge, resolve,
  silence, and replay.
- REQ-3.6: Lifecycle actions SHALL create audit/history entries.
- REQ-3.7: Acknowledgement or resolution SHALL be able to stop or alter later
  escalation once escalation exists.

### Deliverables

- Alert group model and storage.
- Lifecycle state machine.
- REST API handlers.
- Audit/history storage.
- Tests for ack, resolve, silence, and replay state transitions.

### Acceptance

- Operators can inspect one canonical alert group for repeated events.
- Ack/resolve/silence actions update persistent state.
- Replay creates a new delivery attempt without mutating the original attempt.

## Phase 4: Operational UI

### Objective

Provide a compact UI for normal alert inspection and intervention.

### Requirements

- REQ-4.1: The UI SHALL prioritize operational density over marketing-style
  presentation.
- REQ-4.2: The UI SHALL show alert group list, severity/status, title, source,
  event count, last event time, and acknowledgement state.
- REQ-4.3: The UI SHALL show alert detail, raw payload, normalized event data,
  route explanation, delivery attempts, and errors.
- REQ-4.4: The UI SHALL provide ack, resolve, silence, and replay controls.
- REQ-4.5: The UI SHALL handle mobile and desktop widths without overlapping
  text or controls.

### Deliverables

- Static or server-rendered UI served by the Rust service.
- API client layer.
- UI tests or screenshot checks for primary views.

### Acceptance

- An operator can inspect and act on an alert without reading logs.
- Delivery failures are visible and replayable from the alert detail view.

## Phase 5: Targets And Source Presets

### Objective

Expand useful integrations after lifecycle correctness is in place.

### Requirements

- REQ-5.1: The service SHALL support a generic outbound webhook target.
- REQ-5.2: The service SHOULD add Slack, Mattermost, and Discord targets before
  ticketing targets.
- REQ-5.3: The service SHOULD add mapping presets for Alertmanager-compatible
  payloads, Grafana, OpenObserve, and OpenVAS SCAN once its webhook shape
  exists.
- REQ-5.4: Target adapters SHALL share durable delivery, retry, redaction, and
  replay behavior.

### Deliverables

- Generic webhook target.
- Additional chat target adapters.
- Source mapping presets and examples.
- Contract tests for target request construction.

### Acceptance

- Adding a new chat target does not bypass the delivery queue.
- Adding a new source preset does not require Rust code for simple field
  mapping.

## Phase 6: Escalation And On-Duty Routing

### Objective

Add delayed routing behavior that reacts to alert lifecycle state.

### Requirements

- REQ-6.1: The service SHALL define escalation policies with ordered steps,
  delays, and stop conditions.
- REQ-6.2: Escalation SHALL stop when an alert group is acknowledged or
  resolved.
- REQ-6.3: Routes SHALL be able to select escalation policies.
- REQ-6.4: Schedules SHOULD initially come from external sources such as
  iCalendar, Google Calendar, CalDAV, GoAlert, or static YAML.

### Deliverables

- Escalation policy config and validator.
- Escalation scheduler/worker.
- External schedule interface.
- Tests for delayed steps and stop conditions.

### Acceptance

- An unacknowledged alert can escalate after a configured delay.
- Acknowledging before the delay prevents later escalation steps.

## Phase 7: Optional Intelligence

### Objective

Add advisory intelligence without making it part of correctness.

### Requirements

- REQ-7.1: LLM providers SHALL be optional and disabled by default.
- REQ-7.2: LLM output SHALL NOT change lifecycle state unless explicit rules or
  human approval require it.
- REQ-7.3: Suggested summaries, fingerprints, routing labels, and correlations
  SHALL be stored as advisory enrichment.

### Deliverables

- Optional provider abstraction.
- Advisory summary/correlation records.
- UI affordances that distinguish suggestions from canonical state.

### Acceptance

- Core ingestion, routing, dedupe, delivery, ack, and recovery work with no LLM
  configuration.

## Cross-Phase Verification Gates

- Unit tests for parser, mapping, routing, storage, and target adapters.
- Integration tests for webhook acceptance through delivery queue creation.
- Config validation tests for invalid auth, missing mappings, and missing
  target secrets.
- CI must run formatting, linting, tests, and container build checks.
- Release notes must call out config migrations when they eventually exist.

## Initial Implementation Slices

1. Add canonical alert model and SigNoz-to-canonical conversion helpers.
2. Add integration config types and validation without changing runtime routing.
3. Add generic webhook mapping for simple JSON field paths.
4. Add generic `POST /webhooks/{integration}` handler.
5. Add SQLite storage behind a feature or config flag.
6. Add delivery queue records and worker loop.
7. Add alert group lifecycle model and APIs.
