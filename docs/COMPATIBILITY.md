# Compatibility Baseline

This file names the behavior that Alert Webhook Gateway v2 must preserve while
new integrations, storage, lifecycle APIs, and UI work are added.

## SigNoz Compatibility Integration

The current SigNoz integration remains the compatibility baseline:

- Endpoint: `POST /webhooks/signoz` by default, configurable with
  `server.webhook_path`.
- Payload: Alertmanager-style SigNoz webhook JSON with `status`,
  `commonLabels`, `commonAnnotations`, and `alerts[]`.
- Routing: existing YAML `routing.default_receiver`, `routing.routes`, and
  matcher behavior.
- Receiver: existing YAML `google_chat` receiver config and Google Chat card
  payload shape.
- Safety/config: optional bearer-token auth, request body limit,
  optional TLS config, debug payload logging, and `GET /healthz`.
- Grouping: SigNoz alerts sharing `ruleId` produce one outbound Google Chat
  notification with separate instance rows after the debounce window.

No migration is required for the current `examples/config.yaml` shape.

## Compatibility Test Matrix

| Area | Baseline | Coverage |
| --- | --- | --- |
| Health check | `GET /healthz` returns `204 No Content`. | `healthz_returns_no_content` |
| SigNoz endpoint | Existing `POST /webhooks/signoz` path accepts fixture payloads. | `default_signoz_webhook_path_accepts_existing_payload` |
| YAML config | Existing route and `google_chat` receiver config loads and validates unchanged. | `example_config_loads_without_migration` |
| Bearer auth | Missing, wrong, or non-bearer auth is rejected; disabled auth accepts requests. | `rejects_missing_bearer_token`, `rejects_wrong_bearer_token`, `rejects_non_bearer_authorization_scheme`, `accepts_webhook_without_auth_when_auth_disabled` |
| Body limit | Requests over `server.max_body_bytes` are rejected by the HTTP layer. | `rejects_request_bodies_over_configured_limit` |
| Routing | Existing YAML matchers route critical production alerts to Google Chat. | `routes_to_google_chat_receiver`, routing module tests |
| Google Chat payload | Card payload keeps status, severity counts, source link, and instance rows. | Google Chat module tests |
| Grouping | Same-payload and separate-webhook alerts with the same `ruleId` are grouped into one notification with separate instances. | `groups_incoming_alerts_by_rule_id_before_delivery`, `groups_separate_webhooks_by_rule_id_before_delivery`, `groups_separate_webhooks_by_group_labels_rule_id` |
| TLS config | File/env TLS source validation remains accepted and rejects ambiguous config. | config module TLS tests |
| Debug logging | Incoming/outgoing debug payload logging remains gated by `debug.log_alerts`; receiver webhook URLs are not included in outgoing debug logs. | docs contract plus existing debug code path |
