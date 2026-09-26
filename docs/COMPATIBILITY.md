# Compatibility Baseline

This file names the stable behavior that the mainline alert webhook gateway
must preserve as new integrations and operational features are added.

## SigNoz Compatibility Integration

The current SigNoz integration remains the compatibility baseline:

- Endpoint: `POST /webhooks/signoz` by default, now representable as a built-in
  configured integration and still compatible with legacy `server.webhook_path`.
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

No migration is required for older configs that rely on `server.webhook_path`;
new configs should represent SigNoz under `integrations`.

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
| Debug logging | Incoming/outgoing debug payload logging remains gated by `debug.log_alerts`; receiver webhook URLs are not included in outgoing debug logs. | `debug_webhook_logs_payload_with_bearer_token`, redaction and receiver tests |

## Process And Container Coverage

The binary system suite starts the production release binary over real HTTP and
HTTPS sockets. It covers intake, auth, local-user sessions and CSRF, routing,
SQLite persistence, receiver delivery, restart recovery, retry/dead-letter,
replay, health, invalid startup config, and graceful shutdown.

The container suite builds and runs the production image with Podman. It checks
the non-root runtime user, mounted config/data/TLS files, image health, receiver
delivery, persistence across replacement containers, invalid config, and signal
handling. These suites complement the in-process compatibility tests; they do
not contact public receiver services.

Issue #86 tracks a future readable BDD layer for business scenarios at the
in-process application boundary. It does not replace the process/container
coverage above.
