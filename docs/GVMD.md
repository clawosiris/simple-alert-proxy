# gvmd Generic Webhook v1

`simple-alert-proxy` has a first-class inbound profile for the gvmd Generic
Webhook Greenbone data contract. It accepts task run-status and SecInfo events
without an operator-side JSON transformation service.

## Configuration

Configure a built-in integration with a dedicated bearer token:

```yaml
integrations:
  greenbone:
    type: builtin
    preset: gvmd
    path: /webhooks/gvmd
    auth:
      bearer_token: replace-me
```

Configure the gvmd Webhook alert method to use its Generic profile and the
matching URL. Requests must use `Content-Type: application/json`; an optional
`charset` parameter is accepted. The integration-specific bearer token
overrides `server.auth.bearer_token`. If integration auth is omitted, normal
server-level inbound auth applies.

```bash
curl -X POST https://proxy.example.com/webhooks/gvmd \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer replace-me' \
  --data @examples/gvmd/webhook-generic-task.json
```

## Supported upstream contract

The supported domain contract is Greenbone data `version: 1`. The implementation
and tracked fixtures are aligned with gvmd commit
`6872205dfa044dcc978034145206b812d806d794`, merged through
[ClawosirisOrg/gvmd#44](https://github.com/ClawosirisOrg/gvmd/pull/44).
The upstream source of truth is its Draft 2020-12
`docs/architecture/webhook-alert-payload-v1.schema.json` schema.

The sanitized tracked examples are:

- [`webhook-generic-task.json`](../examples/gvmd/webhook-generic-task.json)
- [`webhook-generic-new-secinfo.json`](../examples/gvmd/webhook-generic-new-secinfo.json)
- [`webhook-generic-updated-secinfo.json`](../examples/gvmd/webhook-generic-updated-secinfo.json)
- [`webhook-generic-test.json`](../examples/gvmd/webhook-generic-test.json)

Task payloads require `event.status`. New and updated SecInfo payloads require a
`secinfo` object and deliberately prohibit `event.status`; their `task` and
`report` base fields must be null. The explicit boolean `test` marker is
preserved for both ordinary and `TEST_ALERT` payloads. Optional embedded task
reports follow the upstream `base64` metadata and truncation invariants.

## Canonical mapping

| Canonical field | gvmd mapping |
| --- | --- |
| `integration` | Configured integration name, such as `greenbone`. |
| `group_namespace` | `integration/<configured name>`. |
| `source` | `gvmd`. |
| `status` | Always `firing`; these are point-in-time notifications. |
| `severity` | `unknown`; Generic v1 has no severity field. |
| `title` | Non-empty `alert.name`, falling back to the supported `event.name`. |
| `body` | `event.description`; SecInfo list text is appended when distinct. |
| `raw_payload` | The complete original Greenbone object under normal storage, redaction, body-size, and debug-log rules. |

Task `event.status` is stored as the `gvmd_task_status` label. A gvmd task state
such as `Done` therefore never resolves or otherwise changes the proxy's alert
lifecycle. Other useful normalized metadata includes:

- labels: `gvmd_event_kind`, `gvmd_test`, alert/task/report IDs, task status,
  and SecInfo type/count;
- annotations: alert/task names, event and condition descriptions, and safe
  report format/content-type/encoding/size/truncation metadata.

Embedded report content is retained only in `raw_payload`; it is not copied
into labels, annotations, or the canonical body.

## Identity and notification grouping

Fingerprints are deterministic SHA-256 identities prefixed with the gvmd event
kind. They include:

- test versus live scope;
- alert ID/name and condition identity;
- exact task, new-SecInfo, or updated-SecInfo event kind;
- task ID/name and report ID for task events; or
- SecInfo type for SecInfo events.

This prevents different configured alerts or event kinds from collapsing only
because they refer to the same task or SecInfo family. Test alerts are also
isolated from live alert groups.

The notification group hint uses the same inputs except for task report ID.
Successive reports for one configured alert, event kind, and task can therefore
share a bounded notification batch while retaining separate lifecycle
fingerprints. Route-level `group_by` selectors can override this source hint.

## Validation and delivery behavior

The profile returns actionable JSON errors without echoing payload values:

- `415 Unsupported Media Type` for missing or non-`application/json` media
  types;
- `400 Bad Request` for malformed JSON, missing or invalid common fields,
  unsupported versions, unknown event names, and variant/schema violations;
- `401 Unauthorized` for missing or invalid configured bearer auth.

Accepted events use the same persistence-before-`202`, routing, ownership,
notification batching, retry, dead-letter, replay, and management behavior as
other canonical integrations. Raw payload logging stays redacted by default,
stored management API views redact sensitive keys, and request body limits are
enforced before parsing.
