# gvmd Generic Webhook v1 fixtures

These four fixtures are sanitized copies of the official gvmd Generic Webhook
examples from commit `6872205dfa044dcc978034145206b812d806d794`:

- task run-status event;
- new SecInfo event;
- updated SecInfo event; and
- SecInfo `TEST_ALERT` event.

They implement Greenbone data contract `version: 1` and are aligned with the
upstream Draft 2020-12 schema at
`docs/architecture/webhook-alert-payload-v1.schema.json` in that pinned gvmd
commit. Update the fixtures, parser tests, and operator documentation together
when adopting a later upstream contract version.
