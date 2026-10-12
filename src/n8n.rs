use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::{
    alert::{AlertEvent, AlertInstance, AlertLink},
    notification::NotificationBatch,
    routing::Delivery,
};

pub const CONTRACT: &str = "simple-alert-proxy.n8n.v1";

#[derive(Debug, Deserialize)]
struct N8nAlert {
    status: String,
    #[serde(default)]
    severity: Option<String>,
    title: String,
    #[serde(default)]
    body: Option<String>,
    fingerprint: String,
    #[serde(default)]
    group_key: Option<String>,
    #[serde(default)]
    starts_at: Option<String>,
    #[serde(default)]
    ends_at: Option<String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
    #[serde(default)]
    links: BTreeMap<String, String>,
}

pub fn normalize(name: &str, raw: Value) -> Result<Vec<AlertEvent>, N8nError> {
    let object = raw.as_object().ok_or(N8nError::ExpectedObject)?;
    let values = match object.get("events") {
        Some(Value::Array(events)) if events.is_empty() => return Err(N8nError::EmptyBatch),
        Some(Value::Array(events)) => events.clone(),
        Some(_) => return Err(N8nError::EventsMustBeArray),
        None => vec![raw],
    };

    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| normalize_one(name, value, index))
        .collect()
}

fn normalize_one(name: &str, raw: Value, index: usize) -> Result<AlertEvent, N8nError> {
    let contract: N8nAlert =
        serde_json::from_value(raw.clone()).map_err(|error| N8nError::MalformedEvent {
            index,
            reason: error.to_string(),
        })?;
    for (field, value) in [
        ("status", contract.status.as_str()),
        ("title", contract.title.as_str()),
        ("fingerprint", contract.fingerprint.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(N8nError::EmptyRequired { index, field });
        }
    }

    let severity = contract
        .severity
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let mut event = AlertEvent::new(
        name,
        "n8n",
        contract.status,
        severity,
        contract.title,
        contract.fingerprint,
        raw,
    );
    event.body = contract.body;
    event.notification_group_key = contract.group_key;
    event.starts_at = contract.starts_at;
    event.ends_at = contract.ends_at;
    event.labels = contract.labels;
    event.annotations = contract.annotations;
    event.links = contract
        .links
        .into_iter()
        .map(|(label, url)| AlertLink { label, url })
        .collect();
    Ok(event)
}

pub fn build_event_payload(
    event: &AlertEvent,
    delivery: &Delivery,
    idempotency_key: &str,
) -> Value {
    serde_json::to_value(N8nEventDelivery {
        contract: CONTRACT,
        kind: "event",
        event: NormalizedAlert::from(event),
        delivery: DeliveryMetadata::new(delivery, idempotency_key),
    })
    .expect("n8n event contract contains only serializable values")
}

pub fn build_batch_payload(
    batch: &NotificationBatch,
    delivery: &Delivery,
    idempotency_key: &str,
) -> Value {
    serde_json::to_value(N8nBatchDelivery {
        contract: CONTRACT,
        kind: "notification_batch",
        batch: BatchSummary {
            group_key: &batch.group_key,
            count: batch.instance_count(),
            severity_counts: batch.severity_counts(),
        },
        events: batch.events.iter().map(NormalizedAlert::from).collect(),
        delivery: DeliveryMetadata::new(delivery, idempotency_key),
    })
    .expect("n8n batch contract contains only serializable values")
}

#[derive(Debug, thiserror::Error)]
pub enum N8nError {
    #[error("payload must be a JSON object")]
    ExpectedObject,
    #[error("events must be an array")]
    EventsMustBeArray,
    #[error("events must contain at least one event")]
    EmptyBatch,
    #[error("event {index} is malformed: {reason}")]
    MalformedEvent { index: usize, reason: String },
    #[error("event {index} field {field} must not be empty")]
    EmptyRequired { index: usize, field: &'static str },
}

#[derive(Serialize)]
struct N8nEventDelivery<'a> {
    contract: &'static str,
    kind: &'static str,
    event: NormalizedAlert<'a>,
    delivery: DeliveryMetadata<'a>,
}

#[derive(Serialize)]
struct N8nBatchDelivery<'a> {
    contract: &'static str,
    kind: &'static str,
    batch: BatchSummary<'a>,
    events: Vec<NormalizedAlert<'a>>,
    delivery: DeliveryMetadata<'a>,
}

#[derive(Serialize)]
struct BatchSummary<'a> {
    group_key: &'a str,
    count: usize,
    severity_counts: BTreeMap<String, usize>,
}

#[derive(Serialize)]
struct DeliveryMetadata<'a> {
    route: &'a str,
    receiver: &'a str,
    idempotency_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_team: Option<&'a str>,
}

impl<'a> DeliveryMetadata<'a> {
    fn new(delivery: &'a Delivery, idempotency_key: &'a str) -> Self {
        Self {
            route: &delivery.route_name,
            receiver: &delivery.receiver,
            idempotency_key,
            owner_team: delivery.owner_team.as_deref(),
        }
    }
}

#[derive(Serialize)]
struct NormalizedAlert<'a> {
    event_id: &'a str,
    integration: &'a str,
    group_namespace: &'a str,
    source: &'a str,
    received_at: Option<&'a str>,
    status: &'a str,
    severity: &'a str,
    title: &'a str,
    body: Option<&'a str>,
    labels: &'a BTreeMap<String, String>,
    annotations: &'a BTreeMap<String, String>,
    links: &'a [AlertLink],
    starts_at: Option<&'a str>,
    ends_at: Option<&'a str>,
    fingerprint: &'a str,
    notification_group_key: Option<&'a str>,
    instances: &'a [AlertInstance],
}

impl<'a> From<&'a AlertEvent> for NormalizedAlert<'a> {
    fn from(event: &'a AlertEvent) -> Self {
        Self {
            event_id: &event.event_id,
            integration: &event.integration,
            group_namespace: &event.group_namespace,
            source: &event.source,
            received_at: event.received_at.as_deref(),
            status: &event.status,
            severity: &event.severity,
            title: &event.title,
            body: event.body.as_deref(),
            labels: &event.labels,
            annotations: &event.annotations,
            links: &event.links,
            starts_at: event.starts_at.as_deref(),
            ends_at: event.ends_at.as_deref(),
            fingerprint: &event.fingerprint,
            notification_group_key: event.notification_group_key.as_deref(),
            instances: &event.instances,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivery() -> Delivery {
        Delivery {
            route_name: "automation".to_string(),
            receiver: "n8n".to_string(),
            owner_team: Some("platform".to_string()),
            escalation_policy: None,
            group_by: Vec::new(),
        }
    }

    #[test]
    fn normalizes_single_and_batch_contracts() {
        let first = serde_json::json!({
            "status": "firing",
            "severity": "critical",
            "title": "Checkout errors",
            "body": "Error rate exceeded 5%",
            "fingerprint": "checkout-errors",
            "group_key": "checkout-production",
            "starts_at": "2026-10-11T06:00:00Z",
            "labels": {"service": "checkout", "environment": "production"},
            "annotations": {"runbook": "Investigate the latest deploy"},
            "links": {"source": "https://n8n.example.test/executions/123"}
        });
        let single = normalize("n8n-alerts", first.clone()).unwrap();
        let batch = normalize(
            "n8n-alerts",
            serde_json::json!({
                "events": [first, {
                    "status": "resolved",
                    "title": "Checkout errors",
                    "fingerprint": "checkout-errors"
                }]
            }),
        )
        .unwrap();

        assert_eq!(single.len(), 1);
        assert_eq!(batch.len(), 2);
        assert_eq!(single[0].integration, "n8n-alerts");
        assert_eq!(single[0].group_namespace, "integration/n8n-alerts");
        assert_eq!(single[0].source, "n8n");
        assert_eq!(
            single[0].notification_group_key.as_deref(),
            Some("checkout-production")
        );
        assert_eq!(single[0].labels["service"], "checkout");
        assert_eq!(
            single[0].annotations["runbook"],
            "Investigate the latest deploy"
        );
        assert_eq!(single[0].links[0].label, "source");
        assert_eq!(batch[1].status, "resolved");
        assert_eq!(batch[1].severity, "unknown");
    }

    #[test]
    fn rejects_empty_required_fields_and_empty_batches() {
        let empty_title = normalize(
            "n8n",
            serde_json::json!({
                "status": "firing",
                "title": "   ",
                "fingerprint": "one"
            }),
        )
        .unwrap_err();
        let empty_batch = normalize("n8n", serde_json::json!({"events": []})).unwrap_err();

        assert!(
            empty_title
                .to_string()
                .contains("field title must not be empty")
        );
        assert!(empty_batch.to_string().contains("at least one event"));
    }

    #[test]
    fn outbound_contract_excludes_raw_payload_and_carries_delivery_identity() {
        let mut event = AlertEvent::new(
            "n8n-alerts",
            "n8n",
            "firing",
            "critical",
            "Checkout errors",
            "checkout-errors",
            serde_json::json!({"secret": "must-not-leave"}),
        );
        event
            .labels
            .insert("service".to_string(), "checkout".to_string());

        let payload = build_event_payload(&event, &delivery(), "delivery-42");

        assert_eq!(payload["contract"], CONTRACT);
        assert_eq!(payload["kind"], "event");
        assert_eq!(payload["delivery"]["idempotency_key"], "delivery-42");
        assert_eq!(payload["delivery"]["route"], "automation");
        assert_eq!(payload["event"]["labels"]["service"], "checkout");
        assert!(payload["event"].get("raw_payload").is_none());
    }

    #[test]
    fn outbound_batch_is_one_versioned_delivery_unit() {
        let events = ["one", "two"]
            .into_iter()
            .map(|fingerprint| {
                AlertEvent::new(
                    "n8n-alerts",
                    "n8n",
                    "firing",
                    "warning",
                    "Worker backlog",
                    fingerprint,
                    Value::Null,
                )
            })
            .collect();
        let batch = NotificationBatch::new("workers", events);

        let payload = build_batch_payload(&batch, &delivery(), "batch-7");

        assert_eq!(payload["kind"], "notification_batch");
        assert_eq!(payload["batch"]["group_key"], "workers");
        assert_eq!(payload["batch"]["count"], 2);
        assert_eq!(payload["events"].as_array().unwrap().len(), 2);
        assert_eq!(payload["delivery"]["idempotency_key"], "batch-7");
    }
}
