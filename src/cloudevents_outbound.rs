use crate::{
    alert::{AlertEvent, AlertInstance, AlertLink},
    config::{CloudEventsWebhookMode, CloudEventsWebhookReceiverConfig},
    notification::NotificationBatch,
    routing::Delivery,
};
use cloudevents::{Event, EventBuilder, EventBuilderV10};
use cloudevents::{
    binding::reqwest::{RequestBuilderExt, RequestSerializer},
    message::StructuredDeserializer,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

const JSON_MEDIA_TYPE: &str = "application/json";

#[derive(Debug, thiserror::Error)]
pub enum OutboundCloudEventsError {
    #[error("failed to build outbound CloudEvent: {0}")]
    Build(#[from] cloudevents::event::EventBuilderError),
    #[error("failed to encode outbound CloudEvent: {0}")]
    Encode(#[from] cloudevents::message::Error),
    #[error("failed to serialize outbound CloudEvent data: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub fn build_alert_event(
    receiver: &CloudEventsWebhookReceiverConfig,
    event: &AlertEvent,
    delivery: &Delivery,
    delivery_idempotency_key: &str,
    data_override: Option<Value>,
) -> Result<Event, OutboundCloudEventsError> {
    let data = data_override.unwrap_or(serde_json::to_value(AlertDeliveryData {
        event: NormalizedAlert::from(event),
        delivery: DeliveryData::from(delivery),
    })?);
    build_event(
        receiver,
        event,
        delivery,
        delivery_idempotency_key,
        &receiver.event_type,
        alert_subject(event),
        false,
        data,
    )
}

pub fn build_batch_event(
    receiver: &CloudEventsWebhookReceiverConfig,
    batch: &NotificationBatch,
    delivery: &Delivery,
    delivery_idempotency_key: &str,
    data_override: Option<Value>,
) -> Result<Event, OutboundCloudEventsError> {
    let data = data_override.unwrap_or(serde_json::to_value(BatchDeliveryData {
        batch: BatchSummary {
            group_key: &batch.group_key,
            count: batch.instance_count(),
            severity_counts: batch.severity_counts(),
        },
        events: batch.events.iter().map(NormalizedAlert::from).collect(),
        delivery: DeliveryData::from(delivery),
    })?);
    build_event(
        receiver,
        batch.primary(),
        delivery,
        delivery_idempotency_key,
        &receiver.batch_type,
        batch_subject(&batch.group_key),
        true,
        data,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_event(
    receiver: &CloudEventsWebhookReceiverConfig,
    event: &AlertEvent,
    delivery: &Delivery,
    delivery_idempotency_key: &str,
    event_type: &str,
    subject: String,
    batched: bool,
    data: Value,
) -> Result<Event, OutboundCloudEventsError> {
    let mut builder = EventBuilderV10::new()
        .id(delivery_idempotency_key)
        .source(receiver.source.clone())
        .ty(event_type)
        .subject(subject)
        .extension("route", header_safe_extension(&delivery.route_name))
        .extension("receiver", header_safe_extension(&delivery.receiver))
        .extension("status", header_safe_extension(&event.status))
        .extension("severity", header_safe_extension(&event.severity))
        .extension("integration", header_safe_extension(&event.integration))
        .extension("batched", batched.to_string())
        .data(JSON_MEDIA_TYPE, data);
    if let Some(received_at) = &event.received_at {
        builder = builder.time(received_at.as_str());
    }
    Ok(builder.build()?)
}

pub fn encode_request(
    event: Event,
    mode: CloudEventsWebhookMode,
    request: reqwest::RequestBuilder,
) -> Result<reqwest::RequestBuilder, OutboundCloudEventsError> {
    match mode {
        CloudEventsWebhookMode::Structured => Ok(StructuredDeserializer::deserialize_structured(
            event,
            RequestSerializer::new(request),
        )?),
        CloudEventsWebhookMode::Binary => Ok(request.event(event)?),
    }
}

fn alert_subject(event: &AlertEvent) -> String {
    format!(
        "alert-group/{}/{}",
        percent_encode_segment(&event.group_namespace),
        percent_encode_segment(&event.fingerprint)
    )
}

fn batch_subject(group_key: &str) -> String {
    format!("notification-batch/{}", percent_encode_segment(group_key))
}

fn header_safe_extension(value: &str) -> String {
    if reqwest::header::HeaderValue::from_str(value).is_ok() {
        value.to_string()
    } else {
        percent_encode_segment(value)
    }
}

fn percent_encode_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[derive(Serialize)]
struct AlertDeliveryData<'a> {
    event: NormalizedAlert<'a>,
    delivery: DeliveryData<'a>,
}

#[derive(Serialize)]
struct BatchDeliveryData<'a> {
    batch: BatchSummary<'a>,
    events: Vec<NormalizedAlert<'a>>,
    delivery: DeliveryData<'a>,
}

#[derive(Serialize)]
struct BatchSummary<'a> {
    group_key: &'a str,
    count: usize,
    severity_counts: BTreeMap<String, usize>,
}

#[derive(Serialize)]
struct DeliveryData<'a> {
    route: &'a str,
    receiver: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_team: Option<&'a str>,
}

impl<'a> From<&'a Delivery> for DeliveryData<'a> {
    fn from(delivery: &'a Delivery) -> Self {
        Self {
            route: &delivery.route_name,
            receiver: &delivery.receiver,
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
    use crate::config::NotificationTemplateConfig;
    use axum::http::header;
    use cloudevents::AttributesReader;
    use serde_json::json;

    fn receiver(mode: CloudEventsWebhookMode) -> CloudEventsWebhookReceiverConfig {
        CloudEventsWebhookReceiverConfig {
            webhook_url: "https://events.example.test/alerts".to_string(),
            source: "urn:simple-alert-proxy:test".to_string(),
            mode,
            event_type: "io.example.alert.v1".to_string(),
            batch_type: "io.example.batch.v1".to_string(),
            owner_team: None,
            timeout_secs: 10,
            template: None::<NotificationTemplateConfig>,
        }
    }

    fn event(fingerprint: &str) -> AlertEvent {
        let mut event = AlertEvent::new(
            "grafana",
            "grafana",
            "firing",
            "critical",
            "Disk full",
            fingerprint,
            json!({"authorization": "must-not-leave-the-proxy"}),
        );
        event.event_id = format!("occurrence-{fingerprint}");
        event.group_namespace = "integration/grafana/org/1".to_string();
        event.received_at = Some("2026-09-25T18:00:00Z".to_string());
        event
    }

    fn delivery(receiver: &str) -> Delivery {
        Delivery {
            route_name: "critical-alerts".to_string(),
            receiver: receiver.to_string(),
            owner_team: Some("platform".to_string()),
            escalation_policy: None,
            group_by: Vec::new(),
        }
    }

    fn request_body(request: &reqwest::Request) -> &[u8] {
        request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .expect("encoded request has an in-memory body")
    }

    #[test]
    fn structured_and_binary_requests_decode_to_equivalent_events() {
        let event = event("disk/root");
        let delivery = delivery("event-bus");
        let cloud_event = build_alert_event(
            &receiver(CloudEventsWebhookMode::Structured),
            &event,
            &delivery,
            "simple-alert-proxy-42",
            None,
        )
        .unwrap();
        let client = reqwest::Client::new();
        let structured = encode_request(
            cloud_event.clone(),
            CloudEventsWebhookMode::Structured,
            client.post("https://events.example.test/alerts"),
        )
        .unwrap()
        .build()
        .unwrap();
        let binary = encode_request(
            cloud_event,
            CloudEventsWebhookMode::Binary,
            client.post("https://events.example.test/alerts"),
        )
        .unwrap()
        .build()
        .unwrap();

        assert_eq!(
            structured.headers()[header::CONTENT_TYPE],
            "application/cloudevents+json"
        );
        assert_eq!(binary.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(binary.headers()["ce-id"], "simple-alert-proxy-42");

        let structured =
            crate::cloudevents::decode(structured.headers(), request_body(&structured)).unwrap();
        let binary = crate::cloudevents::decode(binary.headers(), request_body(&binary)).unwrap();
        assert_eq!(structured, binary);
        assert_eq!(
            structured.envelope["subject"],
            "alert-group/integration%2Fgrafana%2Forg%2F1/disk%2Froot"
        );
        assert_eq!(structured.envelope["batched"], "false");
        assert_eq!(
            structured.envelope["data"]["event"]["event_id"],
            "occurrence-disk/root"
        );
        assert!(
            structured.envelope["data"]["event"]
                .get("raw_payload")
                .is_none()
        );
    }

    #[test]
    fn batch_is_one_event_with_summary_and_normalized_members() {
        let batch = NotificationBatch::new("prod/api", vec![event("one"), event("two")]);
        let cloud_event = build_batch_event(
            &receiver(CloudEventsWebhookMode::Structured),
            &batch,
            &delivery("event-bus"),
            "simple-alert-proxy-batch-7",
            None,
        )
        .unwrap();
        let data: Value = cloud_event.data().unwrap().clone().try_into().unwrap();

        assert_eq!(cloud_event.id(), "simple-alert-proxy-batch-7");
        assert_eq!(cloud_event.ty(), "io.example.batch.v1");
        assert_eq!(
            cloud_event.subject().unwrap(),
            "notification-batch/prod%2Fapi"
        );
        assert_eq!(data["batch"]["count"], 2);
        assert_eq!(data["events"].as_array().unwrap().len(), 2);
        assert!(data["events"][0].get("raw_payload").is_none());
    }

    #[test]
    fn data_override_cannot_replace_context_attributes() {
        let cloud_event = build_alert_event(
            &receiver(CloudEventsWebhookMode::Binary),
            &event("disk"),
            &delivery("event-bus"),
            "delivery-1",
            Some(json!({
                "id": "not-the-context-id",
                "specversion": "0.3",
                "custom": true
            })),
        )
        .unwrap();
        let data: Value = cloud_event.data().unwrap().clone().try_into().unwrap();

        assert_eq!(cloud_event.id(), "delivery-1");
        assert_eq!(cloud_event.specversion().to_string(), "1.0");
        assert_eq!(data["id"], "not-the-context-id");
        assert_eq!(data["custom"], true);
    }

    #[test]
    fn delivery_keys_define_retry_recovery_and_route_identity() {
        let receiver = receiver(CloudEventsWebhookMode::Structured);
        let event = event("disk");
        let first = build_alert_event(
            &receiver,
            &event,
            &delivery("first-bus"),
            "delivery-41",
            None,
        )
        .unwrap();
        let retry_or_recovery = build_alert_event(
            &receiver,
            &event,
            &delivery("first-bus"),
            "delivery-41",
            None,
        )
        .unwrap();
        let second_route = build_alert_event(
            &receiver,
            &event,
            &delivery("second-bus"),
            "delivery-42",
            None,
        )
        .unwrap();

        assert_eq!(first.id(), retry_or_recovery.id());
        assert_ne!(first.id(), second_route.id());
    }

    #[test]
    fn complete_envelope_is_subject_to_cloudevents_payload_limit() {
        let mut event = event("large");
        event.title = "x".repeat(256 * 1024);
        let cloud_event = build_alert_event(
            &receiver(CloudEventsWebhookMode::Structured),
            &event,
            &delivery("event-bus"),
            "delivery-large",
            None,
        )
        .unwrap();
        let envelope = serde_json::to_value(cloud_event).unwrap();
        let error = crate::template::validate_payload_size(
            "event-bus",
            crate::template::PayloadKind::CloudEventsWebhook,
            &envelope,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            crate::template::NotificationTemplateError::PayloadLimit { .. }
        ));
    }
}
