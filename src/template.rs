use anyhow::Context;
use minijinja::{Environment, UndefinedBehavior};
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, fmt, io, sync::Arc};

use crate::{
    alert::{AlertEvent, AlertInstance, AlertLink},
    config::ReceiverConfig,
    notification::NotificationBatch,
    routing::Delivery,
};

pub const MAX_TEMPLATE_SOURCE_BYTES: usize = 64 * 1024;
const MAX_TITLE_BYTES: usize = 4 * 1024;
const MAX_RENDER_FUEL: u64 = 50_000;
const MAX_RECURSION_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    GoogleChat,
    GenericWebhook,
    CloudEventsWebhook,
    Slack,
    Mattermost,
    Discord,
    Matrix,
}

impl PayloadKind {
    fn byte_limit(self) -> usize {
        match self {
            Self::GoogleChat => 32 * 1024,
            Self::Slack | Self::Mattermost => 40 * 1024,
            Self::Discord => 16 * 1024,
            Self::Matrix => 64 * 1024,
            Self::GenericWebhook | Self::CloudEventsWebhook => 256 * 1024,
        }
    }
}

impl fmt::Display for PayloadKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GoogleChat => "google_chat",
            Self::GenericWebhook => "generic_webhook",
            Self::CloudEventsWebhook => "cloudevents_webhook",
            Self::Slack => "slack",
            Self::Mattermost => "mattermost",
            Self::Discord => "discord",
            Self::Matrix => "matrix",
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NotificationTemplateError {
    #[error("receiver {receiver} template.{field} exceeded the {limit} byte rendered output limit")]
    OutputLimit {
        receiver: String,
        field: &'static str,
        limit: usize,
    },
    #[error("receiver {receiver} template.{field} failed: {kind}{location}")]
    Render {
        receiver: String,
        field: &'static str,
        kind: String,
        location: ErrorLocation,
    },
    #[error(
        "receiver {receiver} template.payload did not render valid JSON at line {line}, column {column}"
    )]
    InvalidJson {
        receiver: String,
        line: usize,
        column: usize,
    },
    #[error("receiver {receiver} template.payload must render a JSON object")]
    NonObjectJson { receiver: String },
    #[error("receiver {receiver} template.payload is not a valid {target} payload: {reason}")]
    InvalidPayloadShape {
        receiver: String,
        target: PayloadKind,
        reason: &'static str,
    },
    #[error("receiver {receiver} rendered {target} payload exceeds the {limit} byte limit")]
    PayloadLimit {
        receiver: String,
        target: PayloadKind,
        limit: usize,
    },
}

#[derive(Debug)]
pub struct ErrorLocation(Option<usize>);

impl fmt::Display for ErrorLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(line) = self.0 {
            write!(formatter, " at line {line}")
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Default)]
struct CompiledReceiverTemplates {
    title: Option<String>,
    body: Option<String>,
    payload: Option<String>,
}

pub struct NotificationTemplateEngine {
    environment: Environment<'static>,
    receivers: BTreeMap<String, CompiledReceiverTemplates>,
}

impl fmt::Debug for NotificationTemplateEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotificationTemplateEngine")
            .field("receiver_count", &self.receivers.len())
            .finish_non_exhaustive()
    }
}

impl NotificationTemplateEngine {
    pub fn compile(receivers: &BTreeMap<String, ReceiverConfig>) -> anyhow::Result<Arc<Self>> {
        let mut environment = Environment::new();
        environment.set_undefined_behavior(UndefinedBehavior::Strict);
        environment.set_fuel(Some(MAX_RENDER_FUEL));
        environment.set_recursion_limit(MAX_RECURSION_DEPTH);

        let mut compiled_receivers = BTreeMap::new();
        for (receiver_name, receiver) in receivers {
            let Some(config) = receiver.notification_template() else {
                continue;
            };
            let mut compiled = CompiledReceiverTemplates::default();
            for (field, source, destination) in [
                ("title", config.title.as_ref(), &mut compiled.title),
                ("body", config.body.as_ref(), &mut compiled.body),
                ("payload", config.payload.as_ref(), &mut compiled.payload),
            ] {
                let Some(source) = source else {
                    continue;
                };
                if source.len() > MAX_TEMPLATE_SOURCE_BYTES {
                    anyhow::bail!(
                        "receiver {receiver_name} template.{field} exceeds the {MAX_TEMPLATE_SOURCE_BYTES} byte source limit"
                    );
                }
                if field == "payload" && is_static_template(source) {
                    let payload: Value = serde_json::from_str(source).map_err(|error| {
                        anyhow::anyhow!(
                            "receiver {receiver_name} template.payload is invalid static JSON at line {}, column {}",
                            error.line(),
                            error.column()
                        )
                    })?;
                    let target = receiver_payload_kind(receiver);
                    validate_payload_shape(receiver_name, target, &payload)
                        .map_err(anyhow::Error::new)?;
                    validate_payload_size(receiver_name, target, &payload)
                        .map_err(anyhow::Error::new)?;
                }
                let template_name = format!("receiver:{receiver_name}:{field}");
                environment
                    .add_template_owned(template_name.clone(), source.clone())
                    .with_context(|| {
                        format!("receiver {receiver_name} template.{field} has invalid syntax")
                    })?;
                *destination = Some(template_name);
            }
            compiled_receivers.insert(receiver_name.clone(), compiled);
        }

        Ok(Arc::new(Self {
            environment,
            receivers: compiled_receivers,
        }))
    }

    pub fn render_event(
        &self,
        receiver: &str,
        event: &AlertEvent,
        delivery: &Delivery,
        target: PayloadKind,
    ) -> Result<Option<RenderedNotification>, NotificationTemplateError> {
        self.render(
            receiver,
            NotificationContext::event(event, delivery),
            target,
        )
    }

    pub fn render_batch(
        &self,
        receiver: &str,
        batch: &NotificationBatch,
        delivery: &Delivery,
        target: PayloadKind,
    ) -> Result<Option<RenderedNotification>, NotificationTemplateError> {
        self.render(
            receiver,
            NotificationContext::batch(batch, delivery),
            target,
        )
    }

    fn render(
        &self,
        receiver: &str,
        context: NotificationContext<'_>,
        target: PayloadKind,
    ) -> Result<Option<RenderedNotification>, NotificationTemplateError> {
        let Some(templates) = self.receivers.get(receiver) else {
            return Ok(None);
        };
        let title = templates
            .title
            .as_deref()
            .map(|name| self.render_one(receiver, "title", name, &context, MAX_TITLE_BYTES))
            .transpose()?;
        let body = templates
            .body
            .as_deref()
            .map(|name| self.render_one(receiver, "body", name, &context, target.byte_limit()))
            .transpose()?;
        let payload = templates
            .payload
            .as_deref()
            .map(|name| {
                let rendered =
                    self.render_one(receiver, "payload", name, &context, target.byte_limit())?;
                let value: Value = serde_json::from_str(&rendered).map_err(|error| {
                    NotificationTemplateError::InvalidJson {
                        receiver: receiver.to_string(),
                        line: error.line(),
                        column: error.column(),
                    }
                })?;
                validate_payload_shape(receiver, target, &value)?;
                Ok(value)
            })
            .transpose()?;

        Ok(Some(RenderedNotification {
            title,
            body,
            payload,
        }))
    }

    fn render_one(
        &self,
        receiver: &str,
        field: &'static str,
        template_name: &str,
        context: &NotificationContext<'_>,
        limit: usize,
    ) -> Result<String, NotificationTemplateError> {
        let template = self
            .environment
            .get_template(template_name)
            .expect("compiled notification template is present");
        let mut writer = BoundedWriter::new(limit);
        if let Err(error) = template.render_captured_to(context, &mut writer) {
            if writer.exceeded {
                return Err(NotificationTemplateError::OutputLimit {
                    receiver: receiver.to_string(),
                    field,
                    limit,
                });
            }
            return Err(NotificationTemplateError::Render {
                receiver: receiver.to_string(),
                field,
                kind: error.kind().to_string(),
                location: ErrorLocation(error.line()),
            });
        }
        Ok(String::from_utf8(writer.bytes).expect("MiniJinja output is UTF-8"))
    }
}

fn receiver_payload_kind(receiver: &ReceiverConfig) -> PayloadKind {
    match receiver {
        ReceiverConfig::GoogleChat(_) => PayloadKind::GoogleChat,
        ReceiverConfig::GenericWebhook(_) => PayloadKind::GenericWebhook,
        ReceiverConfig::CloudEventsWebhook(_) => PayloadKind::CloudEventsWebhook,
        ReceiverConfig::Slack(_) => PayloadKind::Slack,
        ReceiverConfig::Mattermost(_) => PayloadKind::Mattermost,
        ReceiverConfig::Discord(_) => PayloadKind::Discord,
        ReceiverConfig::Matrix(_) => PayloadKind::Matrix,
    }
}

fn is_static_template(source: &str) -> bool {
    !source.contains("{{") && !source.contains("{%") && !source.contains("{#")
}

#[derive(Debug)]
pub struct RenderedNotification {
    pub title: Option<String>,
    pub body: Option<String>,
    pub payload: Option<Value>,
}

pub fn validate_payload_size(
    receiver: &str,
    target: PayloadKind,
    payload: &Value,
) -> Result<(), NotificationTemplateError> {
    let limit = target.byte_limit();
    if serde_json::to_vec(payload).is_ok_and(|payload| payload.len() <= limit) {
        Ok(())
    } else {
        Err(NotificationTemplateError::PayloadLimit {
            receiver: receiver.to_string(),
            target,
            limit,
        })
    }
}

fn validate_payload_shape(
    receiver: &str,
    target: PayloadKind,
    payload: &Value,
) -> Result<(), NotificationTemplateError> {
    let Some(object) = payload.as_object() else {
        return Err(NotificationTemplateError::NonObjectJson {
            receiver: receiver.to_string(),
        });
    };
    let valid = match target {
        PayloadKind::GenericWebhook | PayloadKind::CloudEventsWebhook => true,
        PayloadKind::GoogleChat => {
            object.get("text").is_some_and(Value::is_string)
                || object.get("cardsV2").is_some_and(Value::is_array)
        }
        PayloadKind::Slack | PayloadKind::Mattermost => {
            object.get("text").is_some_and(Value::is_string)
                || object.get("blocks").is_some_and(Value::is_array)
        }
        PayloadKind::Discord => {
            object.get("content").is_some_and(Value::is_string)
                || object.get("embeds").is_some_and(Value::is_array)
        }
        PayloadKind::Matrix => {
            object.get("msgtype").is_some_and(Value::is_string)
                && object.get("body").is_some_and(Value::is_string)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(NotificationTemplateError::InvalidPayloadShape {
            receiver: receiver.to_string(),
            target,
            reason: match target {
                PayloadKind::GoogleChat => "expected string text or array cardsV2",
                PayloadKind::Slack | PayloadKind::Mattermost => {
                    "expected string text or array blocks"
                }
                PayloadKind::Discord => "expected string content or array embeds",
                PayloadKind::Matrix => "expected string msgtype and body",
                PayloadKind::GenericWebhook | PayloadKind::CloudEventsWebhook => unreachable!(),
            },
        })
    }
}

#[derive(Serialize)]
struct NotificationContext<'a> {
    alert: TemplateAlert<'a>,
    delivery: TemplateDelivery<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<TemplateGroup>,
    status: &'a str,
    severity: &'a str,
    title: &'a str,
    alertname: &'a str,
}

impl<'a> NotificationContext<'a> {
    fn event(event: &'a AlertEvent, delivery: &'a Delivery) -> Self {
        Self::new(event, delivery, None)
    }

    fn batch(batch: &'a NotificationBatch, delivery: &'a Delivery) -> Self {
        let event = batch.primary();
        let group = TemplateGroup {
            count: batch.instance_count(),
            status: event.status.clone(),
            severity_counts: batch.severity_counts(),
            instances: batch.flattened_instances(),
        };
        Self::new(event, delivery, Some(group))
    }

    fn new(event: &'a AlertEvent, delivery: &'a Delivery, group: Option<TemplateGroup>) -> Self {
        Self {
            alert: TemplateAlert::from(event),
            delivery: TemplateDelivery {
                route: &delivery.route_name,
                receiver: &delivery.receiver,
                owner_team: delivery.owner_team.as_deref(),
            },
            group,
            status: &event.status,
            severity: &event.severity,
            title: &event.title,
            alertname: &event.title,
        }
    }
}

#[derive(Serialize)]
struct TemplateAlert<'a> {
    integration: &'a str,
    source: &'a str,
    status: &'a str,
    severity: &'a str,
    title: &'a str,
    body: Option<&'a str>,
    fingerprint: &'a str,
    starts_at: Option<&'a str>,
    ends_at: Option<&'a str>,
    labels: &'a BTreeMap<String, String>,
    annotations: &'a BTreeMap<String, String>,
    links: &'a [AlertLink],
}

impl<'a> From<&'a AlertEvent> for TemplateAlert<'a> {
    fn from(event: &'a AlertEvent) -> Self {
        Self {
            integration: &event.integration,
            source: &event.source,
            status: &event.status,
            severity: &event.severity,
            title: &event.title,
            body: event.body.as_deref(),
            fingerprint: &event.fingerprint,
            starts_at: event.starts_at.as_deref(),
            ends_at: event.ends_at.as_deref(),
            labels: &event.labels,
            annotations: &event.annotations,
            links: &event.links,
        }
    }
}

#[derive(Serialize)]
struct TemplateDelivery<'a> {
    route: &'a str,
    receiver: &'a str,
    owner_team: Option<&'a str>,
}

#[derive(Serialize)]
struct TemplateGroup {
    count: usize,
    status: String,
    severity_counts: BTreeMap<String, usize>,
    instances: Vec<AlertInstance>,
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl io::Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(buffer.len()) > self.limit {
            self.exceeded = true;
            return Err(io::Error::other(
                "notification template output limit exceeded",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        CloudEventsWebhookMode, CloudEventsWebhookReceiverConfig, GenericWebhookReceiverConfig,
        NotificationTemplateConfig,
    };
    use serde_json::json;

    fn event() -> AlertEvent {
        let mut event = AlertEvent::new(
            "grafana",
            "grafana",
            "firing",
            "critical",
            "Disk full",
            "disk-1",
            json!({"secret": "must-not-render"}),
        );
        event.body = Some("Disk is 95% full".to_string());
        event.labels.insert("host".to_string(), "db-1".to_string());
        event
            .annotations
            .insert("summary".to_string(), "urgent".to_string());
        event.links.push(AlertLink {
            label: "source".to_string(),
            url: "https://alerts.example.test/1".to_string(),
        });
        event
    }

    fn delivery() -> Delivery {
        Delivery {
            route_name: "ops".to_string(),
            receiver: "target".to_string(),
            owner_team: Some("platform".to_string()),
            escalation_policy: None,
            group_by: Vec::new(),
        }
    }

    fn engine(config: NotificationTemplateConfig) -> Arc<NotificationTemplateEngine> {
        NotificationTemplateEngine::compile(&BTreeMap::from([(
            "target".to_string(),
            ReceiverConfig::GenericWebhook(GenericWebhookReceiverConfig {
                webhook_url: "https://example.test/hook".to_string(),
                owner_team: None,
                timeout_secs: 10,
                template: Some(config),
            }),
        )]))
        .unwrap()
    }

    fn cloudevents_engine(config: NotificationTemplateConfig) -> Arc<NotificationTemplateEngine> {
        NotificationTemplateEngine::compile(&BTreeMap::from([(
            "target".to_string(),
            ReceiverConfig::CloudEventsWebhook(CloudEventsWebhookReceiverConfig {
                webhook_url: "https://events.example.test/hook".to_string(),
                source: "urn:simple-alert-proxy:test".to_string(),
                mode: CloudEventsWebhookMode::Structured,
                event_type: "io.example.alert.v1".to_string(),
                batch_type: "io.example.batch.v1".to_string(),
                owner_team: None,
                timeout_secs: 10,
                template: Some(config),
            }),
        )]))
        .unwrap()
    }

    #[test]
    fn renders_allowlisted_event_delivery_and_group_context() {
        let engine = engine(NotificationTemplateConfig {
            payload: Some(
                r#"{"summary": {{ alert.title | tojson }}, "route": {{ delivery.route | tojson }}, "count": {{ group.count }}, "host": {{ group.instances[0].labels.host | tojson }}, "legacy": {{ alertname | tojson }}, "optional": "{% if alert.body %}present{% endif %}", "labels": "{% for name, value in alert.labels | items %}{{ name }}={{ value }}{% endfor %}", "annotations": "{% for name, value in alert.annotations | items %}{{ name }}={{ value }}{% endfor %}", "links": "{% for link in alert.links %}{{ link.label }}={{ link.url }}{% endfor %}"}"#.to_string(),
            ),
            ..Default::default()
        });
        let batch = NotificationBatch::new("group", vec![event()]);

        let rendered = engine
            .render_batch("target", &batch, &delivery(), PayloadKind::GenericWebhook)
            .unwrap()
            .unwrap();

        let payload = rendered.payload.unwrap();
        assert_eq!(payload["summary"], "Disk full");
        assert_eq!(payload["route"], "ops");
        assert_eq!(payload["count"], 1);
        assert_eq!(payload["host"], "db-1");
        assert_eq!(payload["legacy"], "Disk full");
        assert_eq!(payload["optional"], "present");
        assert_eq!(payload["labels"], "host=db-1");
        assert_eq!(payload["annotations"], "summary=urgent");
        assert_eq!(payload["links"], "source=https://alerts.example.test/1");
    }

    #[test]
    fn raw_payload_and_configuration_are_not_available() {
        for source in [
            r#"{"leak": {{ alert.raw_payload.secret | tojson }}}"#,
            r#"{"leak": {{ receiver.webhook_url | tojson }}}"#,
        ] {
            let engine = engine(NotificationTemplateConfig {
                payload: Some(source.to_string()),
                ..Default::default()
            });
            let error = engine
                .render_event("target", &event(), &delivery(), PayloadKind::GenericWebhook)
                .unwrap_err();

            assert!(matches!(error, NotificationTemplateError::Render { .. }));
            assert!(!error.to_string().contains("must-not-render"));
            assert!(!error.to_string().contains("example.test"));
        }
    }

    #[test]
    fn rejects_non_object_and_target_incompatible_payloads() {
        let non_object = engine(NotificationTemplateConfig {
            payload: Some("{{ [] | tojson }}".to_string()),
            ..Default::default()
        });
        assert!(matches!(
            non_object
                .render_event("target", &event(), &delivery(), PayloadKind::GenericWebhook)
                .unwrap_err(),
            NotificationTemplateError::NonObjectJson { .. }
        ));

        let incompatible = engine(NotificationTemplateConfig {
            payload: Some(r#"{"unexpected": {{ true | tojson }}}"#.to_string()),
            ..Default::default()
        });
        assert!(matches!(
            incompatible
                .render_event("target", &event(), &delivery(), PayloadKind::Slack)
                .unwrap_err(),
            NotificationTemplateError::InvalidPayloadShape { .. }
        ));

        let invalid_json = engine(NotificationTemplateConfig {
            payload: Some(r#"{"title": {{ alert.title }}}"#.to_string()),
            ..Default::default()
        });
        assert!(matches!(
            invalid_json
                .render_event("target", &event(), &delivery(), PayloadKind::GenericWebhook)
                .unwrap_err(),
            NotificationTemplateError::InvalidJson { .. }
        ));
    }

    #[test]
    fn bounds_rendered_output() {
        let oversized = engine(NotificationTemplateConfig {
            payload: Some(r#"{"content":{{ alert.title | tojson }}}"#.to_string()),
            ..Default::default()
        });
        let mut large_event = event();
        large_event.title = "x".repeat(20 * 1024);
        let error = oversized
            .render_event("target", &large_event, &delivery(), PayloadKind::Discord)
            .unwrap_err();
        assert!(matches!(
            error,
            NotificationTemplateError::OutputLimit { .. }
        ));
    }

    #[test]
    fn bounds_instruction_count() {
        let engine = engine(NotificationTemplateConfig {
            payload: Some(
                r#"{% for item in range(100000) %}{% set value = item + 1 %}{% endfor %}{"ok":true}"#
                    .to_string(),
            ),
            ..Default::default()
        });

        let error = engine
            .render_event("target", &event(), &delivery(), PayloadKind::GenericWebhook)
            .unwrap_err();
        assert!(matches!(
            error,
            NotificationTemplateError::Render { ref kind, .. }
                if kind == "engine ran out of fuel"
        ));
    }

    #[test]
    fn bounds_recursive_rendering() {
        let engine = engine(NotificationTemplateConfig {
            payload: Some(
                r#"{"value":"{% for item in [1] recursive %}x{{ loop([1]) }}{% endfor %}"}"#
                    .to_string(),
            ),
            ..Default::default()
        });

        let error = engine
            .render_event("target", &event(), &delivery(), PayloadKind::GenericWebhook)
            .unwrap_err();
        assert!(matches!(error, NotificationTemplateError::Render { .. }));
    }

    #[test]
    fn accepts_minimal_payload_shapes_for_every_receiver() {
        for (target, source) in [
            (PayloadKind::GoogleChat, r#"{"text":"ok"}"#),
            (PayloadKind::GenericWebhook, r#"{"anything":true}"#),
            (PayloadKind::CloudEventsWebhook, r#"{"anything":true}"#),
            (PayloadKind::Slack, r#"{"text":"ok"}"#),
            (PayloadKind::Mattermost, r#"{"text":"ok"}"#),
            (PayloadKind::Discord, r#"{"content":"ok"}"#),
            (PayloadKind::Matrix, r#"{"msgtype":"m.notice","body":"ok"}"#),
        ] {
            let engine = engine(NotificationTemplateConfig {
                payload: Some(source.to_string()),
                ..Default::default()
            });
            let rendered = engine
                .render_event("target", &event(), &delivery(), target)
                .unwrap()
                .unwrap();
            assert!(rendered.payload.unwrap().is_object(), "{target}");
        }
    }

    #[test]
    fn rejects_invalid_static_payloads_during_compilation() {
        let receiver = ReceiverConfig::GenericWebhook(GenericWebhookReceiverConfig {
            webhook_url: "https://example.test/hook".to_string(),
            owner_team: None,
            timeout_secs: 10,
            template: Some(NotificationTemplateConfig {
                payload: Some("not-json".to_string()),
                ..Default::default()
            }),
        });

        let error = NotificationTemplateEngine::compile(&BTreeMap::from([(
            "target".to_string(),
            receiver,
        )]))
        .unwrap_err();

        assert!(error.to_string().contains("invalid static JSON"));
    }

    #[test]
    fn cloudevents_template_renders_only_normalized_data() {
        let engine = cloudevents_engine(NotificationTemplateConfig {
            payload: Some(
                r#"{"summary": {{ alert.title | tojson }}, "route": {{ delivery.route | tojson }}}"#
                    .to_string(),
            ),
            ..Default::default()
        });

        let rendered = engine
            .render_event(
                "target",
                &event(),
                &delivery(),
                PayloadKind::CloudEventsWebhook,
            )
            .unwrap()
            .unwrap();

        assert_eq!(
            rendered.payload.unwrap(),
            json!({
                "summary": "Disk full",
                "route": "ops"
            })
        );
    }
}
