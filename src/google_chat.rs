use crate::{
    alert::AlertEvent,
    config::{
        ChatWebhookReceiverConfig, GenericWebhookReceiverConfig, GoogleChatReceiverConfig,
        MatrixReceiverConfig, ReceiverConfig,
    },
    notification::NotificationBatch,
    redaction,
    routing::Delivery,
};
use reqwest::StatusCode;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GoogleChatClient {
    http: reqwest::Client,
}

impl GoogleChatClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }

    pub async fn send_event(
        &self,
        receiver: &GoogleChatReceiverConfig,
        event: &AlertEvent,
        delivery: &Delivery,
        debug: Option<DebugDeliveryLog<'_>>,
    ) -> Result<(), GoogleChatError> {
        let message = if event.instances.is_empty() {
            build_event_message(receiver, event, delivery)
        } else {
            build_batch_message(
                receiver,
                &NotificationBatch::new(
                    event.notification_group_key.clone().unwrap_or_default(),
                    vec![event.clone()],
                ),
                delivery,
            )
        };

        if let Some(debug) = debug {
            log_outgoing_alert(&message, debug);
        }

        let response = self
            .http
            .post(&receiver.webhook_url)
            .timeout(Duration::from_secs(receiver.timeout_secs))
            .json(&message)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(GoogleChatError::Rejected(response.status()))
        }
    }

    pub async fn send_receiver_event(
        &self,
        receiver: &ReceiverConfig,
        event: &AlertEvent,
        delivery: &Delivery,
        matrix_transaction_id: &str,
        debug: Option<DebugDeliveryLog<'_>>,
    ) -> Result<(), GoogleChatError> {
        match receiver {
            ReceiverConfig::GoogleChat(receiver) => {
                self.send_event(receiver, event, delivery, debug).await
            }
            ReceiverConfig::GenericWebhook(receiver) => {
                self.send_generic_webhook(receiver, event, delivery, debug)
                    .await
            }
            ReceiverConfig::Slack(receiver) => {
                self.send_chat_webhook(receiver, event, delivery, debug, ChatTarget::Slack)
                    .await
            }
            ReceiverConfig::Mattermost(receiver) => {
                self.send_chat_webhook(receiver, event, delivery, debug, ChatTarget::Mattermost)
                    .await
            }
            ReceiverConfig::Discord(receiver) => {
                self.send_chat_webhook(receiver, event, delivery, debug, ChatTarget::Discord)
                    .await
            }
            ReceiverConfig::Matrix(receiver) => {
                self.send_matrix(receiver, event, delivery, matrix_transaction_id, debug)
                    .await
            }
        }
    }

    pub async fn send_receiver_batch(
        &self,
        receiver: &ReceiverConfig,
        batch: &NotificationBatch,
        delivery: &Delivery,
        matrix_transaction_id: &str,
        debug: Option<DebugDeliveryLog<'_>>,
    ) -> Result<(), GoogleChatError> {
        match receiver {
            ReceiverConfig::GoogleChat(receiver) => {
                let message = build_batch_message(receiver, batch, delivery);
                self.post_json(
                    &receiver.webhook_url,
                    receiver.timeout_secs,
                    &message,
                    debug,
                )
                .await
            }
            ReceiverConfig::GenericWebhook(receiver) => {
                if batch.events.len() == 1 {
                    return self
                        .send_generic_webhook(receiver, batch.primary(), delivery, debug)
                        .await;
                }
                let message = build_generic_batch_message(batch, delivery);
                self.post_json(
                    &receiver.webhook_url,
                    receiver.timeout_secs,
                    &message,
                    debug,
                )
                .await
            }
            ReceiverConfig::Slack(receiver) => {
                self.send_chat_batch(receiver, batch, delivery, debug, ChatTarget::Slack)
                    .await
            }
            ReceiverConfig::Mattermost(receiver) => {
                self.send_chat_batch(receiver, batch, delivery, debug, ChatTarget::Mattermost)
                    .await
            }
            ReceiverConfig::Discord(receiver) => {
                self.send_chat_batch(receiver, batch, delivery, debug, ChatTarget::Discord)
                    .await
            }
            ReceiverConfig::Matrix(receiver) => {
                self.send_matrix_batch(receiver, batch, delivery, matrix_transaction_id, debug)
                    .await
            }
        }
    }

    async fn send_generic_webhook(
        &self,
        receiver: &GenericWebhookReceiverConfig,
        event: &AlertEvent,
        delivery: &Delivery,
        debug: Option<DebugDeliveryLog<'_>>,
    ) -> Result<(), GoogleChatError> {
        let message = json!({
            "event": event,
            "delivery": {
                "route": delivery.route_name,
                "receiver": delivery.receiver,
            }
        });
        self.post_json(
            &receiver.webhook_url,
            receiver.timeout_secs,
            &message,
            debug,
        )
        .await
    }

    async fn send_chat_webhook(
        &self,
        receiver: &ChatWebhookReceiverConfig,
        event: &AlertEvent,
        delivery: &Delivery,
        debug: Option<DebugDeliveryLog<'_>>,
        target: ChatTarget,
    ) -> Result<(), GoogleChatError> {
        let title = receiver
            .title_template
            .replace("{{status}}", &event.status)
            .replace("{{alertname}}", &event.title)
            .replace("{{title}}", &event.title)
            .replace("{{severity}}", &event.severity);
        let text = format!(
            "{title} via {} | {} | {}",
            delivery.route_name, event.source, event.fingerprint
        );
        let message = match target {
            ChatTarget::Slack | ChatTarget::Mattermost => json!({ "text": text }),
            ChatTarget::Discord => json!({
                "content": text,
                "embeds": [{
                    "title": event.title,
                    "description": event.body,
                    "fields": [
                        { "name": "Status", "value": event.status, "inline": true },
                        { "name": "Severity", "value": event.severity, "inline": true },
                        { "name": "Source", "value": event.source, "inline": true }
                    ]
                }]
            }),
        };
        self.post_json(
            &receiver.webhook_url,
            receiver.timeout_secs,
            &message,
            debug,
        )
        .await
    }

    async fn send_chat_batch(
        &self,
        receiver: &ChatWebhookReceiverConfig,
        batch: &NotificationBatch,
        delivery: &Delivery,
        debug: Option<DebugDeliveryLog<'_>>,
        target: ChatTarget,
    ) -> Result<(), GoogleChatError> {
        let message = build_chat_batch_message(receiver, batch, delivery, target);
        self.post_json(
            &receiver.webhook_url,
            receiver.timeout_secs,
            &message,
            debug,
        )
        .await
    }

    async fn send_matrix(
        &self,
        receiver: &MatrixReceiverConfig,
        event: &AlertEvent,
        delivery: &Delivery,
        transaction_id: &str,
        debug: Option<DebugDeliveryLog<'_>>,
    ) -> Result<(), GoogleChatError> {
        let title = receiver
            .title_template
            .replace("{{status}}", &event.status)
            .replace("{{alertname}}", &event.title)
            .replace("{{title}}", &event.title)
            .replace("{{severity}}", &event.severity);
        let body = matrix_plaintext_body(&title, event, delivery);
        let formatted_body = matrix_html_body(&title, event, delivery);
        let message = json!({
            "msgtype": "m.notice",
            "body": body,
            "format": "org.matrix.custom.html",
            "formatted_body": formatted_body,
        });
        let token = receiver
            .resolved_access_token()
            .map_err(|error| GoogleChatError::Config(error.to_string()))?;
        let url = matrix_send_url(receiver, transaction_id);

        if let Some(debug) = debug {
            log_outgoing_alert(&message, debug);
        }

        let response = self
            .http
            .put(url)
            .bearer_auth(token)
            .timeout(Duration::from_secs(receiver.timeout_secs))
            .json(&message)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(GoogleChatError::Rejected(response.status()))
        }
    }

    async fn send_matrix_batch(
        &self,
        receiver: &MatrixReceiverConfig,
        batch: &NotificationBatch,
        delivery: &Delivery,
        transaction_id: &str,
        debug: Option<DebugDeliveryLog<'_>>,
    ) -> Result<(), GoogleChatError> {
        let message = build_matrix_batch_message(receiver, batch, delivery);
        let token = receiver
            .resolved_access_token()
            .map_err(|error| GoogleChatError::Config(error.to_string()))?;
        let url = matrix_send_url(receiver, transaction_id);

        if let Some(debug) = debug {
            log_outgoing_alert(&message, debug);
        }

        let response = self
            .http
            .put(url)
            .bearer_auth(token)
            .timeout(Duration::from_secs(receiver.timeout_secs))
            .json(&message)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(GoogleChatError::Rejected(response.status()))
        }
    }

    async fn post_json(
        &self,
        webhook_url: &str,
        timeout_secs: u64,
        message: &serde_json::Value,
        debug: Option<DebugDeliveryLog<'_>>,
    ) -> Result<(), GoogleChatError> {
        if let Some(debug) = debug {
            log_outgoing_alert(message, debug);
        }

        let response = self
            .http
            .post(webhook_url)
            .timeout(Duration::from_secs(timeout_secs))
            .json(message)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(GoogleChatError::Rejected(response.status()))
        }
    }
}

fn matrix_send_url(receiver: &MatrixReceiverConfig, transaction_id: &str) -> String {
    let homeserver = receiver.homeserver_url.trim().trim_end_matches('/');
    let room_id = percent_encode_path_segment(receiver.room_id.trim());
    let transaction_id = percent_encode_path_segment(transaction_id);
    format!("{homeserver}/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{transaction_id}")
}

fn matrix_plaintext_body(title: &str, event: &AlertEvent, delivery: &Delivery) -> String {
    let mut lines = vec![
        title.to_string(),
        format!("Route: {}", delivery.route_name),
        format!("Receiver: {}", delivery.receiver),
        format!("Source: {} / {}", event.integration, event.source),
        format!("Status: {}", event.status),
        format!("Severity: {}", event.severity),
        format!("Fingerprint: {}", event.fingerprint),
    ];

    if let Some(body) = &event.body
        && !body.is_empty()
    {
        lines.push(String::new());
        lines.push(body.clone());
    }

    if !event.links.is_empty() {
        lines.push(String::new());
        lines.extend(
            event
                .links
                .iter()
                .map(|link| format!("{}: {}", link.label, link.url)),
        );
    }

    lines.join("\n")
}

fn matrix_html_body(title: &str, event: &AlertEvent, delivery: &Delivery) -> String {
    let mut lines = vec![
        format!("<strong>{}</strong>", escape_html(title)),
        format!("Route: {}", escape_html(&delivery.route_name)),
        format!("Receiver: {}", escape_html(&delivery.receiver)),
        format!(
            "Source: {} / {}",
            escape_html(&event.integration),
            escape_html(&event.source)
        ),
        format!("Status: {}", escape_html(&event.status)),
        format!("Severity: {}", escape_html(&event.severity)),
        format!("Fingerprint: {}", escape_html(&event.fingerprint)),
    ];

    if let Some(body) = &event.body
        && !body.is_empty()
    {
        lines.push(String::new());
        lines.push(escape_html(body));
    }

    if !event.links.is_empty() {
        lines.push(String::new());
        lines.extend(event.links.iter().map(matrix_html_link));
    }

    lines.join("<br>")
}

fn matrix_html_link(link: &crate::alert::AlertLink) -> String {
    let is_safe_link =
        reqwest::Url::parse(&link.url).is_ok_and(|url| matches!(url.scheme(), "http" | "https"));
    if is_safe_link {
        format!(
            r#"<a href="{}">{}</a>"#,
            escape_html(&link.url),
            escape_html(&link.label)
        )
    } else {
        format!("{}: {}", escape_html(&link.label), escape_html(&link.url))
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn percent_encode_path_segment(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

#[derive(Debug, Clone, Copy)]
enum ChatTarget {
    Slack,
    Mattermost,
    Discord,
}

#[derive(Debug, Clone, Copy)]
pub struct DebugDeliveryLog<'a> {
    pub route_name: &'a str,
    pub receiver_name: &'a str,
}

fn log_outgoing_alert(message: &serde_json::Value, debug: DebugDeliveryLog<'_>) {
    let log = json!({
        "route": debug.route_name,
        "receiver": debug.receiver_name,
        "payload": redaction::redact_json_value(message),
    });

    match serde_json::to_string_pretty(&log) {
        Ok(json) => eprintln!("simple-alert-proxy debug outgoing alert:\n{json}"),
        Err(error) => {
            eprintln!("simple-alert-proxy debug outgoing alert: failed to render JSON: {error}")
        }
    }
}

fn build_event_message(
    receiver: &GoogleChatReceiverConfig,
    event: &AlertEvent,
    delivery: &Delivery,
) -> serde_json::Value {
    let title = format_event_title(receiver, event, delivery);

    json!({
        "cardsV2": [{
            "cardId": "alert-event",
            "card": {
                "header": {
                    "title": title,
                    "subtitle": format!("{} | {} | {}", event.source, event.status, event.severity),
                },
                "sections": build_event_sections(event),
            }
        }],
    })
}

fn build_batch_message(
    receiver: &GoogleChatReceiverConfig,
    batch: &NotificationBatch,
    delivery: &Delivery,
) -> serde_json::Value {
    let event = batch.primary();
    let title = format_event_title(receiver, event, delivery);
    let mut summary_widgets = vec![
        json!({
            "decoratedText": {
                "text": format!("Status: {}", event.status),
            }
        }),
        json!({
            "decoratedText": {
                "text": format!(
                    "Severity counts: {}",
                    format_severity_counts(&batch.severity_counts())
                ),
            }
        }),
    ];

    if let Some(source) = event.links.iter().find(|link| link.label == "source") {
        summary_widgets.push(json!({
            "textParagraph": {
                "text": format!(
                    "Source: <a href=\"{}\">SOURCE</a>",
                    escape_chat_html(&source.url)
                ),
            }
        }));
    }

    let instance_widgets = batch_instance_lines(batch)
        .into_iter()
        .map(|line| json!({ "textParagraph": { "text": line } }))
        .collect::<Vec<_>>();
    let mut sections = vec![json!({ "widgets": summary_widgets })];
    if !instance_widgets.is_empty() {
        sections.push(json!({
            "header": "Instances",
            "widgets": instance_widgets,
        }));
    }

    json!({
        "cardsV2": [{
            "cardId": "notification-batch",
            "card": {
                "header": {
                    "title": title,
                    "subtitle": format!(
                        "{} instance{} | {}",
                        batch.instance_count(),
                        if batch.instance_count() == 1 { "" } else { "s" },
                        format_severity_counts(&batch.severity_counts())
                    ),
                },
                "sections": sections,
            }
        }],
    })
}

fn build_generic_batch_message(
    batch: &NotificationBatch,
    delivery: &Delivery,
) -> serde_json::Value {
    json!({
        "batch": {
            "group_key": batch.group_key,
            "count": batch.instance_count(),
            "severity_counts": batch.severity_counts(),
        },
        "events": batch.events,
        "delivery": {
            "route": delivery.route_name,
            "receiver": delivery.receiver,
        }
    })
}

fn build_chat_batch_message(
    receiver: &ChatWebhookReceiverConfig,
    batch: &NotificationBatch,
    delivery: &Delivery,
    target: ChatTarget,
) -> serde_json::Value {
    let event = batch.primary();
    let title = format_template_title(&receiver.title_template, event);
    let summary = format!(
        "{title} via {} | {} instances | {}",
        delivery.route_name,
        batch.instance_count(),
        format_severity_counts(&batch.severity_counts())
    );
    let lines = batch_instance_lines(batch);
    let text = std::iter::once(summary.clone())
        .chain(lines.iter().map(|line| format!("- {line}")))
        .collect::<Vec<_>>()
        .join("\n");
    match target {
        ChatTarget::Slack | ChatTarget::Mattermost => json!({ "text": text }),
        ChatTarget::Discord => json!({
            "content": summary,
            "embeds": [{
                "title": event.title,
                "description": truncate_chars(&lines.join("\n"), 3500),
                "fields": [
                    { "name": "Status", "value": event.status, "inline": true },
                    { "name": "Instances", "value": batch.instance_count().to_string(), "inline": true },
                    { "name": "Source", "value": event.source, "inline": true }
                ]
            }]
        }),
    }
}

fn build_matrix_batch_message(
    receiver: &MatrixReceiverConfig,
    batch: &NotificationBatch,
    delivery: &Delivery,
) -> serde_json::Value {
    let event = batch.primary();
    let title = format_template_title(&receiver.title_template, event);
    let mut lines = vec![
        title,
        format!("Route: {}", delivery.route_name),
        format!("Receiver: {}", delivery.receiver),
        format!("Source: {} / {}", event.integration, event.source),
        format!("Status: {}", event.status),
        format!("Instances: {}", batch.instance_count()),
        format!(
            "Severities: {}",
            format_severity_counts(&batch.severity_counts())
        ),
        String::new(),
    ];
    lines.extend(batch_instance_lines(batch));
    let body = lines.join("\n");
    let formatted_body = lines
        .iter()
        .map(|line| escape_html(line))
        .collect::<Vec<_>>()
        .join("<br>");
    json!({
        "msgtype": "m.notice",
        "body": body,
        "format": "org.matrix.custom.html",
        "formatted_body": formatted_body,
    })
}

fn format_template_title(template: &str, event: &AlertEvent) -> String {
    template
        .replace("{{status}}", &event.status)
        .replace("{{alertname}}", &event.title)
        .replace("{{title}}", &event.title)
        .replace("{{severity}}", &event.severity)
}

fn batch_instance_lines(batch: &NotificationBatch) -> Vec<String> {
    batch
        .flattened_instances()
        .iter()
        .map(|instance| {
            let host = map_first(
                &instance.labels,
                &[
                    "host.name",
                    "host",
                    "instance",
                    "node",
                    "service.instance.id",
                    "pod",
                    "container",
                ],
            )
            .unwrap_or(instance.title.as_str());
            let resource = map_first(
                &instance.labels,
                &[
                    "mountpoint",
                    "resource.name",
                    "resource",
                    "service",
                    "job",
                    "namespace",
                    "device",
                ],
            )
            .or(instance.fingerprint.as_deref())
            .unwrap_or("general");
            format!("{host} | {} | {resource}", instance.severity)
        })
        .collect()
}

fn map_first<'a>(values: &'a BTreeMap<String, String>, names: &[&str]) -> Option<&'a str> {
    names
        .iter()
        .find_map(|name| values.get(*name).map(String::as_str))
}

fn truncate_chars(value: &str, max: usize) -> String {
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(max).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}…")
    } else {
        truncated
    }
}

fn format_event_title(
    receiver: &GoogleChatReceiverConfig,
    event: &AlertEvent,
    delivery: &Delivery,
) -> String {
    let mut title = receiver
        .title_template
        .replace("{{status}}", &event.status)
        .replace("{{alertname}}", &event.title)
        .replace("{{title}}", &event.title)
        .replace("{{severity}}", &event.severity);

    if !delivery.route_name.is_empty() {
        title.push_str(&format!(" via {}", delivery.route_name));
    }

    title
}

fn build_event_sections(event: &AlertEvent) -> Vec<serde_json::Value> {
    let mut summary_widgets = vec![
        json!({
            "decoratedText": {
                "text": format!("Status: {}", event.status),
            }
        }),
        json!({
            "decoratedText": {
                "text": format!("Severity: {}", event.severity),
            }
        }),
        json!({
            "decoratedText": {
                "text": format!("Fingerprint: {}", event.fingerprint),
            }
        }),
    ];

    if let Some(body) = &event.body {
        summary_widgets.push(json!({
            "textParagraph": {
                "text": escape_chat_html(body),
            }
        }));
    }

    for link in &event.links {
        summary_widgets.push(json!({
            "textParagraph": {
                "text": format!(
                    "{}: <a href=\"{}\">LINK</a>",
                    escape_chat_html(&link.label),
                    escape_chat_html(&link.url)
                ),
            }
        }));
    }

    let mut sections = vec![json!({ "widgets": summary_widgets })];

    if !event.labels.is_empty() {
        sections.push(json!({
            "header": "Labels",
            "widgets": map_lines(&event.labels),
        }));
    }

    if !event.annotations.is_empty() {
        sections.push(json!({
            "header": "Annotations",
            "widgets": map_lines(&event.annotations),
        }));
    }

    sections
}

fn map_lines(values: &BTreeMap<String, String>) -> Vec<serde_json::Value> {
    values
        .iter()
        .map(|(key, value)| {
            json!({
                "decoratedText": {
                    "topLabel": key,
                    "text": value,
                }
            })
        })
        .collect()
}

fn escape_chat_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn format_severity_counts(counts: &BTreeMap<String, usize>) -> String {
    counts
        .iter()
        .map(|(severity, count)| format!("{severity}: {count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, thiserror::Error)]
pub enum GoogleChatError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("target rejected message with status {0}")]
    Rejected(StatusCode),
    #[error("target config error: {0}")]
    Config(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signoz::SigNozAlert;

    #[test]
    fn builds_card_payload_with_grouped_instances() {
        let alert = SigNozAlert::from_value(
            serde_json::from_str(include_str!("../examples/signoz-webhook-disk-space.json"))
                .unwrap(),
        )
        .unwrap();
        let receiver = GoogleChatReceiverConfig {
            webhook_url: "https://chat.googleapis.test/ops".to_string(),
            owner_team: None,
            title_template: "[{{status}}] {{alertname}}".to_string(),
            timeout_secs: 10,
        };
        let delivery = Delivery {
            route_name: "ops".to_string(),
            receiver: "ops-chat".to_string(),
            owner_team: None,
            escalation_policy: None,
            group_by: Vec::new(),
        };

        let batch = NotificationBatch::new("batch-1", vec![alert.to_alert_event("signoz")]);
        let payload = build_batch_message(&receiver, &batch, &delivery);
        let summary_widgets = payload["cardsV2"][0]["card"]["sections"][0]["widgets"]
            .as_array()
            .unwrap();
        let instances = payload["cardsV2"][0]["card"]["sections"][1]["widgets"]
            .as_array()
            .unwrap();

        assert!(payload.get("text").is_none());
        assert_eq!(
            summary_widgets[2]["textParagraph"]["text"].as_str(),
            Some(
                "Source: <a href=\"https://signoz00.het.example.com/alerts/edit?ruleId=019ef5e1-2027-7be3-a458-88b6a8707d8f\">SOURCE</a>"
            )
        );
        assert_eq!(instances.len(), 2);
        assert_eq!(
            instances[0]["textParagraph"]["text"].as_str(),
            Some("host000.het.example.com | warning | /")
        );
    }

    #[test]
    fn renders_each_alert_instance_as_its_own_row() {
        let alert = SigNozAlert::from_value(serde_json::json!({
            "status": "firing",
            "commonLabels": {
                "alertname": "Disk Space Low",
                "severity": "critical"
            },
            "commonAnnotations": {},
            "alerts": [
                {
                    "status": "firing",
                    "labels": {
                        "host.name": "host-a",
                        "mountpoint": "/",
                        "severity": "critical"
                    },
                    "annotations": {}
                },
                {
                    "status": "firing",
                    "labels": {
                        "host.name": "host-a",
                        "mountpoint": "/",
                        "severity": "critical"
                    },
                    "annotations": {}
                }
            ]
        }))
        .unwrap();
        let receiver = GoogleChatReceiverConfig {
            webhook_url: "https://chat.googleapis.test/ops".to_string(),
            owner_team: None,
            title_template: "[{{status}}] {{alertname}}".to_string(),
            timeout_secs: 10,
        };
        let delivery = Delivery {
            route_name: "ops".to_string(),
            receiver: "ops-chat".to_string(),
            owner_team: None,
            escalation_policy: None,
            group_by: Vec::new(),
        };

        let batch = NotificationBatch::new("batch-1", vec![alert.to_alert_event("signoz")]);
        let payload = build_batch_message(&receiver, &batch, &delivery);
        let instances = payload["cardsV2"][0]["card"]["sections"][1]["widgets"]
            .as_array()
            .unwrap();

        assert_eq!(instances.len(), 2);
        assert_eq!(
            instances[0]["textParagraph"]["text"].as_str(),
            Some("host-a | critical | /")
        );
        assert_eq!(
            instances[1]["textParagraph"]["text"].as_str(),
            Some("host-a | critical | /")
        );
    }

    #[test]
    fn builds_batch_payloads_for_every_receiver_family() {
        let mut first = AlertEvent::new(
            "grafana",
            "grafana",
            "firing",
            "critical",
            "<HighLatency>",
            "instance-1",
            serde_json::json!({}),
        );
        first
            .labels
            .insert("instance".to_string(), "api-1".to_string());
        let mut second = first.clone();
        second.fingerprint = "instance-2".to_string();
        second.severity = "warning".to_string();
        second
            .labels
            .insert("instance".to_string(), "api-2".to_string());
        let batch = NotificationBatch::new("batch-1", vec![first, second]);
        let delivery = Delivery {
            route_name: "ops".to_string(),
            receiver: "target".to_string(),
            owner_team: None,
            escalation_policy: None,
            group_by: Vec::new(),
        };
        let chat = ChatWebhookReceiverConfig {
            webhook_url: "https://hooks.example.test".to_string(),
            owner_team: None,
            title_template: "[{{status}}] {{title}}".to_string(),
            timeout_secs: 10,
        };
        let matrix = MatrixReceiverConfig {
            homeserver_url: "https://matrix.example.test".to_string(),
            room_id: "!ops:example.test".to_string(),
            access_token: Some("secret".to_string()),
            access_token_env: None,
            owner_team: None,
            title_template: "[{{status}}] {{title}}".to_string(),
            timeout_secs: 10,
        };

        let generic = build_generic_batch_message(&batch, &delivery);
        assert_eq!(generic["batch"]["count"], 2);
        assert_eq!(generic["events"].as_array().unwrap().len(), 2);

        for target in [ChatTarget::Slack, ChatTarget::Mattermost] {
            let payload = build_chat_batch_message(&chat, &batch, &delivery, target);
            let text = payload["text"].as_str().unwrap();
            assert!(text.contains("2 instances"));
            assert!(text.contains("api-1 | critical"));
            assert!(text.contains("api-2 | warning"));
        }

        let discord = build_chat_batch_message(&chat, &batch, &delivery, ChatTarget::Discord);
        assert_eq!(discord["embeds"][0]["fields"][1]["value"], "2");
        assert!(
            discord["embeds"][0]["description"]
                .as_str()
                .unwrap()
                .contains("api-2 | warning")
        );

        let matrix = build_matrix_batch_message(&matrix, &batch, &delivery);
        assert!(matrix["body"].as_str().unwrap().contains("Instances: 2"));
        assert!(
            matrix["formatted_body"]
                .as_str()
                .unwrap()
                .contains("&lt;HighLatency&gt;")
        );
    }

    #[test]
    fn builds_generic_event_card_payload() {
        let mut event = AlertEvent::new(
            "openvas",
            "openvas",
            "firing",
            "high",
            "TLS certificate expired",
            "finding-1",
            serde_json::json!({}),
        );
        event.body = Some("Certificate expired yesterday".to_string());
        event
            .labels
            .insert("asset".to_string(), "edge-1".to_string());
        let receiver = GoogleChatReceiverConfig {
            webhook_url: "https://chat.googleapis.test/ops".to_string(),
            owner_team: None,
            title_template: "[{{status}}] {{alertname}}".to_string(),
            timeout_secs: 10,
        };
        let delivery = Delivery {
            route_name: "ops".to_string(),
            receiver: "ops-chat".to_string(),
            owner_team: None,
            escalation_policy: None,
            group_by: Vec::new(),
        };

        let payload = build_event_message(&receiver, &event, &delivery);

        assert_eq!(
            payload["cardsV2"][0]["card"]["header"]["title"].as_str(),
            Some("[firing] TLS certificate expired via ops")
        );
        assert_eq!(
            payload["cardsV2"][0]["card"]["sections"][1]["widgets"][0]["decoratedText"]["text"]
                .as_str(),
            Some("edge-1")
        );
    }

    #[test]
    fn outgoing_debug_payload_redacts_sensitive_fields() {
        let message = serde_json::json!({
            "event": {
                "title": "Alert",
                "authorization": "Bearer secret"
            },
            "delivery": {
                "receiver": "target",
                "webhook_url": "https://hooks.example.test/token"
            }
        });

        let redacted = redaction::redact_json_value(&message);

        assert_eq!(redacted["event"]["authorization"], "[redacted]");
        assert_eq!(redacted["delivery"]["webhook_url"], "[redacted]");
        assert_eq!(redacted["event"]["title"], "Alert");
    }

    #[test]
    fn builds_matrix_send_url_with_encoded_room_id() {
        let receiver = MatrixReceiverConfig {
            homeserver_url: "https://matrix.example.test/".to_string(),
            room_id: "!room:example.test".to_string(),
            access_token: Some("token".to_string()),
            access_token_env: None,
            owner_team: None,
            title_template: "[{{status}}] {{title}}".to_string(),
            timeout_secs: 10,
        };

        assert_eq!(
            matrix_send_url(&receiver, "simple-alert-proxy-42"),
            "https://matrix.example.test/_matrix/client/v3/rooms/%21room%3Aexample.test/send/m.room.message/simple-alert-proxy-42"
        );
    }

    #[test]
    fn matrix_message_escapes_formatted_body() {
        let mut event = AlertEvent::new(
            "grafana",
            "grafana",
            "firing",
            "critical",
            "CPU <high>",
            "cpu-1",
            serde_json::json!({}),
        );
        event.body = Some("5 > 4 & rising".to_string());
        event.links.push(crate::alert::AlertLink {
            label: "source".to_string(),
            url: "https://grafana.example.test/a?b=1&c=2".to_string(),
        });
        let delivery = Delivery {
            route_name: "critical".to_string(),
            receiver: "matrix-alerts".to_string(),
            owner_team: None,
            escalation_policy: None,
            group_by: Vec::new(),
        };

        let html = matrix_html_body("[firing] CPU <high>", &event, &delivery);

        assert!(html.contains("CPU &lt;high&gt;"));
        assert!(html.contains("5 &gt; 4 &amp; rising"));
        assert!(html.contains("https://grafana.example.test/a?b=1&amp;c=2"));
    }

    #[test]
    fn matrix_message_does_not_link_unsafe_url_schemes() {
        let mut event = AlertEvent::new(
            "grafana",
            "grafana",
            "firing",
            "critical",
            "CPU high",
            "cpu-1",
            serde_json::json!({}),
        );
        event.links.push(crate::alert::AlertLink {
            label: "source".to_string(),
            url: "javascript:alert(1)".to_string(),
        });
        let delivery = Delivery {
            route_name: "critical".to_string(),
            receiver: "matrix-alerts".to_string(),
            owner_team: None,
            escalation_policy: None,
            group_by: Vec::new(),
        };

        let html = matrix_html_body("[firing] CPU high", &event, &delivery);

        assert!(html.contains("source: javascript:alert(1)"));
        assert!(!html.contains("href="));
    }
}
