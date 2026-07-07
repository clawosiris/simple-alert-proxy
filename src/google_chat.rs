use crate::{
    alert::AlertEvent, config::GoogleChatReceiverConfig, routing::Delivery, signoz::SigNozAlert,
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

    pub async fn send(
        &self,
        receiver: &GoogleChatReceiverConfig,
        alert: &SigNozAlert,
        delivery: &Delivery,
        debug: Option<DebugDeliveryLog<'_>>,
    ) -> Result<(), GoogleChatError> {
        let message = build_message(receiver, alert, delivery);

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

    pub async fn send_event(
        &self,
        receiver: &GoogleChatReceiverConfig,
        event: &AlertEvent,
        delivery: &Delivery,
        debug: Option<DebugDeliveryLog<'_>>,
    ) -> Result<(), GoogleChatError> {
        let message = build_event_message(receiver, event, delivery);

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
        "payload": message,
    });

    match serde_json::to_string_pretty(&log) {
        Ok(json) => eprintln!("simple-alert-proxy debug outgoing alert:\n{json}"),
        Err(error) => {
            eprintln!("simple-alert-proxy debug outgoing alert: failed to render JSON: {error}")
        }
    }
}

fn build_message(
    receiver: &GoogleChatReceiverConfig,
    alert: &SigNozAlert,
    delivery: &Delivery,
) -> serde_json::Value {
    let title = format_title(receiver, alert, delivery);

    json!({
        "cardsV2": [{
            "cardId": "signoz-alert",
            "card": {
                "header": {
                    "title": title,
                    "subtitle": format_subtitle(alert),
                },
                "sections": build_sections(alert),
            }
        }],
    })
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

fn format_title(
    receiver: &GoogleChatReceiverConfig,
    alert: &SigNozAlert,
    delivery: &Delivery,
) -> String {
    let status = alert.enrichment.overall_status.as_str();
    let mut title = receiver
        .title_template
        .replace("{{status}}", status)
        .replace("{{alertname}}", &alert.alert_name());

    if !delivery.route_name.is_empty() {
        title.push_str(&format!(" via {}", delivery.route_name));
    }

    title
}

fn format_subtitle(alert: &SigNozAlert) -> String {
    format!(
        "{} instance{} | {}",
        alert.alerts.len(),
        if alert.alerts.len() == 1 { "" } else { "s" },
        format_severity_counts(&alert.enrichment.severity_counts)
    )
}

fn build_sections(alert: &SigNozAlert) -> Vec<serde_json::Value> {
    let mut sections = Vec::new();
    let mut summary_widgets = vec![
        json!({
            "decoratedText": {
                "text": format!("Status: {}", alert.enrichment.overall_status),
            }
        }),
        json!({
            "decoratedText": {
                "text": format!(
                    "Severity counts: {}",
                    format_severity_counts(&alert.enrichment.severity_counts)
                ),
            }
        }),
    ];

    if let Some(source_url) = &alert.enrichment.source_url {
        summary_widgets.push(json!({
            "textParagraph": {
                "text": format!("Source: <a href=\"{}\">SOURCE</a>", escape_chat_html(source_url)),
            }
        }));
    }

    sections.push(json!({
        "widgets": summary_widgets,
    }));

    let instance_widgets = grouped_instance_lines(alert)
        .into_iter()
        .map(|line| {
            json!({
                "textParagraph": {
                    "text": line,
                }
            })
        })
        .collect::<Vec<_>>();

    if !instance_widgets.is_empty() {
        sections.push(json!({
            "header": "Instances",
            "widgets": instance_widgets,
        }));
    }

    sections
}

fn grouped_instance_lines(alert: &SigNozAlert) -> Vec<String> {
    alert
        .enrichment
        .instances
        .iter()
        .map(|instance| {
            format!(
                "{} | {} | {}",
                instance.host, instance.severity, instance.resource
            )
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
    #[error("Google Chat webhook rejected message with status {0}")]
    Rejected(StatusCode),
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
            title_template: "[{{status}}] {{alertname}}".to_string(),
            timeout_secs: 10,
        };
        let delivery = Delivery {
            route_name: "ops".to_string(),
            receiver: "ops-chat".to_string(),
        };

        let payload = build_message(&receiver, &alert, &delivery);
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
            title_template: "[{{status}}] {{alertname}}".to_string(),
            timeout_secs: 10,
        };
        let delivery = Delivery {
            route_name: "ops".to_string(),
            receiver: "ops-chat".to_string(),
        };

        let payload = build_message(&receiver, &alert, &delivery);
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
            title_template: "[{{status}}] {{alertname}}".to_string(),
            timeout_secs: 10,
        };
        let delivery = Delivery {
            route_name: "ops".to_string(),
            receiver: "ops-chat".to_string(),
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
}
