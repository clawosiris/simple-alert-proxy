use crate::{config::GoogleChatReceiverConfig, routing::Delivery, signoz::SigNozAlert};
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
    let fallback_text = format_text_message(&title, alert);

    json!({
        "text": fallback_text,
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

fn format_text_message(title: &str, alert: &SigNozAlert) -> String {
    let mut lines = vec![title.to_string()];

    if let Some(summary) = alert
        .enrichment
        .summary
        .as_deref()
        .or(alert.enrichment.description.as_deref())
    {
        lines.push(summary.to_string());
    }

    lines.push(format!(
        "Status: {} | Instances: {} | Severity: {}",
        alert.enrichment.overall_status,
        alert.alerts.len(),
        format_severity_counts(&alert.enrichment.severity_counts)
    ));

    for line in grouped_instance_lines(alert) {
        lines.push(line);
    }

    if let Some(source_url) = &alert.enrichment.source_url {
        lines.push(format!("Source: {source_url}"));
    }

    lines.join("\n")
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
    let mut summary_lines = vec![format!("Status: {}", alert.enrichment.overall_status)];
    summary_lines.push(format!(
        "Severity counts: {}",
        format_severity_counts(&alert.enrichment.severity_counts)
    ));

    if let Some(summary) = alert
        .enrichment
        .summary
        .as_deref()
        .or(alert.enrichment.description.as_deref())
    {
        summary_lines.push(summary.to_string());
    }

    if let Some(source_url) = &alert.enrichment.source_url {
        summary_lines.push(format!("Source: {source_url}"));
    }

    sections.push(json!({
        "header": "Summary",
        "widgets": [{
            "textParagraph": {
                "text": summary_lines.join("\n"),
            }
        }]
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
    let mut groups: BTreeMap<(String, String, String), Vec<String>> = BTreeMap::new();

    for instance in &alert.enrichment.instances {
        let key = (
            instance.host.clone(),
            instance.severity.clone(),
            instance.resource.clone(),
        );
        let detail = instance
            .description
            .clone()
            .or_else(|| instance.summary.clone())
            .unwrap_or_else(|| "No details provided.".to_string());
        groups.entry(key).or_default().push(detail);
    }

    groups
        .into_iter()
        .map(|((host, severity, resource), details)| {
            let mut line = format!("{host} | {severity} | {resource}");
            if let Some(first_detail) = details.first() {
                line.push_str(&format!(" - {first_detail}"));
            }
            if details.len() > 1 {
                line.push_str(&format!(" ({})", details.len()));
            }
            line
        })
        .collect()
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
        let text = payload["text"].as_str().unwrap();
        let instances = payload["cardsV2"][0]["card"]["sections"][1]["widgets"]
            .as_array()
            .unwrap();

        assert!(text.contains("warning: 2"));
        assert!(text.contains("host000.het.example.com | warning | /"));
        assert!(text.contains("Source: https://signoz00.het.example.com/alerts/edit?ruleId=019ef5e1-2027-7be3-a458-88b6a8707d8f"));
        assert_eq!(instances.len(), 2);
    }
}
