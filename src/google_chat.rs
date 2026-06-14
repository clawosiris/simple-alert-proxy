use crate::{config::GoogleChatReceiverConfig, routing::Delivery, signoz::SigNozAlert};
use reqwest::StatusCode;
use serde_json::json;
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
    ) -> Result<(), GoogleChatError> {
        let message = json!({
            "text": format_message(receiver, alert, delivery),
        });

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

fn format_message(
    receiver: &GoogleChatReceiverConfig,
    alert: &SigNozAlert,
    delivery: &Delivery,
) -> String {
    let status = alert.status.as_deref().unwrap_or("unknown");
    let mut title = receiver
        .title_template
        .replace("{{status}}", status)
        .replace("{{alertname}}", &alert.alert_name());

    if !delivery.route_name.is_empty() {
        title.push_str(&format!(" via {}", delivery.route_name));
    }

    let summary = alert
        .common_annotations
        .get("summary")
        .or_else(|| alert.common_annotations.get("description"))
        .cloned()
        .unwrap_or_else(|| "No summary provided.".to_string());

    format!("{title}\n{summary}\nInstances: {}", alert.alerts.len())
}

#[derive(Debug, thiserror::Error)]
pub enum GoogleChatError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("Google Chat webhook rejected message with status {0}")]
    Rejected(StatusCode),
}
