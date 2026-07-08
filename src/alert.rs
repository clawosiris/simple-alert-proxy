use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertEvent {
    pub event_id: String,
    pub integration: String,
    pub source: String,
    pub received_at: Option<String>,
    pub status: String,
    pub severity: String,
    pub title: String,
    pub body: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
    pub links: Vec<AlertLink>,
    pub starts_at: Option<String>,
    pub ends_at: Option<String>,
    pub fingerprint: String,
    pub raw_payload: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertLink {
    pub label: String,
    pub url: String,
}

impl AlertEvent {
    pub fn new(
        integration: impl Into<String>,
        source: impl Into<String>,
        status: impl Into<String>,
        severity: impl Into<String>,
        title: impl Into<String>,
        fingerprint: impl Into<String>,
        raw_payload: Value,
    ) -> Self {
        let integration = integration.into();
        let source = source.into();
        let status = status.into();
        let severity = severity.into();
        let title = title.into();
        let fingerprint = fingerprint.into();
        let event_id = format!("{integration}:{fingerprint}");

        Self {
            event_id,
            integration,
            source,
            received_at: None,
            status,
            severity,
            title,
            body: None,
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            links: Vec::new(),
            starts_at: None,
            ends_at: None,
            fingerprint,
            raw_payload,
        }
    }
}
