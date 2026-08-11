use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::alert::{AlertEvent, AlertLink};

#[derive(Debug, Clone)]
pub struct GrafanaIntegration {
    name: String,
}

impl GrafanaIntegration {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub fn normalize(&self, raw: Value) -> Result<Vec<AlertEvent>, GrafanaParseError> {
        let payload: GrafanaWebhookPayload = serde_json::from_value(raw.clone())?;
        Ok(payload.into_events(self.name.as_str(), raw))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrafanaWebhookPayload {
    receiver: Option<String>,
    status: Option<String>,
    state: Option<String>,
    #[serde(rename = "orgId")]
    org_id: Option<i64>,
    #[serde(default)]
    alerts: Vec<GrafanaAlertInstance>,
    #[serde(default)]
    group_labels: BTreeMap<String, String>,
    #[serde(default)]
    common_labels: BTreeMap<String, String>,
    #[serde(default)]
    common_annotations: BTreeMap<String, String>,
    #[serde(rename = "externalURL")]
    external_url: Option<String>,
    version: Option<String>,
    group_key: Option<String>,
    truncated_alerts: Option<u64>,
    title: Option<String>,
    message: Option<String>,
}

impl GrafanaWebhookPayload {
    fn into_events(self, integration: &str, raw: Value) -> Vec<AlertEvent> {
        if self.alerts.is_empty() {
            return vec![self.group_event(integration, raw)];
        }

        self.alerts
            .iter()
            .map(|alert| self.alert_event(integration, raw.clone(), alert))
            .collect()
    }

    fn alert_event(
        &self,
        integration: &str,
        raw: Value,
        alert: &GrafanaAlertInstance,
    ) -> AlertEvent {
        let status = self.canonical_status(alert.status.as_deref());
        let labels = self.merged_labels(alert);
        let annotations = self.merged_annotations(alert);
        let title = title_from(&labels, self.title.as_deref());
        let severity = labels
            .get("severity")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let fingerprint = alert
            .fingerprint
            .as_deref()
            .filter(|fingerprint| !fingerprint.trim().is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                stable_fingerprint(
                    integration,
                    "alert",
                    self.group_key.as_deref(),
                    &self.identity_labels_for(alert),
                )
            });

        let mut event = AlertEvent::new(
            integration,
            "grafana",
            status,
            severity,
            title,
            fingerprint,
            raw,
        );
        event.body = body_from(&annotations, self.message.as_deref());
        event.labels = labels;
        event.annotations = annotations;
        if let Some(value_string) = &alert.value_string
            && !value_string.is_empty()
        {
            event
                .annotations
                .insert("grafana_value_string".to_string(), value_string.clone());
        }
        event.starts_at = alert.starts_at.clone();
        event.ends_at = alert.ends_at.clone();
        event.links = self.links_for(alert);
        event
    }

    fn group_event(&self, integration: &str, raw: Value) -> AlertEvent {
        let status = self.canonical_status(None);
        let mut labels = self.group_labels.clone();
        labels.extend(self.common_labels.clone());
        self.add_group_context(&mut labels);
        let annotations = self.common_annotations.clone();
        let title = title_from(&labels, self.title.as_deref());
        let severity = labels
            .get("severity")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let fingerprint = self.group_key.clone().unwrap_or_else(|| {
            stable_fingerprint(integration, "group", None, &self.group_identity_labels())
        });

        let mut event = AlertEvent::new(
            integration,
            "grafana",
            status,
            severity,
            title,
            fingerprint,
            raw,
        );
        event.body = body_from(&annotations, self.message.as_deref());
        event.labels = labels;
        event.annotations = annotations;
        event.links = self.group_links();
        event
    }

    fn canonical_status(&self, instance_status: Option<&str>) -> String {
        if let Some(status) = instance_status
            .filter(|status| !status.trim().is_empty())
            .or_else(|| {
                self.status
                    .as_deref()
                    .filter(|status| !status.trim().is_empty())
            })
        {
            return status.to_string();
        }

        match self.state.as_deref().map(str::trim) {
            Some(state) if state.eq_ignore_ascii_case("alerting") => "firing".to_string(),
            Some(state) if state.eq_ignore_ascii_case("ok") => "resolved".to_string(),
            Some(state) if !state.is_empty() => state.to_string(),
            _ => "unknown".to_string(),
        }
    }

    fn identity_labels_for(&self, alert: &GrafanaAlertInstance) -> BTreeMap<String, String> {
        let mut labels = self.group_labels.clone();
        labels.extend(self.common_labels.clone());
        labels.extend(alert.labels.clone());
        labels.remove("grafana_instance_status");
        labels
    }

    fn group_identity_labels(&self) -> BTreeMap<String, String> {
        let mut labels = self.group_labels.clone();
        labels.extend(self.common_labels.clone());
        if let Some(receiver) = &self.receiver {
            labels.insert("grafana_receiver".to_string(), receiver.clone());
        }
        if let Some(org_id) = self.org_id {
            labels.insert("grafana_org_id".to_string(), org_id.to_string());
        }
        labels
    }

    fn merged_labels(&self, alert: &GrafanaAlertInstance) -> BTreeMap<String, String> {
        let mut labels = self.group_labels.clone();
        labels.extend(self.common_labels.clone());
        labels.extend(alert.labels.clone());
        self.add_group_context(&mut labels);
        if let Some(status) = &alert.status
            && !status.is_empty()
        {
            labels.insert("grafana_instance_status".to_string(), status.clone());
        }
        labels
    }

    fn merged_annotations(&self, alert: &GrafanaAlertInstance) -> BTreeMap<String, String> {
        let mut annotations = self.common_annotations.clone();
        annotations.extend(alert.annotations.clone());
        annotations
    }

    fn add_group_context(&self, labels: &mut BTreeMap<String, String>) {
        if let Some(group_key) = &self.group_key {
            labels.insert("grafana_group_key".to_string(), group_key.clone());
        }
        if let Some(receiver) = &self.receiver {
            labels.insert("grafana_receiver".to_string(), receiver.clone());
        }
        if let Some(org_id) = self.org_id {
            labels.insert("grafana_org_id".to_string(), org_id.to_string());
        }
        if let Some(version) = &self.version {
            labels.insert("grafana_version".to_string(), version.clone());
        }
        if let Some(truncated) = self.truncated_alerts {
            labels.insert(
                "grafana_truncated_alerts".to_string(),
                truncated.to_string(),
            );
        }
    }

    fn links_for(&self, alert: &GrafanaAlertInstance) -> Vec<AlertLink> {
        let mut links = self.group_links();
        push_link(&mut links, "generator", alert.generator_url.as_deref());
        push_link(&mut links, "silence", alert.silence_url.as_deref());
        push_link(&mut links, "dashboard", alert.dashboard_url.as_deref());
        push_link(&mut links, "panel", alert.panel_url.as_deref());
        links
    }

    fn group_links(&self) -> Vec<AlertLink> {
        let mut links = Vec::new();
        push_link(&mut links, "source", self.external_url.as_deref());
        links
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct GrafanaAlertInstance {
    status: Option<String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
    starts_at: Option<String>,
    ends_at: Option<String>,
    #[serde(rename = "generatorURL")]
    generator_url: Option<String>,
    fingerprint: Option<String>,
    #[serde(rename = "silenceURL")]
    silence_url: Option<String>,
    #[serde(rename = "dashboardURL")]
    dashboard_url: Option<String>,
    #[serde(rename = "panelURL")]
    panel_url: Option<String>,
    #[serde(default)]
    values: BTreeMap<String, Value>,
    #[serde(rename = "valueString")]
    value_string: Option<String>,
}

fn title_from(labels: &BTreeMap<String, String>, fallback: Option<&str>) -> String {
    labels
        .get("alertname")
        .or_else(|| labels.get("rule_name"))
        .cloned()
        .or_else(|| {
            fallback
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "Grafana alert".to_string())
}

fn body_from(annotations: &BTreeMap<String, String>, fallback: Option<&str>) -> Option<String> {
    annotations
        .get("summary")
        .or_else(|| annotations.get("description"))
        .cloned()
        .or_else(|| {
            fallback
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
}

fn push_link(links: &mut Vec<AlertLink>, label: &str, url: Option<&str>) {
    let Some(url) = url.filter(|value| !value.is_empty()) else {
        return;
    };
    links.push(AlertLink {
        label: label.to_string(),
        url: url.to_string(),
    });
}

fn stable_fingerprint(
    integration: &str,
    event_kind: &str,
    group_key: Option<&str>,
    labels: &BTreeMap<String, String>,
) -> String {
    let mut digest = Sha256::new();
    update_fingerprint(&mut digest, "grafana-fallback-v1");
    update_fingerprint(&mut digest, integration);
    update_fingerprint(&mut digest, event_kind);
    update_fingerprint(&mut digest, group_key.unwrap_or_default());
    for (key, value) in labels {
        update_fingerprint(&mut digest, key);
        update_fingerprint(&mut digest, value);
    }

    let hex = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("grafana:{hex}")
}

fn update_fingerprint(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

#[derive(Debug, thiserror::Error)]
pub enum GrafanaParseError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_grafana_alert_instances() {
        let integration = GrafanaIntegration::new("grafana");
        let events = integration
            .normalize(
                serde_json::from_str(include_str!("../examples/grafana-webhook.json")).unwrap(),
            )
            .unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].integration, "grafana");
        assert_eq!(events[0].source, "grafana");
        assert_eq!(events[0].status, "firing");
        assert_eq!(events[0].severity, "critical");
        assert_eq!(events[0].title, "HighLatency");
        assert_eq!(events[0].body.as_deref(), Some("Checkout latency is high"));
        assert_eq!(events[0].fingerprint, "grafana-latency-1");
        assert_eq!(events[0].labels["grafana_folder"], "Production");
        assert_eq!(
            events[0].labels["grafana_group_key"],
            "{alertname=\"HighLatency\"}"
        );
        assert_eq!(
            events[0].annotations["runbook_url"],
            "https://runbooks.example.test/latency"
        );
        assert_eq!(events[0].starts_at.as_deref(), Some("2026-08-11T16:00:00Z"));
        assert!(events[0].links.iter().any(|link| link.label == "dashboard"));
        assert!(events[0].links.iter().any(|link| link.label == "panel"));
        assert_eq!(events[1].fingerprint, "grafana-latency-2");
    }

    #[test]
    fn emits_group_event_for_empty_alerts() {
        let integration = GrafanaIntegration::new("grafana");
        let events = integration
            .normalize(serde_json::json!({
                "status": "firing",
                "groupKey": "group-empty",
                "title": "Grafana test notification",
                "message": "test payload",
                "commonLabels": { "severity": "warning" },
                "alerts": []
            }))
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fingerprint, "group-empty");
        assert_eq!(events[0].title, "Grafana test notification");
        assert_eq!(events[0].severity, "warning");
        assert_eq!(events[0].body.as_deref(), Some("test payload"));
    }

    #[test]
    fn fallback_fingerprint_survives_resolution() {
        let integration = GrafanaIntegration::new("grafana");
        let firing = integration
            .normalize(serde_json::json!({
                "status": "firing",
                "groupKey": "{alertname=\"DiskFull\"}",
                "alerts": [{
                    "status": "firing",
                    "fingerprint": "",
                    "labels": {
                        "alertname": "DiskFull",
                        "instance": "db-1"
                    }
                }]
            }))
            .unwrap();
        let resolved = integration
            .normalize(serde_json::json!({
                "status": "resolved",
                "groupKey": "{alertname=\"DiskFull\"}",
                "alerts": [{
                    "status": "resolved",
                    "fingerprint": "",
                    "labels": {
                        "alertname": "DiskFull",
                        "instance": "db-1"
                    }
                }]
            }))
            .unwrap();

        assert_eq!(firing[0].status, "firing");
        assert_eq!(resolved[0].status, "resolved");
        assert_eq!(firing[0].fingerprint, resolved[0].fingerprint);
    }

    #[test]
    fn fallback_fingerprints_survive_alert_reordering() {
        let integration = GrafanaIntegration::new("grafana");
        let first = integration
            .normalize(serde_json::json!({
                "status": "firing",
                "groupKey": "{alertname=\"DiskFull\"}",
                "alerts": [
                    {
                        "status": "firing",
                        "labels": { "alertname": "DiskFull", "instance": "db-1" }
                    },
                    {
                        "status": "firing",
                        "labels": { "alertname": "DiskFull", "instance": "db-2" }
                    }
                ]
            }))
            .unwrap();
        let reordered = integration
            .normalize(serde_json::json!({
                "status": "firing",
                "groupKey": "{alertname=\"DiskFull\"}",
                "alerts": [
                    {
                        "status": "firing",
                        "labels": { "alertname": "DiskFull", "instance": "db-2" }
                    },
                    {
                        "status": "firing",
                        "labels": { "alertname": "DiskFull", "instance": "db-1" }
                    }
                ]
            }))
            .unwrap();

        let fingerprints = |events: &[AlertEvent]| {
            events
                .iter()
                .map(|event| (event.labels["instance"].clone(), event.fingerprint.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(fingerprints(&first), fingerprints(&reordered));
    }

    #[test]
    fn maps_state_only_lifecycle_statuses_and_keeps_group_identity() {
        let integration = GrafanaIntegration::new("grafana");
        let alerting = integration
            .normalize(serde_json::json!({
                "state": "alerting",
                "receiver": "simple-alert-proxy",
                "orgId": 1,
                "commonLabels": { "alertname": "StateOnly" },
                "alerts": []
            }))
            .unwrap();
        let ok = integration
            .normalize(serde_json::json!({
                "state": "ok",
                "receiver": "simple-alert-proxy",
                "orgId": 1,
                "commonLabels": { "alertname": "StateOnly" },
                "alerts": []
            }))
            .unwrap();

        assert_eq!(alerting[0].status, "firing");
        assert_eq!(ok[0].status, "resolved");
        assert_eq!(alerting[0].fingerprint, ok[0].fingerprint);
    }

    #[test]
    fn instance_status_overrides_group_status() {
        let integration = GrafanaIntegration::new("grafana");
        let events = integration
            .normalize(serde_json::json!({
                "status": "firing",
                "alerts": [{
                    "status": "resolved",
                    "fingerprint": "resolved-instance",
                    "labels": { "alertname": "MixedStatus" }
                }]
            }))
            .unwrap();

        assert_eq!(events[0].status, "resolved");
    }
}
