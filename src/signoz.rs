use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::alert::{AlertEvent, AlertLink};

#[derive(Debug, Clone)]
pub struct SigNozAlert {
    pub status: Option<String>,
    pub common_labels: BTreeMap<String, String>,
    pub common_annotations: BTreeMap<String, String>,
    pub group_labels: BTreeMap<String, String>,
    pub group_key: Option<String>,
    pub alerts: Vec<AlertInstance>,
    pub enrichment: AlertEnrichment,
    pub raw: Value,
}

impl SigNozAlert {
    #[cfg(test)]
    pub fn from_value(raw: Value) -> Result<Self, AlertParseError> {
        let decoded: SigNozAlertPayload = serde_json::from_value(raw.clone())?;
        Ok(decoded.into_alert(raw))
    }

    pub fn from_value_grouped_by_rule_id(raw: Value) -> Result<Vec<Self>, AlertParseError> {
        let decoded: SigNozAlertPayload = serde_json::from_value(raw)?;
        decoded.into_rule_id_groups()
    }

    pub fn alert_name(&self) -> String {
        self.enrichment.alert_name.clone()
    }

    pub fn rule_id(&self) -> Option<String> {
        map_value(&self.common_labels, &["ruleId", "rule_id"])
            .or_else(|| map_value(&self.group_labels, &["ruleId", "rule_id"]))
            .or_else(|| map_value(&self.common_annotations, &["ruleId", "rule_id"]))
            .or_else(|| self.group_key.as_deref().and_then(rule_id_from_group_key))
            .or_else(|| {
                map_value(
                    &self.common_labels,
                    &["ruleSource", "source", "source_url", "generatorURL"],
                )
                .and_then(|url| rule_id_from_url(&url))
            })
            .or_else(|| {
                self.enrichment
                    .source_url
                    .as_deref()
                    .and_then(rule_id_from_url)
            })
            .or_else(|| self.alerts.iter().find_map(AlertInstance::rule_id))
    }

    pub fn merged_for_delivery(alerts: &[Self]) -> Result<Self, AlertParseError> {
        let Some((first, _)) = alerts.split_first() else {
            let payload = SigNozAlertPayload::default();
            let raw = serde_json::to_value(&payload)?;
            return Ok(payload.into_alert(raw));
        };

        if alerts.len() == 1 {
            return Ok(first.clone());
        }

        let mut instances = Vec::new();
        for alert in alerts {
            instances.extend(alert.alerts.iter().cloned());
        }

        let mut payload = SigNozAlertPayload {
            status: first.status.clone(),
            common_labels: grouped_common_map(&first.common_labels, &instances, |alert| {
                &alert.labels
            }),
            common_annotations: grouped_common_map(
                &first.common_annotations,
                &instances,
                |alert| &alert.annotations,
            ),
            group_labels: first.group_labels.clone(),
            group_key: first.group_key.clone(),
            alerts: instances,
            external_url: first.enrichment.source_url.clone(),
        };

        if let Some(rule_id) = first.rule_id() {
            payload.common_labels.insert("ruleId".to_string(), rule_id);
        }

        let raw = serde_json::to_value(&payload)?;
        Ok(payload.into_alert(raw))
    }

    pub fn to_alert_event(&self, integration: impl Into<String>) -> AlertEvent {
        let integration = integration.into();
        let fingerprint = self.canonical_fingerprint();
        let mut event = AlertEvent::new(
            integration,
            "signoz",
            self.enrichment.overall_status.clone(),
            self.canonical_severity(),
            self.alert_name(),
            fingerprint,
            self.raw.clone(),
        );

        event.body = self
            .enrichment
            .summary
            .clone()
            .or_else(|| self.enrichment.description.clone());
        event.labels = self.canonical_labels();
        event.annotations = self.canonical_annotations();
        event.starts_at = self
            .alerts
            .iter()
            .filter_map(|alert| alert.starts_at.clone())
            .min();
        event.ends_at = self
            .alerts
            .iter()
            .filter_map(|alert| alert.ends_at.clone())
            .max();

        if let Some(source_url) = &self.enrichment.source_url {
            event.links.push(AlertLink {
                label: "source".to_string(),
                url: source_url.clone(),
            });
        }

        event
    }

    fn canonical_labels(&self) -> BTreeMap<String, String> {
        let mut labels = self.group_labels.clone();
        labels.extend(self.common_labels.clone());
        labels
    }

    fn canonical_annotations(&self) -> BTreeMap<String, String> {
        let mut annotations = self
            .alerts
            .first()
            .map(|alert| alert.annotations.clone())
            .unwrap_or_default();
        annotations.extend(self.common_annotations.clone());
        annotations
    }

    fn canonical_fingerprint(&self) -> String {
        self.rule_id()
            .or_else(|| {
                self.alerts
                    .iter()
                    .find_map(|alert| alert.fingerprint.clone())
            })
            .or_else(|| self.group_key.clone())
            .unwrap_or_else(|| {
                format!(
                    "signoz:{}:{}",
                    self.enrichment.alert_name, self.enrichment.overall_status
                )
            })
    }

    fn canonical_severity(&self) -> String {
        ["critical", "error", "warning", "warn", "info", "unknown"]
            .into_iter()
            .find(|severity| self.enrichment.severity_counts.contains_key(*severity))
            .map(ToOwned::to_owned)
            .or_else(|| self.enrichment.severity_counts.keys().next().cloned())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SigNozAlertPayload {
    status: Option<String>,
    #[serde(default)]
    common_labels: BTreeMap<String, String>,
    #[serde(default)]
    common_annotations: BTreeMap<String, String>,
    #[serde(default)]
    group_labels: BTreeMap<String, String>,
    #[serde(default)]
    group_key: Option<String>,
    #[serde(default)]
    alerts: Vec<AlertInstance>,
    #[serde(default)]
    external_url: Option<String>,
}

impl SigNozAlertPayload {
    fn into_alert(self, raw: Value) -> SigNozAlert {
        let enrichment = AlertEnrichment::from_payload(&self);
        SigNozAlert {
            status: self.status,
            common_labels: self.common_labels,
            common_annotations: self.common_annotations,
            group_labels: self.group_labels,
            group_key: self.group_key,
            alerts: self.alerts,
            enrichment,
            raw,
        }
    }

    fn into_rule_id_groups(self) -> Result<Vec<SigNozAlert>, AlertParseError> {
        if self.alerts.len() <= 1 {
            let raw = serde_json::to_value(&self)?;
            return Ok(vec![self.into_alert(raw)]);
        }

        let mut grouped_alerts: BTreeMap<Option<String>, Vec<AlertInstance>> = BTreeMap::new();
        for alert in &self.alerts {
            grouped_alerts
                .entry(alert.rule_id().or_else(|| self.common_rule_id()))
                .or_default()
                .push(alert.clone());
        }

        if grouped_alerts.len() <= 1 {
            let raw = serde_json::to_value(&self)?;
            return Ok(vec![self.into_alert(raw)]);
        }

        grouped_alerts
            .into_iter()
            .map(|(rule_id, alerts)| {
                let mut payload = self.clone();
                payload.alerts = alerts;
                payload.common_labels =
                    grouped_common_map(&self.common_labels, &payload.alerts, |alert| &alert.labels);
                payload.common_annotations =
                    grouped_common_map(&self.common_annotations, &payload.alerts, |alert| {
                        &alert.annotations
                    });

                if let Some(rule_id) = rule_id {
                    payload.common_labels.insert("ruleId".to_string(), rule_id);
                }

                let raw = serde_json::to_value(&payload)?;
                Ok(payload.into_alert(raw))
            })
            .collect()
    }

    fn common_rule_id(&self) -> Option<String> {
        map_value(&self.common_labels, &["ruleId", "rule_id"])
            .or_else(|| map_value(&self.group_labels, &["ruleId", "rule_id"]))
            .or_else(|| map_value(&self.common_annotations, &["ruleId", "rule_id"]))
            .or_else(|| self.group_key.as_deref().and_then(rule_id_from_group_key))
            .or_else(|| {
                map_value(
                    &self.common_labels,
                    &["ruleSource", "source", "source_url", "generatorURL"],
                )
                .and_then(|url| rule_id_from_url(&url))
            })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertInstance {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    #[serde(default)]
    pub starts_at: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub ends_at: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub generator_url: Option<String>,
}

impl AlertInstance {
    fn rule_id(&self) -> Option<String> {
        map_value(&self.labels, &["ruleId", "rule_id"])
            .or_else(|| map_value(&self.annotations, &["ruleId", "rule_id"]))
            .or_else(|| {
                map_value(
                    &self.labels,
                    &["ruleSource", "source", "source_url", "generatorURL"],
                )
                .and_then(|url| rule_id_from_url(&url))
            })
            .or_else(|| self.generator_url.as_deref().and_then(rule_id_from_url))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertEnrichment {
    pub alert_name: String,
    pub overall_status: String,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub source_url: Option<String>,
    pub severity_counts: BTreeMap<String, usize>,
    pub instances: Vec<EnrichedAlertInstance>,
}

impl AlertEnrichment {
    fn from_payload(payload: &SigNozAlertPayload) -> Self {
        let alert_name = map_value(&payload.common_labels, &["alertname", "alert"])
            .or_else(|| {
                payload
                    .alerts
                    .iter()
                    .find_map(|alert| map_value(&alert.labels, &["alertname", "alert"]))
            })
            .unwrap_or_else(|| "SigNoz alert".to_string());
        let overall_status = payload
            .status
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let summary = map_value(&payload.common_annotations, &["summary"]).or_else(|| {
            payload
                .alerts
                .iter()
                .find_map(|alert| map_value(&alert.annotations, &["summary"]))
        });
        let description = map_value(&payload.common_annotations, &["description"]).or_else(|| {
            payload
                .alerts
                .iter()
                .find_map(|alert| map_value(&alert.annotations, &["description"]))
        });
        let source_url = map_value(
            &payload.common_labels,
            &["ruleSource", "source", "source_url", "generatorURL"],
        )
        .or_else(|| payload.alerts.iter().find_map(AlertInstance::source_url))
        .or_else(|| payload.external_url.clone());

        let instances: Vec<EnrichedAlertInstance> = payload
            .alerts
            .iter()
            .map(|alert| EnrichedAlertInstance::from_alert(payload, alert))
            .collect();
        let mut severity_counts = BTreeMap::new();

        if instances.is_empty() {
            let fallback_severity =
                map_value(&payload.common_labels, &["severity", "threshold.name"])
                    .unwrap_or_else(|| "unknown".to_string());
            severity_counts.insert(fallback_severity, 1);
        } else {
            for instance in &instances {
                *severity_counts
                    .entry(instance.severity.clone())
                    .or_insert(0) += 1;
            }
        }

        Self {
            alert_name,
            overall_status,
            summary,
            description,
            source_url,
            severity_counts,
            instances,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrichedAlertInstance {
    pub status: String,
    pub severity: String,
    pub host: String,
    pub resource: String,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub source_url: Option<String>,
    pub starts_at: Option<String>,
    pub fingerprint: Option<String>,
}

impl EnrichedAlertInstance {
    fn from_alert(payload: &SigNozAlertPayload, alert: &AlertInstance) -> Self {
        let status = alert
            .status
            .clone()
            .or_else(|| payload.status.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let severity = map_value(&alert.labels, &["severity", "threshold.name"])
            .or_else(|| map_value(&payload.common_labels, &["severity", "threshold.name"]))
            .unwrap_or_else(|| "unknown".to_string());
        let host = map_value(
            &alert.labels,
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
        .or_else(|| {
            map_value(
                &payload.common_labels,
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
        })
        .unwrap_or_else(|| "unknown host".to_string());
        let resource = map_value(
            &alert.labels,
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
        .or_else(|| {
            map_value(
                &payload.common_labels,
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
        })
        .unwrap_or_else(|| "general".to_string());
        let summary = map_value(&alert.annotations, &["summary"])
            .or_else(|| map_value(&payload.common_annotations, &["summary"]));
        let description = map_value(&alert.annotations, &["description"])
            .or_else(|| map_value(&payload.common_annotations, &["description"]));

        Self {
            status,
            severity,
            host,
            resource,
            summary,
            description,
            source_url: alert
                .source_url()
                .or_else(|| {
                    map_value(
                        &payload.common_labels,
                        &["ruleSource", "source", "source_url"],
                    )
                })
                .or_else(|| payload.external_url.clone()),
            starts_at: alert.starts_at.clone(),
            fingerprint: alert.fingerprint.clone(),
        }
    }
}

impl AlertInstance {
    fn source_url(&self) -> Option<String> {
        self.generator_url
            .clone()
            .or_else(|| map_value(&self.labels, &["ruleSource", "source", "source_url"]))
    }
}

fn map_value(map: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| map.get(*key).cloned())
}

fn rule_id_from_url(url: &str) -> Option<String> {
    url.split(['?', '&'])
        .skip(1)
        .find_map(|part| part.strip_prefix("ruleId="))
        .and_then(|value| value.split(['&', '#']).next())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn rule_id_from_group_key(group_key: &str) -> Option<String> {
    group_key
        .split('{')
        .skip(1)
        .filter_map(|labels| labels.split('}').next())
        .find_map(|labels| {
            labels.split(',').find_map(|label| {
                let (key, value) = label.trim().split_once('=')?;
                if key.trim_matches('"') == "ruleId" || key.trim_matches('"') == "rule_id" {
                    Some(value.trim().trim_matches('"').to_string())
                } else {
                    None
                }
            })
        })
        .filter(|value| !value.is_empty())
}

fn grouped_common_map<F>(
    original_common: &BTreeMap<String, String>,
    alerts: &[AlertInstance],
    map_for_alert: F,
) -> BTreeMap<String, String>
where
    F: Fn(&AlertInstance) -> &BTreeMap<String, String>,
{
    let Some((first, rest)) = alerts.split_first() else {
        return original_common.clone();
    };

    let mut common = original_common.clone();
    for (key, value) in map_for_alert(first) {
        if rest
            .iter()
            .all(|alert| map_for_alert(alert).get(key) == Some(value))
        {
            common.insert(key.clone(), value.clone());
        }
    }

    common
}

#[derive(Debug, thiserror::Error)]
pub enum AlertParseError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_enrichment_from_issue_fixture() {
        let alert = SigNozAlert::from_value(
            serde_json::from_str(include_str!("../examples/signoz-webhook-disk-space.json"))
                .unwrap(),
        )
        .unwrap();

        assert_eq!(alert.enrichment.alert_name, "Disk Space Low");
        assert_eq!(alert.enrichment.overall_status, "firing");
        assert_eq!(
            alert.enrichment.source_url.as_deref(),
            Some(
                "https://signoz00.het.example.com/alerts/edit?ruleId=019ef5e1-2027-7be3-a458-88b6a8707d8f"
            )
        );
        assert_eq!(alert.enrichment.severity_counts.get("warning"), Some(&2));
        assert_eq!(alert.enrichment.instances.len(), 2);
        assert_eq!(
            alert.enrichment.instances[0].host,
            "host000.het.example.com"
        );
        assert_eq!(alert.enrichment.instances[0].resource, "/");
        assert_eq!(alert.enrichment.instances[1].resource, "/var/cache/fscache");
    }

    #[test]
    fn converts_issue_fixture_to_canonical_alert_event() {
        let alert = SigNozAlert::from_value(
            serde_json::from_str(include_str!("../examples/signoz-webhook-disk-space.json"))
                .unwrap(),
        )
        .unwrap();

        let event = alert.to_alert_event("signoz-prod");

        assert_eq!(event.integration, "signoz-prod");
        assert_eq!(event.source, "signoz");
        assert_eq!(event.status, "firing");
        assert_eq!(event.severity, "warning");
        assert_eq!(event.title, "Disk Space Low");
        assert_eq!(
            event.body.as_deref(),
            Some(
                "This alert is fired when the defined metric (current value: 0.8831764314370117) crosses the threshold (0.8)"
            )
        );
        assert_eq!(event.fingerprint, "019ef5e1-2027-7be3-a458-88b6a8707d8f");
        assert_eq!(
            event.event_id,
            "signoz-prod:019ef5e1-2027-7be3-a458-88b6a8707d8f"
        );
        assert_eq!(
            event.labels.get("alertname").map(String::as_str),
            Some("Disk Space Low")
        );
        assert_eq!(
            event.annotations.get("summary").map(String::as_str),
            Some(
                "This alert is fired when the defined metric (current value: 0.8831764314370117) crosses the threshold (0.8)"
            )
        );
        assert_eq!(event.links.len(), 1);
        assert_eq!(event.links[0].label, "source");
        assert_eq!(
            event.links[0].url,
            "https://signoz00.het.example.com/alerts/edit?ruleId=019ef5e1-2027-7be3-a458-88b6a8707d8f"
        );
        assert_eq!(
            event.starts_at.as_deref(),
            Some("2026-06-23T19:09:27.583939484Z")
        );
        assert!(event.raw_payload.is_object());
    }

    #[test]
    fn extracts_rule_id_from_source_urls() {
        let alert = SigNozAlert::from_value(serde_json::json!({
            "status": "firing",
            "commonLabels": {
                "alertname": "Disk Space Low",
                "ruleSource": "https://signoz.example.test/alerts/edit?ruleId=rule-disk"
            },
            "commonAnnotations": {},
            "alerts": [{
                "status": "firing",
                "labels": {
                    "host.name": "host-a",
                    "severity": "critical"
                },
                "annotations": {},
                "generatorURL": "https://signoz.example.test/alerts/edit?ruleId=rule-disk"
            }]
        }))
        .unwrap();

        assert_eq!(alert.rule_id().as_deref(), Some("rule-disk"));
    }

    #[test]
    fn extracts_rule_id_from_group_labels() {
        let alert = SigNozAlert::from_value(serde_json::json!({
            "status": "firing",
            "commonLabels": {
                "alertname": "Disk Space Low",
                "severity": "critical"
            },
            "groupLabels": {
                "ruleId": "rule-disk"
            },
            "commonAnnotations": {},
            "alerts": [{
                "status": "firing",
                "labels": {
                    "host.name": "host-a",
                    "severity": "critical"
                },
                "annotations": {}
            }]
        }))
        .unwrap();

        assert_eq!(alert.rule_id().as_deref(), Some("rule-disk"));
    }

    #[test]
    fn extracts_rule_id_from_group_key() {
        let alert = SigNozAlert::from_value(serde_json::json!({
            "status": "firing",
            "commonLabels": {
                "alertname": "Disk Space Low",
                "severity": "critical"
            },
            "groupKey": "{__receiver__=\"ops\"}:{ruleId=\"rule-disk\"}",
            "commonAnnotations": {},
            "alerts": [{
                "status": "firing",
                "labels": {
                    "host.name": "host-a",
                    "severity": "critical"
                },
                "annotations": {}
            }]
        }))
        .unwrap();

        assert_eq!(alert.rule_id().as_deref(), Some("rule-disk"));
    }

    #[test]
    fn merges_alerts_for_delivery() {
        let first = SigNozAlert::from_value(serde_json::json!({
            "status": "firing",
            "commonLabels": {
                "alertname": "Disk Space Low",
                "ruleSource": "https://signoz.example.test/alerts/edit?ruleId=rule-disk"
            },
            "commonAnnotations": {},
            "alerts": [{
                "status": "firing",
                "labels": {
                    "host.name": "host-a",
                    "mountpoint": "/",
                    "severity": "warning"
                },
                "annotations": {},
                "generatorURL": "https://signoz.example.test/alerts/edit?ruleId=rule-disk"
            }]
        }))
        .unwrap();
        let second = SigNozAlert::from_value(serde_json::json!({
            "status": "firing",
            "commonLabels": {
                "alertname": "Disk Space Low",
                "ruleSource": "https://signoz.example.test/alerts/edit?ruleId=rule-disk"
            },
            "commonAnnotations": {},
            "alerts": [{
                "status": "firing",
                "labels": {
                    "host.name": "host-b",
                    "mountpoint": "/var",
                    "severity": "warning"
                },
                "annotations": {},
                "generatorURL": "https://signoz.example.test/alerts/edit?ruleId=rule-disk"
            }]
        }))
        .unwrap();

        let merged = SigNozAlert::merged_for_delivery(&[first, second]).unwrap();

        assert_eq!(merged.rule_id().as_deref(), Some("rule-disk"));
        assert_eq!(merged.alert_name(), "Disk Space Low");
        assert_eq!(merged.alerts.len(), 2);
        assert_eq!(merged.enrichment.severity_counts.get("warning"), Some(&2));
    }

    #[test]
    fn splits_mixed_payloads_by_rule_id() {
        let alerts = SigNozAlert::from_value_grouped_by_rule_id(serde_json::json!({
            "status": "firing",
            "commonLabels": {
                "environment": "production"
            },
            "commonAnnotations": {},
            "alerts": [
                {
                    "status": "firing",
                    "labels": {
                        "alertname": "Disk Space Low",
                        "host.name": "host-a",
                        "mountpoint": "/",
                        "ruleId": "rule-disk",
                        "severity": "warning"
                    },
                    "annotations": {}
                },
                {
                    "status": "firing",
                    "labels": {
                        "alertname": "Disk Space Low",
                        "host.name": "host-b",
                        "mountpoint": "/var",
                        "ruleId": "rule-disk",
                        "severity": "warning"
                    },
                    "annotations": {}
                },
                {
                    "status": "firing",
                    "labels": {
                        "alertname": "CPU Saturated",
                        "host.name": "host-a",
                        "ruleId": "rule-cpu",
                        "severity": "critical"
                    },
                    "annotations": {}
                }
            ]
        }))
        .unwrap();

        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].common_labels.get("ruleId").unwrap(), "rule-cpu");
        assert_eq!(alerts[0].alert_name(), "CPU Saturated");
        assert_eq!(alerts[0].alerts.len(), 1);
        assert_eq!(alerts[1].common_labels.get("ruleId").unwrap(), "rule-disk");
        assert_eq!(alerts[1].alert_name(), "Disk Space Low");
        assert_eq!(alerts[1].alerts.len(), 2);
        assert_eq!(alerts[1].enrichment.instances.len(), 2);
    }
}
