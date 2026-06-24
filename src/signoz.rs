use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct SigNozAlert {
    pub status: Option<String>,
    pub common_labels: BTreeMap<String, String>,
    pub common_annotations: BTreeMap<String, String>,
    pub alerts: Vec<AlertInstance>,
    pub enrichment: AlertEnrichment,
    pub raw: Value,
}

impl SigNozAlert {
    pub fn from_value(raw: Value) -> Result<Self, AlertParseError> {
        let decoded: SigNozAlertPayload = serde_json::from_value(raw.clone())?;
        let enrichment = AlertEnrichment::from_payload(&decoded);
        Ok(Self {
            status: decoded.status,
            common_labels: decoded.common_labels,
            common_annotations: decoded.common_annotations,
            alerts: decoded.alerts,
            enrichment,
            raw,
        })
    }

    pub fn alert_name(&self) -> String {
        self.enrichment.alert_name.clone()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigNozAlertPayload {
    status: Option<String>,
    #[serde(default)]
    common_labels: BTreeMap<String, String>,
    #[serde(default)]
    common_annotations: BTreeMap<String, String>,
    #[serde(default)]
    alerts: Vec<AlertInstance>,
    #[serde(default)]
    external_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
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
}
