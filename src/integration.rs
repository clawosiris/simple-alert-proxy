use serde_json::Value;
use std::collections::BTreeMap;

use crate::{
    alert::{AlertEvent, AlertLink},
    config::{BuiltinIntegrationConfig, GenericJsonIntegrationConfig, IntegrationConfig},
    signoz::{self, SigNozAlert},
};

pub trait Integration {
    fn normalize(&self, raw: Value) -> Result<Vec<AlertEvent>, IntegrationError>;
}

#[derive(Debug, Clone)]
pub struct SigNozIntegration {
    name: String,
}

impl SigNozIntegration {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub fn parse_alerts(&self, raw: Value) -> Result<Vec<SigNozAlert>, IntegrationError> {
        Ok(SigNozAlert::from_value_grouped_by_rule_id(raw)?)
    }
}

impl Integration for SigNozIntegration {
    fn normalize(&self, raw: Value) -> Result<Vec<AlertEvent>, IntegrationError> {
        self.parse_alerts(raw)?
            .into_iter()
            .map(|alert| Ok(alert.to_alert_event(self.name.clone())))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct GenericJsonIntegration<'a> {
    name: &'a str,
    config: &'a GenericJsonIntegrationConfig,
}

impl<'a> GenericJsonIntegration<'a> {
    pub fn new(name: &'a str, config: &'a GenericJsonIntegrationConfig) -> Self {
        Self { name, config }
    }
}

impl Integration for GenericJsonIntegration<'_> {
    fn normalize(&self, raw: Value) -> Result<Vec<AlertEvent>, IntegrationError> {
        let status = required_string(&raw, &self.config.status, "status")?;
        let title = required_string(&raw, &self.config.title, "title")?;
        let fingerprint = required_string(&raw, &self.config.fingerprint, "fingerprint")?;
        let severity = optional_string(&raw, self.config.severity.as_deref())
            .unwrap_or_else(|| "unknown".to_string());

        let mut event = AlertEvent::new(
            self.name,
            self.config.source.clone(),
            status,
            severity,
            title,
            fingerprint,
            raw.clone(),
        );

        event.body = optional_string(&raw, self.config.body.as_deref());
        event.labels = mapped_strings(&raw, &self.config.labels);
        event.annotations = mapped_strings(&raw, &self.config.annotations);
        event.starts_at = optional_string(&raw, self.config.starts_at.as_deref());
        event.ends_at = optional_string(&raw, self.config.ends_at.as_deref());
        event.links = self
            .config
            .links
            .iter()
            .filter_map(|(label, path)| {
                optional_string(&raw, Some(path)).map(|url| AlertLink {
                    label: label.clone(),
                    url,
                })
            })
            .collect();

        Ok(vec![event])
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IntegrationError {
    #[error("unknown integration {0}")]
    Unknown(String),
    #[error("invalid SigNoz payload: {0}")]
    SigNoz(#[from] signoz::AlertParseError),
    #[error("missing required field {field} at {path}")]
    MissingRequired { field: &'static str, path: String },
}

pub enum ConfiguredIntegration<'a> {
    Builtin(&'a str, &'a BuiltinIntegrationConfig),
    GenericJson(&'a str, &'a GenericJsonIntegrationConfig),
}

pub fn configured_integration_for_path<'a>(
    integrations: &'a BTreeMap<String, IntegrationConfig>,
    path: &str,
) -> Result<ConfiguredIntegration<'a>, IntegrationError> {
    integrations
        .iter()
        .find_map(|(name, integration)| match integration {
            IntegrationConfig::Builtin(config) if config.path == path => {
                Some(ConfiguredIntegration::Builtin(name.as_str(), config))
            }
            IntegrationConfig::GenericJson(config) if config.path == path => {
                Some(ConfiguredIntegration::GenericJson(name.as_str(), config))
            }
            _ => None,
        })
        .ok_or_else(|| IntegrationError::Unknown(path.to_string()))
}

fn required_string(
    raw: &Value,
    path: &str,
    field: &'static str,
) -> Result<String, IntegrationError> {
    optional_string(raw, Some(path)).ok_or_else(|| IntegrationError::MissingRequired {
        field,
        path: path.to_string(),
    })
}

fn optional_string(raw: &Value, path: Option<&str>) -> Option<String> {
    let path = path?;
    value_at_path(raw, path).and_then(value_to_string)
}

fn mapped_strings(raw: &Value, mappings: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    mappings
        .iter()
        .filter_map(|(name, path)| {
            optional_string(raw, Some(path)).map(|value| (name.clone(), value))
        })
        .collect()
}

fn value_at_path<'a>(raw: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(raw);
    }

    if path.starts_with('/') {
        return raw.pointer(path);
    }

    let pointer = format!("/{}", path.replace('.', "/"));
    raw.pointer(&pointer)
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_generic_json_payload_from_config() {
        let config = GenericJsonIntegrationConfig {
            preset: None,
            path: "/webhooks/openvas".to_string(),
            auth: None,
            source: "openvas".to_string(),
            status: "state".to_string(),
            severity: Some("risk.level".to_string()),
            title: "finding.title".to_string(),
            body: Some("finding.description".to_string()),
            fingerprint: "finding.id".to_string(),
            starts_at: Some("observed_at".to_string()),
            ends_at: None,
            labels: BTreeMap::from([("asset".to_string(), "asset.host".to_string())]),
            annotations: BTreeMap::from([("plugin".to_string(), "finding.plugin".to_string())]),
            links: BTreeMap::from([("source".to_string(), "finding.url".to_string())]),
        };
        let integration = GenericJsonIntegration::new("openvas", &config);

        let events = integration
            .normalize(serde_json::json!({
                "state": "firing",
                "risk": { "level": "high" },
                "finding": {
                    "id": "finding-1",
                    "title": "TLS certificate expired",
                    "description": "Certificate expired yesterday",
                    "plugin": "ssl-cert-check",
                    "url": "https://scanner.example.test/findings/1"
                },
                "asset": { "host": "edge-1" },
                "observed_at": "2026-07-07T10:00:00Z"
            }))
            .unwrap();

        let event = &events[0];
        assert_eq!(event.integration, "openvas");
        assert_eq!(event.source, "openvas");
        assert_eq!(event.status, "firing");
        assert_eq!(event.severity, "high");
        assert_eq!(event.title, "TLS certificate expired");
        assert_eq!(event.fingerprint, "finding-1");
        assert_eq!(event.labels["asset"], "edge-1");
        assert_eq!(event.annotations["plugin"], "ssl-cert-check");
        assert_eq!(
            event.links[0].url,
            "https://scanner.example.test/findings/1"
        );
    }

    #[test]
    fn rejects_generic_json_payload_missing_required_field() {
        let config = GenericJsonIntegrationConfig {
            preset: None,
            path: "/webhooks/openvas".to_string(),
            auth: None,
            source: "openvas".to_string(),
            status: "state".to_string(),
            severity: None,
            title: "title".to_string(),
            body: None,
            fingerprint: "id".to_string(),
            starts_at: None,
            ends_at: None,
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            links: BTreeMap::new(),
        };
        let integration = GenericJsonIntegration::new("openvas", &config);

        let error = integration
            .normalize(serde_json::json!({ "state": "firing", "id": "finding-1" }))
            .unwrap_err();

        assert!(error.to_string().contains("missing required field title"));
    }
}
