use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct SigNozAlert {
    pub status: Option<String>,
    pub common_labels: BTreeMap<String, String>,
    pub common_annotations: BTreeMap<String, String>,
    pub alerts: Vec<AlertInstance>,
    pub raw: Value,
}

impl SigNozAlert {
    pub fn from_value(raw: Value) -> Result<Self, AlertParseError> {
        let decoded: SigNozAlertPayload = serde_json::from_value(raw.clone())?;
        Ok(Self {
            status: decoded.status,
            common_labels: decoded.common_labels,
            common_annotations: decoded.common_annotations,
            alerts: decoded.alerts,
            raw,
        })
    }

    pub fn alert_name(&self) -> String {
        self.common_labels
            .get("alertname")
            .or_else(|| self.common_labels.get("alert"))
            .cloned()
            .unwrap_or_else(|| "SigNoz alert".to_string())
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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
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
    pub ends_at: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AlertParseError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
