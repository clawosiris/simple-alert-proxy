use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt::Write};

use crate::alert::AlertEvent;

const SUPPORTED_VERSION: u64 = 1;
const SOURCE: &str = "gvmd";

pub fn normalize(integration: &str, raw: Value) -> Result<Vec<AlertEvent>, GvmdError> {
    let payload = GvmdPayload::parse(&raw)?;
    Ok(vec![payload.into_alert_event(integration, raw)])
}

#[derive(Debug, thiserror::Error)]
pub enum GvmdError {
    #[error("malformed JSON at line {line}, column {column}")]
    MalformedJson { line: usize, column: usize },
    #[error("unsupported Greenbone data version {0}; expected version 1")]
    UnsupportedVersion(u64),
    #[error("{0}")]
    Invalid(String),
}

impl GvmdError {
    pub fn malformed_json(error: serde_json::Error) -> Self {
        Self::MalformedJson {
            line: error.line(),
            column: error.column(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

#[derive(Debug)]
struct GvmdPayload {
    test: bool,
    alert: AlertMetadata,
    event: EventMetadata,
    condition: ConditionMetadata,
    task: TaskMetadata,
    report: ReportMetadata,
    kind: EventKind,
}

#[derive(Debug)]
struct AlertMetadata {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Debug)]
struct EventMetadata {
    name: String,
    description: Option<String>,
}

#[derive(Debug)]
struct ConditionMetadata {
    name: Option<String>,
    description: Option<String>,
}

#[derive(Debug)]
struct TaskMetadata {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Debug)]
struct ReportMetadata {
    id: Option<String>,
    format: Option<String>,
    content: Option<String>,
    content_type: Option<Option<String>>,
    encoding: Option<String>,
    size: Option<u64>,
    truncated: Option<bool>,
}

#[derive(Debug)]
struct SecInfoMetadata {
    kind: Option<String>,
    count: u64,
    list: Option<String>,
}

#[derive(Debug)]
enum EventKind {
    TaskRunStatusChanged { status: String },
    NewSecInfo(SecInfoMetadata),
    UpdatedSecInfo(SecInfoMetadata),
}

impl GvmdPayload {
    fn parse(raw: &Value) -> Result<Self, GvmdError> {
        let root = raw
            .as_object()
            .ok_or_else(|| GvmdError::invalid("payload must be a JSON object"))?;

        let version = required_u64(root, "version", "version")?;
        if version != SUPPORTED_VERSION {
            return Err(GvmdError::UnsupportedVersion(version));
        }
        let test = required_bool(root, "test", "test")?;

        let alert_object = required_object(root, "alert", "alert")?;
        let alert = AlertMetadata {
            id: required_nullable_string(alert_object, "id", "alert.id")?,
            name: required_nullable_string(alert_object, "name", "alert.name")?,
        };
        let method = required_string(alert_object, "method", "alert.method")?;
        if method != "Webhook" {
            return Err(GvmdError::invalid("alert.method must be \"Webhook\""));
        }

        let event_object = required_object(root, "event", "event")?;
        let event_name = required_nullable_string(event_object, "name", "event.name")?
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| GvmdError::invalid("event.name must identify a supported gvmd event"))?;
        let event = EventMetadata {
            name: event_name.clone(),
            description: required_nullable_string(
                event_object,
                "description",
                "event.description",
            )?,
        };

        let condition_object = required_object(root, "condition", "condition")?;
        let condition = ConditionMetadata {
            name: required_nullable_string(condition_object, "name", "condition.name")?,
            description: required_nullable_string(
                condition_object,
                "description",
                "condition.description",
            )?,
        };

        let task_object = required_object(root, "task", "task")?;
        let task = TaskMetadata {
            id: required_nullable_string(task_object, "id", "task.id")?,
            name: required_nullable_string(task_object, "name", "task.name")?,
        };

        let report_object = required_object(root, "report", "report")?;
        let report = ReportMetadata::parse(report_object)?;

        let kind = match event_name.as_str() {
            "Task run status changed" => {
                if root.contains_key("secinfo") {
                    return Err(GvmdError::invalid(
                        "task run-status payload must not contain secinfo",
                    ));
                }
                let status = required_string(event_object, "status", "event.status")?;
                if status.trim().is_empty() {
                    return Err(GvmdError::invalid("event.status must not be empty"));
                }
                EventKind::TaskRunStatusChanged { status }
            }
            "New SecInfo arrived" => {
                EventKind::NewSecInfo(parse_secinfo(root, event_object, &task, &report)?)
            }
            "Updated SecInfo arrived" => {
                EventKind::UpdatedSecInfo(parse_secinfo(root, event_object, &task, &report)?)
            }
            _ => {
                return Err(GvmdError::invalid(
                    "event.name must be one of: Task run status changed, New SecInfo arrived, Updated SecInfo arrived",
                ));
            }
        };

        Ok(Self {
            test,
            alert,
            event,
            condition,
            task,
            report,
            kind,
        })
    }

    fn into_alert_event(self, integration: &str, raw: Value) -> AlertEvent {
        let fingerprint = self.fingerprint();
        let notification_group_key = self.notification_group_key();
        let title = non_empty(self.alert.name.as_deref())
            .unwrap_or(self.event.name.as_str())
            .to_string();
        let body = self.body();
        let mut labels = BTreeMap::from([
            ("gvmd_event_kind".to_string(), self.kind.slug().to_string()),
            ("gvmd_test".to_string(), self.test.to_string()),
        ]);
        let mut annotations = BTreeMap::new();

        insert_non_empty(&mut labels, "gvmd_alert_id", self.alert.id.as_deref());
        insert_non_empty(&mut labels, "gvmd_task_id", self.task.id.as_deref());
        insert_non_empty(&mut labels, "gvmd_report_id", self.report.id.as_deref());
        insert_non_empty(
            &mut annotations,
            "gvmd_alert_name",
            self.alert.name.as_deref(),
        );
        insert_non_empty(
            &mut annotations,
            "gvmd_event_description",
            self.event.description.as_deref(),
        );
        insert_non_empty(
            &mut annotations,
            "gvmd_condition_name",
            self.condition.name.as_deref(),
        );
        insert_non_empty(
            &mut annotations,
            "gvmd_condition_description",
            self.condition.description.as_deref(),
        );
        insert_non_empty(
            &mut annotations,
            "gvmd_task_name",
            self.task.name.as_deref(),
        );
        insert_non_empty(
            &mut annotations,
            "gvmd_report_format",
            self.report.format.as_deref(),
        );
        if let Some(content_type) = self.report.content_type.as_ref().and_then(Option::as_deref) {
            insert_non_empty(
                &mut annotations,
                "gvmd_report_content_type",
                Some(content_type),
            );
        }
        insert_non_empty(
            &mut annotations,
            "gvmd_report_encoding",
            self.report.encoding.as_deref(),
        );
        if let Some(size) = self.report.size {
            annotations.insert("gvmd_report_size".to_string(), size.to_string());
        }
        if let Some(truncated) = self.report.truncated {
            annotations.insert("gvmd_report_truncated".to_string(), truncated.to_string());
        }

        match &self.kind {
            EventKind::TaskRunStatusChanged { status } => {
                labels.insert("gvmd_task_status".to_string(), status.clone());
            }
            EventKind::NewSecInfo(secinfo) | EventKind::UpdatedSecInfo(secinfo) => {
                insert_non_empty(&mut labels, "gvmd_secinfo_type", secinfo.kind.as_deref());
                labels.insert("gvmd_secinfo_count".to_string(), secinfo.count.to_string());
            }
        }

        let mut event = AlertEvent::new(
            integration,
            SOURCE,
            "firing",
            "unknown",
            title,
            fingerprint,
            raw,
        );
        event.body = body;
        event.notification_group_key = Some(notification_group_key);
        event.labels = labels;
        event.annotations = annotations;
        event
    }

    fn body(&self) -> Option<String> {
        let description = non_empty(self.event.description.as_deref());
        let detail = match &self.kind {
            EventKind::TaskRunStatusChanged { status } => description
                .is_none()
                .then(|| format!("Task status changed to '{status}'")),
            EventKind::NewSecInfo(secinfo) | EventKind::UpdatedSecInfo(secinfo) => {
                non_empty(secinfo.list.as_deref()).map(ToOwned::to_owned)
            }
        };

        match (description, detail) {
            (Some(description), Some(detail)) if description != detail => {
                Some(format!("{description}\n\n{detail}"))
            }
            (Some(description), _) => Some(description.to_string()),
            (None, detail) => detail,
        }
    }

    fn fingerprint(&self) -> String {
        let mut parts = self.common_identity_parts();
        match &self.kind {
            EventKind::TaskRunStatusChanged { .. } => {
                parts.push(self.task.id.as_deref());
                parts.push(self.task.name.as_deref());
                parts.push(self.report.id.as_deref());
            }
            EventKind::NewSecInfo(secinfo) | EventKind::UpdatedSecInfo(secinfo) => {
                parts.push(secinfo.kind.as_deref());
            }
        }
        format!("gvmd:{}:{}", self.kind.slug(), stable_digest(&parts))
    }

    fn notification_group_key(&self) -> String {
        let mut parts = self.common_identity_parts();
        match &self.kind {
            EventKind::TaskRunStatusChanged { .. } => {
                parts.push(self.task.id.as_deref());
                parts.push(self.task.name.as_deref());
            }
            EventKind::NewSecInfo(secinfo) | EventKind::UpdatedSecInfo(secinfo) => {
                parts.push(secinfo.kind.as_deref());
            }
        }
        format!("gvmd:{}:{}", self.kind.slug(), stable_digest(&parts))
    }

    fn common_identity_parts(&self) -> Vec<Option<&str>> {
        vec![
            Some(if self.test { "test" } else { "live" }),
            Some(self.kind.slug()),
            self.alert.id.as_deref(),
            self.alert.name.as_deref(),
            self.condition.name.as_deref(),
            self.condition.description.as_deref(),
        ]
    }
}

impl ReportMetadata {
    fn parse(report: &Map<String, Value>) -> Result<Self, GvmdError> {
        let metadata = Self {
            id: required_nullable_string(report, "id", "report.id")?,
            format: required_nullable_string(report, "format", "report.format")?,
            content: required_nullable_string(report, "content", "report.content")?,
            content_type: optional_nullable_string(report, "content_type", "report.content_type")?,
            encoding: optional_string(report, "encoding", "report.encoding")?,
            size: optional_u64(report, "size", "report.size")?,
            truncated: optional_bool(report, "truncated", "report.truncated")?,
        };

        let embedded_fields = [
            metadata.content_type.is_some(),
            metadata.encoding.is_some(),
            metadata.size.is_some(),
        ];
        let embedded_count = embedded_fields
            .into_iter()
            .filter(|present| *present)
            .count();
        if !matches!(embedded_count, 0 | 3) {
            return Err(GvmdError::invalid(
                "report.content_type, report.encoding, and report.size must be supplied together",
            ));
        }
        if metadata.truncated.is_some() && embedded_count != 3 {
            return Err(GvmdError::invalid(
                "report.truncated requires report.content_type, report.encoding, and report.size",
            ));
        }
        if metadata
            .encoding
            .as_deref()
            .is_some_and(|value| value != "base64")
        {
            return Err(GvmdError::invalid("report.encoding must be \"base64\""));
        }
        if metadata.truncated == Some(false) {
            return Err(GvmdError::invalid(
                "report.truncated may only be present when true",
            ));
        }
        if embedded_count == 3 {
            if metadata.format.is_none() {
                return Err(GvmdError::invalid(
                    "report.format must be a string when report metadata is embedded",
                ));
            }
            if metadata.truncated == Some(true) {
                if metadata.content.is_some() {
                    return Err(GvmdError::invalid(
                        "report.content must be null when report.truncated is true",
                    ));
                }
            } else if metadata.content.is_none() {
                return Err(GvmdError::invalid(
                    "report.content must be a string when report metadata is embedded",
                ));
            }
        }

        Ok(metadata)
    }

    fn has_embedding_metadata(&self) -> bool {
        self.content_type.is_some()
            || self.encoding.is_some()
            || self.size.is_some()
            || self.truncated.is_some()
    }
}

impl EventKind {
    fn slug(&self) -> &'static str {
        match self {
            Self::TaskRunStatusChanged { .. } => "task_run_status_changed",
            Self::NewSecInfo(_) => "secinfo_new",
            Self::UpdatedSecInfo(_) => "secinfo_updated",
        }
    }
}

fn parse_secinfo(
    root: &Map<String, Value>,
    event: &Map<String, Value>,
    task: &TaskMetadata,
    report: &ReportMetadata,
) -> Result<SecInfoMetadata, GvmdError> {
    if event.contains_key("status") {
        return Err(GvmdError::invalid(
            "SecInfo payload event must not contain status",
        ));
    }
    if task.id.is_some() || task.name.is_some() {
        return Err(GvmdError::invalid(
            "SecInfo payload task.id and task.name must be null",
        ));
    }
    if report.id.is_some()
        || report.format.is_some()
        || report.content.is_some()
        || report.has_embedding_metadata()
    {
        return Err(GvmdError::invalid(
            "SecInfo payload report fields must be null and report metadata must be absent",
        ));
    }

    let secinfo = required_object(root, "secinfo", "secinfo")?;
    Ok(SecInfoMetadata {
        kind: required_nullable_string(secinfo, "type", "secinfo.type")?,
        count: required_u64(secinfo, "count", "secinfo.count")?,
        list: required_nullable_string(secinfo, "list", "secinfo.list")?,
    })
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Map<String, Value>, GvmdError> {
    object
        .get(key)
        .ok_or_else(|| GvmdError::invalid(format!("missing required field {path}")))?
        .as_object()
        .ok_or_else(|| GvmdError::invalid(format!("field {path} must be an object")))
}

fn required_nullable_string(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<String>, GvmdError> {
    match object.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Null) => Ok(None),
        Some(_) => Err(GvmdError::invalid(format!(
            "field {path} must be a string or null"
        ))),
        None => Err(GvmdError::invalid(format!("missing required field {path}"))),
    }
}

fn required_string(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<String, GvmdError> {
    match object.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(GvmdError::invalid(format!("field {path} must be a string"))),
        None => Err(GvmdError::invalid(format!("missing required field {path}"))),
    }
}

fn required_u64(object: &Map<String, Value>, key: &str, path: &str) -> Result<u64, GvmdError> {
    match object.get(key).and_then(Value::as_u64) {
        Some(value) => Ok(value),
        None if !object.contains_key(key) => {
            Err(GvmdError::invalid(format!("missing required field {path}")))
        }
        None => Err(GvmdError::invalid(format!(
            "field {path} must be a non-negative integer"
        ))),
    }
}

fn required_bool(object: &Map<String, Value>, key: &str, path: &str) -> Result<bool, GvmdError> {
    match object.get(key).and_then(Value::as_bool) {
        Some(value) => Ok(value),
        None if !object.contains_key(key) => {
            Err(GvmdError::invalid(format!("missing required field {path}")))
        }
        None => Err(GvmdError::invalid(format!(
            "field {path} must be a boolean"
        ))),
    }
}

fn optional_nullable_string(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<Option<String>>, GvmdError> {
    match object.get(key) {
        Some(Value::String(value)) => Ok(Some(Some(value.clone()))),
        Some(Value::Null) => Ok(Some(None)),
        Some(_) => Err(GvmdError::invalid(format!(
            "field {path} must be a string or null"
        ))),
        None => Ok(None),
    }
}

fn optional_string(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<String>, GvmdError> {
    match object.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(GvmdError::invalid(format!("field {path} must be a string"))),
        None => Ok(None),
    }
}

fn optional_u64(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<u64>, GvmdError> {
    match object.get(key) {
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            GvmdError::invalid(format!("field {path} must be a non-negative integer"))
        }),
        None => Ok(None),
    }
}

fn optional_bool(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<bool>, GvmdError> {
    match object.get(key) {
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| GvmdError::invalid(format!("field {path} must be a boolean"))),
        None => Ok(None),
    }
}

fn stable_digest(parts: &[Option<&str>]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        match part {
            Some(value) => {
                hasher.update([1]);
                let length = u64::try_from(value.len())
                    .expect("gvmd identity component length must fit in u64");
                hasher.update(length.to_be_bytes());
                hasher.update(value.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn insert_non_empty(map: &mut BTreeMap<String, String>, key: &str, value: Option<&str>) {
    if let Some(value) = non_empty(value) {
        map.insert(key.to_string(), value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(path: &str) -> Value {
        let raw = match path {
            "task" => include_str!("../examples/gvmd/webhook-generic-task.json"),
            "new" => include_str!("../examples/gvmd/webhook-generic-new-secinfo.json"),
            "updated" => {
                include_str!("../examples/gvmd/webhook-generic-updated-secinfo.json")
            }
            "test" => include_str!("../examples/gvmd/webhook-generic-test.json"),
            _ => panic!("unknown fixture"),
        };
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn normalizes_all_upstream_generic_v1_examples() {
        let task = normalize("greenbone", fixture("task")).unwrap().remove(0);
        assert_eq!(task.integration, "greenbone");
        assert_eq!(task.group_namespace, "integration/greenbone");
        assert_eq!(task.source, "gvmd");
        assert_eq!(task.status, "firing");
        assert_eq!(task.severity, "unknown");
        assert_eq!(task.title, "Completed scan");
        assert_eq!(task.body.as_deref(), Some("Task status changed to 'Done'"));
        assert_eq!(task.labels["gvmd_task_status"], "Done");
        assert_eq!(task.labels["gvmd_test"], "false");
        assert_eq!(task.labels["gvmd_event_kind"], "task_run_status_changed");
        assert_eq!(task.raw_payload, fixture("task"));

        let new = normalize("greenbone", fixture("new")).unwrap().remove(0);
        assert_eq!(new.status, "firing");
        assert_eq!(new.labels["gvmd_event_kind"], "secinfo_new");
        assert_eq!(new.labels["gvmd_secinfo_type"], "nvt");
        assert_eq!(new.labels["gvmd_secinfo_count"], "2");
        assert!(new.body.as_deref().unwrap().contains("Example NVT list"));

        let updated = normalize("greenbone", fixture("updated"))
            .unwrap()
            .remove(0);
        assert_eq!(updated.labels["gvmd_event_kind"], "secinfo_updated");
        assert_eq!(updated.labels["gvmd_secinfo_type"], "cve");
        assert_ne!(new.fingerprint, updated.fingerprint);

        let test = normalize("greenbone", fixture("test")).unwrap().remove(0);
        assert_eq!(test.labels["gvmd_test"], "true");
        assert_eq!(test.labels["gvmd_secinfo_type"], "nvt_example");
        assert_ne!(new.fingerprint, test.fingerprint);
        assert_ne!(new.notification_group_key, test.notification_group_key);
    }

    #[test]
    fn fingerprints_are_stable_and_isolate_alert_kind_report_and_test_scope() {
        let raw = fixture("task");
        let first = normalize("greenbone", raw.clone()).unwrap().remove(0);
        let repeated = normalize("greenbone", raw.clone()).unwrap().remove(0);
        assert_eq!(first.fingerprint, repeated.fingerprint);
        assert_eq!(
            first.notification_group_key,
            repeated.notification_group_key
        );

        let mut other_alert = raw.clone();
        other_alert["alert"]["id"] = Value::String("another-alert".to_string());
        let other_alert = normalize("greenbone", other_alert).unwrap().remove(0);
        assert_ne!(first.fingerprint, other_alert.fingerprint);

        let mut other_report = raw.clone();
        other_report["report"]["id"] = Value::String("another-report".to_string());
        let other_report = normalize("greenbone", other_report).unwrap().remove(0);
        assert_ne!(first.fingerprint, other_report.fingerprint);
        assert_eq!(
            first.notification_group_key,
            other_report.notification_group_key
        );

        let mut test = raw;
        test["test"] = Value::Bool(true);
        let test = normalize("greenbone", test).unwrap().remove(0);
        assert_ne!(first.fingerprint, test.fingerprint);
        assert_ne!(first.notification_group_key, test.notification_group_key);

        let new = fixture("new");
        let new_event = normalize("greenbone", new.clone()).unwrap().remove(0);
        let mut updated = new;
        updated["event"]["name"] = Value::String("Updated SecInfo arrived".to_string());
        updated["event"]["description"] = Value::String("Updated SecInfo arrived".to_string());
        let updated_event = normalize("greenbone", updated).unwrap().remove(0);
        assert_ne!(new_event.fingerprint, updated_event.fingerprint);
        assert_ne!(
            new_event.notification_group_key,
            updated_event.notification_group_key
        );
    }

    #[test]
    fn rejects_unsupported_versions_malformed_common_objects_and_unknown_events() {
        let mut unsupported = fixture("task");
        unsupported["version"] = Value::from(2);
        assert!(matches!(
            normalize("greenbone", unsupported),
            Err(GvmdError::UnsupportedVersion(2))
        ));

        let mut malformed = fixture("task");
        malformed["alert"].as_object_mut().unwrap().remove("name");
        assert!(
            normalize("greenbone", malformed)
                .unwrap_err()
                .to_string()
                .contains("missing required field alert.name")
        );

        let mut unknown = fixture("task");
        unknown["event"]["name"] = Value::String("Ticket received".to_string());
        assert!(
            normalize("greenbone", unknown)
                .unwrap_err()
                .to_string()
                .contains("event.name must be one of")
        );
    }

    #[test]
    fn secinfo_requires_no_task_status_or_report_context() {
        let mut with_status = fixture("new");
        with_status["event"]["status"] = Value::String("Done".to_string());
        assert!(
            normalize("greenbone", with_status)
                .unwrap_err()
                .to_string()
                .contains("must not contain status")
        );

        let mut with_task = fixture("new");
        with_task["task"]["id"] = Value::String("task-id".to_string());
        assert!(
            normalize("greenbone", with_task)
                .unwrap_err()
                .to_string()
                .contains("task.id and task.name must be null")
        );

        let mut with_report_metadata = fixture("new");
        with_report_metadata["report"]["content_type"] =
            Value::String("application/pdf".to_string());
        with_report_metadata["report"]["encoding"] = Value::String("base64".to_string());
        with_report_metadata["report"]["size"] = Value::from(0);
        assert!(
            normalize("greenbone", with_report_metadata)
                .unwrap_err()
                .to_string()
                .contains("report.")
        );
    }

    #[test]
    fn validates_and_preserves_safe_embedded_report_metadata() {
        let mut embedded = fixture("task");
        embedded["report"]["format"] = Value::String("PDF".to_string());
        embedded["report"]["content"] = Value::String("cGRm".to_string());
        embedded["report"]["content_type"] = Value::String("application/pdf".to_string());
        embedded["report"]["encoding"] = Value::String("base64".to_string());
        embedded["report"]["size"] = Value::from(3);
        let normalized = normalize("greenbone", embedded).unwrap().remove(0);
        assert_eq!(normalized.annotations["gvmd_report_format"], "PDF");
        assert_eq!(
            normalized.annotations["gvmd_report_content_type"],
            "application/pdf"
        );
        assert_eq!(normalized.annotations["gvmd_report_encoding"], "base64");
        assert_eq!(normalized.annotations["gvmd_report_size"], "3");
        assert!(!normalized.annotations.contains_key("gvmd_report_content"));

        let mut truncated = fixture("task");
        truncated["report"]["format"] = Value::String("PDF".to_string());
        truncated["report"]["content_type"] = Value::String("application/pdf".to_string());
        truncated["report"]["encoding"] = Value::String("base64".to_string());
        truncated["report"]["size"] = Value::from(1_048_577);
        truncated["report"]["truncated"] = Value::Bool(true);
        let normalized = normalize("greenbone", truncated).unwrap().remove(0);
        assert_eq!(normalized.annotations["gvmd_report_truncated"], "true");

        let mut invalid = fixture("task");
        invalid["report"]["encoding"] = Value::String("base64".to_string());
        assert!(
            normalize("greenbone", invalid)
                .unwrap_err()
                .to_string()
                .contains("must be supplied together")
        );
    }
}
