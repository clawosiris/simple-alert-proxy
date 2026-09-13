use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::{
    alert::{AlertEvent, AlertInstance},
    routing::Delivery,
};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NotificationBatch {
    pub group_key: String,
    pub events: Vec<AlertEvent>,
}

impl NotificationBatch {
    pub fn new(group_key: impl Into<String>, events: Vec<AlertEvent>) -> Self {
        Self {
            group_key: group_key.into(),
            events,
        }
    }

    pub fn primary(&self) -> &AlertEvent {
        self.events
            .first()
            .expect("a notification batch always has at least one event")
    }

    pub fn instance_count(&self) -> usize {
        self.events
            .iter()
            .map(|event| event.instances.len().max(1))
            .sum()
    }

    pub fn severity_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for event in &self.events {
            if event.instances.is_empty() {
                *counts.entry(event.severity.clone()).or_default() += 1;
            } else {
                for instance in &event.instances {
                    *counts.entry(instance.severity.clone()).or_default() += 1;
                }
            }
        }
        counts
    }

    pub fn flattened_instances(&self) -> Vec<AlertInstance> {
        self.events
            .iter()
            .flat_map(|event| {
                if event.instances.is_empty() {
                    vec![AlertInstance {
                        status: event.status.clone(),
                        severity: event.severity.clone(),
                        title: event.title.clone(),
                        body: event.body.clone(),
                        labels: event.labels.clone(),
                        annotations: event.annotations.clone(),
                        links: event.links.clone(),
                        starts_at: event.starts_at.clone(),
                        ends_at: event.ends_at.clone(),
                        fingerprint: Some(event.fingerprint.clone()),
                    }]
                } else {
                    event.instances.clone()
                }
            })
            .collect()
    }
}

pub fn batch_key(event: &AlertEvent, delivery: &Delivery) -> Option<String> {
    let grouping = if delivery.group_by.is_empty() {
        vec![(
            "source_hint".to_string(),
            event.notification_group_key.clone()?,
        )]
    } else {
        delivery
            .group_by
            .iter()
            .map(|selector| selector_value(event, selector).map(|value| (selector.clone(), value)))
            .collect::<Option<Vec<_>>>()?
    };

    if grouping.iter().any(|(_, value)| value.is_empty()) {
        return None;
    }

    let identity = (
        &delivery.receiver,
        &delivery.route_name,
        &delivery.owner_team,
        &delivery.escalation_policy,
        &event.group_namespace,
        &event.status,
        grouping,
    );
    let encoded = serde_json::to_vec(&identity)
        .expect("notification batch identity contains only serializable strings");
    let digest = Sha256::digest(encoded);
    Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn validate_group_by_selector(selector: &str) -> bool {
    matches!(
        selector,
        "event_id"
            | "integration"
            | "group_namespace"
            | "source"
            | "status"
            | "severity"
            | "title"
            | "fingerprint"
    ) || selector
        .strip_prefix("label.")
        .is_some_and(|name| !name.is_empty())
        || selector
            .strip_prefix("annotation.")
            .is_some_and(|name| !name.is_empty())
}

fn selector_value(event: &AlertEvent, selector: &str) -> Option<String> {
    match selector {
        "event_id" => Some(event.event_id.clone()),
        "integration" => Some(event.integration.clone()),
        "group_namespace" => Some(event.group_namespace.clone()),
        "source" => Some(event.source.clone()),
        "status" => Some(event.status.clone()),
        "severity" => Some(event.severity.clone()),
        "title" => Some(event.title.clone()),
        "fingerprint" => Some(event.fingerprint.clone()),
        _ => selector
            .strip_prefix("label.")
            .and_then(|name| event.labels.get(name).cloned())
            .or_else(|| {
                selector
                    .strip_prefix("annotation.")
                    .and_then(|name| event.annotations.get(name).cloned())
            }),
    }
    .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivery() -> Delivery {
        Delivery {
            route_name: "ops".to_string(),
            receiver: "chat".to_string(),
            owner_team: Some("platform".to_string()),
            escalation_policy: Some("primary".to_string()),
            group_by: Vec::new(),
        }
    }

    #[test]
    fn source_hint_builds_isolated_batch_key() {
        let mut event = AlertEvent::new(
            "grafana",
            "grafana",
            "firing",
            "critical",
            "Disk full",
            "instance-1",
            serde_json::json!({}),
        );
        event.group_namespace = "integration/grafana/grafana-org/42".to_string();
        event.notification_group_key = Some("group-1".to_string());

        let key = batch_key(&event, &delivery()).unwrap();

        assert_eq!(key.len(), 64);

        let mut other_scope = delivery();
        other_scope.owner_team = Some("security".to_string());
        assert_ne!(
            batch_key(&event, &delivery()),
            batch_key(&event, &other_scope)
        );

        for mutate in [
            |delivery: &mut Delivery| delivery.receiver = "pager".to_string(),
            |delivery: &mut Delivery| delivery.route_name = "secondary".to_string(),
            |delivery: &mut Delivery| delivery.escalation_policy = Some("secondary".to_string()),
        ] {
            let mut isolated = delivery();
            mutate(&mut isolated);
            assert_ne!(batch_key(&event, &delivery()), batch_key(&event, &isolated));
        }

        let mut other_namespace = event.clone();
        other_namespace.group_namespace = "integration/grafana/grafana-org/43".to_string();
        assert_ne!(
            batch_key(&event, &delivery()),
            batch_key(&other_namespace, &delivery())
        );

        let mut resolved = event.clone();
        resolved.status = "resolved".to_string();
        assert_ne!(
            batch_key(&event, &delivery()),
            batch_key(&resolved, &delivery())
        );
    }

    #[test]
    fn route_selectors_override_source_hint() {
        let mut event = AlertEvent::new(
            "generic",
            "generic",
            "firing",
            "warning",
            "High load",
            "instance-1",
            serde_json::json!({}),
        );
        event.notification_group_key = Some("source-group".to_string());
        event
            .labels
            .insert("cluster".to_string(), "prod-a".to_string());
        let mut target_delivery = delivery();
        target_delivery.group_by = vec!["integration".to_string(), "label.cluster".to_string()];

        let key = batch_key(&event, &target_delivery).unwrap();

        let source_key = {
            let mut source_delivery = delivery();
            source_delivery.group_by.clear();
            batch_key(&event, &source_delivery).unwrap()
        };
        assert_ne!(key, source_key);

        target_delivery.group_by = vec!["label.cluster".to_string(), "integration".to_string()];
        assert_ne!(
            Some(key),
            batch_key(&event, &target_delivery),
            "selector names and ordering are part of the batch identity"
        );
    }

    #[test]
    fn missing_route_selector_disables_batching() {
        let event = AlertEvent::new(
            "generic",
            "generic",
            "firing",
            "warning",
            "High load",
            "instance-1",
            serde_json::json!({}),
        );
        let mut delivery = delivery();
        delivery.group_by = vec!["label.cluster".to_string()];

        assert_eq!(batch_key(&event, &delivery), None);
    }
}
