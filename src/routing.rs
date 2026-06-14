use crate::{
    config::{AppConfig, MatcherConfig, RouteConfig},
    signoz::SigNozAlert,
};
use regex::Regex;

#[derive(Debug, Clone)]
pub struct DeliveryPlan {
    pub deliveries: Vec<Delivery>,
}

#[derive(Debug, Clone)]
pub struct Delivery {
    pub route_name: String,
    pub receiver: String,
}

#[derive(Debug)]
pub struct RouteEngine {
    routes: Vec<CompiledRoute>,
    default_receiver: Option<String>,
}

impl RouteEngine {
    pub fn new(config: AppConfig) -> anyhow::Result<Self> {
        let mut routes = Vec::with_capacity(config.routing.routes.len());
        for route in config.routing.routes {
            routes.push(CompiledRoute::new(route)?);
        }

        Ok(Self {
            routes,
            default_receiver: config.routing.default_receiver,
        })
    }

    pub fn plan(&self, alert: &SigNozAlert) -> DeliveryPlan {
        let mut deliveries = Vec::new();

        for route in &self.routes {
            if route.matches(alert) {
                deliveries.push(Delivery {
                    route_name: route.name.clone(),
                    receiver: route.receiver.clone(),
                });

                if !route.continue_matching {
                    return DeliveryPlan { deliveries };
                }
            }
        }

        if deliveries.is_empty()
            && let Some(receiver) = &self.default_receiver
        {
            deliveries.push(Delivery {
                route_name: "default".to_string(),
                receiver: receiver.clone(),
            });
        }

        DeliveryPlan { deliveries }
    }
}

#[derive(Debug)]
struct CompiledRoute {
    name: String,
    receiver: String,
    continue_matching: bool,
    matchers: Vec<CompiledMatcher>,
}

impl CompiledRoute {
    fn new(route: RouteConfig) -> anyhow::Result<Self> {
        let mut matchers = Vec::with_capacity(route.matchers.len());
        for matcher in route.matchers {
            matchers.push(CompiledMatcher::new(matcher)?);
        }

        Ok(Self {
            name: route.name,
            receiver: route.receiver,
            continue_matching: route.continue_matching,
            matchers,
        })
    }

    fn matches(&self, alert: &SigNozAlert) -> bool {
        self.matchers.iter().all(|matcher| matcher.matches(alert))
    }
}

#[derive(Debug)]
struct CompiledMatcher {
    field: String,
    equals: Option<String>,
    contains: Option<String>,
    regex: Option<Regex>,
}

impl CompiledMatcher {
    fn new(matcher: MatcherConfig) -> anyhow::Result<Self> {
        let regex = matcher.regex.map(|raw| Regex::new(&raw)).transpose()?;
        Ok(Self {
            field: matcher.field,
            equals: matcher.equals,
            contains: matcher.contains,
            regex,
        })
    }

    fn matches(&self, alert: &SigNozAlert) -> bool {
        let Some(value) = field_value(alert, &self.field) else {
            return false;
        };

        if let Some(expected) = &self.equals
            && value != *expected
        {
            return false;
        }

        if let Some(needle) = &self.contains
            && !value.contains(needle)
        {
            return false;
        }

        if let Some(regex) = &self.regex
            && !regex.is_match(&value)
        {
            return false;
        }

        true
    }
}

fn field_value(alert: &SigNozAlert, field: &str) -> Option<String> {
    if field == "status" {
        return alert.status.clone();
    }

    if let Some(name) = field.strip_prefix("label.") {
        return alert.common_labels.get(name).cloned();
    }

    if let Some(name) = field.strip_prefix("annotation.") {
        return alert.common_annotations.get(name).cloned();
    }

    if let Some(pointer) = field.strip_prefix("payload.") {
        let pointer = if pointer.starts_with('/') {
            pointer.to_string()
        } else {
            format!("/{pointer}")
        };
        return alert
            .raw
            .pointer(&pointer)
            .and_then(|value| value.as_str().map(ToOwned::to_owned));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DebugConfig, GoogleChatReceiverConfig, ReceiverConfig, RoutingConfig};
    use std::collections::BTreeMap;

    #[test]
    fn routes_by_common_label() {
        let config = AppConfig {
            server: crate::config::ServerConfig {
                bind: "127.0.0.1:0".to_string(),
                webhook_path: "/webhooks/signoz".to_string(),
                max_body_bytes: 1024 * 1024,
                auth: None,
                tls: None,
            },
            debug: DebugConfig { log_alerts: false },
            routing: RoutingConfig {
                default_receiver: Some("default".to_string()),
                routes: vec![RouteConfig {
                    name: "prod-critical".to_string(),
                    receiver: "prod".to_string(),
                    continue_matching: false,
                    matchers: vec![MatcherConfig {
                        field: "label.severity".to_string(),
                        equals: Some("critical".to_string()),
                        regex: None,
                        contains: None,
                    }],
                }],
            },
            receivers: BTreeMap::from([
                (
                    "prod".to_string(),
                    ReceiverConfig::GoogleChat(GoogleChatReceiverConfig {
                        webhook_url: "https://chat.googleapis.test/prod".to_string(),
                        title_template: "[{{status}}] {{alertname}}".to_string(),
                        timeout_secs: 10,
                    }),
                ),
                (
                    "default".to_string(),
                    ReceiverConfig::GoogleChat(GoogleChatReceiverConfig {
                        webhook_url: "https://chat.googleapis.test/default".to_string(),
                        title_template: "[{{status}}] {{alertname}}".to_string(),
                        timeout_secs: 10,
                    }),
                ),
            ]),
        };
        let engine = RouteEngine::new(config).unwrap();
        let alert = SigNozAlert {
            status: Some("firing".to_string()),
            common_labels: BTreeMap::from([("severity".to_string(), "critical".to_string())]),
            common_annotations: BTreeMap::new(),
            alerts: vec![],
            raw: serde_json::json!({}),
        };

        let plan = engine.plan(&alert);

        assert_eq!(plan.deliveries.len(), 1);
        assert_eq!(plan.deliveries[0].receiver, "prod");
    }
}
