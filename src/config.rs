use anyhow::{Context, bail};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub receivers: BTreeMap<String, ReceiverConfig>,
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        serde_yaml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.receivers.is_empty() {
            bail!("at least one receiver must be configured");
        }

        if let Some(default_receiver) = &self.routing.default_receiver {
            self.require_receiver(default_receiver)?;
        }

        for route in &self.routing.routes {
            self.require_receiver(&route.receiver)?;
        }

        Ok(())
    }

    fn require_receiver(&self, name: &str) -> anyhow::Result<()> {
        if self.receivers.contains_key(name) {
            Ok(())
        } else {
            bail!("route references unknown receiver {name}")
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_webhook_path")]
    pub webhook_path: String,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RoutingConfig {
    pub default_receiver: Option<String>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    pub name: String,
    pub receiver: String,
    #[serde(default)]
    pub continue_matching: bool,
    #[serde(default)]
    pub matchers: Vec<MatcherConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatcherConfig {
    pub field: String,
    pub equals: Option<String>,
    pub regex: Option<String>,
    pub contains: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReceiverConfig {
    GoogleChat(GoogleChatReceiverConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct GoogleChatReceiverConfig {
    pub webhook_url: String,
    #[serde(default = "default_title_template")]
    pub title_template: String,
}

fn default_bind() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_webhook_path() -> String {
    "/webhooks/signoz".to_string()
}

fn default_title_template() -> String {
    "[{{status}}] {{alertname}}".to_string()
}
