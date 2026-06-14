use anyhow::{Context, bail};
use serde::Deserialize;
use std::{collections::BTreeMap, env, fs, path::Path};

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

        if self.server.max_body_bytes == 0 {
            bail!("server.max_body_bytes must be greater than zero");
        }

        if let Some(auth) = &self.server.auth
            && auth.bearer_token.is_empty()
        {
            bail!("server.auth.bearer_token must not be empty");
        }

        if let Some(default_receiver) = &self.routing.default_receiver {
            self.require_receiver(default_receiver)?;
        }

        for route in &self.routing.routes {
            self.require_receiver(&route.receiver)?;
        }

        for (name, receiver) in &self.receivers {
            match receiver {
                ReceiverConfig::GoogleChat(receiver) if receiver.timeout_secs == 0 => {
                    bail!("receiver {name} timeout_secs must be greater than zero")
                }
                ReceiverConfig::GoogleChat(_) => {}
            }
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
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    pub auth: Option<AuthConfig>,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    pub bearer_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl TlsConfig {
    pub fn resolved_cert_path(&self) -> anyhow::Result<String> {
        resolve_env_reference(&self.cert_path)
    }

    pub fn resolved_key_path(&self) -> anyhow::Result<String> {
        resolve_env_reference(&self.key_path)
    }
}

fn resolve_env_reference(value: &str) -> anyhow::Result<String> {
    if let Some(name) = value
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        return env::var(name).with_context(|| format!("environment variable {name} is not set"));
    }

    if let Some(name) = value.strip_prefix('$')
        && !name.is_empty()
        && name
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return env::var(name).with_context(|| format!("environment variable {name} is not set"));
    }

    Ok(value.to_string())
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
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_bind() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_webhook_path() -> String {
    "/webhooks/signoz".to_string()
}

fn default_max_body_bytes() -> usize {
    1024 * 1024
}

fn default_title_template() -> String {
    "[{{status}}] {{alertname}}".to_string()
}

fn default_timeout_secs() -> u64 {
    10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_tls_path_from_env_reference() {
        let expected = env::var("PATH").unwrap();

        assert_eq!(resolve_env_reference("$PATH").unwrap(), expected);
    }

    #[test]
    fn leaves_literal_tls_path_unchanged() {
        assert_eq!(
            resolve_env_reference("/etc/simple-alert-proxy/tls.crt").unwrap(),
            "/etc/simple-alert-proxy/tls.crt"
        );
    }
}
