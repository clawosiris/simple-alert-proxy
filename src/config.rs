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

        if let Some(tls) = &self.server.tls {
            tls.validate()?;
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
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub cert_env: Option<String>,
    pub key_env: Option<String>,
}

impl TlsConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        match (self.cert_source()?, self.key_source()?) {
            (TlsSource::Path(_), TlsSource::Path(_)) | (TlsSource::Pem(_), TlsSource::Pem(_)) => {
                Ok(())
            }
            (TlsSource::Path(_), TlsSource::Pem(_)) | (TlsSource::Pem(_), TlsSource::Path(_)) => {
                bail!(
                    "server.tls cert and key must both use file paths or both use environment variables"
                )
            }
        }
    }

    pub fn cert_source(&self) -> anyhow::Result<TlsSource> {
        tls_source("cert", self.cert_path.as_deref(), self.cert_env.as_deref())
    }

    pub fn key_source(&self) -> anyhow::Result<TlsSource> {
        tls_source("key", self.key_path.as_deref(), self.key_env.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsSource {
    Path(String),
    Pem(Vec<u8>),
}

fn tls_source(kind: &str, path: Option<&str>, env_name: Option<&str>) -> anyhow::Result<TlsSource> {
    match (path, env_name) {
        (Some(_), Some(_)) => {
            bail!("server.tls.{kind}_path and server.tls.{kind}_env are mutually exclusive")
        }
        (None, None) => bail!("server.tls.{kind}_path or server.tls.{kind}_env must be set"),
        (Some(path), None) => Ok(TlsSource::Path(resolve_env_reference(path)?)),
        (None, Some(name)) => {
            if name.is_empty() {
                bail!("server.tls.{kind}_env must not be empty");
            }
            let pem = env::var(name)
                .with_context(|| format!("environment variable {name} is not set"))?;
            Ok(TlsSource::Pem(decode_env_pem(&pem).into_bytes()))
        }
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

fn decode_env_pem(value: &str) -> String {
    if value.contains("\\n") && !value.contains('\n') {
        value.replace("\\n", "\n")
    } else {
        value.to_string()
    }
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

    #[test]
    fn decodes_escaped_newlines_in_env_pem() {
        assert_eq!(decode_env_pem("line1\\nline2\\n"), "line1\nline2\n");
    }

    #[test]
    fn rejects_ambiguous_tls_sources() {
        let error = tls_source("cert", Some("/tmp/cert.pem"), Some("CERT_PEM")).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("server.tls.cert_path and server.tls.cert_env are mutually exclusive")
        );
    }

    #[test]
    fn rejects_mixed_tls_source_types() {
        let config = TlsConfig {
            cert_path: Some("/tmp/cert.pem".to_string()),
            key_path: None,
            cert_env: None,
            key_env: Some("PATH".to_string()),
        };

        let error = config.validate().unwrap_err();

        assert!(
            error.to_string().contains(
                "cert and key must both use file paths or both use environment variables"
            )
        );
    }
}
