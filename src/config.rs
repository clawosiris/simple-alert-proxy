use anyhow::{Context, bail};
use serde::Deserialize;
use std::{collections::BTreeMap, env, fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub integrations: BTreeMap<String, IntegrationConfig>,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub delivery: DeliveryConfig,
    #[serde(default)]
    pub escalation: EscalationConfig,
    #[serde(default)]
    pub alert_grouping: AlertGroupingConfig,
    #[serde(default)]
    pub debug: DebugConfig,
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

        self.storage.validate()?;
        self.delivery.validate()?;
        self.escalation.validate()?;

        if let Some(auth) = &self.server.auth
            && auth.bearer_token.is_empty()
        {
            bail!("server.auth.bearer_token must not be empty");
        }

        if let Some(tls) = &self.server.tls {
            tls.validate()?;
        }

        for (name, integration) in &self.integrations {
            validate_integration_name(name)?;
            match integration {
                IntegrationConfig::GenericJson(config) => {
                    config.validate(name)?;
                }
            }
        }

        if self.alert_grouping.enabled && self.alert_grouping.debounce_millis == 0 {
            bail!("alert_grouping.debounce_millis must be greater than zero when enabled");
        }

        if let Some(default_receiver) = &self.routing.default_receiver {
            self.require_receiver(default_receiver)?;
        }

        for route in &self.routing.routes {
            self.require_receiver(&route.receiver)?;
            if let Some(policy) = &route.escalation_policy {
                self.require_escalation_policy(policy)?;
            }
        }

        for (name, receiver) in &self.receivers {
            match receiver {
                ReceiverConfig::GoogleChat(receiver) if receiver.timeout_secs == 0 => {
                    bail!("receiver {name} timeout_secs must be greater than zero")
                }
                ReceiverConfig::GoogleChat(_) => {}
                ReceiverConfig::GenericWebhook(receiver) if receiver.timeout_secs == 0 => {
                    bail!("receiver {name} timeout_secs must be greater than zero")
                }
                ReceiverConfig::GenericWebhook(_) => {}
                ReceiverConfig::Slack(receiver) if receiver.timeout_secs == 0 => {
                    bail!("receiver {name} timeout_secs must be greater than zero")
                }
                ReceiverConfig::Slack(_) => {}
                ReceiverConfig::Mattermost(receiver) if receiver.timeout_secs == 0 => {
                    bail!("receiver {name} timeout_secs must be greater than zero")
                }
                ReceiverConfig::Mattermost(_) => {}
                ReceiverConfig::Discord(receiver) if receiver.timeout_secs == 0 => {
                    bail!("receiver {name} timeout_secs must be greater than zero")
                }
                ReceiverConfig::Discord(_) => {}
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

    fn require_escalation_policy(&self, name: &str) -> anyhow::Result<()> {
        if self.escalation.policies.contains_key(name) {
            Ok(())
        } else {
            bail!("route references unknown escalation policy {name}")
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
pub struct StorageConfig {
    #[serde(default = "default_storage_type")]
    pub r#type: String,
    #[serde(default = "default_storage_path")]
    pub path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            r#type: default_storage_type(),
            path: default_storage_path(),
        }
    }
}

impl StorageConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.r#type != "sqlite" {
            bail!("storage.type must be sqlite");
        }

        if self.path.is_empty() {
            bail!("storage.path must not be empty");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeliveryConfig {
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_initial_backoff_millis")]
    pub initial_backoff_millis: u64,
    #[serde(default = "default_max_backoff_millis")]
    pub max_backoff_millis: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EscalationConfig {
    #[serde(default)]
    pub policies: BTreeMap<String, EscalationPolicyConfig>,
}

impl EscalationConfig {
    fn validate(&self) -> anyhow::Result<()> {
        for (name, policy) in &self.policies {
            policy.validate(name)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EscalationPolicyConfig {
    pub steps: Vec<EscalationStepConfig>,
}

impl EscalationPolicyConfig {
    fn validate(&self, name: &str) -> anyhow::Result<()> {
        if self.steps.is_empty() {
            bail!("escalation policy {name} must have at least one step");
        }

        for (index, step) in self.steps.iter().enumerate() {
            if step.delay_millis == 0 {
                bail!(
                    "escalation policy {name} step {index} delay_millis must be greater than zero"
                );
            }
            if step.receiver.is_empty() {
                bail!("escalation policy {name} step {index} receiver must not be empty");
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EscalationStepConfig {
    pub receiver: String,
    pub delay_millis: u64,
    #[serde(default = "default_stop_on_ack")]
    pub stop_on_ack: bool,
    #[serde(default = "default_stop_on_resolve")]
    pub stop_on_resolve: bool,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            initial_backoff_millis: default_initial_backoff_millis(),
            max_backoff_millis: default_max_backoff_millis(),
        }
    }
}

impl DeliveryConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.max_attempts == 0 {
            bail!("delivery.max_attempts must be greater than zero");
        }

        if self.initial_backoff_millis == 0 {
            bail!("delivery.initial_backoff_millis must be greater than zero");
        }

        if self.max_backoff_millis < self.initial_backoff_millis {
            bail!(
                "delivery.max_backoff_millis must be greater than or equal to delivery.initial_backoff_millis"
            );
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IntegrationConfig {
    GenericJson(GenericJsonIntegrationConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct GenericJsonIntegrationConfig {
    pub preset: Option<String>,
    pub path: String,
    pub auth: Option<AuthConfig>,
    pub source: String,
    pub status: String,
    pub severity: Option<String>,
    pub title: String,
    pub body: Option<String>,
    pub fingerprint: String,
    pub starts_at: Option<String>,
    pub ends_at: Option<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    #[serde(default)]
    pub links: BTreeMap<String, String>,
}

impl GenericJsonIntegrationConfig {
    fn validate(&self, name: &str) -> anyhow::Result<()> {
        if self.path.is_empty() {
            bail!("integration {name} path must not be empty");
        }

        if let Some(preset) = &self.preset {
            validate_source_preset(name, preset)?;
        }

        if !self.path.starts_with("/webhooks/") {
            bail!("integration {name} path must start with /webhooks/");
        }

        if self.source.is_empty() {
            bail!("integration {name} source must not be empty");
        }

        if self.status.is_empty() {
            bail!("integration {name} status field must not be empty");
        }

        if self.title.is_empty() {
            bail!("integration {name} title field must not be empty");
        }

        if self.fingerprint.is_empty() {
            bail!("integration {name} fingerprint field must not be empty");
        }

        if let Some(auth) = &self.auth
            && auth.bearer_token.is_empty()
        {
            bail!("integration {name} auth.bearer_token must not be empty");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlertGroupingConfig {
    #[serde(default = "default_alert_grouping_enabled")]
    pub enabled: bool,
    #[serde(default = "default_alert_grouping_debounce_millis")]
    pub debounce_millis: u64,
}

impl Default for AlertGroupingConfig {
    fn default() -> Self {
        Self {
            enabled: default_alert_grouping_enabled(),
            debounce_millis: default_alert_grouping_debounce_millis(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DebugConfig {
    #[serde(default)]
    pub log_alerts: bool,
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
    pub escalation_policy: Option<String>,
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
    GenericWebhook(GenericWebhookReceiverConfig),
    Slack(ChatWebhookReceiverConfig),
    Mattermost(ChatWebhookReceiverConfig),
    Discord(ChatWebhookReceiverConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct GoogleChatReceiverConfig {
    pub webhook_url: String,
    #[serde(default = "default_title_template")]
    pub title_template: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GenericWebhookReceiverConfig {
    pub webhook_url: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChatWebhookReceiverConfig {
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

fn default_storage_type() -> String {
    "sqlite".to_string()
}

fn default_storage_path() -> String {
    "simple-alert-proxy.db".to_string()
}

fn default_max_attempts() -> u32 {
    3
}

fn default_initial_backoff_millis() -> u64 {
    250
}

fn default_max_backoff_millis() -> u64 {
    30_000
}

fn default_stop_on_ack() -> bool {
    true
}

fn default_stop_on_resolve() -> bool {
    true
}

fn default_alert_grouping_enabled() -> bool {
    true
}

fn default_alert_grouping_debounce_millis() -> u64 {
    1_000
}

fn default_title_template() -> String {
    "[{{status}}] {{alertname}}".to_string()
}

fn default_timeout_secs() -> u64 {
    10
}

fn validate_integration_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        bail!("integration name must not be empty");
    }

    if !name
        .chars()
        .all(|ch| ch == '-' || ch == '_' || ch.is_ascii_alphanumeric())
    {
        bail!("integration name {name} must contain only letters, numbers, '-' or '_'");
    }

    Ok(())
}

fn validate_source_preset(integration_name: &str, preset: &str) -> anyhow::Result<()> {
    match preset {
        "alertmanager" | "grafana" | "openobserve" | "openvas_scan" => Ok(()),
        _ => bail!("integration {integration_name} preset {preset} is not supported"),
    }
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

    #[test]
    fn validates_generic_json_integration_required_fields() {
        let config = AppConfig {
            server: ServerConfig {
                bind: "127.0.0.1:0".to_string(),
                webhook_path: "/webhooks/signoz".to_string(),
                max_body_bytes: 1024 * 1024,
                auth: None,
                tls: None,
            },
            integrations: BTreeMap::from([(
                "openvas".to_string(),
                IntegrationConfig::GenericJson(GenericJsonIntegrationConfig {
                    preset: None,
                    path: "/webhooks/openvas".to_string(),
                    auth: None,
                    source: "openvas".to_string(),
                    status: "state".to_string(),
                    severity: None,
                    title: "".to_string(),
                    body: None,
                    fingerprint: "id".to_string(),
                    starts_at: None,
                    ends_at: None,
                    labels: BTreeMap::new(),
                    annotations: BTreeMap::new(),
                    links: BTreeMap::new(),
                }),
            )]),
            storage: StorageConfig {
                r#type: "sqlite".to_string(),
                path: ":memory:".to_string(),
            },
            delivery: DeliveryConfig::default(),
            escalation: EscalationConfig::default(),
            alert_grouping: AlertGroupingConfig::default(),
            debug: DebugConfig::default(),
            routing: RoutingConfig::default(),
            receivers: BTreeMap::from([(
                "default".to_string(),
                ReceiverConfig::GoogleChat(GoogleChatReceiverConfig {
                    webhook_url: "https://chat.googleapis.test/default".to_string(),
                    title_template: "[{{status}}] {{alertname}}".to_string(),
                    timeout_secs: 10,
                }),
            )]),
        };

        let error = config.validate().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("integration openvas title field must not be empty")
        );
    }
}
