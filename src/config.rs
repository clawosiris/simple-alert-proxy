use anyhow::{Context, bail};
use serde::Deserialize;
use std::{collections::BTreeMap, env, fs, net::SocketAddr, path::Path};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub management: ManagementConfig,
    #[serde(default)]
    pub integrations: BTreeMap<String, IntegrationConfig>,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub delivery: DeliveryConfig,
    #[serde(default)]
    pub escalation: EscalationConfig,
    #[serde(default)]
    pub schedules: ScheduleConfig,
    #[serde(default)]
    pub intelligence: IntelligenceConfig,
    #[serde(default, alias = "alert_grouping")]
    pub notification_batching: NotificationBatchingConfig,
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
        self.server.limits.validate()?;

        self.storage.validate()?;
        self.delivery.validate()?;
        self.schedules.validate()?;
        self.escalation.validate()?;
        for (policy_name, policy) in &self.escalation.policies {
            for (index, step) in policy.steps.iter().enumerate() {
                if let Some(receiver) = step.receiver_target() {
                    self.require_receiver(receiver).with_context(|| {
                        format!(
                            "escalation policy {policy_name} step {index} references unknown receiver"
                        )
                    })?;
                }
                if let Some(schedule) = &step.schedule {
                    self.require_schedule(schedule).with_context(|| {
                        format!(
                            "escalation policy {policy_name} step {index} references unknown on-call schedule"
                        )
                    })?;
                }
            }
        }
        self.intelligence.validate()?;

        if let Some(auth) = &self.server.auth
            && auth.bearer_token.is_empty()
        {
            bail!("server.auth.bearer_token must not be empty");
        }

        self.management.validate()?;
        self.validate_management_exposure()?;

        if let Some(tls) = &self.server.tls {
            tls.validate()?;
        }

        for (name, integration) in &self.integrations {
            validate_integration_name(name)?;
            match integration {
                IntegrationConfig::Builtin(config) => {
                    config.validate(name)?;
                }
                IntegrationConfig::GenericJson(config) => {
                    config.validate(name)?;
                }
                IntegrationConfig::CloudEvents(config) => {
                    config.validate(name)?;
                }
            }
        }
        self.validate_integration_paths()?;

        if self.notification_batching.enabled && self.notification_batching.group_wait_millis == 0 {
            bail!("notification_batching.group_wait_millis must be greater than zero when enabled");
        }
        if self.notification_batching.enabled && self.notification_batching.max_events == 0 {
            bail!("notification_batching.max_events must be greater than zero when enabled");
        }
        if self.notification_batching.enabled && self.notification_batching.max_payload_bytes == 0 {
            bail!("notification_batching.max_payload_bytes must be greater than zero when enabled");
        }

        if let Some(default_receiver) = &self.routing.default_receiver {
            self.require_receiver(default_receiver)?;
        }

        for route in &self.routing.routes {
            self.require_receiver(&route.receiver)?;
            for selector in &route.group_by {
                if !crate::notification::validate_group_by_selector(selector) {
                    bail!(
                        "route {} has invalid notification group_by selector {selector}",
                        route.name
                    );
                }
            }
            if let Some(policy) = &route.escalation_policy {
                self.require_escalation_policy(policy)?;
            }
        }

        for (name, schedule) in &self.schedules.on_call {
            for (index, entry) in schedule.entries.iter().enumerate() {
                if let Some(receiver) = &entry.receiver {
                    self.require_receiver(receiver).with_context(|| {
                        format!("on-call schedule {name} entry {index} references unknown receiver")
                    })?;
                }
            }
        }

        for (name, receiver) in &self.receivers {
            receiver.validate_template(name)?;
            match receiver {
                ReceiverConfig::GoogleChat(receiver) if receiver.timeout_secs == 0 => {
                    bail!("receiver {name} timeout_secs must be greater than zero")
                }
                ReceiverConfig::GoogleChat(_) => {}
                ReceiverConfig::GenericWebhook(receiver) if receiver.timeout_secs == 0 => {
                    bail!("receiver {name} timeout_secs must be greater than zero")
                }
                ReceiverConfig::GenericWebhook(_) => {}
                ReceiverConfig::CloudEventsWebhook(receiver) => {
                    receiver.validate().with_context(|| {
                        format!("receiver {name} cloudevents_webhook config is invalid")
                    })?
                }
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
                ReceiverConfig::Matrix(receiver) => receiver
                    .validate()
                    .with_context(|| format!("receiver {name} matrix config is invalid"))?,
            }
        }

        Ok(())
    }

    pub fn management_auth(&self) -> Option<&AuthConfig> {
        self.management.auth.as_ref().or(self.server.auth.as_ref())
    }

    pub fn management_allows_unauthenticated(&self) -> bool {
        self.management.allow_unauthenticated
    }

    pub fn management_local_users_enabled(&self) -> bool {
        self.management.local_users
    }

    pub fn management_secure_cookies(&self) -> bool {
        self.management
            .secure_cookies
            .unwrap_or(self.server.tls.is_some())
    }

    fn validate_management_exposure(&self) -> anyhow::Result<()> {
        if self.management_auth().is_some()
            || self.management.allow_unauthenticated
            || self.management.local_users
        {
            return Ok(());
        }

        let bind = self
            .server
            .bind
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid bind address {}", self.server.bind))?;
        if bind.ip().is_loopback() {
            return Ok(());
        }

        bail!(
            "management auth is required when server.bind is not loopback; set management.auth.bearer_token or management.allow_unauthenticated: true"
        )
    }

    fn validate_integration_paths(&self) -> anyhow::Result<()> {
        let mut paths = BTreeMap::new();
        for (name, integration) in &self.integrations {
            let path = integration.path();
            if let Some(previous) = paths.insert(path, name) {
                bail!("integration {name} path {path} duplicates integration {previous}");
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

    fn require_schedule(&self, name: &str) -> anyhow::Result<()> {
        if self.schedules.on_call.contains_key(name) {
            Ok(())
        } else {
            bail!("escalation step references unknown on-call schedule {name}")
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
    #[serde(default)]
    pub limits: ServerLimitsConfig,
    pub auth: Option<AuthConfig>,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerLimitsConfig {
    #[serde(default = "default_webhook_concurrency")]
    pub webhook_concurrency: usize,
    #[serde(default = "default_management_concurrency")]
    pub management_concurrency: usize,
}

impl Default for ServerLimitsConfig {
    fn default() -> Self {
        Self {
            webhook_concurrency: default_webhook_concurrency(),
            management_concurrency: default_management_concurrency(),
        }
    }
}

impl ServerLimitsConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.webhook_concurrency == 0 {
            bail!("server.limits.webhook_concurrency must be greater than zero");
        }

        if self.management_concurrency == 0 {
            bail!("server.limits.management_concurrency must be greater than zero");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    pub bearer_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagementConfig {
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub allow_unauthenticated: bool,
    #[serde(default = "default_management_local_users")]
    pub local_users: bool,
    #[serde(default = "default_bootstrap_admin_password_env")]
    pub bootstrap_admin_password_env: String,
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,
    #[serde(default)]
    pub secure_cookies: Option<bool>,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            auth: None,
            allow_unauthenticated: false,
            local_users: default_management_local_users(),
            bootstrap_admin_password_env: default_bootstrap_admin_password_env(),
            session_ttl_secs: default_session_ttl_secs(),
            secure_cookies: None,
        }
    }
}

impl ManagementConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if let Some(auth) = &self.auth
            && auth.bearer_token.is_empty()
        {
            bail!("management.auth.bearer_token must not be empty");
        }

        if self.local_users && self.bootstrap_admin_password_env.trim().is_empty() {
            bail!("management.bootstrap_admin_password_env must not be empty");
        }

        if self.local_users && self.session_ttl_secs == 0 {
            bail!("management.session_ttl_secs must be greater than zero");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_storage_type")]
    pub r#type: String,
    #[serde(default = "default_storage_path")]
    pub path: String,
    #[serde(default = "default_retention_days")]
    pub retention_days: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            r#type: default_storage_type(),
            path: default_storage_path(),
            retention_days: default_retention_days(),
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

        if self.retention_days == 0 {
            bail!("storage.retention_days must be greater than zero");
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
            match step.target_count() {
                0 => {
                    bail!(
                        "escalation policy {name} step {index} must set receiver, schedule, webhook, user, or team"
                    );
                }
                1 => {}
                _ => {
                    bail!(
                        "escalation policy {name} step {index} must set exactly one of receiver, schedule, webhook, user, or team"
                    );
                }
            }

            if let Some(receiver) = &step.receiver
                && receiver.is_empty()
            {
                bail!("escalation policy {name} step {index} receiver must not be empty");
            }
            if let Some(schedule) = &step.schedule
                && schedule.is_empty()
            {
                bail!("escalation policy {name} step {index} schedule must not be empty");
            }
            if let Some(webhook) = &step.webhook
                && webhook.is_empty()
            {
                bail!("escalation policy {name} step {index} webhook must not be empty");
            }
            if let Some(user) = &step.user
                && user.is_empty()
            {
                bail!("escalation policy {name} step {index} user must not be empty");
            }
            if let Some(team) = &step.team
                && team.is_empty()
            {
                bail!("escalation policy {name} step {index} team must not be empty");
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EscalationStepConfig {
    pub receiver: Option<String>,
    pub schedule: Option<String>,
    pub webhook: Option<String>,
    pub user: Option<String>,
    pub team: Option<String>,
    pub delay_millis: u64,
    #[serde(default = "default_stop_on_ack")]
    pub stop_on_ack: bool,
    #[serde(default = "default_stop_on_resolve")]
    pub stop_on_resolve: bool,
}

impl EscalationStepConfig {
    fn target_count(&self) -> usize {
        [
            self.receiver.as_ref(),
            self.schedule.as_ref(),
            self.webhook.as_ref(),
            self.user.as_ref(),
            self.team.as_ref(),
        ]
        .into_iter()
        .filter(|target| target.is_some())
        .count()
    }

    fn receiver_target(&self) -> Option<&str> {
        self.receiver.as_deref().or(self.webhook.as_deref())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScheduleConfig {
    #[serde(default)]
    pub on_call: BTreeMap<String, OnCallScheduleConfig>,
}

impl ScheduleConfig {
    fn validate(&self) -> anyhow::Result<()> {
        for (name, schedule) in &self.on_call {
            schedule.validate(name)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnCallScheduleConfig {
    pub entries: Vec<OnCallScheduleEntryConfig>,
}

impl OnCallScheduleConfig {
    fn validate(&self, name: &str) -> anyhow::Result<()> {
        if self.entries.is_empty() {
            bail!("on-call schedule {name} must have at least one entry");
        }

        for (index, entry) in self.entries.iter().enumerate() {
            match (&entry.receiver, &entry.user, &entry.team) {
                (Some(receiver), None, None) if receiver.is_empty() => {
                    bail!("on-call schedule {name} entry {index} receiver must not be empty");
                }
                (None, Some(user), None) if user.is_empty() => {
                    bail!("on-call schedule {name} entry {index} user must not be empty");
                }
                (None, None, Some(team)) if team.is_empty() => {
                    bail!("on-call schedule {name} entry {index} team must not be empty");
                }
                (Some(_), None, None) | (None, Some(_), None) | (None, None, Some(_)) => {}
                _ => {
                    bail!(
                        "on-call schedule {name} entry {index} must set exactly one of receiver, user, or team"
                    );
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnCallScheduleEntryConfig {
    pub receiver: Option<String>,
    pub user: Option<String>,
    pub team: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct IntelligenceConfig {
    #[serde(default)]
    pub enabled: bool,
    pub provider: Option<String>,
    #[serde(default)]
    pub allow_lifecycle_mutation: bool,
}

impl IntelligenceConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.enabled
            && self
                .provider
                .as_deref()
                .is_none_or(|provider| provider.is_empty())
        {
            bail!("intelligence.provider must be set when intelligence.enabled is true");
        }

        if self.allow_lifecycle_mutation && !self.enabled {
            bail!("intelligence.allow_lifecycle_mutation requires intelligence.enabled");
        }

        Ok(())
    }
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
    Builtin(BuiltinIntegrationConfig),
    GenericJson(Box<GenericJsonIntegrationConfig>),
    CloudEvents(Box<CloudEventsIntegrationConfig>),
}

impl IntegrationConfig {
    pub fn path(&self) -> &str {
        match self {
            IntegrationConfig::Builtin(config) => &config.path,
            IntegrationConfig::GenericJson(config) => &config.path,
            IntegrationConfig::CloudEvents(config) => &config.path,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BuiltinIntegrationConfig {
    pub preset: String,
    pub path: String,
    pub auth: Option<AuthConfig>,
}

impl BuiltinIntegrationConfig {
    fn validate(&self, name: &str) -> anyhow::Result<()> {
        if self.path.is_empty() {
            bail!("integration {name} path must not be empty");
        }

        validate_builtin_preset(name, &self.preset)?;

        if !self.path.starts_with("/webhooks/") {
            bail!("integration {name} path must start with /webhooks/");
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
pub struct GenericJsonIntegrationConfig {
    pub preset: Option<String>,
    pub path: String,
    pub auth: Option<AuthConfig>,
    pub source: String,
    #[serde(flatten)]
    pub mapping: AlertMappingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CloudEventsIntegrationConfig {
    pub path: String,
    pub auth: Option<AuthConfig>,
    pub mapping: AlertMappingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlertMappingConfig {
    pub status: String,
    pub severity: Option<String>,
    pub title: String,
    pub body: Option<String>,
    pub fingerprint: String,
    pub notification_group_key: Option<String>,
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
        validate_integration_path_and_auth(name, &self.path, self.auth.as_ref())?;

        if let Some(preset) = &self.preset {
            validate_source_preset(name, preset)?;
        }

        if self.source.is_empty() {
            bail!("integration {name} source must not be empty");
        }

        self.mapping.validate(name)
    }
}

impl CloudEventsIntegrationConfig {
    fn validate(&self, name: &str) -> anyhow::Result<()> {
        validate_integration_path_and_auth(name, &self.path, self.auth.as_ref())?;
        self.mapping.validate(name)
    }
}

impl AlertMappingConfig {
    fn validate(&self, name: &str) -> anyhow::Result<()> {
        if self.status.is_empty() {
            bail!("integration {name} status field must not be empty");
        }

        if self.title.is_empty() {
            bail!("integration {name} title field must not be empty");
        }

        if self.fingerprint.is_empty() {
            bail!("integration {name} fingerprint field must not be empty");
        }

        Ok(())
    }
}

fn validate_integration_path_and_auth(
    name: &str,
    path: &str,
    auth: Option<&AuthConfig>,
) -> anyhow::Result<()> {
    if path.is_empty() {
        bail!("integration {name} path must not be empty");
    }

    if !path.starts_with("/webhooks/") {
        bail!("integration {name} path must start with /webhooks/");
    }

    if let Some(auth) = auth
        && auth.bearer_token.is_empty()
    {
        bail!("integration {name} auth.bearer_token must not be empty");
    }

    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotificationBatchingConfig {
    #[serde(default = "default_notification_batching_enabled")]
    pub enabled: bool,
    #[serde(
        default = "default_notification_batch_group_wait_millis",
        alias = "debounce_millis"
    )]
    pub group_wait_millis: u64,
    #[serde(default = "default_notification_batch_max_events")]
    pub max_events: usize,
    #[serde(default = "default_notification_batch_max_payload_bytes")]
    pub max_payload_bytes: usize,
}

impl Default for NotificationBatchingConfig {
    fn default() -> Self {
        Self {
            enabled: default_notification_batching_enabled(),
            group_wait_millis: default_notification_batch_group_wait_millis(),
            max_events: default_notification_batch_max_events(),
            max_payload_bytes: default_notification_batch_max_payload_bytes(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DebugConfig {
    #[serde(default)]
    pub log_alerts: bool,
    #[serde(default)]
    pub log_full_payloads: bool,
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
    #[serde(default, alias = "team")]
    pub owner_team: Option<String>,
    pub escalation_policy: Option<String>,
    #[serde(default)]
    pub continue_matching: bool,
    #[serde(default)]
    pub group_by: Vec<String>,
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
    #[serde(rename = "cloudevents_webhook")]
    CloudEventsWebhook(CloudEventsWebhookReceiverConfig),
    Slack(ChatWebhookReceiverConfig),
    Mattermost(ChatWebhookReceiverConfig),
    Discord(ChatWebhookReceiverConfig),
    Matrix(MatrixReceiverConfig),
}

impl ReceiverConfig {
    pub fn owner_team(&self) -> Option<&str> {
        match self {
            Self::GoogleChat(receiver) => receiver.owner_team.as_deref(),
            Self::GenericWebhook(receiver) => receiver.owner_team.as_deref(),
            Self::CloudEventsWebhook(receiver) => receiver.owner_team.as_deref(),
            Self::Slack(receiver) | Self::Mattermost(receiver) | Self::Discord(receiver) => {
                receiver.owner_team.as_deref()
            }
            Self::Matrix(receiver) => receiver.owner_team.as_deref(),
        }
    }

    pub fn notification_template(&self) -> Option<&NotificationTemplateConfig> {
        match self {
            Self::GoogleChat(receiver) => receiver.template.as_ref(),
            Self::GenericWebhook(receiver) => receiver.template.as_ref(),
            Self::CloudEventsWebhook(receiver) => receiver.template.as_ref(),
            Self::Slack(receiver) | Self::Mattermost(receiver) | Self::Discord(receiver) => {
                receiver.template.as_ref()
            }
            Self::Matrix(receiver) => receiver.template.as_ref(),
        }
    }

    pub fn legacy_title_template(&self) -> Option<&str> {
        match self {
            Self::GoogleChat(receiver) => receiver.title_template.as_deref(),
            Self::Slack(receiver) | Self::Mattermost(receiver) | Self::Discord(receiver) => {
                receiver.title_template.as_deref()
            }
            Self::Matrix(receiver) => receiver.title_template.as_deref(),
            Self::GenericWebhook(_) | Self::CloudEventsWebhook(_) => None,
        }
    }

    fn validate_template(&self, name: &str) -> anyhow::Result<()> {
        let template = self.notification_template();
        if template.is_some() && self.legacy_title_template().is_some() {
            bail!("receiver {name} cannot combine title_template with the template block");
        }
        if let Some(template) = template {
            let payload_only = match self {
                Self::GenericWebhook(_) => Some("generic_webhook"),
                Self::CloudEventsWebhook(_) => Some("cloudevents_webhook"),
                _ => None,
            };
            template.validate(name, payload_only)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationTemplateConfig {
    pub title: Option<String>,
    pub body: Option<String>,
    pub payload: Option<String>,
}

impl NotificationTemplateConfig {
    fn validate(
        &self,
        receiver_name: &str,
        payload_only_receiver_type: Option<&str>,
    ) -> anyhow::Result<()> {
        if self.title.is_none() && self.body.is_none() && self.payload.is_none() {
            bail!("receiver {receiver_name} template block must configure title, body, or payload");
        }
        if self.payload.is_some() && (self.title.is_some() || self.body.is_some()) {
            bail!(
                "receiver {receiver_name} template.payload is mutually exclusive with template.title and template.body"
            );
        }
        if let Some(receiver_type) = payload_only_receiver_type
            && (self.title.is_some() || self.body.is_some())
        {
            bail!(
                "receiver {receiver_name} {receiver_type} templates support template.payload only"
            );
        }
        for (field, source) in [
            ("title", self.title.as_deref()),
            ("body", self.body.as_deref()),
            ("payload", self.payload.as_deref()),
        ] {
            if source
                .is_some_and(|source| source.len() > crate::template::MAX_TEMPLATE_SOURCE_BYTES)
            {
                bail!(
                    "receiver {receiver_name} template.{field} exceeds the {} byte source limit",
                    crate::template::MAX_TEMPLATE_SOURCE_BYTES
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GoogleChatReceiverConfig {
    pub webhook_url: String,
    #[serde(default, alias = "team")]
    pub owner_team: Option<String>,
    #[serde(default)]
    pub title_template: Option<String>,
    #[serde(default)]
    pub template: Option<NotificationTemplateConfig>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GenericWebhookReceiverConfig {
    pub webhook_url: String,
    #[serde(default, alias = "team")]
    pub owner_team: Option<String>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub template: Option<NotificationTemplateConfig>,
}

pub const DEFAULT_CLOUDEVENTS_ALERT_TYPE: &str = "io.github.clawosiris.simple-alert-proxy.alert.v1";
pub const DEFAULT_CLOUDEVENTS_BATCH_TYPE: &str =
    "io.github.clawosiris.simple-alert-proxy.notification-batch.v1";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudEventsWebhookMode {
    #[default]
    Structured,
    Binary,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CloudEventsWebhookReceiverConfig {
    pub webhook_url: String,
    pub source: String,
    #[serde(default)]
    pub mode: CloudEventsWebhookMode,
    #[serde(default = "default_cloudevents_alert_type")]
    pub event_type: String,
    #[serde(default = "default_cloudevents_batch_type")]
    pub batch_type: String,
    #[serde(default, alias = "team")]
    pub owner_team: Option<String>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub template: Option<NotificationTemplateConfig>,
}

impl CloudEventsWebhookReceiverConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        let webhook_url = self.webhook_url.trim();
        let url =
            reqwest::Url::parse(webhook_url).context("webhook_url must be a valid absolute URL")?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            bail!("webhook_url must use http or https and include a host");
        }
        if self.timeout_secs == 0 {
            bail!("timeout_secs must be greater than zero");
        }
        validate_uri_reference(&self.source).context("source must be a valid URI-reference")?;
        validate_cloudevents_type(&self.event_type, "event_type")?;
        validate_cloudevents_type(&self.batch_type, "batch_type")?;
        Ok(())
    }
}

fn validate_uri_reference(value: &str) -> anyhow::Result<()> {
    if value.is_empty() || value.trim() != value || !value.is_ascii() {
        bail!("URI-reference must be non-empty ASCII without surrounding whitespace");
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b':'
                    | b'/'
                    | b'?'
                    | b'#'
                    | b'['
                    | b']'
                    | b'@'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
            )
    }) {
        bail!("URI-reference contains an invalid character");
    }
    for (index, byte) in value.bytes().enumerate() {
        if byte == b'%'
            && value
                .as_bytes()
                .get(index + 1..index + 3)
                .is_none_or(|escape| !escape.iter().all(u8::is_ascii_hexdigit))
        {
            bail!("URI-reference contains an invalid percent escape");
        }
    }
    let base = reqwest::Url::parse("https://simple-alert-proxy.invalid/")
        .expect("static URI-reference validation base is valid");
    reqwest::Url::options()
        .base_url(Some(&base))
        .parse(value)
        .context("URI-reference could not be parsed")?;
    Ok(())
}

fn validate_cloudevents_type(value: &str, field: &str) -> anyhow::Result<()> {
    if value.trim().is_empty() {
        bail!("{field} must not be empty");
    }
    reqwest::header::HeaderValue::from_str(value)
        .with_context(|| format!("{field} must be representable in an HTTP header"))?;
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChatWebhookReceiverConfig {
    pub webhook_url: String,
    #[serde(default, alias = "team")]
    pub owner_team: Option<String>,
    #[serde(default)]
    pub title_template: Option<String>,
    #[serde(default)]
    pub template: Option<NotificationTemplateConfig>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatrixReceiverConfig {
    pub homeserver_url: String,
    pub room_id: String,
    pub access_token: Option<String>,
    pub access_token_env: Option<String>,
    #[serde(default, alias = "team")]
    pub owner_team: Option<String>,
    #[serde(default)]
    pub title_template: Option<String>,
    #[serde(default)]
    pub template: Option<NotificationTemplateConfig>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

impl MatrixReceiverConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        let homeserver_url = self.homeserver_url.trim();
        if homeserver_url.is_empty() {
            bail!("homeserver_url must not be empty");
        }
        let homeserver = reqwest::Url::parse(homeserver_url)
            .context("homeserver_url must be a valid absolute URL")?;
        if !matches!(homeserver.scheme(), "http" | "https") || homeserver.host_str().is_none() {
            bail!("homeserver_url must use http or https and include a host");
        }
        if !homeserver.username().is_empty() || homeserver.password().is_some() {
            bail!("homeserver_url must not include credentials");
        }
        if homeserver.query().is_some() || homeserver.fragment().is_some() {
            bail!("homeserver_url must not include a query or fragment");
        }

        let room_id = self.room_id.trim();
        if room_id.is_empty() {
            bail!("room_id must not be empty");
        }
        let Some((localpart, server_name)) = room_id
            .strip_prefix('!')
            .and_then(|room_id| room_id.split_once(':'))
        else {
            bail!("room_id must use the canonical !room:server form");
        };
        if localpart.is_empty() || server_name.is_empty() {
            bail!("room_id must use the canonical !room:server form");
        }
        if self.timeout_secs == 0 {
            bail!("timeout_secs must be greater than zero");
        }
        match (&self.access_token, &self.access_token_env) {
            (Some(_), Some(_)) => bail!("access_token and access_token_env are mutually exclusive"),
            (Some(token), None) if token.trim().is_empty() => {
                bail!("access_token must not be empty")
            }
            (None, Some(env_name)) if env_name.trim().is_empty() => {
                bail!("access_token_env must not be empty")
            }
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (None, None) => bail!("access_token or access_token_env must be set"),
        }
    }

    pub fn resolved_access_token(&self) -> anyhow::Result<String> {
        if let Some(token) = &self.access_token {
            return Ok(token.clone());
        }

        let env_name = self
            .access_token_env
            .as_deref()
            .context("access_token or access_token_env must be set")?;
        let token = env::var(env_name)
            .with_context(|| format!("environment variable {env_name} is not set"))?;
        if token.trim().is_empty() {
            bail!("environment variable {env_name} must not be empty");
        }
        Ok(token)
    }
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

fn default_webhook_concurrency() -> usize {
    64
}

fn default_management_concurrency() -> usize {
    16
}

fn default_management_local_users() -> bool {
    true
}

fn default_bootstrap_admin_password_env() -> String {
    "SIMPLE_ALERT_PROXY_BOOTSTRAP_ADMIN_PASSWORD".to_string()
}

fn default_session_ttl_secs() -> u64 {
    8 * 60 * 60
}

fn default_storage_type() -> String {
    "sqlite".to_string()
}

fn default_storage_path() -> String {
    "simple-alert-proxy.db".to_string()
}

fn default_retention_days() -> u64 {
    90
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

fn default_notification_batching_enabled() -> bool {
    true
}

fn default_notification_batch_group_wait_millis() -> u64 {
    1_000
}

fn default_notification_batch_max_events() -> usize {
    100
}

fn default_notification_batch_max_payload_bytes() -> usize {
    256 * 1024
}

pub fn default_title_template() -> &'static str {
    "[{{status}}] {{alertname}}"
}

fn default_timeout_secs() -> u64 {
    10
}

fn default_cloudevents_alert_type() -> String {
    DEFAULT_CLOUDEVENTS_ALERT_TYPE.to_string()
}

fn default_cloudevents_batch_type() -> String {
    DEFAULT_CLOUDEVENTS_BATCH_TYPE.to_string()
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

fn validate_builtin_preset(integration_name: &str, preset: &str) -> anyhow::Result<()> {
    match preset {
        "signoz" | "alertmanager" | "grafana" => Ok(()),
        _ => bail!("integration {integration_name} builtin preset {preset} is not supported"),
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
                limits: ServerLimitsConfig::default(),
                auth: None,
                tls: None,
            },
            management: ManagementConfig::default(),
            integrations: BTreeMap::from([(
                "openvas".to_string(),
                IntegrationConfig::GenericJson(Box::new(GenericJsonIntegrationConfig {
                    preset: None,
                    path: "/webhooks/openvas".to_string(),
                    auth: None,
                    source: "openvas".to_string(),
                    mapping: AlertMappingConfig {
                        status: "state".to_string(),
                        severity: None,
                        title: "".to_string(),
                        body: None,
                        fingerprint: "id".to_string(),
                        notification_group_key: None,
                        starts_at: None,
                        ends_at: None,
                        labels: BTreeMap::new(),
                        annotations: BTreeMap::new(),
                        links: BTreeMap::new(),
                    },
                })),
            )]),
            storage: StorageConfig {
                r#type: "sqlite".to_string(),
                path: ":memory:".to_string(),
                retention_days: 90,
            },
            delivery: DeliveryConfig::default(),
            escalation: EscalationConfig::default(),
            schedules: ScheduleConfig::default(),
            intelligence: IntelligenceConfig::default(),
            notification_batching: NotificationBatchingConfig::default(),
            debug: DebugConfig::default(),
            routing: RoutingConfig::default(),
            receivers: BTreeMap::from([(
                "default".to_string(),
                ReceiverConfig::GoogleChat(GoogleChatReceiverConfig {
                    webhook_url: "https://chat.googleapis.test/default".to_string(),
                    owner_team: None,
                    title_template: Some("[{{status}}] {{alertname}}".to_string()),
                    template: None,
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

    #[test]
    fn validates_cloudevents_integration_path_auth_and_mapping() {
        let mut config = minimal_valid_config();
        config.integrations.insert(
            "platform-events".to_string(),
            IntegrationConfig::CloudEvents(Box::new(CloudEventsIntegrationConfig {
                path: "/webhooks/cloudevents/platform".to_string(),
                auth: None,
                mapping: AlertMappingConfig {
                    status: "data.status".to_string(),
                    severity: Some("data.severity".to_string()),
                    title: "data.title".to_string(),
                    body: None,
                    fingerprint: "subject".to_string(),
                    notification_group_key: None,
                    starts_at: Some("time".to_string()),
                    ends_at: None,
                    labels: BTreeMap::new(),
                    annotations: BTreeMap::new(),
                    links: BTreeMap::new(),
                },
            })),
        );

        config.validate().unwrap();

        let IntegrationConfig::CloudEvents(integration) = config
            .integrations
            .get_mut("platform-events")
            .expect("CloudEvents integration")
        else {
            panic!("expected CloudEvents integration")
        };
        integration.mapping.fingerprint.clear();
        let error = config.validate().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("integration platform-events fingerprint field must not be empty")
        );
    }

    #[test]
    fn cloudevents_webhook_receiver_defaults_and_validation() {
        let receiver: ReceiverConfig = serde_yaml::from_str(
            r#"
type: cloudevents_webhook
webhook_url: https://events.example.test/alerts
source: urn:simple-alert-proxy:production
"#,
        )
        .unwrap();
        let ReceiverConfig::CloudEventsWebhook(receiver) = receiver else {
            panic!("expected CloudEvents webhook receiver")
        };

        assert_eq!(receiver.mode, CloudEventsWebhookMode::Structured);
        assert_eq!(receiver.event_type, DEFAULT_CLOUDEVENTS_ALERT_TYPE);
        assert_eq!(receiver.batch_type, DEFAULT_CLOUDEVENTS_BATCH_TYPE);
        assert_eq!(receiver.timeout_secs, 10);
        receiver.validate().unwrap();
    }

    #[test]
    fn validates_cloudevents_webhook_receiver_fields() {
        let valid = CloudEventsWebhookReceiverConfig {
            webhook_url: "https://events.example.test/alerts".to_string(),
            source: "../simple-alert-proxy/production?tenant=platform#alerts".to_string(),
            mode: CloudEventsWebhookMode::Binary,
            event_type: "io.example.alert.v1".to_string(),
            batch_type: "io.example.batch.v1".to_string(),
            owner_team: None,
            timeout_secs: 10,
            template: None,
        };
        valid.validate().unwrap();

        for (receiver, expected) in [
            (
                CloudEventsWebhookReceiverConfig {
                    webhook_url: "events.example.test".to_string(),
                    ..valid.clone()
                },
                "valid absolute URL",
            ),
            (
                CloudEventsWebhookReceiverConfig {
                    source: "urn:test bad".to_string(),
                    ..valid.clone()
                },
                "valid URI-reference",
            ),
            (
                CloudEventsWebhookReceiverConfig {
                    source: "urn:test:%zz".to_string(),
                    ..valid.clone()
                },
                "valid URI-reference",
            ),
            (
                CloudEventsWebhookReceiverConfig {
                    event_type: " ".to_string(),
                    ..valid.clone()
                },
                "event_type must not be empty",
            ),
            (
                CloudEventsWebhookReceiverConfig {
                    batch_type: "invalid\nvalue".to_string(),
                    ..valid.clone()
                },
                "batch_type must be representable",
            ),
            (
                CloudEventsWebhookReceiverConfig {
                    timeout_secs: 0,
                    ..valid.clone()
                },
                "timeout_secs must be greater than zero",
            ),
        ] {
            let error = receiver.validate().unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn rejects_unknown_cloudevents_webhook_mode_and_non_payload_template() {
        let error = serde_yaml::from_str::<ReceiverConfig>(
            r#"
type: cloudevents_webhook
webhook_url: https://events.example.test/alerts
source: urn:simple-alert-proxy:test
mode: envelope
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown variant"));

        let receiver = ReceiverConfig::CloudEventsWebhook(CloudEventsWebhookReceiverConfig {
            webhook_url: "https://events.example.test/alerts".to_string(),
            source: "urn:simple-alert-proxy:test".to_string(),
            mode: CloudEventsWebhookMode::Structured,
            event_type: DEFAULT_CLOUDEVENTS_ALERT_TYPE.to_string(),
            batch_type: DEFAULT_CLOUDEVENTS_BATCH_TYPE.to_string(),
            owner_team: None,
            timeout_secs: 10,
            template: Some(NotificationTemplateConfig {
                title: Some("{{ alert.title }}".to_string()),
                ..Default::default()
            }),
        });
        let error = receiver.validate_template("event-bus").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cloudevents_webhook templates support template.payload only")
        );
    }

    #[test]
    fn validates_matrix_receiver_required_fields() {
        let receiver = MatrixReceiverConfig {
            homeserver_url: "https://matrix.example.test".to_string(),
            room_id: "!ops:example.test".to_string(),
            access_token: None,
            access_token_env: Some("MATRIX_TOKEN".to_string()),
            owner_team: None,
            title_template: Some("[{{status}}] {{title}}".to_string()),
            template: None,
            timeout_secs: 10,
        };

        receiver.validate().unwrap();
    }

    #[test]
    fn rejects_matrix_receiver_without_token_source() {
        let receiver = MatrixReceiverConfig {
            homeserver_url: "https://matrix.example.test".to_string(),
            room_id: "!ops:example.test".to_string(),
            access_token: None,
            access_token_env: None,
            owner_team: None,
            title_template: Some("[{{status}}] {{title}}".to_string()),
            template: None,
            timeout_secs: 10,
        };

        let error = receiver.validate().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("access_token or access_token_env must be set")
        );
    }

    #[test]
    fn rejects_matrix_receiver_ambiguous_token_sources() {
        let receiver = MatrixReceiverConfig {
            homeserver_url: "https://matrix.example.test".to_string(),
            room_id: "!ops:example.test".to_string(),
            access_token: Some("inline".to_string()),
            access_token_env: Some("MATRIX_TOKEN".to_string()),
            owner_team: None,
            title_template: Some("[{{status}}] {{title}}".to_string()),
            template: None,
            timeout_secs: 10,
        };

        let error = receiver.validate().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("access_token and access_token_env are mutually exclusive")
        );
    }

    #[test]
    fn rejects_matrix_receiver_with_invalid_homeserver_url() {
        let receiver = MatrixReceiverConfig {
            homeserver_url: "matrix.example.test?token=secret".to_string(),
            room_id: "!ops:example.test".to_string(),
            access_token: Some("inline".to_string()),
            access_token_env: None,
            owner_team: None,
            title_template: Some("[{{status}}] {{title}}".to_string()),
            template: None,
            timeout_secs: 10,
        };

        let error = receiver.validate().unwrap_err();

        assert!(error.to_string().contains("valid absolute URL"));
    }

    #[test]
    fn rejects_matrix_receiver_with_room_alias() {
        let receiver = MatrixReceiverConfig {
            homeserver_url: "https://matrix.example.test".to_string(),
            room_id: "#ops:example.test".to_string(),
            access_token: Some("inline".to_string()),
            access_token_env: None,
            owner_team: None,
            title_template: Some("[{{status}}] {{title}}".to_string()),
            template: None,
            timeout_secs: 10,
        };

        let error = receiver.validate().unwrap_err();

        assert!(error.to_string().contains("canonical !room:server form"));
    }

    #[test]
    fn rejects_zero_webhook_concurrency_limit() {
        let limits = ServerLimitsConfig {
            webhook_concurrency: 0,
            ..Default::default()
        };

        let error = limits.validate().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("server.limits.webhook_concurrency must be greater than zero")
        );
    }

    #[test]
    fn rejects_zero_management_concurrency_limit() {
        let limits = ServerLimitsConfig {
            management_concurrency: 0,
            ..Default::default()
        };

        let error = limits.validate().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("server.limits.management_concurrency must be greater than zero")
        );
    }

    #[test]
    fn defaults_storage_retention_to_ninety_days() {
        assert_eq!(StorageConfig::default().retention_days, 90);
    }

    #[test]
    fn rejects_zero_storage_retention() {
        let config = StorageConfig {
            retention_days: 0,
            ..Default::default()
        };

        let error = config.validate().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("storage.retention_days must be greater than zero")
        );
    }

    #[test]
    fn escalation_step_can_target_on_call_schedule() {
        let mut config = minimal_valid_config();
        config.schedules.on_call.insert(
            "primary".to_string(),
            OnCallScheduleConfig {
                entries: vec![OnCallScheduleEntryConfig {
                    receiver: Some("default".to_string()),
                    user: None,
                    team: None,
                }],
            },
        );
        config.escalation.policies.insert(
            "page-primary".to_string(),
            EscalationPolicyConfig {
                steps: vec![EscalationStepConfig {
                    receiver: None,
                    schedule: Some("primary".to_string()),
                    webhook: None,
                    user: None,
                    team: None,
                    delay_millis: 1_000,
                    stop_on_ack: true,
                    stop_on_resolve: true,
                }],
            },
        );

        config.validate().unwrap();
    }

    #[test]
    fn rejects_missing_on_call_schedule_reference() {
        let mut config = minimal_valid_config();
        config.escalation.policies.insert(
            "page-primary".to_string(),
            EscalationPolicyConfig {
                steps: vec![EscalationStepConfig {
                    receiver: None,
                    schedule: Some("missing".to_string()),
                    webhook: None,
                    user: None,
                    team: None,
                    delay_millis: 1_000,
                    stop_on_ack: true,
                    stop_on_resolve: true,
                }],
            },
        );

        let error = config.validate().unwrap_err();

        assert!(
            error.to_string().contains(
                "escalation policy page-primary step 0 references unknown on-call schedule"
            )
        );
    }

    #[test]
    fn rejects_escalation_steps_with_multiple_targets() {
        let mut config = minimal_valid_config();
        config.escalation.policies.insert(
            "page-primary".to_string(),
            EscalationPolicyConfig {
                steps: vec![EscalationStepConfig {
                    receiver: Some("default".to_string()),
                    schedule: None,
                    webhook: None,
                    user: Some("casey".to_string()),
                    team: None,
                    delay_millis: 1_000,
                    stop_on_ack: true,
                    stop_on_resolve: true,
                }],
            },
        );

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains(
            "escalation policy page-primary step 0 must set exactly one of receiver, schedule, webhook, user, or team"
        ));
    }

    #[test]
    fn rejects_schedule_entries_without_exactly_one_target() {
        let mut config = minimal_valid_config();
        config.schedules.on_call.insert(
            "primary".to_string(),
            OnCallScheduleConfig {
                entries: vec![OnCallScheduleEntryConfig {
                    receiver: Some("default".to_string()),
                    user: Some("casey".to_string()),
                    team: None,
                }],
            },
        );

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains(
            "on-call schedule primary entry 0 must set exactly one of receiver, user, or team"
        ));
    }

    #[test]
    fn exposed_bind_requires_management_auth() {
        let mut config = minimal_valid_config();
        config.server.bind = "0.0.0.0:8080".to_string();
        config.server.auth = None;
        config.management.local_users = false;

        let error = config.validate().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("management auth is required when server.bind is not loopback")
        );
    }

    #[test]
    fn exposed_bind_allows_local_user_management_auth() {
        let mut config = minimal_valid_config();
        config.server.bind = "0.0.0.0:8080".to_string();
        config.server.auth = None;

        config.validate().unwrap();
    }

    #[test]
    fn exposed_bind_allows_explicit_unauthenticated_management_escape_hatch() {
        let mut config = minimal_valid_config();
        config.server.bind = "0.0.0.0:8080".to_string();
        config.server.auth = None;
        config.management.allow_unauthenticated = true;

        config.validate().unwrap();
    }

    #[test]
    fn management_escape_hatch_overrides_server_auth_fallback() {
        let mut config = minimal_valid_config();
        config.management.allow_unauthenticated = true;

        assert!(config.server.auth.is_some());
        assert!(config.management_allows_unauthenticated());
    }

    #[test]
    fn accepts_legacy_notification_batching_names() {
        let current = include_str!("../examples/config.yaml");
        let legacy = current
            .replace("notification_batching:", "alert_grouping:")
            .replace("group_wait_millis:", "debounce_millis:");

        let config: AppConfig = serde_yaml::from_str(&legacy).unwrap();

        assert!(config.notification_batching.enabled);
        assert_eq!(config.notification_batching.group_wait_millis, 1_000);
    }

    #[test]
    fn rejects_invalid_notification_group_selector() {
        let mut config = minimal_valid_config();
        config.routing.routes.push(RouteConfig {
            name: "invalid-grouping".to_string(),
            receiver: "default".to_string(),
            owner_team: None,
            escalation_policy: None,
            continue_matching: false,
            group_by: vec!["raw_payload.secret".to_string()],
            matchers: Vec::new(),
        });

        let error = config.validate().unwrap_err();

        assert!(
            error
                .to_string()
                .contains("invalid notification group_by selector")
        );
    }

    #[test]
    fn rejects_zero_notification_batching_bounds_when_enabled() {
        for (batching, expected) in [
            (
                NotificationBatchingConfig {
                    enabled: true,
                    group_wait_millis: 0,
                    ..NotificationBatchingConfig::default()
                },
                "notification_batching.group_wait_millis",
            ),
            (
                NotificationBatchingConfig {
                    enabled: true,
                    max_events: 0,
                    ..NotificationBatchingConfig::default()
                },
                "notification_batching.max_events",
            ),
            (
                NotificationBatchingConfig {
                    enabled: true,
                    max_payload_bytes: 0,
                    ..NotificationBatchingConfig::default()
                },
                "notification_batching.max_payload_bytes",
            ),
        ] {
            let mut config = minimal_valid_config();
            config.notification_batching = batching;

            let error = config.validate().unwrap_err();

            assert!(error.to_string().contains(expected));
        }
    }

    #[test]
    fn rejects_ambiguous_and_invalid_receiver_template_configuration() {
        let cases = [
            (
                NotificationTemplateConfig {
                    title: Some("{{ alert.title }}".to_string()),
                    body: None,
                    payload: Some("{}".to_string()),
                },
                Some("legacy".to_string()),
                "cannot combine title_template",
            ),
            (
                NotificationTemplateConfig {
                    title: Some("{{ alert.title }}".to_string()),
                    body: None,
                    payload: None,
                },
                None,
                "generic_webhook templates support template.payload only",
            ),
            (
                NotificationTemplateConfig {
                    title: Some("{{ alert.title }}".to_string()),
                    body: None,
                    payload: Some("{}".to_string()),
                },
                None,
                "template.payload is mutually exclusive",
            ),
            (
                NotificationTemplateConfig::default(),
                None,
                "must configure title, body, or payload",
            ),
        ];

        for (template, legacy_title, expected) in cases {
            let mut config = minimal_valid_config();
            config.receivers.insert(
                "templated".to_string(),
                if expected.contains("generic_webhook") {
                    ReceiverConfig::GenericWebhook(GenericWebhookReceiverConfig {
                        webhook_url: "https://example.test/hook".to_string(),
                        owner_team: None,
                        timeout_secs: 10,
                        template: Some(template),
                    })
                } else {
                    ReceiverConfig::GoogleChat(GoogleChatReceiverConfig {
                        webhook_url: "https://example.test/hook".to_string(),
                        owner_team: None,
                        title_template: legacy_title,
                        template: Some(template),
                        timeout_secs: 10,
                    })
                },
            );

            let error = config.validate().unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn rejects_template_sources_over_the_internal_limit() {
        let mut config = minimal_valid_config();
        config.receivers.insert(
            "templated".to_string(),
            ReceiverConfig::GenericWebhook(GenericWebhookReceiverConfig {
                webhook_url: "https://example.test/hook".to_string(),
                owner_team: None,
                timeout_secs: 10,
                template: Some(NotificationTemplateConfig {
                    payload: Some("x".repeat(crate::template::MAX_TEMPLATE_SOURCE_BYTES + 1)),
                    ..Default::default()
                }),
            }),
        );

        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("source limit"));
    }

    #[test]
    fn loopback_bind_allows_local_management_without_auth() {
        let mut config = minimal_valid_config();
        config.server.auth = None;

        config.validate().unwrap();
    }

    fn minimal_valid_config() -> AppConfig {
        AppConfig {
            server: ServerConfig {
                bind: "127.0.0.1:8080".to_string(),
                webhook_path: "/webhooks/signoz".to_string(),
                max_body_bytes: 1024 * 1024,
                auth: Some(AuthConfig {
                    bearer_token: "inbound-token".to_string(),
                }),
                limits: ServerLimitsConfig::default(),
                tls: None,
            },
            management: ManagementConfig::default(),
            integrations: BTreeMap::new(),
            storage: StorageConfig::default(),
            delivery: DeliveryConfig::default(),
            escalation: EscalationConfig::default(),
            schedules: ScheduleConfig::default(),
            intelligence: IntelligenceConfig::default(),
            notification_batching: NotificationBatchingConfig::default(),
            debug: DebugConfig::default(),
            routing: RoutingConfig {
                default_receiver: Some("default".to_string()),
                routes: Vec::new(),
            },
            receivers: BTreeMap::from([(
                "default".to_string(),
                ReceiverConfig::GoogleChat(GoogleChatReceiverConfig {
                    webhook_url: "https://chat.example.test/hook".to_string(),
                    owner_team: None,
                    title_template: Some(default_title_template().to_string()),
                    template: None,
                    timeout_secs: default_timeout_secs(),
                }),
            )]),
        }
    }
}
