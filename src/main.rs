use anyhow::Context;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
    BoxError, Json, Router,
    body::Bytes,
    error_handling::HandleErrorLayer,
    extract::{ConnectInfo, OriginalUri, Path, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
};
use clap::Parser;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex as AsyncMutex, oneshot};
use tower::{ServiceBuilder, limit::ConcurrencyLimitLayer, load_shed::LoadShedLayer};
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing::{error, info, warn};

mod alert;
mod config;
mod google_chat;
mod integration;
mod redaction;
mod routing;
mod signoz;
mod storage;
mod tls;
mod ui;

use crate::{
    alert::AlertEvent,
    config::{AppConfig, GoogleChatReceiverConfig, ReceiverConfig},
    google_chat::{DebugDeliveryLog, GoogleChatClient},
    integration::{GenericJsonIntegration, Integration, SigNozIntegration},
    routing::{Delivery, RouteEngine},
    signoz::SigNozAlert,
    storage::{AuditActor, DisableUserOutcome, SessionUserRecord, Storage, UserRecord},
};

const SESSION_COOKIE: &str = "sap_session";
const CSRF_HEADER: &str = "x-csrf-token";
const LOGIN_FAILURE_LIMIT: u32 = 5;
const LOGIN_LOCKOUT_MILLIS: i64 = 15 * 60 * 1000;

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Args {
    #[arg(
        short,
        long,
        env = "SIGNOZ_ALERT_PROXY_CONFIG",
        default_value = "config.yaml"
    )]
    config: PathBuf,
}

#[derive(Clone)]
struct AppState {
    config: Arc<AppConfig>,
    router: Arc<RouteEngine>,
    aggregator: AlertAggregator,
    storage: Storage,
    login_attempts: LoginAttemptLimiter,
}

#[derive(Debug, Clone)]
struct LoginAttemptLimiter {
    attempts: Arc<Mutex<BTreeMap<String, LoginAttemptState>>>,
}

#[derive(Debug, Clone, Copy)]
struct LoginAttemptState {
    failures: u32,
    locked_until: i64,
}

impl LoginAttemptLimiter {
    fn new() -> Self {
        Self {
            attempts: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn check_allowed(&self, username: &str) -> bool {
        let now = storage::now_epoch_millis();
        let key = login_attempt_key(username);
        let mut attempts = self.attempts.lock().unwrap();
        let Some(state) = attempts.get(&key) else {
            return true;
        };

        if state.locked_until > now {
            return false;
        }

        if state.locked_until > 0 {
            attempts.remove(&key);
        }
        true
    }

    fn record_failure(&self, username: &str) {
        let now = storage::now_epoch_millis();
        let key = login_attempt_key(username);
        let mut attempts = self.attempts.lock().unwrap();
        let state = attempts.entry(key).or_insert(LoginAttemptState {
            failures: 0,
            locked_until: 0,
        });
        state.failures = state.failures.saturating_add(1);
        if state.failures >= LOGIN_FAILURE_LIMIT {
            state.locked_until = now + LOGIN_LOCKOUT_MILLIS;
        }
    }

    fn record_success(&self, username: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.remove(&login_attempt_key(username));
    }
}

fn login_attempt_key(username: &str) -> String {
    username.trim().to_string()
}

#[derive(Clone)]
struct AlertAggregator {
    enabled: bool,
    debounce: Duration,
    google_chat: GoogleChatClient,
    pending: Arc<AsyncMutex<BTreeMap<AggregationKey, PendingAggregation>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AggregationKey {
    receiver: String,
    route_name: String,
    status: String,
    rule_id: String,
}

struct PendingAggregation {
    receiver: GoogleChatReceiverConfig,
    delivery: Delivery,
    alerts: Vec<SigNozAlert>,
    debug_enabled: bool,
    completions: Vec<oneshot::Sender<Result<(), String>>>,
}

impl AlertAggregator {
    fn new(config: &AppConfig, google_chat: GoogleChatClient) -> Self {
        Self {
            enabled: config.alert_grouping.enabled,
            debounce: Duration::from_millis(config.alert_grouping.debounce_millis),
            google_chat,
            pending: Arc::new(AsyncMutex::new(BTreeMap::new())),
        }
    }

    async fn enqueue_google_chat(
        &self,
        receiver: &GoogleChatReceiverConfig,
        alert: SigNozAlert,
        delivery: Delivery,
        debug_enabled: bool,
    ) -> Result<(), String> {
        let Some(rule_id) = alert
            .rule_id()
            .filter(|rule_id| self.enabled && !rule_id.is_empty())
        else {
            let debug = debug_enabled.then_some(DebugDeliveryLog {
                route_name: delivery.route_name.as_str(),
                receiver_name: delivery.receiver.as_str(),
            });
            self.google_chat
                .send(receiver, &alert, &delivery, debug)
                .await
                .map_err(redacted_delivery_error)?;
            return Ok(());
        };

        let key = AggregationKey {
            receiver: delivery.receiver.clone(),
            route_name: delivery.route_name.clone(),
            status: alert.enrichment.overall_status.clone(),
            rule_id,
        };
        let mut should_spawn = false;
        let (completion, delivered) = oneshot::channel();

        {
            use std::collections::btree_map::Entry;

            let mut pending = self.pending.lock().await;
            match pending.entry(key.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(PendingAggregation {
                        receiver: receiver.clone(),
                        delivery,
                        alerts: vec![alert],
                        debug_enabled,
                        completions: vec![completion],
                    });
                    should_spawn = true;
                }
                Entry::Occupied(mut entry) => {
                    let bucket = entry.get_mut();
                    bucket.alerts.push(alert);
                    bucket.completions.push(completion);
                    bucket.debug_enabled |= debug_enabled;
                }
            }
        }

        if should_spawn {
            let aggregator = self.clone();
            tokio::spawn(async move {
                aggregator.flush_after(key).await;
            });
        }

        delivered
            .await
            .unwrap_or_else(|_| Err("grouped alert delivery canceled".to_string()))
    }

    async fn flush_after(&self, key: AggregationKey) {
        tokio::time::sleep(self.debounce).await;

        let Some(bucket) = self.pending.lock().await.remove(&key) else {
            return;
        };

        let result = self.flush_bucket(&bucket).await;
        if let Err(error) = &result {
            error!(%error, "grouped alert delivery failed");
        }
        for completion in bucket.completions {
            let _ = completion.send(result.clone());
        }
    }

    async fn flush_bucket(&self, bucket: &PendingAggregation) -> Result<(), String> {
        let alert =
            SigNozAlert::merged_for_delivery(&bucket.alerts).map_err(|error| error.to_string())?;
        let debug = bucket.debug_enabled.then_some(DebugDeliveryLog {
            route_name: bucket.delivery.route_name.as_str(),
            receiver_name: bucket.delivery.receiver.as_str(),
        });

        self.google_chat
            .send(&bucket.receiver, &alert, &bucket.delivery, debug)
            .await
            .map_err(redacted_delivery_error)
    }
}

fn init_crypto_provider() -> anyhow::Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_crypto_provider()?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let config = Arc::new(AppConfig::load(&args.config)?);
    config.validate()?;

    let bind_addr: SocketAddr = config
        .server
        .bind
        .parse()
        .with_context(|| format!("invalid bind address {}", config.server.bind))?;
    let webhook_path = config.server.webhook_path.clone();

    let app = build_app(Arc::clone(&config), webhook_path.clone())?;

    if config.management_allows_unauthenticated() {
        warn!(
            "management API/UI authentication explicitly disabled by management.allow_unauthenticated"
        );
    }

    info!(%bind_addr, %webhook_path, tls = config.server.tls.is_some(), "starting simple-alert-proxy");

    if let Some(tls_config) = &config.server.tls {
        tls::serve_tls(bind_addr, app, tls_config).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    }

    Ok(())
}

fn build_app(config: Arc<AppConfig>, webhook_path: String) -> anyhow::Result<Router> {
    let max_body_bytes = config.server.max_body_bytes;
    let webhook_concurrency = config.server.limits.webhook_concurrency;
    let management_concurrency = config.server.limits.management_concurrency;
    let google_chat = GoogleChatClient::new();
    let storage = Storage::open(&config.storage.path)?;
    let pruned_alerts = storage.prune_alerts_older_than_days(config.storage.retention_days)?;
    if pruned_alerts > 0 {
        info!(
            pruned_alerts,
            retention_days = config.storage.retention_days,
            "pruned alert records past retention period"
        );
    }
    storage.delete_expired_sessions()?;
    bootstrap_admin_user(&config, &storage)?;
    start_retention_pruner(storage.clone(), config.storage.retention_days);
    let state = AppState {
        router: Arc::new(RouteEngine::new(config.as_ref().clone())?),
        aggregator: AlertAggregator::new(&config, google_chat),
        storage,
        login_attempts: LoginAttemptLimiter::new(),
        config: Arc::clone(&config),
    };

    let health = Router::new().route("/healthz", post(healthz).get(healthz));
    let mut webhooks = Router::new().route("/webhooks/{*integration}", post(handle_webhook));
    if !webhook_path.starts_with("/webhooks/") {
        webhooks = webhooks.route(&webhook_path, post(handle_legacy_signoz_webhook));
    }
    let webhooks = webhooks.layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(handle_overload))
            .layer(LoadShedLayer::new())
            .layer(ConcurrencyLimitLayer::new(webhook_concurrency)),
    );
    let management = Router::new()
        .route("/", get(operator_ui))
        .route("/ui", get(operator_ui))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/api/me", get(current_user))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/{id}/password", post(change_user_password))
        .route("/api/users/{id}/disable", post(disable_user))
        .route("/api/teams", get(list_teams).post(create_team))
        .route("/api/team-memberships", get(list_team_memberships))
        .route(
            "/api/teams/{team_id}/members/{user_id}",
            put(set_team_membership).delete(remove_team_membership),
        )
        .route("/debug/webhook", post(handle_debug_webhook))
        .route("/api/alert-groups", get(list_alert_groups))
        .route("/api/alert-events", get(list_alert_events))
        .route("/api/deliveries", get(list_deliveries))
        .route("/api/advisories", get(list_advisories))
        .route("/api/integrations", get(list_integrations))
        .route("/api/routes", get(list_routes))
        .route("/api/alert-groups/{id}/ack", post(acknowledge_group))
        .route("/api/alert-groups/{id}/resolve", post(resolve_group))
        .route("/api/alert-groups/{id}/silence", post(silence_group))
        .route("/api/deliveries/{id}/replay", post(replay_delivery))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_overload))
                .layer(LoadShedLayer::new())
                .layer(ConcurrencyLimitLayer::new(management_concurrency)),
        );

    Ok(health
        .merge(webhooks)
        .merge(management)
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(log_webhook_failures))
        .with_state(state))
}

fn start_retention_pruner(storage: Storage, retention_days: u64) {
    tokio::spawn(async move {
        let retention_interval = Duration::from_secs(24 * 60 * 60);
        loop {
            tokio::time::sleep(retention_interval).await;
            match storage.prune_alerts_older_than_days(retention_days) {
                Ok(pruned_alerts) if pruned_alerts > 0 => {
                    info!(
                        pruned_alerts,
                        retention_days, "pruned alert records past retention period"
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    error!(%error, retention_days, "failed to prune alert records");
                }
            }
        }
    });
}

async fn handle_overload(_error: BoxError) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": "request concurrency limit exceeded" })),
    )
        .into_response()
}

async fn log_webhook_failures(request: Request, next: Next) -> Response {
    let caller = CallerDetails::from_request(&request);
    let response = next.run(request).await;

    if let Some(log) = response.extensions().get::<WebhookErrorLog>() {
        error!(
            error = %log.error,
            status = %response.status(),
            method = %caller.method,
            path = %caller.path,
            source_ip = caller.source_ip.as_deref().unwrap_or("unknown"),
            peer_addr = caller.peer_addr.as_deref().unwrap_or("unknown"),
            x_forwarded_for = caller.x_forwarded_for.as_deref().unwrap_or(""),
            x_real_ip = caller.x_real_ip.as_deref().unwrap_or(""),
            user_agent = caller.user_agent.as_deref().unwrap_or(""),
            headers = ?caller.headers,
            "webhook failed"
        );
    }

    response
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallerDetails {
    method: String,
    path: String,
    source_ip: Option<String>,
    peer_addr: Option<String>,
    x_forwarded_for: Option<String>,
    x_real_ip: Option<String>,
    user_agent: Option<String>,
    headers: BTreeMap<String, String>,
}

impl CallerDetails {
    fn from_request(request: &Request) -> Self {
        let headers = request.headers();
        let peer_addr = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.to_string());
        let x_forwarded_for = header_string(headers, "x-forwarded-for");
        let x_real_ip = header_string(headers, "x-real-ip");
        let user_agent = header_string(headers, "user-agent");
        let source_ip = first_forwarded_ip(x_forwarded_for.as_deref())
            .or_else(|| x_real_ip.clone())
            .or_else(|| peer_addr.as_deref().and_then(peer_ip));

        Self {
            method: request.method().to_string(),
            path: request.uri().path().to_string(),
            source_ip,
            peer_addr,
            x_forwarded_for,
            x_real_ip,
            user_agent,
            headers: logged_headers(headers),
        }
    }
}

const MAX_LOGGED_HEADER_VALUE_LEN: usize = 256;
const REDACTED_HEADER_VALUE: &str = "[redacted]";
const NON_UTF8_HEADER_VALUE: &str = "[non-utf8]";

fn logged_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                logged_header_value(name, value),
            )
        })
        .collect()
}

fn logged_header_value(name: &HeaderName, value: &HeaderValue) -> String {
    if is_sensitive_header(name.as_str()) {
        return REDACTED_HEADER_VALUE.to_owned();
    }

    value.to_str().map_or_else(
        |_| NON_UTF8_HEADER_VALUE.to_owned(),
        |value| truncate_header_value(value.trim()),
    )
}

fn is_sensitive_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "key"
    ) || name.contains("token")
        || name.contains("secret")
        || name.contains("password")
        || name.contains("credential")
        || name.contains("api-key")
        || name.ends_with("-key")
}

fn truncate_header_value(value: &str) -> String {
    if value.chars().count() <= MAX_LOGGED_HEADER_VALUE_LEN {
        return value.to_owned();
    }

    let mut truncated = value
        .chars()
        .take(MAX_LOGGED_HEADER_VALUE_LEN)
        .collect::<String>();
    truncated.push_str("...[truncated]");
    truncated
}

fn header_string(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn first_forwarded_ip(value: Option<&str>) -> Option<String> {
    value?
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn peer_ip(value: &str) -> Option<String> {
    value
        .parse::<SocketAddr>()
        .ok()
        .map(|addr| addr.ip().to_string())
}

async fn healthz() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

async fn operator_ui() -> Html<&'static str> {
    Html(ui::OPERATOR_UI)
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    display_name: String,
    password: String,
    #[serde(default = "default_viewer_role")]
    global_role: String,
}

#[derive(Debug, Deserialize)]
struct ChangePasswordRequest {
    password: String,
}

#[derive(Debug, Deserialize)]
struct CreateTeamRequest {
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Deserialize)]
struct SetTeamMembershipRequest {
    #[serde(default = "default_team_viewer_role")]
    team_role: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    user: UserRecord,
    csrf_token: String,
}

#[derive(Debug, Serialize)]
struct MeResponse {
    authenticated: bool,
    auth_kind: String,
    user: Option<UserRecord>,
    csrf_token: Option<String>,
    role: String,
}

async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, WebhookError> {
    if !state.config.management_local_users_enabled() {
        return Err(WebhookError::Unauthorized);
    }

    if !state.login_attempts.check_allowed(&request.username) {
        return Err(WebhookError::TooManyLoginAttempts);
    }

    let Some(user) = state.storage.authenticate_user(&request.username)? else {
        state.login_attempts.record_failure(&request.username);
        return Err(WebhookError::Unauthorized);
    };

    if user.status != "active" || !verify_password(&user.password_hash, &request.password) {
        state.login_attempts.record_failure(&request.username);
        return Err(WebhookError::Unauthorized);
    }

    state.storage.delete_expired_sessions()?;
    let token = new_secret_token();
    let csrf_token = new_secret_token();
    let token_hash = token_hash(&token);
    let expires_at = storage::now_epoch_millis()
        + i64::try_from(state.config.management.session_ttl_secs).unwrap_or(i64::MAX / 1000) * 1000;
    state
        .storage
        .create_session(&token_hash, user.id, &csrf_token, expires_at)?;
    state.storage.update_last_login(user.id)?;
    state.login_attempts.record_success(&request.username);

    Ok((
        [(
            header::SET_COOKIE,
            session_cookie(&token, expires_at, state.config.management_secure_cookies()),
        )],
        Json(LoginResponse {
            user: user.public_record(),
            csrf_token,
        }),
    ))
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    if let Some(principal) = authenticate_session(&state, &headers)? {
        require_csrf(&principal, &headers)?;
        if let Some(token) = session_token_from_headers(&headers) {
            state.storage.delete_session(&token_hash(&token))?;
        }
    } else if let Some(token) = session_token_from_headers(&headers) {
        state.storage.delete_session(&token_hash(&token))?;
    }

    Ok((
        [(
            header::SET_COOKIE,
            expired_session_cookie(state.config.management_secure_cookies()),
        )],
        StatusCode::NO_CONTENT,
    ))
}

async fn current_user(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    let principal = authenticate_management(&state, &headers)?;
    Ok(Json(MeResponse {
        authenticated: principal.auth_kind != "anonymous",
        auth_kind: principal.auth_kind.to_string(),
        user: principal.user.clone(),
        csrf_token: principal.csrf_token.clone(),
        role: principal.role.as_str().to_string(),
    }))
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    require_management(&state, &headers, Permission::Admin)?;
    Ok(Json(state.storage.list_users()?))
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, WebhookError> {
    let principal = require_management(&state, &headers, Permission::Admin)?;
    require_csrf(&principal, &headers)?;
    validate_password(&request.password)?;
    let password_hash = hash_password(&request.password)?;
    let user = state.storage.create_user(
        &request.username,
        &request.display_name,
        &password_hash,
        &request.global_role,
    )?;
    Ok((StatusCode::CREATED, Json(user)))
}

async fn change_user_password(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, WebhookError> {
    let principal = require_management(&state, &headers, Permission::Admin)?;
    require_csrf(&principal, &headers)?;
    validate_password(&request.password)?;
    let password_hash = hash_password(&request.password)?;
    state
        .storage
        .update_user_password(id, &password_hash, principal.audit_actor())?;
    Ok(StatusCode::NO_CONTENT)
}

async fn disable_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    let principal = require_management(&state, &headers, Permission::Admin)?;
    require_csrf(&principal, &headers)?;
    if principal.user.as_ref().is_some_and(|user| user.id == id) {
        return Err(WebhookError::Forbidden);
    }

    match state.storage.disable_user(id, principal.audit_actor())? {
        DisableUserOutcome::Disabled => Ok(StatusCode::NO_CONTENT),
        DisableUserOutcome::LastActiveAdmin => Err(WebhookError::Forbidden),
    }
}

async fn list_teams(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    require_management(&state, &headers, Permission::Read)?;
    Ok(Json(state.storage.list_teams()?))
}

async fn create_team(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTeamRequest>,
) -> Result<impl IntoResponse, WebhookError> {
    let principal = require_management(&state, &headers, Permission::Admin)?;
    require_csrf(&principal, &headers)?;
    let team = state
        .storage
        .create_team(&request.name, &request.description)?;
    Ok((StatusCode::CREATED, Json(team)))
}

async fn list_team_memberships(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    require_management(&state, &headers, Permission::Read)?;
    Ok(Json(state.storage.list_team_memberships()?))
}

async fn set_team_membership(
    State(state): State<AppState>,
    Path((team_id, user_id)): Path<(i64, i64)>,
    headers: HeaderMap,
    Json(request): Json<SetTeamMembershipRequest>,
) -> Result<impl IntoResponse, WebhookError> {
    let principal = require_management(&state, &headers, Permission::Admin)?;
    require_csrf(&principal, &headers)?;
    let membership = state
        .storage
        .set_team_membership(team_id, user_id, &request.team_role)?;
    Ok(Json(membership))
}

async fn remove_team_membership(
    State(state): State<AppState>,
    Path((team_id, user_id)): Path<(i64, i64)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    let principal = require_management(&state, &headers, Permission::Admin)?;
    require_csrf(&principal, &headers)?;
    state.storage.remove_team_membership(team_id, user_id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_alert_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    require_management(&state, &headers, Permission::Read)?;
    Ok(Json(state.storage.list_alert_groups()?))
}

async fn list_alert_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    require_management(&state, &headers, Permission::Read)?;
    Ok(Json(state.storage.list_alert_events()?))
}

async fn list_deliveries(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    require_management(&state, &headers, Permission::Read)?;
    Ok(Json(state.storage.list_deliveries()?))
}

async fn list_advisories(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    require_management(&state, &headers, Permission::Read)?;
    Ok(Json(state.storage.list_advisories()?))
}

async fn list_integrations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    require_management(&state, &headers, Permission::Read)?;
    let mut integrations = state
        .config
        .integrations
        .iter()
        .map(|(name, integration)| match integration {
            config::IntegrationConfig::Builtin(config) => serde_json::json!({
                "name": name,
                "type": "builtin",
                "preset": config.preset,
                "path": config.path,
            }),
            config::IntegrationConfig::GenericJson(config) => serde_json::json!({
                "name": name,
                "type": "generic_json",
                "preset": config.preset,
                "path": config.path,
            }),
        })
        .collect::<Vec<_>>();
    if !state
        .config
        .integrations
        .values()
        .any(|integration| integration.path() == state.config.server.webhook_path)
    {
        integrations.push(serde_json::json!({
            "name": "signoz",
            "type": "builtin",
            "preset": "signoz",
            "path": state.config.server.webhook_path,
            "compatibility_default": true,
        }));
    }
    Ok(Json(integrations))
}

async fn list_routes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    require_management(&state, &headers, Permission::Read)?;
    let routes = state
        .config
        .routing
        .routes
        .iter()
        .map(|route| {
            serde_json::json!({
                "name": route.name,
                "receiver": route.receiver,
                "continue_matching": route.continue_matching,
                "matcher_count": route.matchers.len(),
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(routes))
}

async fn acknowledge_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    let principal = require_management(&state, &headers, Permission::Operate)?;
    require_csrf(&principal, &headers)?;
    state
        .storage
        .acknowledge_group_as(id, principal.audit_actor())?;
    Ok(StatusCode::ACCEPTED)
}

async fn resolve_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    let principal = require_management(&state, &headers, Permission::Operate)?;
    require_csrf(&principal, &headers)?;
    state
        .storage
        .resolve_group_as(id, principal.audit_actor())?;
    Ok(StatusCode::ACCEPTED)
}

async fn silence_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    let principal = require_management(&state, &headers, Permission::Operate)?;
    require_csrf(&principal, &headers)?;
    state
        .storage
        .silence_group_as(id, principal.audit_actor())?;
    Ok(StatusCode::ACCEPTED)
}

async fn replay_delivery(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    let principal = require_management(&state, &headers, Permission::Operate)?;
    require_csrf(&principal, &headers)?;
    state
        .storage
        .replay_delivery_as(id, principal.audit_actor())?;
    Ok(StatusCode::ACCEPTED)
}

async fn handle_debug_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, WebhookError> {
    let principal = require_management(&state, &headers, Permission::Operate)?;
    require_csrf(&principal, &headers)?;

    let payload = serde_json::from_slice::<Value>(&body).map_err(signoz::AlertParseError::from)?;
    log_debug_json(
        "authenticated debug webhook",
        &payload,
        state.config.debug.log_full_payloads,
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "logged": true })),
    ))
}

async fn handle_legacy_signoz_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, WebhookError> {
    authorize(state.config.server.auth.as_ref(), &headers)?;

    let payload = serde_json::from_slice::<Value>(&body).map_err(signoz::AlertParseError::from)?;
    if state.config.debug.log_alerts {
        log_debug_json(
            "incoming signoz alert",
            &payload,
            state.config.debug.log_full_payloads,
        );
    }

    process_signoz_alerts(&state, "signoz", payload)
}

async fn handle_webhook(
    State(state): State<AppState>,
    Path(_integration): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, WebhookError> {
    let path = uri.path();
    match integration::configured_integration_for_path(&state.config.integrations, path) {
        Ok(integration::ConfiguredIntegration::Builtin(name, config)) => {
            authorize(
                config.auth.as_ref().or(state.config.server.auth.as_ref()),
                &headers,
            )?;
            let payload =
                serde_json::from_slice::<Value>(&body).map_err(signoz::AlertParseError::from)?;
            if state.config.debug.log_alerts {
                log_debug_json(
                    "incoming builtin alert",
                    &payload,
                    state.config.debug.log_full_payloads,
                );
            }

            process_builtin_alerts(&state, name, &config.preset, payload)
        }
        Ok(integration::ConfiguredIntegration::GenericJson(name, config)) => {
            authorize(
                config.auth.as_ref().or(state.config.server.auth.as_ref()),
                &headers,
            )?;
            let payload =
                serde_json::from_slice::<Value>(&body).map_err(signoz::AlertParseError::from)?;
            if state.config.debug.log_alerts {
                log_debug_json(
                    "incoming generic alert",
                    &payload,
                    state.config.debug.log_full_payloads,
                );
            }

            let integration = GenericJsonIntegration::new(name, config);
            let events = integration.normalize(payload)?;
            process_generic_events(&state, &events)
        }
        Err(integration::IntegrationError::Unknown(_))
            if path == state.config.server.webhook_path =>
        {
            authorize(state.config.server.auth.as_ref(), &headers)?;
            let payload =
                serde_json::from_slice::<Value>(&body).map_err(signoz::AlertParseError::from)?;
            if state.config.debug.log_alerts {
                log_debug_json(
                    "incoming default signoz alert",
                    &payload,
                    state.config.debug.log_full_payloads,
                );
            }

            process_signoz_alerts(&state, "signoz", payload)
        }
        Err(error) => Err(error.into()),
    }
}

fn process_builtin_alerts(
    state: &AppState,
    name: &str,
    preset: &str,
    payload: Value,
) -> Result<(StatusCode, Json<Value>), WebhookError> {
    match preset {
        "signoz" | "alertmanager" => process_signoz_alerts(state, name, payload),
        _ => Err(integration::IntegrationError::Unknown(preset.to_string()).into()),
    }
}

fn process_signoz_alerts(
    state: &AppState,
    name: &str,
    payload: Value,
) -> Result<(StatusCode, Json<Value>), WebhookError> {
    let signoz = SigNozIntegration::new(name);
    let alerts = signoz.parse_alerts(payload)?;
    let mut delivered_receivers = Vec::new();

    for alert in &alerts {
        let event = alert.to_alert_event(name);
        let plan = state.router.plan(&event);
        let mut alert_event_id = None;

        for delivery in &plan.deliveries {
            let Some(receiver) = state.config.receivers.get(&delivery.receiver) else {
                error!(receiver = %delivery.receiver, "route selected missing receiver");
                continue;
            };
            let event_id = match alert_event_id {
                Some(event_id) => event_id,
                None => {
                    let event_id = state.storage.store_event(&event)?;
                    alert_event_id = Some(event_id);
                    event_id
                }
            };

            match receiver {
                config::ReceiverConfig::GoogleChat(receiver) => {
                    queue_signoz_google_chat_delivery(
                        state,
                        event_id,
                        receiver,
                        alert.clone(),
                        delivery.clone(),
                    )?;
                    delivered_receivers.push(delivery.receiver.clone());
                }
                receiver => {
                    queue_target_event_delivery(
                        state,
                        &event,
                        event_id,
                        receiver,
                        delivery.clone(),
                    )?;
                    delivered_receivers.push(delivery.receiver.clone());
                }
            }
        }
    }

    if delivered_receivers.is_empty() {
        return Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "delivered": 0 })),
        ));
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(delivery_summary(&delivered_receivers)),
    ))
}

fn process_generic_events(
    state: &AppState,
    events: &[AlertEvent],
) -> Result<(StatusCode, Json<Value>), WebhookError> {
    let mut delivered_receivers = Vec::new();

    for event in events {
        let plan = state.router.plan(event);
        let mut alert_event_id = None;

        for delivery in &plan.deliveries {
            let Some(receiver) = state.config.receivers.get(&delivery.receiver) else {
                error!(receiver = %delivery.receiver, "route selected missing receiver");
                continue;
            };
            let event_id = match alert_event_id {
                Some(event_id) => event_id,
                None => {
                    let event_id = state.storage.store_event(event)?;
                    alert_event_id = Some(event_id);
                    event_id
                }
            };

            queue_target_event_delivery(state, event, event_id, receiver, delivery.clone())?;
            delivered_receivers.push(delivery.receiver.clone());
        }
    }

    if delivered_receivers.is_empty() {
        return Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "delivered": 0 })),
        ));
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(delivery_summary(&delivered_receivers)),
    ))
}

fn queue_signoz_google_chat_delivery(
    state: &AppState,
    alert_event_id: i64,
    receiver: &GoogleChatReceiverConfig,
    alert: SigNozAlert,
    delivery: Delivery,
) -> Result<(), WebhookError> {
    let delivery_id = state.storage.queue_delivery(alert_event_id, &delivery)?;
    queue_escalation_if_configured(state, alert_event_id, &delivery)?;
    let worker = DeliveryWorker::new(
        state.storage.clone(),
        state.config.delivery.clone(),
        state.config.debug.log_alerts,
    );
    let aggregator = state.aggregator.clone();
    let receiver = receiver.clone();

    tokio::spawn(async move {
        worker
            .run(delivery_id, move |debug_enabled| {
                let aggregator = aggregator.clone();
                let receiver = receiver.clone();
                let alert = alert.clone();
                let delivery = delivery.clone();
                async move {
                    aggregator
                        .enqueue_google_chat(&receiver, alert, delivery, debug_enabled)
                        .await
                }
            })
            .await;
    });

    Ok(())
}

fn queue_target_event_delivery(
    state: &AppState,
    event: &AlertEvent,
    alert_event_id: i64,
    receiver: &ReceiverConfig,
    delivery: Delivery,
) -> Result<(), WebhookError> {
    let delivery_id = state.storage.queue_delivery(alert_event_id, &delivery)?;
    queue_escalation_if_configured(state, alert_event_id, &delivery)?;
    let worker = DeliveryWorker::new(
        state.storage.clone(),
        state.config.delivery.clone(),
        state.config.debug.log_alerts,
    );
    let target_client = state.aggregator.google_chat.clone();
    let receiver = receiver.clone();
    let event = event.clone();

    tokio::spawn(async move {
        worker
            .run(delivery_id, move |debug_enabled| {
                let target_client = target_client.clone();
                let receiver = receiver.clone();
                let event = event.clone();
                let delivery = delivery.clone();
                async move {
                    let debug = debug_enabled.then_some(DebugDeliveryLog {
                        route_name: delivery.route_name.as_str(),
                        receiver_name: delivery.receiver.as_str(),
                    });
                    target_client
                        .send_receiver_event(&receiver, &event, &delivery, debug)
                        .await
                        .map_err(redacted_delivery_error)
                }
            })
            .await;
    });

    Ok(())
}

fn queue_escalation_if_configured(
    state: &AppState,
    alert_event_id: i64,
    delivery: &Delivery,
) -> Result<(), WebhookError> {
    let Some(policy_name) = &delivery.escalation_policy else {
        return Ok(());
    };
    let Some(policy) = state.config.escalation.policies.get(policy_name) else {
        return Ok(());
    };
    let Some(first_step) = policy.steps.first() else {
        return Ok(());
    };
    let _stop_conditions = (first_step.stop_on_ack, first_step.stop_on_resolve);
    state
        .storage
        .queue_escalation(alert_event_id, policy_name, first_step.delay_millis)?;
    Ok(())
}

#[derive(Clone)]
struct DeliveryWorker {
    storage: Storage,
    config: config::DeliveryConfig,
    debug_enabled: bool,
}

impl DeliveryWorker {
    fn new(storage: Storage, config: config::DeliveryConfig, debug_enabled: bool) -> Self {
        Self {
            storage,
            config,
            debug_enabled,
        }
    }

    async fn run<F, Fut>(&self, delivery_id: i64, mut send: F)
    where
        F: FnMut(bool) -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        let mut backoff = Duration::from_millis(self.config.initial_backoff_millis);

        for attempt in 1..=self.config.max_attempts {
            if let Err(error) = self.storage.mark_attempt(delivery_id, attempt) {
                error!(%error, delivery_id, "failed to mark delivery attempt");
            }

            match send(self.debug_enabled).await {
                Ok(()) => {
                    if let Err(error) = self.storage.mark_succeeded(delivery_id, "delivered") {
                        error!(%error, delivery_id, "failed to mark delivery success");
                    }
                    return;
                }
                Err(error) if attempt >= self.config.max_attempts => {
                    if let Err(store_error) = self.storage.mark_dead_letter(delivery_id, &error) {
                        error!(%store_error, delivery_id, "failed to mark delivery dead-letter");
                    }
                    error!(delivery_id, %error, "delivery exhausted retries");
                    return;
                }
                Err(error) => {
                    let next_retry_at = storage::now_epoch_millis() + backoff.as_millis() as i64;
                    if let Err(store_error) =
                        self.storage
                            .mark_retrying(delivery_id, next_retry_at, &error)
                    {
                        error!(%store_error, delivery_id, "failed to mark delivery retry");
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(
                        backoff.saturating_mul(2),
                        Duration::from_millis(self.config.max_backoff_millis),
                    );
                }
            }
        }
    }
}

fn redacted_delivery_error(error: google_chat::GoogleChatError) -> String {
    match error {
        google_chat::GoogleChatError::Rejected(status) => {
            format!("target rejected delivery with status {status}")
        }
        google_chat::GoogleChatError::Http(_) => "target delivery failed".to_string(),
    }
}

fn bootstrap_admin_user(config: &AppConfig, storage: &Storage) -> anyhow::Result<()> {
    if !config.management_local_users_enabled() || storage.user_count()? > 0 {
        return Ok(());
    }

    let env_name = &config.management.bootstrap_admin_password_env;
    let Ok(password) = env::var(env_name) else {
        warn!(
            env = %env_name,
            "local user auth is enabled but no bootstrap admin password env var is set"
        );
        return Ok(());
    };

    if password.is_empty() {
        warn!(env = %env_name, "bootstrap admin password env var is empty");
        return Ok(());
    }

    let password_hash = hash_password(&password)?;
    storage.create_user("admin", "Administrator", &password_hash, "admin")?;
    info!("initialized bootstrap admin user from environment");
    Ok(())
}

fn authorize(auth: Option<&config::AuthConfig>, headers: &HeaderMap) -> Result<(), WebhookError> {
    let Some(auth) = auth else {
        return Ok(());
    };

    authorize_required(Some(auth), headers)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Permission {
    Read,
    Operate,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagementRole {
    Admin,
    Operator,
    Viewer,
}

impl ManagementRole {
    fn from_str(value: &str) -> Self {
        match value {
            "admin" => Self::Admin,
            "operator" => Self::Operator,
            _ => Self::Viewer,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }

    fn allows(self, permission: Permission) -> bool {
        matches!(
            (self, permission),
            (Self::Admin, _)
                | (Self::Operator, Permission::Read | Permission::Operate)
                | (Self::Viewer, Permission::Read)
        )
    }
}

#[derive(Debug, Clone)]
struct ManagementPrincipal {
    role: ManagementRole,
    user: Option<UserRecord>,
    csrf_token: Option<String>,
    auth_kind: &'static str,
}

impl ManagementPrincipal {
    fn audit_actor(&self) -> AuditActor {
        let Some(user) = &self.user else {
            return AuditActor::default();
        };

        AuditActor {
            user_id: Some(user.id),
            display_name: Some(user.display_name.clone()),
            team_id: None,
        }
    }
}

fn require_management(
    state: &AppState,
    headers: &HeaderMap,
    permission: Permission,
) -> Result<ManagementPrincipal, WebhookError> {
    let principal = authenticate_management(state, headers)?;
    if principal.role.allows(permission) {
        Ok(principal)
    } else {
        Err(WebhookError::Forbidden)
    }
}

fn authenticate_management(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<ManagementPrincipal, WebhookError> {
    if state.config.management_allows_unauthenticated() {
        return Ok(ManagementPrincipal {
            role: ManagementRole::Admin,
            user: None,
            csrf_token: None,
            auth_kind: "anonymous",
        });
    }

    if let Some(auth) = state.config.management_auth()
        && has_valid_bearer(auth, headers)
    {
        return Ok(ManagementPrincipal {
            role: ManagementRole::Admin,
            user: None,
            csrf_token: None,
            auth_kind: "bearer",
        });
    }

    if let Some(principal) = authenticate_session(state, headers)? {
        return Ok(principal);
    }

    if legacy_loopback_management_open(&state.config, &state.storage)? {
        return Ok(ManagementPrincipal {
            role: ManagementRole::Admin,
            user: None,
            csrf_token: None,
            auth_kind: "legacy-loopback",
        });
    }

    Err(WebhookError::Unauthorized)
}

fn authenticate_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<ManagementPrincipal>, WebhookError> {
    if state.config.management_local_users_enabled()
        && let Some(token) = session_token_from_headers(headers)
        && let Some(session_user) = state.storage.session_user(&token_hash(&token))?
    {
        return Ok(Some(principal_from_session_user(session_user)));
    }

    Ok(None)
}

fn principal_from_session_user(user: SessionUserRecord) -> ManagementPrincipal {
    ManagementPrincipal {
        role: ManagementRole::from_str(&user.global_role),
        user: Some(user.public_record()),
        csrf_token: Some(user.csrf_token),
        auth_kind: "session",
    }
}

fn legacy_loopback_management_open(config: &AppConfig, storage: &Storage) -> anyhow::Result<bool> {
    if config.management_auth().is_some()
        || config.management_local_users_enabled() && storage.user_count()? > 0
    {
        return Ok(false);
    }

    let bind = config
        .server
        .bind
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid bind address {}", config.server.bind))?;
    Ok(bind.ip().is_loopback())
}

fn require_csrf(principal: &ManagementPrincipal, headers: &HeaderMap) -> Result<(), WebhookError> {
    if principal.auth_kind != "session" {
        return Ok(());
    }

    let Some(expected) = principal.csrf_token.as_deref() else {
        return Err(WebhookError::Unauthorized);
    };
    let Some(presented) = header_string(headers, CSRF_HEADER) else {
        return Err(WebhookError::Unauthorized);
    };

    if presented.as_bytes().ct_eq(expected.as_bytes()).into() {
        Ok(())
    } else {
        Err(WebhookError::Unauthorized)
    }
}

fn has_valid_bearer(auth: &config::AuthConfig, headers: &HeaderMap) -> bool {
    authorize_required(Some(auth), headers).is_ok()
}

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == SESSION_COOKIE && !value.is_empty()).then(|| value.to_string())
    })
}

fn session_cookie(token: &str, expires_at: i64, secure: bool) -> String {
    let max_age = ((expires_at - storage::now_epoch_millis()) / 1000).max(0);
    let secure = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}")
}

fn expired_session_cookie(secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}")
}

fn new_secret_token() -> String {
    uuid::Uuid::new_v4().as_simple().to_string()
}

fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    validate_password(password)?;
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("failed to hash password: {error}"))?
        .to_string())
}

fn verify_password(hash: &str, password: &str) -> bool {
    let Ok(hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

fn validate_password(password: &str) -> anyhow::Result<()> {
    if password.len() < 12 {
        anyhow::bail!("password must be at least 12 characters");
    }
    Ok(())
}

fn default_viewer_role() -> String {
    "viewer".to_string()
}

fn default_team_viewer_role() -> String {
    "viewer".to_string()
}

fn authorize_required(
    auth: Option<&config::AuthConfig>,
    headers: &HeaderMap,
) -> Result<(), WebhookError> {
    let Some(auth) = auth else {
        return Err(WebhookError::Unauthorized);
    };

    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Err(WebhookError::Unauthorized);
    };

    let presented = parse_bearer_token(value).ok_or(WebhookError::Unauthorized)?;
    let expected = auth.bearer_token.as_bytes();

    if presented.len() != expected.len() {
        return Err(WebhookError::Unauthorized);
    }

    if bool::from(presented.ct_eq(expected)) {
        Ok(())
    } else {
        Err(WebhookError::Unauthorized)
    }
}

fn parse_bearer_token(value: &header::HeaderValue) -> Option<&[u8]> {
    let value = value.as_bytes();
    let prefix = b"Bearer ";

    if value.len() <= prefix.len() || &value[..prefix.len()] != prefix {
        return None;
    }

    Some(&value[prefix.len()..])
}

fn log_debug_json(label: &str, value: &Value, log_full_payloads: bool) {
    let log_value = redaction::debug_payload_for_logging(value, log_full_payloads);
    match serde_json::to_string_pretty(&log_value) {
        Ok(json) => eprintln!("simple-alert-proxy debug {label}:\n{json}"),
        Err(error) => eprintln!("simple-alert-proxy debug {label}: failed to render JSON: {error}"),
    }
}

fn delivery_summary(receivers: &[String]) -> Value {
    serde_json::json!({
        "delivered": receivers.len(),
        "receivers": receivers,
    })
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[derive(Debug, thiserror::Error)]
enum WebhookError {
    #[error("missing or invalid authorization")]
    Unauthorized,
    #[error("too many failed login attempts")]
    TooManyLoginAttempts,
    #[error("forbidden")]
    Forbidden,
    #[error("invalid SigNoz payload: {0}")]
    InvalidPayload(#[from] signoz::AlertParseError),
    #[error("invalid integration payload: {0}")]
    Integration(#[from] integration::IntegrationError),
    #[error("storage failed: {0}")]
    Storage(#[from] anyhow::Error),
    #[error("delivery failed: {0}")]
    Delivery(#[from] google_chat::GoogleChatError),
}

#[derive(Debug, Clone)]
struct WebhookErrorLog {
    error: String,
}

impl IntoResponse for WebhookError {
    fn into_response(self) -> axum::response::Response {
        let error = self.to_string();
        let status = match &self {
            WebhookError::Unauthorized => StatusCode::UNAUTHORIZED,
            WebhookError::TooManyLoginAttempts => StatusCode::TOO_MANY_REQUESTS,
            WebhookError::Forbidden => StatusCode::FORBIDDEN,
            WebhookError::InvalidPayload(_) => StatusCode::BAD_REQUEST,
            WebhookError::Integration(integration::IntegrationError::Unknown(_)) => {
                StatusCode::NOT_FOUND
            }
            WebhookError::Integration(_) => StatusCode::BAD_REQUEST,
            WebhookError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WebhookError::Delivery(_) => StatusCode::BAD_GATEWAY,
        };
        let mut response =
            (status, Json(serde_json::json!({ "error": error.clone() }))).into_response();
        response.extensions_mut().insert(WebhookErrorLog { error });
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AlertGroupingConfig, AuthConfig, BuiltinIntegrationConfig, DebugConfig, DeliveryConfig,
        EscalationConfig, EscalationPolicyConfig, EscalationStepConfig,
        GenericJsonIntegrationConfig, GenericWebhookReceiverConfig, GoogleChatReceiverConfig,
        IntegrationConfig, IntelligenceConfig, ManagementConfig, ReceiverConfig, RoutingConfig,
        ServerConfig, ServerLimitsConfig, StorageConfig,
    };
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use std::{collections::BTreeMap, sync::Mutex};
    use tower::ServiceExt;

    #[test]
    fn installs_rustls_crypto_provider() {
        init_crypto_provider().unwrap();

        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[tokio::test]
    async fn healthz_returns_no_content() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn overload_handler_returns_service_unavailable() {
        let response = handle_overload(Box::<std::io::Error>::from(std::io::Error::other(
            "overloaded",
        )))
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "request concurrency limit exceeded");
    }

    #[test]
    fn caller_details_prefers_forwarded_ip_over_peer_addr() {
        let mut request = Request::builder()
            .method("POST")
            .uri("/debug/webhook")
            .header("x-forwarded-for", "203.0.113.10, 10.0.0.2")
            .header("x-real-ip", "198.51.100.5")
            .header(header::USER_AGENT, "curl/8.0")
            .header(header::AUTHORIZATION, "Bearer super-secret-token")
            .header("x-api-key", "also-secret")
            .header("x-request-id", "req-123")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:55220".parse::<SocketAddr>().unwrap(),
        ));

        let caller = CallerDetails::from_request(&request);

        assert_eq!(caller.method, "POST");
        assert_eq!(caller.path, "/debug/webhook");
        assert_eq!(caller.source_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(caller.peer_addr.as_deref(), Some("127.0.0.1:55220"));
        assert_eq!(
            caller.x_forwarded_for.as_deref(),
            Some("203.0.113.10, 10.0.0.2")
        );
        assert_eq!(caller.x_real_ip.as_deref(), Some("198.51.100.5"));
        assert_eq!(caller.user_agent.as_deref(), Some("curl/8.0"));
        assert_eq!(
            caller.headers.get("authorization").map(String::as_str),
            Some(REDACTED_HEADER_VALUE)
        );
        assert_eq!(
            caller.headers.get("x-api-key").map(String::as_str),
            Some(REDACTED_HEADER_VALUE)
        );
        assert_eq!(
            caller.headers.get("x-request-id").map(String::as_str),
            Some("req-123")
        );
    }

    #[test]
    fn logged_headers_redact_invalid_and_truncate_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer nope"),
        );
        headers.insert(
            HeaderName::from_static("x-custom-token"),
            HeaderValue::from_static("secret"),
        );
        headers.insert(
            HeaderName::from_static("x-invalid"),
            HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-long-header"),
            HeaderValue::from_str(&"a".repeat(MAX_LOGGED_HEADER_VALUE_LEN + 1)).unwrap(),
        );

        let logged = logged_headers(&headers);

        assert_eq!(
            logged.get("authorization").map(String::as_str),
            Some(REDACTED_HEADER_VALUE)
        );
        assert_eq!(
            logged.get("x-custom-token").map(String::as_str),
            Some(REDACTED_HEADER_VALUE)
        );
        assert_eq!(
            logged.get("x-invalid").map(String::as_str),
            Some(NON_UTF8_HEADER_VALUE)
        );
        assert_eq!(
            logged
                .get("x-long-header")
                .expect("long header should be logged")
                .len(),
            MAX_LOGGED_HEADER_VALUE_LEN + "...[truncated]".len()
        );
    }

    #[tokio::test]
    async fn unauthorized_response_carries_error_log_extension() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/debug/webhook")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("x-forwarded-for", "203.0.113.10")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let log = response.extensions().get::<WebhookErrorLog>().unwrap();
        assert_eq!(log.error, "missing or invalid authorization");
    }

    #[tokio::test]
    async fn ui_route_serves_operator_console() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/ui")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("Simple Alert Proxy"));
        assert!(body.contains("/api/alert-groups"));
        assert!(body.contains("simple-alert-proxy.managementToken"));
        assert!(body.contains("Authorization"));
    }

    #[tokio::test]
    async fn management_api_uses_management_auth_when_configured() {
        let mut config = test_config("http://127.0.0.1:1");
        config.management.auth = Some(AuthConfig {
            bearer_token: "management-token".to_string(),
        });
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/alert-groups")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let inbound_token = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/alert-groups")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(inbound_token.status(), StatusCode::UNAUTHORIZED);

        let management_token = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/alert-groups")
                    .header(header::AUTHORIZATION, "Bearer management-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(management_token.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn local_user_login_allows_admin_api_with_csrf() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "daniel",
                            "display_name": "Daniel",
                            "password": "correct horse battery",
                            "global_role": "admin"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::CREATED);

        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "daniel",
                            "password": "correct horse battery"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let session_cookie = response_cookie(&login);
        let bytes = to_bytes(login.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let csrf = body["csrf_token"].as_str().unwrap();

        let users = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/users")
                    .header(header::COOKIE, session_cookie)
                    .header(CSRF_HEADER, csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(users.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn logout_requires_csrf_for_session_auth() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "logout-user",
                            "display_name": "Logout User",
                            "password": "correct horse battery",
                            "global_role": "admin"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::CREATED);

        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "logout-user",
                            "password": "correct horse battery"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let session_cookie = response_cookie(&login);
        let bytes = to_bytes(login.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let csrf = body["csrf_token"].as_str().unwrap();

        let missing_csrf = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_csrf.status(), StatusCode::UNAUTHORIZED);

        let users = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/users")
                    .header(header::COOKIE, session_cookie.clone())
                    .header(CSRF_HEADER, csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(users.status(), StatusCode::OK);

        let logout = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/logout")
                    .header(header::COOKIE, session_cookie)
                    .header(CSRF_HEADER, csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    }

    #[test]
    fn login_attempt_key_preserves_username_case() {
        assert_eq!(login_attempt_key(" Daniel "), "Daniel");
        assert_ne!(login_attempt_key("daniel"), login_attempt_key("Daniel"));
    }

    #[tokio::test]
    async fn login_rate_limiter_locks_after_repeated_failures() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "limited",
                            "display_name": "Limited",
                            "password": "correct horse battery",
                            "global_role": "admin"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::CREATED);

        for _ in 0..LOGIN_FAILURE_LIMIT {
            assert_eq!(
                login_status(app.clone(), "limited", "wrong horse battery").await,
                StatusCode::UNAUTHORIZED
            );
        }

        assert_eq!(
            login_status(app, "limited", "correct horse battery").await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn admin_session_cannot_disable_itself() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "selfdisable",
                            "display_name": "Self Disable",
                            "password": "correct horse battery",
                            "global_role": "admin"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::CREATED);
        let bytes = to_bytes(create.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let user_id = body["id"].as_i64().unwrap();

        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "selfdisable",
                            "password": "correct horse battery"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let session_cookie = response_cookie(&login);
        let bytes = to_bytes(login.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let csrf = body["csrf_token"].as_str().unwrap();

        let disable = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/users/{user_id}/disable"))
                    .header(header::COOKIE, session_cookie)
                    .header(CSRF_HEADER, csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(disable.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn viewer_session_cannot_mutate_lifecycle_actions() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "viewer",
                            "display_name": "Viewer",
                            "password": "correct horse battery",
                            "global_role": "viewer"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::CREATED);

        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "username": "viewer",
                            "password": "correct horse battery"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let session_cookie = response_cookie(&login);
        let bytes = to_bytes(login.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let csrf = body["csrf_token"].as_str().unwrap();

        let mutate = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/alert-groups/1/ack")
                    .header(header::COOKIE, session_cookie)
                    .header(CSRF_HEADER, csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mutate.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn bootstrap_admin_password_env_does_not_override_database_password() {
        let env_name = format!("SAP_TEST_BOOTSTRAP_{}", uuid::Uuid::new_v4().as_simple());
        let db_path = std::env::temp_dir().join(format!(
            "simple-alert-proxy-{}.db",
            uuid::Uuid::new_v4().as_simple()
        ));
        let mut config = test_config("http://127.0.0.1:1");
        config.storage.path = db_path.to_string_lossy().to_string();
        config.management.auth = None;
        config.management.bootstrap_admin_password_env = env_name.clone();

        unsafe {
            env::set_var(&env_name, "initial bootstrap password");
        }
        let first = build_app(Arc::new(config.clone()), "/webhooks/signoz".to_string()).unwrap();
        assert_eq!(
            login_status(first, "admin", "initial bootstrap password").await,
            StatusCode::OK
        );

        unsafe {
            env::set_var(&env_name, "changed bootstrap password");
        }
        let second = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();
        assert_eq!(
            login_status(second.clone(), "admin", "initial bootstrap password").await,
            StatusCode::OK
        );
        assert_eq!(
            login_status(second, "admin", "changed bootstrap password").await,
            StatusCode::UNAUTHORIZED
        );

        unsafe {
            env::remove_var(&env_name);
        }
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn session_cookie_uses_secure_attribute_when_enabled() {
        let expires_at = storage::now_epoch_millis() + 60_000;

        assert!(session_cookie("token", expires_at, true).contains("; Secure"));
        assert!(expired_session_cookie(true).contains("; Secure"));
        assert!(!session_cookie("token", expires_at, false).contains("; Secure"));
        assert!(!expired_session_cookie(false).contains("; Secure"));
    }

    #[test]
    fn password_change_audit_records_acting_admin() {
        let storage = Storage::open(":memory:").unwrap();
        let admin = storage
            .create_user("admin", "Administrator", "hash", "admin")
            .unwrap();
        let user = storage
            .create_user("target", "Target", "hash", "viewer")
            .unwrap();

        storage
            .update_user_password(
                user.id,
                "new-hash",
                AuditActor {
                    user_id: Some(admin.id),
                    display_name: Some(admin.display_name),
                    team_id: None,
                },
            )
            .unwrap();

        assert_eq!(storage.audit_actions().unwrap(), vec!["change_password"]);
        assert_eq!(
            storage.audit_actor_user_ids().unwrap(),
            vec![Some(admin.id)]
        );
    }

    #[test]
    fn password_change_revokes_existing_sessions() {
        let storage = Storage::open(":memory:").unwrap();
        let user = storage
            .create_user("target", "Target", "hash", "viewer")
            .unwrap();
        let now = storage::now_epoch_millis();
        storage
            .create_session("session-hash", user.id, "csrf-token", now + 60_000)
            .unwrap();

        storage
            .update_user_password(user.id, "new-hash", AuditActor::default())
            .unwrap();

        assert!(storage.session_user("session-hash").unwrap().is_none());
        assert_eq!(storage.session_count().unwrap(), 0);
    }

    #[test]
    fn cannot_disable_last_active_admin() {
        let storage = Storage::open(":memory:").unwrap();
        let first = storage
            .create_user("first", "First", "hash", "admin")
            .unwrap();

        assert_eq!(
            storage
                .disable_user(first.id, AuditActor::default())
                .unwrap(),
            DisableUserOutcome::LastActiveAdmin
        );

        storage
            .create_user("second", "Second", "hash", "admin")
            .unwrap();
        assert_eq!(
            storage
                .disable_user(first.id, AuditActor::default())
                .unwrap(),
            DisableUserOutcome::Disabled
        );
    }

    #[test]
    fn expired_sessions_can_be_swept_without_token_lookup() {
        let storage = Storage::open(":memory:").unwrap();
        let user = storage
            .create_user("session-user", "Session User", "hash", "admin")
            .unwrap();
        let now = storage::now_epoch_millis();
        storage
            .create_session("expired", user.id, "csrf-expired", now - 1)
            .unwrap();
        storage
            .create_session("active", user.id, "csrf-active", now + 60_000)
            .unwrap();

        assert_eq!(storage.session_count().unwrap(), 2);
        assert_eq!(storage.delete_expired_sessions().unwrap(), 1);
        assert_eq!(storage.session_count().unwrap(), 1);
    }

    #[tokio::test]
    async fn management_allow_unauthenticated_overrides_server_auth_fallback() {
        let mut config = test_config("http://127.0.0.1:1");
        config.management.allow_unauthenticated = true;
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let api_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/alert-groups")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(api_response.status(), StatusCode::OK);

        let debug_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/debug/webhook")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(debug_response.status(), StatusCode::ACCEPTED);

        let webhook_response = app
            .oneshot(signoz_request(fixture_payload()))
            .await
            .unwrap();
        assert_eq!(webhook_response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn debug_webhook_uses_management_auth() {
        let mut config = test_config("http://127.0.0.1:1");
        config.management.auth = Some(AuthConfig {
            bearer_token: "management-token".to_string(),
        });
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/debug/webhook")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer management-token")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[test]
    fn example_config_loads_without_migration() {
        let config = AppConfig::load("examples/config.yaml").unwrap();

        config.validate().unwrap();
        assert_eq!(config.server.webhook_path, "/webhooks/signoz");
        assert_eq!(config.server.max_body_bytes, 1024 * 1024);
        assert!(config.server.auth.is_some());
        assert!(config.alert_grouping.enabled);
        assert!(matches!(
            config.integrations.get("openvas-example"),
            Some(IntegrationConfig::GenericJson(_))
        ));
        assert!(matches!(
            config.integrations.get("signoz"),
            Some(IntegrationConfig::Builtin(integration))
                if integration.preset == "signoz" && integration.path == "/webhooks/signoz"
        ));
        assert_eq!(
            config.routing.default_receiver.as_deref(),
            Some("default-chat")
        );
        assert!(matches!(
            config.receivers.get("critical-chat"),
            Some(ReceiverConfig::GoogleChat(_))
        ));
    }

    #[test]
    fn duplicate_integration_paths_are_rejected() {
        let mut config = test_config("http://127.0.0.1:1");
        config.integrations = BTreeMap::from([
            (
                "signoz".to_string(),
                IntegrationConfig::Builtin(BuiltinIntegrationConfig {
                    preset: "signoz".to_string(),
                    path: "/webhooks/shared".to_string(),
                    auth: None,
                }),
            ),
            (
                "openvas".to_string(),
                IntegrationConfig::GenericJson(Box::new(GenericJsonIntegrationConfig {
                    preset: None,
                    path: "/webhooks/shared".to_string(),
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
                })),
            ),
        ]);

        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("duplicates integration"));
    }

    #[tokio::test]
    async fn default_signoz_webhook_path_accepts_existing_payload() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let config = test_config(&chat_url);
        let app = build_app(Arc::new(config.clone()), config.server.webhook_path).unwrap();

        let response = app
            .oneshot(signoz_request(fixture_payload()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        wait_for_received_count(&received, 1).await;
        let received = received.lock().unwrap();
        assert_eq!(
            received[0]["cardsV2"][0]["card"]["header"]["title"].as_str(),
            Some("[firing] HighErrorRate via critical-production")
        );
    }

    #[tokio::test]
    async fn legacy_server_webhook_path_under_webhooks_still_accepts_signoz() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let mut config = test_config(&chat_url);
        config.server.webhook_path = "/webhooks/legacy-signoz".to_string();
        let app = build_app(Arc::new(config.clone()), config.server.webhook_path).unwrap();

        let response = app
            .oneshot(signoz_request_to(
                "/webhooks/legacy-signoz",
                fixture_payload(),
                "test-token",
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        wait_for_received_count(&received, 1).await;
    }

    #[tokio::test]
    async fn configured_builtin_signoz_path_accepts_existing_payload() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let mut config = test_config(&chat_url);
        config.integrations = BTreeMap::from([(
            "sig-noz-prod".to_string(),
            IntegrationConfig::Builtin(BuiltinIntegrationConfig {
                preset: "signoz".to_string(),
                path: "/webhooks/sig-noz-prod".to_string(),
                auth: Some(AuthConfig {
                    bearer_token: "integration-token".to_string(),
                }),
            }),
        )]);
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(signoz_request_to(
                "/webhooks/sig-noz-prod",
                fixture_payload(),
                "integration-token",
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        wait_for_received_count(&received, 1).await;
        let received = received.lock().unwrap();
        assert_eq!(
            received[0]["cardsV2"][0]["card"]["header"]["title"].as_str(),
            Some("[firing] HighErrorRate via critical-production")
        );
    }

    #[tokio::test]
    async fn configured_builtin_signoz_auth_overrides_server_auth() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let mut config = test_config(&chat_url);
        config.integrations = BTreeMap::from([(
            "signoz".to_string(),
            IntegrationConfig::Builtin(BuiltinIntegrationConfig {
                preset: "signoz".to_string(),
                path: "/webhooks/signoz".to_string(),
                auth: Some(AuthConfig {
                    bearer_token: "integration-token".to_string(),
                }),
            }),
        )]);
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let server_auth_response = app
            .clone()
            .oneshot(signoz_request_to(
                "/webhooks/signoz",
                fixture_payload(),
                "test-token",
            ))
            .await
            .unwrap();
        assert_eq!(server_auth_response.status(), StatusCode::UNAUTHORIZED);

        let integration_auth_response = app
            .oneshot(signoz_request_to(
                "/webhooks/signoz",
                fixture_payload(),
                "integration-token",
            ))
            .await
            .unwrap();
        assert_eq!(integration_auth_response.status(), StatusCode::ACCEPTED);
        wait_for_received_count(&received, 1).await;
    }

    #[tokio::test]
    async fn generic_webhook_path_normalizes_and_delivers_event() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let mut config = test_config(&chat_url);
        config.server.auth = None;
        config.routing.routes[0].matchers = vec![config::MatcherConfig {
            field: "label.severity".to_string(),
            equals: Some("high".to_string()),
            regex: None,
            contains: None,
        }];
        config.integrations = BTreeMap::from([(
            "openvas".to_string(),
            IntegrationConfig::GenericJson(Box::new(GenericJsonIntegrationConfig {
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
                labels: BTreeMap::from([("severity".to_string(), "risk.level".to_string())]),
                annotations: BTreeMap::from([("asset".to_string(), "asset.host".to_string())]),
                links: BTreeMap::from([("source".to_string(), "finding.url".to_string())]),
            })),
        )]);
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/openvas")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(include_str!(
                        "../examples/generic-json-webhook.json"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        wait_for_received_count(&received, 1).await;
        let received = received.lock().unwrap();
        assert_eq!(
            received[0]["cardsV2"][0]["card"]["header"]["title"].as_str(),
            Some("[firing] TLS certificate expired via critical-production")
        );
        assert_eq!(
            received[0]["cardsV2"][0]["card"]["header"]["subtitle"].as_str(),
            Some("openvas | firing | high")
        );
    }

    #[tokio::test]
    async fn webhook_accepts_after_persisting_before_delivery_finishes() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_slow_mock_google_chat(Arc::clone(&received)).await;
        let mut config = test_config(&chat_url);
        config.server.auth = None;
        config.alert_grouping.enabled = false;
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(signoz_request(fixture_payload()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(received.lock().unwrap().len(), 0);
        wait_for_received_count(&received, 1).await;
    }

    #[tokio::test]
    async fn delivery_worker_dead_letters_after_retry_exhaustion() {
        let storage = Storage::open(":memory:").unwrap();
        let event = AlertEvent::new(
            "test",
            "test",
            "firing",
            "critical",
            "Retry Test",
            "retry-test",
            serde_json::json!({}),
        );
        let event_id = storage.store_event(&event).unwrap();
        let delivery = Delivery {
            route_name: "default".to_string(),
            receiver: "dead-target".to_string(),
            escalation_policy: None,
        };
        let delivery_id = storage.queue_delivery(event_id, &delivery).unwrap();
        let worker = DeliveryWorker::new(
            storage.clone(),
            DeliveryConfig {
                max_attempts: 2,
                initial_backoff_millis: 1,
                max_backoff_millis: 1,
            },
            false,
        );

        worker
            .run(delivery_id, |_| async {
                Err::<(), String>("target delivery failed".to_string())
            })
            .await;

        assert_eq!(storage.event_count().unwrap(), 1);
        assert_eq!(storage.delivery_statuses().unwrap(), vec!["dead_letter"]);
        assert_eq!(storage.delivery_attempts().unwrap(), vec![2]);
    }

    #[tokio::test]
    async fn grouped_google_chat_delivery_dead_letters_when_flush_fails() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_rejecting_mock_google_chat(Arc::clone(&received)).await;
        let mut config = test_config(&chat_url);
        config.server.auth = None;
        config.management.allow_unauthenticated = true;
        config.alert_grouping.enabled = true;
        config.alert_grouping.debounce_millis = 1;
        config.delivery = DeliveryConfig {
            max_attempts: 1,
            initial_backoff_millis: 1,
            max_backoff_millis: 1,
        };
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .clone()
            .oneshot(signoz_request(fixture_payload()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        wait_for_delivery_status(app.clone(), "dead_letter", 1).await;
        wait_for_received_count(&received, 1).await;

        let deliveries = get_api_json(app, "/api/deliveries").await;
        assert_eq!(deliveries[0]["status"], "dead_letter");
        assert_eq!(
            deliveries[0]["last_error"],
            "target rejected delivery with status 500 Internal Server Error"
        );
    }

    #[tokio::test]
    async fn alert_group_api_tracks_repeated_and_resolved_events() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let mut config = test_config(&chat_url);
        config.server.auth = None;
        config.alert_grouping.enabled = false;
        config.routing.routes[0].matchers = vec![config::MatcherConfig {
            field: "fingerprint".to_string(),
            equals: Some("group-1".to_string()),
            regex: None,
            contains: None,
        }];
        config.integrations = generic_test_integrations();
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        for state in ["firing", "firing", "resolved"] {
            let response = app
                .clone()
                .oneshot(generic_request(serde_json::json!({
                    "state": state,
                    "risk": { "level": "critical" },
                    "finding": {
                        "id": "group-1",
                        "title": "Grouped alert",
                        "description": "repeat",
                        "plugin": "test"
                    }
                })))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/alert-groups")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let groups: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(groups[0]["fingerprint"], "group-1");
        assert_eq!(groups[0]["event_count"], 3);
        assert_eq!(groups[0]["status"], "resolved");
    }

    #[tokio::test]
    async fn lifecycle_actions_update_group_and_audit_records() {
        let storage = Storage::open(":memory:").unwrap();
        let event = AlertEvent::new(
            "test",
            "test",
            "firing",
            "critical",
            "Lifecycle Test",
            "lifecycle-test",
            serde_json::json!({}),
        );
        let event_id = storage.store_event(&event).unwrap();
        let delivery = Delivery {
            route_name: "default".to_string(),
            receiver: "target".to_string(),
            escalation_policy: None,
        };
        let delivery_id = storage.queue_delivery(event_id, &delivery).unwrap();
        storage
            .queue_escalation(event_id, "primary", 1_000)
            .unwrap();
        let group_id = storage.list_alert_groups().unwrap()[0].id;
        assert_eq!(storage.escalation_statuses().unwrap(), vec!["scheduled"]);

        storage.acknowledge_group(group_id).unwrap();
        storage.silence_group(group_id).unwrap();
        storage.resolve_group(group_id).unwrap();
        storage.replay_delivery(delivery_id).unwrap();

        let group = &storage.list_alert_groups().unwrap()[0];
        assert_eq!(group.status, "resolved");
        assert!(group.acknowledged_at.is_some());
        assert!(group.silenced_until.is_some());
        assert_eq!(storage.escalation_statuses().unwrap(), vec!["canceled"]);
        assert_eq!(
            storage.audit_actions().unwrap(),
            vec!["acknowledge", "silence", "resolve", "replay"]
        );
    }

    #[test]
    fn active_alert_group_preserves_ack_and_silence_state_on_duplicate_event() {
        let storage = Storage::open(":memory:").unwrap();
        let first_event = AlertEvent::new(
            "test",
            "test",
            "firing",
            "critical",
            "Continuation Test",
            "continuation-test",
            serde_json::json!({}),
        );
        storage.store_event(&first_event).unwrap();
        let group_id = storage.list_alert_groups().unwrap()[0].id;

        storage.acknowledge_group(group_id).unwrap();
        storage.silence_group(group_id).unwrap();

        let second_event = AlertEvent::new(
            "test",
            "test",
            "firing",
            "critical",
            "Continuation Test",
            "continuation-test",
            serde_json::json!({}),
        );
        storage.store_event(&second_event).unwrap();

        let groups = storage.list_alert_groups().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].status, "active");
        assert_eq!(groups[0].event_count, 2);
        assert!(groups[0].acknowledged_at.is_some());
        assert!(groups[0].silenced_until.is_some());
    }

    #[test]
    fn reactivated_alert_group_clears_stale_ack_and_silence_state() {
        let storage = Storage::open(":memory:").unwrap();
        let first_event = AlertEvent::new(
            "test",
            "test",
            "firing",
            "critical",
            "Continuation Test",
            "continuation-test",
            serde_json::json!({}),
        );
        storage.store_event(&first_event).unwrap();
        let group_id = storage.list_alert_groups().unwrap()[0].id;

        storage.acknowledge_group(group_id).unwrap();
        storage.silence_group(group_id).unwrap();
        storage.resolve_group(group_id).unwrap();

        let second_event = AlertEvent::new(
            "test",
            "test",
            "firing",
            "critical",
            "Continuation Test",
            "continuation-test",
            serde_json::json!({}),
        );
        storage.store_event(&second_event).unwrap();

        let groups = storage.list_alert_groups().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].status, "active");
        assert_eq!(groups[0].event_count, 2);
        assert!(groups[0].acknowledged_at.is_none());
        assert!(groups[0].silenced_until.is_none());
    }

    #[test]
    fn advisory_enrichment_is_stored_separately_from_group_state() {
        let storage = Storage::open(":memory:").unwrap();
        let event = AlertEvent::new(
            "test",
            "test",
            "firing",
            "critical",
            "Advisory Test",
            "advisory-test",
            serde_json::json!({}),
        );
        storage.store_event(&event).unwrap();
        let group_id = storage.list_alert_groups().unwrap()[0].id;

        storage
            .add_advisory(
                Some(group_id),
                "test-provider",
                "summary",
                "Likely duplicate",
            )
            .unwrap();

        let group = &storage.list_alert_groups().unwrap()[0];
        let advisory = &storage.list_advisories().unwrap()[0];
        assert_eq!(group.status, "active");
        assert_eq!(advisory.alert_group_id, Some(group_id));
        assert_eq!(advisory.kind, "summary");
        assert_eq!(advisory.value, "Likely duplicate");
    }

    #[tokio::test]
    async fn route_escalation_policy_schedules_and_ack_cancels_task() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let mut config = test_config(&chat_url);
        config.server.auth = None;
        config.alert_grouping.enabled = false;
        config.escalation = EscalationConfig {
            policies: BTreeMap::from([(
                "primary".to_string(),
                EscalationPolicyConfig {
                    steps: vec![EscalationStepConfig {
                        receiver: "critical-chat".to_string(),
                        delay_millis: 1_000,
                        stop_on_ack: true,
                        stop_on_resolve: true,
                    }],
                },
            )]),
        };
        config.routing.routes[0].escalation_policy = Some("primary".to_string());
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .clone()
            .oneshot(signoz_request(fixture_payload()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let groups = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/alert-groups")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = to_bytes(groups.into_body(), usize::MAX).await.unwrap();
        let groups: Value = serde_json::from_slice(&bytes).unwrap();
        let group_id = groups[0]["id"].as_i64().unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/alert-groups/{group_id}/ack"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn read_apis_expose_events_deliveries_integrations_and_routes() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let mut config = test_config(&chat_url);
        config.server.auth = None;
        config.alert_grouping.enabled = false;
        config.integrations = generic_test_integrations();
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .clone()
            .oneshot(generic_request(serde_json::json!({
                "state": "firing",
                "risk": { "level": "high" },
                "finding": {
                    "id": "api-1",
                    "title": "API alert",
                    "description": "api",
                    "plugin": "test"
                }
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        for uri in [
            "/api/alert-events",
            "/api/deliveries",
            "/api/integrations",
            "/api/routes",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert!(value.as_array().is_some_and(|items| !items.is_empty()));
        }
    }

    #[tokio::test]
    async fn generic_webhook_receiver_gets_canonical_event_payload() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let webhook_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let mut config = test_config("http://127.0.0.1:1");
        config.server.auth = None;
        config.routing.default_receiver = Some("generic-target".to_string());
        config.routing.routes.clear();
        config.integrations = generic_test_integrations();
        config.receivers.insert(
            "generic-target".to_string(),
            ReceiverConfig::GenericWebhook(GenericWebhookReceiverConfig {
                webhook_url,
                timeout_secs: 10,
            }),
        );
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(generic_request(serde_json::json!({
                "state": "firing",
                "risk": { "level": "high" },
                "finding": {
                    "id": "target-1",
                    "title": "Webhook target alert",
                    "description": "target",
                    "plugin": "test"
                }
            })))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        wait_for_received_count(&received, 1).await;
        let received = received.lock().unwrap();
        assert_eq!(received[0]["event"]["fingerprint"], "target-1");
        assert_eq!(received[0]["delivery"]["receiver"], "generic-target");
    }

    #[tokio::test]
    async fn end_to_end_synthetic_webhooks_route_deliver_and_dedupe_alert_groups() {
        let critical_received = Arc::new(Mutex::new(Vec::new()));
        let warning_received = Arc::new(Mutex::new(Vec::new()));
        let default_received = Arc::new(Mutex::new(Vec::new()));
        let critical_url = spawn_mock_google_chat(Arc::clone(&critical_received)).await;
        let warning_url = spawn_mock_google_chat(Arc::clone(&warning_received)).await;
        let default_url = spawn_mock_google_chat(Arc::clone(&default_received)).await;
        let mut config = test_config("http://127.0.0.1:1");
        config.server.auth = None;
        config.alert_grouping.enabled = false;
        config.integrations = synthetic_test_integrations();
        config.routing.default_receiver = Some("default-target".to_string());
        config.routing.routes = vec![
            config::RouteConfig {
                name: "critical-synthetic".to_string(),
                receiver: "critical-target".to_string(),
                escalation_policy: None,
                continue_matching: false,
                matchers: vec![config::MatcherConfig {
                    field: "severity".to_string(),
                    equals: Some("critical".to_string()),
                    regex: None,
                    contains: None,
                }],
            },
            config::RouteConfig {
                name: "warning-synthetic".to_string(),
                receiver: "warning-target".to_string(),
                escalation_policy: None,
                continue_matching: false,
                matchers: vec![config::MatcherConfig {
                    field: "severity".to_string(),
                    equals: Some("warning".to_string()),
                    regex: None,
                    contains: None,
                }],
            },
        ];
        config.receivers = BTreeMap::from([
            (
                "critical-target".to_string(),
                ReceiverConfig::GenericWebhook(GenericWebhookReceiverConfig {
                    webhook_url: critical_url,
                    timeout_secs: 10,
                }),
            ),
            (
                "warning-target".to_string(),
                ReceiverConfig::GenericWebhook(GenericWebhookReceiverConfig {
                    webhook_url: warning_url,
                    timeout_secs: 10,
                }),
            ),
            (
                "default-target".to_string(),
                ReceiverConfig::GenericWebhook(GenericWebhookReceiverConfig {
                    webhook_url: default_url,
                    timeout_secs: 10,
                }),
            ),
        ]);
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();
        let mut generator = SyntheticWebhookGenerator::new();

        for payload in [
            generator.alert("svc-cpu", "firing", "critical", "checkout", "CPU saturated"),
            generator.alert(
                "svc-disk",
                "firing",
                "warning",
                "postgres",
                "Disk space low",
            ),
            generator.alert(
                "svc-latency",
                "firing",
                "info",
                "frontend",
                "Latency rising",
            ),
            generator.alert("svc-cpu", "firing", "critical", "checkout", "CPU saturated"),
            generator.alert(
                "svc-cpu",
                "resolved",
                "critical",
                "checkout",
                "CPU saturated",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(synthetic_request(payload))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }

        wait_for_received_count(&critical_received, 3).await;
        wait_for_received_count(&warning_received, 1).await;
        wait_for_received_count(&default_received, 1).await;
        wait_for_succeeded_deliveries(app.clone(), 5).await;

        let critical = critical_received.lock().unwrap().clone();
        assert_eq!(critical.len(), 3);
        assert!(critical.iter().all(|payload| {
            payload["event"]["fingerprint"] == "svc-cpu"
                && payload["event"]["severity"] == "critical"
                && payload["event"]["source"] == "synthetic-monitor"
                && payload["event"]["labels"]["service"] == "checkout"
                && payload["delivery"]["route"] == "critical-synthetic"
                && payload["delivery"]["receiver"] == "critical-target"
        }));
        assert!(
            critical
                .iter()
                .any(|payload| payload["event"]["status"] == "resolved")
        );

        let warning = warning_received.lock().unwrap().clone();
        assert_eq!(warning[0]["event"]["fingerprint"], "svc-disk");
        assert_eq!(warning[0]["event"]["severity"], "warning");
        assert_eq!(warning[0]["delivery"]["route"], "warning-synthetic");
        assert_eq!(warning[0]["delivery"]["receiver"], "warning-target");

        let default = default_received.lock().unwrap().clone();
        assert_eq!(default[0]["event"]["fingerprint"], "svc-latency");
        assert_eq!(default[0]["event"]["severity"], "info");
        assert_eq!(default[0]["delivery"]["route"], "default");
        assert_eq!(default[0]["delivery"]["receiver"], "default-target");

        let groups = get_api_json(app.clone(), "/api/alert-groups").await;
        let critical_group = find_record(&groups, "fingerprint", "svc-cpu");
        assert_eq!(critical_group["event_count"], 3);
        assert_eq!(critical_group["status"], "resolved");
        assert_eq!(critical_group["severity"], "critical");
        assert_eq!(
            find_record(&groups, "fingerprint", "svc-disk")["event_count"],
            1
        );
        assert_eq!(
            find_record(&groups, "fingerprint", "svc-latency")["status"],
            "active"
        );

        let events = get_api_json(app.clone(), "/api/alert-events").await;
        assert_eq!(events.as_array().unwrap().len(), 5);
        assert_eq!(
            find_record(&events, "fingerprint", "svc-cpu")["raw_payload"]["asset"]["service"],
            "checkout"
        );

        let deliveries = get_api_json(app, "/api/deliveries").await;
        let targets = deliveries
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["target"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            targets
                .iter()
                .filter(|target| **target == "critical-target")
                .count(),
            3
        );
        assert_eq!(
            targets
                .iter()
                .filter(|target| **target == "warning-target")
                .count(),
            1
        );
        assert_eq!(
            targets
                .iter()
                .filter(|target| **target == "default-target")
                .count(),
            1
        );
        assert!(deliveries.as_array().unwrap().iter().all(|record| {
            record["status"] == "succeeded" && record["attempt_count"].as_u64() == Some(1)
        }));
    }

    #[tokio::test]
    async fn end_to_end_continue_matching_delivers_one_event_to_multiple_receivers() {
        let primary_received = Arc::new(Mutex::new(Vec::new()));
        let secondary_received = Arc::new(Mutex::new(Vec::new()));
        let primary_url = spawn_mock_google_chat(Arc::clone(&primary_received)).await;
        let secondary_url = spawn_mock_google_chat(Arc::clone(&secondary_received)).await;
        let mut config = test_config("http://127.0.0.1:1");
        config.server.auth = None;
        config.alert_grouping.enabled = false;
        config.integrations = synthetic_test_integrations();
        config.routing.default_receiver = None;
        config.routing.routes = vec![
            config::RouteConfig {
                name: "primary-critical".to_string(),
                receiver: "primary-target".to_string(),
                escalation_policy: None,
                continue_matching: true,
                matchers: vec![config::MatcherConfig {
                    field: "severity".to_string(),
                    equals: Some("critical".to_string()),
                    regex: None,
                    contains: None,
                }],
            },
            config::RouteConfig {
                name: "checkout-service".to_string(),
                receiver: "secondary-target".to_string(),
                escalation_policy: None,
                continue_matching: false,
                matchers: vec![config::MatcherConfig {
                    field: "label.service".to_string(),
                    equals: Some("checkout".to_string()),
                    regex: None,
                    contains: None,
                }],
            },
        ];
        config.receivers = BTreeMap::from([
            (
                "primary-target".to_string(),
                ReceiverConfig::GenericWebhook(GenericWebhookReceiverConfig {
                    webhook_url: primary_url,
                    timeout_secs: 10,
                }),
            ),
            (
                "secondary-target".to_string(),
                ReceiverConfig::GenericWebhook(GenericWebhookReceiverConfig {
                    webhook_url: secondary_url,
                    timeout_secs: 10,
                }),
            ),
        ]);
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();
        let mut generator = SyntheticWebhookGenerator::new();

        let response = app
            .clone()
            .oneshot(synthetic_request(generator.alert(
                "svc-cpu",
                "firing",
                "critical",
                "checkout",
                "CPU saturated",
            )))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        wait_for_received_count(&primary_received, 1).await;
        wait_for_received_count(&secondary_received, 1).await;
        wait_for_succeeded_deliveries(app.clone(), 2).await;

        assert_eq!(
            primary_received.lock().unwrap()[0]["delivery"]["route"],
            "primary-critical"
        );
        assert_eq!(
            secondary_received.lock().unwrap()[0]["delivery"]["route"],
            "checkout-service"
        );

        let events = get_api_json(app.clone(), "/api/alert-events").await;
        assert_eq!(events.as_array().unwrap().len(), 1);

        let groups = get_api_json(app.clone(), "/api/alert-groups").await;
        assert_eq!(groups.as_array().unwrap().len(), 1);
        assert_eq!(groups[0]["fingerprint"], "svc-cpu");
        assert_eq!(groups[0]["event_count"], 1);

        let deliveries = get_api_json(app, "/api/deliveries").await;
        let delivery_records = deliveries.as_array().unwrap();
        assert_eq!(delivery_records.len(), 2);
        assert!(
            delivery_records
                .iter()
                .all(|record| record["alert_event_id"] == events[0]["id"])
        );
        let routed_targets = delivery_records
            .iter()
            .map(|record| {
                let summary: Value =
                    serde_json::from_str(record["request_summary"].as_str().unwrap()).unwrap();
                (
                    summary["route"].as_str().unwrap().to_string(),
                    summary["receiver"].as_str().unwrap().to_string(),
                )
            })
            .collect::<Vec<_>>();
        assert!(
            routed_targets
                .contains(&("primary-critical".to_string(), "primary-target".to_string()))
        );
        assert!(routed_targets.contains(&(
            "checkout-service".to_string(),
            "secondary-target".to_string()
        )));
    }

    #[tokio::test]
    async fn generic_webhook_path_rejects_unknown_integration() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/unknown")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn accepts_webhook_without_auth_when_auth_disabled() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let mut config = test_config(&chat_url);
        config.server.auth = None;
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/signoz")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(include_str!("../examples/signoz-webhook.json")))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        wait_for_received_count(&received, 1).await;
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
    }

    #[tokio::test]
    async fn debug_webhook_logs_payload_with_bearer_token() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/debug/webhook")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from(
                        serde_json::json!({
                            "source": "manual-debug",
                            "message": "debug payload"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["logged"], true);
    }

    #[tokio::test]
    async fn debug_webhook_requires_bearer_token() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/debug/webhook")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn debug_webhook_accepts_loopback_local_mode_without_management_auth() {
        let mut config = test_config("http://127.0.0.1:1");
        config.server.auth = None;
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/debug/webhook")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn rejects_missing_bearer_token() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/signoz")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(include_str!("../examples/signoz-webhook.json")))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn routes_to_google_chat_receiver() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let config = test_config(&chat_url);
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/signoz")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from(include_str!("../examples/signoz-webhook.json")))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let summary: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(summary["receivers"][0], "critical-chat");

        wait_for_received_count(&received, 1).await;
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert!(received[0].get("text").is_none());
        assert_eq!(
            received[0]["cardsV2"][0]["card"]["header"]["title"].as_str(),
            Some("[firing] HighErrorRate via critical-production")
        );
        assert!(received[0]["cardsV2"].is_array());
    }

    #[tokio::test]
    async fn groups_incoming_alerts_by_rule_id_before_delivery() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let config = test_config(&chat_url);
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/signoz")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::from(
                        serde_json::json!({
                            "status": "firing",
                            "commonLabels": {
                                "environment": "production"
                            },
                            "commonAnnotations": {},
                            "alerts": [
                                {
                                    "status": "firing",
                                    "labels": {
                                        "alertname": "Disk Space Low",
                                        "host.name": "host-a",
                                        "mountpoint": "/",
                                        "ruleId": "rule-disk",
                                        "severity": "critical"
                                    },
                                    "annotations": {}
                                },
                                {
                                    "status": "firing",
                                    "labels": {
                                        "alertname": "Disk Space Low",
                                        "host.name": "host-b",
                                        "mountpoint": "/var",
                                        "ruleId": "rule-disk",
                                        "severity": "critical"
                                    },
                                    "annotations": {}
                                },
                                {
                                    "status": "firing",
                                    "labels": {
                                        "alertname": "CPU Saturated",
                                        "host.name": "host-c",
                                        "ruleId": "rule-cpu",
                                        "severity": "critical"
                                    },
                                    "annotations": {}
                                }
                            ]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let summary: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(summary["delivered"], 2);

        wait_for_received_count(&received, 2).await;
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(
            received[0]["cardsV2"][0]["card"]["header"]["title"].as_str(),
            Some("[firing] CPU Saturated via critical-production")
        );
        assert_eq!(
            received[0]["cardsV2"][0]["card"]["header"]["subtitle"].as_str(),
            Some("1 instance | critical: 1")
        );
        assert_eq!(
            received[1]["cardsV2"][0]["card"]["header"]["title"].as_str(),
            Some("[firing] Disk Space Low via critical-production")
        );
        assert_eq!(
            received[1]["cardsV2"][0]["card"]["header"]["subtitle"].as_str(),
            Some("2 instances | critical: 2")
        );
    }

    #[tokio::test]
    async fn groups_separate_webhooks_by_rule_id_before_delivery() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let config = test_config(&chat_url);
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let first = app
            .clone()
            .oneshot(signoz_request(serde_json::json!({
                "status": "firing",
                "commonLabels": {
                    "alertname": "Disk Space Low",
                    "environment": "production",
                    "severity": "critical",
                    "ruleSource": "https://signoz.example.test/alerts/edit?ruleId=rule-disk"
                },
                "commonAnnotations": {},
                "alerts": [{
                    "status": "firing",
                    "labels": {
                        "host.name": "host-a",
                        "mountpoint": "/",
                        "severity": "critical"
                    },
                    "annotations": {},
                    "generatorURL": "https://signoz.example.test/alerts/edit?ruleId=rule-disk"
                }]
            })))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);

        let second = app
            .oneshot(signoz_request(serde_json::json!({
                "status": "firing",
                "commonLabels": {
                    "alertname": "Disk Space Low",
                    "environment": "production",
                    "severity": "critical",
                    "ruleSource": "https://signoz.example.test/alerts/edit?ruleId=rule-disk"
                },
                "commonAnnotations": {},
                "alerts": [{
                    "status": "firing",
                    "labels": {
                        "host.name": "host-b",
                        "mountpoint": "/var",
                        "severity": "critical"
                    },
                    "annotations": {},
                    "generatorURL": "https://signoz.example.test/alerts/edit?ruleId=rule-disk"
                }]
            })))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::ACCEPTED);

        wait_for_received_count(&received, 1).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(
            received[0]["cardsV2"][0]["card"]["header"]["title"].as_str(),
            Some("[firing] Disk Space Low via critical-production")
        );
        assert_eq!(
            received[0]["cardsV2"][0]["card"]["header"]["subtitle"].as_str(),
            Some("2 instances | critical: 2")
        );
        let instances = received[0]["cardsV2"][0]["card"]["sections"][1]["widgets"]
            .as_array()
            .unwrap();
        assert_eq!(instances.len(), 2);
    }

    #[tokio::test]
    async fn groups_separate_webhooks_by_group_labels_rule_id() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let chat_url = spawn_mock_google_chat(Arc::clone(&received)).await;
        let config = test_config(&chat_url);
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let first = app
            .clone()
            .oneshot(signoz_request(serde_json::json!({
                "status": "firing",
                "commonLabels": {
                    "alertname": "Disk Space Low",
                    "environment": "production",
                    "severity": "critical"
                },
                "groupLabels": {
                    "ruleId": "rule-disk"
                },
                "commonAnnotations": {},
                "alerts": [{
                    "status": "firing",
                    "labels": {
                        "host.name": "host-a",
                        "mountpoint": "/",
                        "severity": "critical"
                    },
                    "annotations": {}
                }]
            })))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);

        let second = app
            .oneshot(signoz_request(serde_json::json!({
                "status": "firing",
                "commonLabels": {
                    "alertname": "Disk Space Low",
                    "environment": "production",
                    "severity": "critical"
                },
                "groupLabels": {
                    "ruleId": "rule-disk"
                },
                "commonAnnotations": {},
                "alerts": [{
                    "status": "firing",
                    "labels": {
                        "host.name": "host-b",
                        "mountpoint": "/var",
                        "severity": "critical"
                    },
                    "annotations": {}
                }]
            })))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::ACCEPTED);

        wait_for_received_count(&received, 1).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(
            received[0]["cardsV2"][0]["card"]["header"]["subtitle"].as_str(),
            Some("2 instances | critical: 2")
        );
        let instances = received[0]["cardsV2"][0]["card"]["sections"][1]["widgets"]
            .as_array()
            .unwrap();
        assert_eq!(instances.len(), 2);
    }

    #[tokio::test]
    async fn rejects_non_bearer_authorization_scheme() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/signoz")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Basic dGVzdDp0b2tlbg==")
                    .body(Body::from(include_str!("../examples/signoz-webhook.json")))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_wrong_bearer_token() {
        let config = test_config("http://127.0.0.1:1");
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/signoz")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-tokenx")
                    .body(Body::from(include_str!("../examples/signoz-webhook.json")))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_request_bodies_over_configured_limit() {
        let mut config = test_config("http://127.0.0.1:1");
        config.server.max_body_bytes = 16;
        config.server.auth = None;
        let app = build_app(Arc::new(config), "/webhooks/signoz".to_string()).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/signoz")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(include_str!("../examples/signoz-webhook.json")))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    async fn spawn_mock_google_chat(received: Arc<Mutex<Vec<Value>>>) -> String {
        let app =
            Router::new()
                .route(
                    "/chat",
                    post(
                        |State(received): State<Arc<Mutex<Vec<Value>>>>,
                         Json(payload): Json<Value>| async move {
                            received.lock().unwrap().push(payload);
                            StatusCode::OK
                        },
                    ),
                )
                .with_state(received);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/chat")
    }

    async fn spawn_slow_mock_google_chat(received: Arc<Mutex<Vec<Value>>>) -> String {
        let app =
            Router::new()
                .route(
                    "/chat",
                    post(
                        |State(received): State<Arc<Mutex<Vec<Value>>>>,
                         Json(payload): Json<Value>| async move {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            received.lock().unwrap().push(payload);
                            StatusCode::OK
                        },
                    ),
                )
                .with_state(received);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/chat")
    }

    async fn spawn_rejecting_mock_google_chat(received: Arc<Mutex<Vec<Value>>>) -> String {
        let app =
            Router::new()
                .route(
                    "/chat",
                    post(
                        |State(received): State<Arc<Mutex<Vec<Value>>>>,
                         Json(payload): Json<Value>| async move {
                            received.lock().unwrap().push(payload);
                            StatusCode::INTERNAL_SERVER_ERROR
                        },
                    ),
                )
                .with_state(received);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/chat")
    }

    async fn wait_for_received_count(received: &Arc<Mutex<Vec<Value>>>, expected: usize) {
        for _ in 0..100 {
            if received.lock().unwrap().len() >= expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "timed out waiting for {expected} Google Chat payloads; received {}",
            received.lock().unwrap().len()
        );
    }

    async fn get_api_json(app: Router, uri: &str) -> Value {
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn wait_for_succeeded_deliveries(app: Router, expected: usize) {
        for _ in 0..100 {
            let deliveries = get_api_json(app.clone(), "/api/deliveries").await;
            if deliveries.as_array().is_some_and(|records| {
                records.len() == expected
                    && records.iter().all(|record| record["status"] == "succeeded")
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let deliveries = get_api_json(app, "/api/deliveries").await;
        panic!("timed out waiting for {expected} succeeded deliveries: {deliveries}");
    }

    async fn wait_for_delivery_status(app: Router, status: &str, expected: usize) {
        for _ in 0..100 {
            let deliveries = get_api_json(app.clone(), "/api/deliveries").await;
            if deliveries.as_array().is_some_and(|records| {
                records.len() == expected && records.iter().all(|record| record["status"] == status)
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let deliveries = get_api_json(app, "/api/deliveries").await;
        panic!("timed out waiting for {expected} {status} deliveries: {deliveries}");
    }

    fn find_record<'a>(records: &'a Value, field: &str, expected: &str) -> &'a Value {
        records
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record[field].as_str() == Some(expected))
            .unwrap_or_else(|| panic!("missing record where {field} is {expected}: {records}"))
    }

    fn signoz_request(payload: Value) -> Request<Body> {
        signoz_request_to("/webhooks/signoz", payload, "test-token")
    }

    fn signoz_request_to(uri: &str, payload: Value, token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(payload.to_string()))
            .unwrap()
    }

    fn generic_request(payload: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/webhooks/openvas")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap()
    }

    fn synthetic_request(payload: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/webhooks/synthetic")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap()
    }

    struct SyntheticWebhookGenerator {
        sequence: u32,
    }

    impl SyntheticWebhookGenerator {
        fn new() -> Self {
            Self { sequence: 0 }
        }

        fn alert(
            &mut self,
            fingerprint: &str,
            status: &str,
            severity: &str,
            service: &str,
            title: &str,
        ) -> Value {
            self.sequence += 1;
            serde_json::json!({
                "state": status,
                "risk": { "level": severity },
                "finding": {
                    "id": fingerprint,
                    "title": title,
                    "description": format!("{title} generated by synthetic webhook {}", self.sequence),
                    "plugin": "synthetic-e2e",
                    "url": format!("https://alerts.example.test/findings/{fingerprint}")
                },
                "asset": {
                    "service": service,
                    "host": format!("{service}-{}", self.sequence)
                },
                "observed_at": format!("2026-07-07T11:{:02}:00Z", self.sequence)
            })
        }
    }

    fn generic_test_integrations() -> BTreeMap<String, IntegrationConfig> {
        BTreeMap::from([(
            "openvas".to_string(),
            IntegrationConfig::GenericJson(Box::new(GenericJsonIntegrationConfig {
                preset: None,
                path: "/webhooks/openvas".to_string(),
                auth: None,
                source: "openvas".to_string(),
                status: "state".to_string(),
                severity: Some("risk.level".to_string()),
                title: "finding.title".to_string(),
                body: Some("finding.description".to_string()),
                fingerprint: "finding.id".to_string(),
                starts_at: None,
                ends_at: None,
                labels: BTreeMap::from([("severity".to_string(), "risk.level".to_string())]),
                annotations: BTreeMap::from([("plugin".to_string(), "finding.plugin".to_string())]),
                links: BTreeMap::new(),
            })),
        )])
    }

    fn synthetic_test_integrations() -> BTreeMap<String, IntegrationConfig> {
        BTreeMap::from([(
            "synthetic".to_string(),
            IntegrationConfig::GenericJson(Box::new(GenericJsonIntegrationConfig {
                preset: None,
                path: "/webhooks/synthetic".to_string(),
                auth: None,
                source: "synthetic-monitor".to_string(),
                status: "state".to_string(),
                severity: Some("risk.level".to_string()),
                title: "finding.title".to_string(),
                body: Some("finding.description".to_string()),
                fingerprint: "finding.id".to_string(),
                starts_at: Some("observed_at".to_string()),
                ends_at: None,
                labels: BTreeMap::from([
                    ("service".to_string(), "asset.service".to_string()),
                    ("host".to_string(), "asset.host".to_string()),
                ]),
                annotations: BTreeMap::from([("plugin".to_string(), "finding.plugin".to_string())]),
                links: BTreeMap::from([("source".to_string(), "finding.url".to_string())]),
            })),
        )])
    }

    fn fixture_payload() -> Value {
        serde_json::from_str(include_str!("../examples/signoz-webhook.json")).unwrap()
    }

    fn response_cookie(response: &Response) -> String {
        response
            .headers()
            .get(header::SET_COOKIE)
            .expect("response should set cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    async fn login_status(app: Router, username: &str, password: &str) -> StatusCode {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username": username,
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    fn test_config(webhook_url: &str) -> AppConfig {
        AppConfig {
            server: ServerConfig {
                bind: "127.0.0.1:0".to_string(),
                webhook_path: "/webhooks/signoz".to_string(),
                max_body_bytes: 1024 * 1024,
                limits: ServerLimitsConfig::default(),
                auth: Some(AuthConfig {
                    bearer_token: "test-token".to_string(),
                }),
                tls: None,
            },
            management: ManagementConfig::default(),
            integrations: BTreeMap::new(),
            storage: StorageConfig {
                r#type: "sqlite".to_string(),
                path: ":memory:".to_string(),
                retention_days: 90,
            },
            delivery: DeliveryConfig {
                max_attempts: 3,
                initial_backoff_millis: 1,
                max_backoff_millis: 1,
            },
            escalation: EscalationConfig::default(),
            intelligence: IntelligenceConfig::default(),
            alert_grouping: AlertGroupingConfig {
                enabled: true,
                debounce_millis: 10,
            },
            debug: DebugConfig {
                log_alerts: false,
                log_full_payloads: false,
            },
            routing: RoutingConfig {
                default_receiver: Some("default-chat".to_string()),
                routes: vec![config::RouteConfig {
                    name: "critical-production".to_string(),
                    receiver: "critical-chat".to_string(),
                    escalation_policy: None,
                    continue_matching: false,
                    matchers: vec![config::MatcherConfig {
                        field: "label.severity".to_string(),
                        equals: Some("critical".to_string()),
                        regex: None,
                        contains: None,
                    }],
                }],
            },
            receivers: BTreeMap::from([
                (
                    "default-chat".to_string(),
                    ReceiverConfig::GoogleChat(GoogleChatReceiverConfig {
                        webhook_url: "http://127.0.0.1:1".to_string(),
                        title_template: "[{{status}}] {{alertname}}".to_string(),
                        timeout_secs: 10,
                    }),
                ),
                (
                    "critical-chat".to_string(),
                    ReceiverConfig::GoogleChat(GoogleChatReceiverConfig {
                        webhook_url: webhook_url.to_string(),
                        title_template: "[{{status}}] {{alertname}}".to_string(),
                        timeout_secs: 10,
                    }),
                ),
            ]),
        }
    }
}
