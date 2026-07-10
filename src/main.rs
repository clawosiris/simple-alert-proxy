use anyhow::Context;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use serde_json::Value;
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex as AsyncMutex;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing::{error, info};

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
    storage::Storage,
};

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
    ) -> Result<(), WebhookError> {
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
                .await?;
            return Ok(());
        };

        let key = AggregationKey {
            receiver: delivery.receiver.clone(),
            route_name: delivery.route_name.clone(),
            status: alert.enrichment.overall_status.clone(),
            rule_id,
        };
        let mut should_spawn = false;

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
                    });
                    should_spawn = true;
                }
                Entry::Occupied(mut entry) => {
                    let bucket = entry.get_mut();
                    bucket.alerts.push(alert);
                }
            }
        }

        if should_spawn {
            let aggregator = self.clone();
            tokio::spawn(async move {
                aggregator.flush_after(key).await;
            });
        }

        Ok(())
    }

    async fn flush_after(&self, key: AggregationKey) {
        tokio::time::sleep(self.debounce).await;

        let Some(bucket) = self.pending.lock().await.remove(&key) else {
            return;
        };

        if let Err(error) = self.flush_bucket(&bucket).await {
            error!(%error, "grouped alert delivery failed");
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
            .map_err(|error| error.to_string())
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
    let google_chat = GoogleChatClient::new();
    let storage = Storage::open(&config.storage.path)?;
    let state = AppState {
        router: Arc::new(RouteEngine::new(config.as_ref().clone())?),
        aggregator: AlertAggregator::new(&config, google_chat),
        storage,
        config: Arc::clone(&config),
    };

    Ok(Router::new()
        .route("/healthz", post(healthz).get(healthz))
        .route("/", get(operator_ui))
        .route("/ui", get(operator_ui))
        .route("/debug/webhook", post(handle_debug_webhook))
        .route(&webhook_path, post(handle_signoz_webhook))
        .route("/webhooks/{integration}", post(handle_generic_webhook))
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
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(log_webhook_failures))
        .with_state(state))
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
        }
    }
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

async fn list_alert_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    authorize(state.config.server.auth.as_ref(), &headers)?;
    Ok(Json(state.storage.list_alert_groups()?))
}

async fn list_alert_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    authorize(state.config.server.auth.as_ref(), &headers)?;
    Ok(Json(state.storage.list_alert_events()?))
}

async fn list_deliveries(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    authorize(state.config.server.auth.as_ref(), &headers)?;
    Ok(Json(state.storage.list_deliveries()?))
}

async fn list_advisories(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    authorize(state.config.server.auth.as_ref(), &headers)?;
    Ok(Json(state.storage.list_advisories()?))
}

async fn list_integrations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    authorize(state.config.server.auth.as_ref(), &headers)?;
    let integrations = state
        .config
        .integrations
        .keys()
        .map(|name| serde_json::json!({ "name": name }))
        .collect::<Vec<_>>();
    Ok(Json(integrations))
}

async fn list_routes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    authorize(state.config.server.auth.as_ref(), &headers)?;
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
    authorize(state.config.server.auth.as_ref(), &headers)?;
    state.storage.acknowledge_group(id)?;
    Ok(StatusCode::ACCEPTED)
}

async fn resolve_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    authorize(state.config.server.auth.as_ref(), &headers)?;
    state.storage.resolve_group(id)?;
    Ok(StatusCode::ACCEPTED)
}

async fn silence_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    authorize(state.config.server.auth.as_ref(), &headers)?;
    state.storage.silence_group(id)?;
    Ok(StatusCode::ACCEPTED)
}

async fn replay_delivery(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, WebhookError> {
    authorize(state.config.server.auth.as_ref(), &headers)?;
    state.storage.replay_delivery(id)?;
    Ok(StatusCode::ACCEPTED)
}

async fn handle_debug_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, WebhookError> {
    authorize_required(state.config.server.auth.as_ref(), &headers)?;

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

async fn handle_signoz_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, WebhookError> {
    authorize(state.config.server.auth.as_ref(), &headers)?;

    let payload = serde_json::from_slice::<Value>(&body).map_err(signoz::AlertParseError::from)?;
    if state.config.debug.log_alerts {
        log_debug_json(
            "incoming alert",
            &payload,
            state.config.debug.log_full_payloads,
        );
    }

    let signoz = SigNozIntegration::new("signoz");
    let alerts = signoz.parse_alerts(payload)?;
    let mut delivered_receivers = Vec::new();

    for alert in &alerts {
        let event = alert.to_alert_event("signoz");
        let plan = state.router.plan(&event);

        for delivery in &plan.deliveries {
            let Some(receiver) = state.config.receivers.get(&delivery.receiver) else {
                error!(receiver = %delivery.receiver, "route selected missing receiver");
                continue;
            };

            match receiver {
                config::ReceiverConfig::GoogleChat(receiver) => {
                    queue_signoz_google_chat_delivery(
                        &state,
                        &event,
                        receiver,
                        alert.clone(),
                        delivery.clone(),
                    )?;
                    delivered_receivers.push(delivery.receiver.clone());
                }
                receiver => {
                    queue_target_event_delivery(&state, &event, receiver, delivery.clone())?;
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

async fn handle_generic_webhook(
    State(state): State<AppState>,
    Path(integration): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, WebhookError> {
    let (name, config) =
        integration::configured_integration(&state.config.integrations, &integration)?;
    authorize(
        config.auth.as_ref().or(state.config.server.auth.as_ref()),
        &headers,
    )?;

    let payload = serde_json::from_slice::<Value>(&body).map_err(signoz::AlertParseError::from)?;
    if state.config.debug.log_alerts {
        log_debug_json(
            "incoming generic alert",
            &payload,
            state.config.debug.log_full_payloads,
        );
    }

    let integration = GenericJsonIntegration::new(name, config);
    let events = integration.normalize(payload)?;
    let mut delivered_receivers = Vec::new();

    for event in &events {
        let plan = state.router.plan(event);

        for delivery in &plan.deliveries {
            let Some(receiver) = state.config.receivers.get(&delivery.receiver) else {
                error!(receiver = %delivery.receiver, "route selected missing receiver");
                continue;
            };

            queue_target_event_delivery(&state, event, receiver, delivery.clone())?;
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
    event: &AlertEvent,
    receiver: &GoogleChatReceiverConfig,
    alert: SigNozAlert,
    delivery: Delivery,
) -> Result<(), WebhookError> {
    let alert_event_id = state.storage.store_event(event)?;
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
                        .map_err(|error| error.to_string())
                }
            })
            .await;
    });

    Ok(())
}

fn queue_target_event_delivery(
    state: &AppState,
    event: &AlertEvent,
    receiver: &ReceiverConfig,
    delivery: Delivery,
) -> Result<(), WebhookError> {
    let alert_event_id = state.storage.store_event(event)?;
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

fn authorize(auth: Option<&config::AuthConfig>, headers: &HeaderMap) -> Result<(), WebhookError> {
    let Some(auth) = auth else {
        return Ok(());
    };

    authorize_required(Some(auth), headers)
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
        AlertGroupingConfig, AuthConfig, DebugConfig, DeliveryConfig, EscalationConfig,
        EscalationPolicyConfig, EscalationStepConfig, GenericJsonIntegrationConfig,
        GenericWebhookReceiverConfig, GoogleChatReceiverConfig, IntegrationConfig,
        IntelligenceConfig, ReceiverConfig, RoutingConfig, ServerConfig, StorageConfig,
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

    #[test]
    fn caller_details_prefers_forwarded_ip_over_peer_addr() {
        let mut request = Request::builder()
            .method("POST")
            .uri("/debug/webhook")
            .header("x-forwarded-for", "203.0.113.10, 10.0.0.2")
            .header("x-real-ip", "198.51.100.5")
            .header(header::USER_AGENT, "curl/8.0")
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
        assert_eq!(
            config.routing.default_receiver.as_deref(),
            Some("default-chat")
        );
        assert!(matches!(
            config.receivers.get("critical-chat"),
            Some(ReceiverConfig::GoogleChat(_))
        ));
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
            IntegrationConfig::GenericJson(GenericJsonIntegrationConfig {
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
            }),
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
    async fn debug_webhook_rejects_when_auth_is_not_configured() {
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

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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

    fn find_record<'a>(records: &'a Value, field: &str, expected: &str) -> &'a Value {
        records
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record[field].as_str() == Some(expected))
            .unwrap_or_else(|| panic!("missing record where {field} is {expected}: {records}"))
    }

    fn signoz_request(payload: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/webhooks/signoz")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-token")
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
            IntegrationConfig::GenericJson(GenericJsonIntegrationConfig {
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
            }),
        )])
    }

    fn synthetic_test_integrations() -> BTreeMap<String, IntegrationConfig> {
        BTreeMap::from([(
            "synthetic".to_string(),
            IntegrationConfig::GenericJson(GenericJsonIntegrationConfig {
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
            }),
        )])
    }

    fn fixture_payload() -> Value {
        serde_json::from_str(include_str!("../examples/signoz-webhook.json")).unwrap()
    }

    fn test_config(webhook_url: &str) -> AppConfig {
        AppConfig {
            server: ServerConfig {
                bind: "127.0.0.1:0".to_string(),
                webhook_path: "/webhooks/signoz".to_string(),
                max_body_bytes: 1024 * 1024,
                auth: Some(AuthConfig {
                    bearer_token: "test-token".to_string(),
                }),
                tls: None,
            },
            integrations: BTreeMap::new(),
            storage: StorageConfig {
                r#type: "sqlite".to_string(),
                path: ":memory:".to_string(),
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
