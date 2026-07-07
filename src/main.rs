use anyhow::Context;
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::post,
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
mod routing;
mod signoz;
mod tls;

use crate::{
    config::{AppConfig, GoogleChatReceiverConfig},
    google_chat::{DebugDeliveryLog, GoogleChatClient},
    routing::{Delivery, RouteEngine},
    signoz::SigNozAlert,
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
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }

    Ok(())
}

fn build_app(config: Arc<AppConfig>, webhook_path: String) -> anyhow::Result<Router> {
    let max_body_bytes = config.server.max_body_bytes;
    let google_chat = GoogleChatClient::new();
    let state = AppState {
        router: Arc::new(RouteEngine::new(config.as_ref().clone())?),
        aggregator: AlertAggregator::new(&config, google_chat),
        config: Arc::clone(&config),
    };

    Ok(Router::new()
        .route("/healthz", post(healthz).get(healthz))
        .route(&webhook_path, post(handle_signoz_webhook))
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(TraceLayer::new_for_http())
        .with_state(state))
}

async fn healthz() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

async fn handle_signoz_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, WebhookError> {
    authorize(&state, &headers)?;

    let payload = serde_json::from_slice::<Value>(&body).map_err(signoz::AlertParseError::from)?;
    if state.config.debug.log_alerts {
        log_debug_json("incoming alert", &payload);
    }

    let alerts = SigNozAlert::from_value_grouped_by_rule_id(payload)?;
    let mut delivered_receivers = Vec::new();

    for alert in &alerts {
        let plan = state.router.plan(alert);

        for delivery in &plan.deliveries {
            let Some(receiver) = state.config.receivers.get(&delivery.receiver) else {
                error!(receiver = %delivery.receiver, "route selected missing receiver");
                continue;
            };

            match receiver {
                config::ReceiverConfig::GoogleChat(receiver) => {
                    state
                        .aggregator
                        .enqueue_google_chat(
                            receiver,
                            alert.clone(),
                            delivery.clone(),
                            state.config.debug.log_alerts,
                        )
                        .await?;
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

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), WebhookError> {
    let Some(auth) = &state.config.server.auth else {
        return Ok(());
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

fn log_debug_json(label: &str, value: &Value) {
    match serde_json::to_string_pretty(value) {
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
    #[error("delivery failed: {0}")]
    Delivery(#[from] google_chat::GoogleChatError),
}

impl IntoResponse for WebhookError {
    fn into_response(self) -> axum::response::Response {
        error!(error = %self, "webhook failed");
        let status = match self {
            WebhookError::Unauthorized => StatusCode::UNAUTHORIZED,
            WebhookError::InvalidPayload(_) => StatusCode::BAD_REQUEST,
            WebhookError::Delivery(_) => StatusCode::BAD_GATEWAY,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AlertGroupingConfig, AuthConfig, DebugConfig, GoogleChatReceiverConfig, ReceiverConfig,
        RoutingConfig, ServerConfig,
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
    fn example_config_loads_without_migration() {
        let config = AppConfig::load("examples/config.yaml").unwrap();

        config.validate().unwrap();
        assert_eq!(config.server.webhook_path, "/webhooks/signoz");
        assert_eq!(config.server.max_body_bytes, 1024 * 1024);
        assert!(config.server.auth.is_some());
        assert!(config.alert_grouping.enabled);
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

    fn signoz_request(payload: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/webhooks/signoz")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-token")
            .body(Body::from(payload.to_string()))
            .unwrap()
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
            alert_grouping: AlertGroupingConfig {
                enabled: true,
                debounce_millis: 10,
            },
            debug: DebugConfig { log_alerts: false },
            routing: RoutingConfig {
                default_receiver: Some("default-chat".to_string()),
                routes: vec![config::RouteConfig {
                    name: "critical-production".to_string(),
                    receiver: "critical-chat".to_string(),
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
