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
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use subtle::ConstantTimeEq;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing::{error, info};

mod config;
mod google_chat;
mod routing;
mod signoz;
mod tls;

use crate::{
    config::AppConfig,
    google_chat::{DebugDeliveryLog, GoogleChatClient},
    routing::RouteEngine,
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
    google_chat: GoogleChatClient,
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
    let state = AppState {
        router: Arc::new(RouteEngine::new(config.as_ref().clone())?),
        google_chat: GoogleChatClient::new(),
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
                    let debug = state.config.debug.log_alerts.then_some(DebugDeliveryLog {
                        route_name: delivery.route_name.as_str(),
                        receiver_name: delivery.receiver.as_str(),
                    });
                    state
                        .google_chat
                        .send(receiver, alert, delivery, debug)
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
        AuthConfig, DebugConfig, GoogleChatReceiverConfig, ReceiverConfig, RoutingConfig,
        ServerConfig,
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
