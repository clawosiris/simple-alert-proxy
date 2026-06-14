use anyhow::Context;
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use clap::Parser;
use serde_json::Value;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::trace::TraceLayer;
use tracing::{error, info};

mod config;
mod google_chat;
mod routing;
mod signoz;
mod tls;

use crate::{
    config::AppConfig,
    google_chat::GoogleChatClient,
    routing::{DeliveryPlan, RouteEngine},
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let state = AppState {
        router: Arc::new(RouteEngine::new(config.as_ref().clone())?),
        google_chat: GoogleChatClient::new(),
        config: Arc::clone(&config),
    };

    let app = Router::new()
        .route("/healthz", post(healthz).get(healthz))
        .route(&webhook_path, post(handle_signoz_webhook))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    info!(%bind_addr, %webhook_path, tls = config.server.tls.is_some(), "starting signoz-alert-proxy");

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

async fn healthz() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

async fn handle_signoz_webhook(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> Result<impl IntoResponse, WebhookError> {
    let alert = SigNozAlert::from_value(payload)?;
    let plan = state.router.plan(&alert);

    if plan.deliveries.is_empty() {
        return Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "delivered": 0 })),
        ));
    }

    for delivery in &plan.deliveries {
        let Some(receiver) = state.config.receivers.get(&delivery.receiver) else {
            error!(receiver = %delivery.receiver, "route selected missing receiver");
            continue;
        };

        match receiver {
            config::ReceiverConfig::GoogleChat(receiver) => {
                state.google_chat.send(receiver, &alert, delivery).await?;
            }
        }
    }

    Ok((StatusCode::ACCEPTED, Json(delivery_summary(&plan))))
}

fn delivery_summary(plan: &DeliveryPlan) -> Value {
    serde_json::json!({
        "delivered": plan.deliveries.len(),
        "receivers": plan.deliveries.iter().map(|item| &item.receiver).collect::<Vec<_>>(),
    })
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[derive(Debug, thiserror::Error)]
enum WebhookError {
    #[error("invalid SigNoz payload: {0}")]
    InvalidPayload(#[from] signoz::AlertParseError),
    #[error("delivery failed: {0}")]
    Delivery(#[from] google_chat::GoogleChatError),
}

impl IntoResponse for WebhookError {
    fn into_response(self) -> axum::response::Response {
        error!(error = %self, "webhook failed");
        let status = match self {
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
