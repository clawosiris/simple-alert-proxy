use crate::config::TlsConfig;
use anyhow::Context;
use axum::Router;
use std::net::SocketAddr;

pub async fn serve_tls(
    bind_addr: SocketAddr,
    app: Router,
    tls_config: &TlsConfig,
) -> anyhow::Result<()> {
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        &tls_config.cert_path,
        &tls_config.key_path,
    )
    .await
    .context("failed to load TLS certificate or key")?;

    axum_server::bind_rustls(bind_addr, rustls_config)
        .serve(app.into_make_service())
        .await
        .context("TLS server failed")
}
