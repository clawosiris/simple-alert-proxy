use crate::config::{TlsConfig, TlsSource};
use anyhow::Context;
use axum::Router;
use std::{future::Future, net::SocketAddr, time::Duration};

pub async fn serve_tls(
    bind_addr: SocketAddr,
    app: Router,
    tls_config: &TlsConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let rustls_config = match (tls_config.cert_source()?, tls_config.key_source()?) {
        (TlsSource::Path(cert_path), TlsSource::Path(key_path)) => {
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
                .await
                .context("failed to load TLS certificate or key")?
        }
        (TlsSource::Pem(cert), TlsSource::Pem(key)) => {
            axum_server::tls_rustls::RustlsConfig::from_pem(cert, key)
                .await
                .context("failed to load TLS certificate or key from environment")?
        }
        (TlsSource::Path(_), TlsSource::Pem(_)) | (TlsSource::Pem(_), TlsSource::Path(_)) => {
            unreachable!("mixed TLS source types should be rejected during config validation")
        }
    };

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
    });

    axum_server::bind_rustls(bind_addr, rustls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("TLS server failed")
}
