//! Control-plane binary. This PR (A2) serves the skeleton (`/healthz`,
//! `/v1/ingest`); further env wiring (alert threshold, durable snapshot path,
//! CORS) arrives with the endpoints that use it — see docs/14-mobile-companion.md.

use std::sync::Arc;

use tokenfuse_cloud::{app, parse_keys, AppState, Store};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let keys = parse_keys(&std::env::var("TOKENFUSE_CLOUD_KEYS").unwrap_or_default());
    let key_count = keys.len();
    let state = AppState::new(Arc::new(Store::new()), Arc::new(keys));

    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind control-plane address");
    tracing::info!("tokenfuse cloud control plane listening on {addr} ({key_count} org key(s))");
    axum::serve(listener, app(state))
        .await
        .expect("serve control plane");
}
