//! Control-plane binary. Serves the read + ingest surface (A2/A3) with optional
//! durable persistence. Mutations, pairing, push and the OpenAPI contract arrive
//! in later PRs — see docs/14-mobile-companion.md.

use std::sync::Arc;
use std::time::Duration;

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

    let alert_pct = std::env::var("TOKENFUSE_CLOUD_ALERT_PCT")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|p| *p > 0.0 && *p <= 1.0)
        .unwrap_or(0.8);

    let store = Arc::new(Store::new());

    // Durable persistence: load a snapshot on startup and autosave every 2s.
    if let Ok(path) = std::env::var("TOKENFUSE_CLOUD_DATA") {
        if !path.is_empty() {
            let p = std::path::PathBuf::from(&path);
            if let Err(e) = store.load(&p) {
                tracing::warn!("could not load snapshot {path}: {e}");
            }
            let s = Arc::clone(&store);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(2));
                loop {
                    ticker.tick().await;
                    if s.take_dirty() {
                        if let Err(e) = s.save(&p) {
                            tracing::warn!("could not save snapshot: {e}");
                        }
                    }
                }
            });
            tracing::info!("persisting state to {path}");
        }
    }

    let state = AppState::new(Arc::clone(&store), Arc::new(keys), alert_pct);

    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind control-plane address");
    tracing::info!("tokenfuse cloud control plane listening on {addr} ({key_count} org key(s))");
    axum::serve(listener, app(state))
        .await
        .expect("serve control plane");
}
