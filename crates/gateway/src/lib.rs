//! TokenFuse gateway library: the budget-enforcing proxy assembled as an axum
//! `Router`. The binary (`main.rs`) wires real config around `app()`; tests
//! drive `app()` directly.

pub mod backtestcli;
pub mod cloudsink;
pub mod compliancecli;
pub mod embedder;
pub mod estimate;
pub mod events;
pub mod firewall;
pub mod focusexport;
pub mod ledger_backend;
pub mod mcpbroker;
pub mod mcpcli;
pub mod mcpclient;
pub mod mcpexposure_probe;
pub mod obs;
pub mod otel;
pub mod outcomescli;
pub mod pricebook;
pub mod provider;
pub mod proxy;
#[cfg(feature = "cluster")]
pub mod raft_ledger;
pub mod savingscli;
pub mod settle;
pub mod sink;
pub mod sqlq;
pub mod state;
pub mod tui;
pub mod wasmpolicy;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use state::AppState;

/// Default maximum request-body size (bytes). Bounds memory a single client can
/// force the gateway to buffer. Generous enough for large prompts; override with
/// `TOKENFUSE_MAX_BODY_BYTES`.
const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Build the gateway router from shared state.
pub fn app(state: AppState) -> Router {
    let max_body = std::env::var("TOKENFUSE_MAX_BODY_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_BODY_BYTES);
    Router::new()
        .route("/healthz", get(proxy::healthz))
        .route("/v1/messages", post(proxy::messages))
        .route("/v1/runs", get(obs::list_runs))
        .route("/v1/runs/{id}/kill", post(obs::kill_run))
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}
