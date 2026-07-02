//! TokenFuse gateway library: the budget-enforcing proxy assembled as an axum
//! `Router`. The binary (`main.rs`) wires real config around `app()`; tests
//! drive `app()` directly.

pub mod backtestcli;
pub mod cloudsink;
pub mod embedder;
pub mod estimate;
pub mod firewall;
pub mod ledger_backend;
pub mod mcpbroker;
pub mod mcpcli;
pub mod obs;
pub mod otel;
pub mod provider;
pub mod proxy;
#[cfg(feature = "cluster")]
pub mod raft_ledger;
pub mod settle;
pub mod sink;
pub mod sqlq;
pub mod state;
pub mod tui;
pub mod wasmpolicy;

use axum::routing::{get, post};
use axum::Router;
use state::AppState;

/// Build the gateway router from shared state.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(proxy::healthz))
        .route("/v1/messages", post(proxy::messages))
        .route("/v1/runs", get(obs::list_runs))
        .route("/v1/runs/{id}/kill", post(obs::kill_run))
        .with_state(state)
}
