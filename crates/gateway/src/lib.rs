//! Tokenfuse gateway library: the budget-enforcing proxy assembled as an axum
//! `Router`. The binary (`main.rs`) wires real config around `app()`; tests
//! drive `app()` directly.

pub mod estimate;
pub mod obs;
pub mod provider;
pub mod proxy;
pub mod settle;
pub mod state;
pub mod tui;

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
