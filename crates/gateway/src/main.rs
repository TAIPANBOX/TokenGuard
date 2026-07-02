//! Tokenfuse gateway binary. Starts the proxy with sane defaults: in-process
//! ledger, an illustrative price book, shadow-mode policy (safe to drop in),
//! and — for now — the stub provider until real forwarding lands.

use std::sync::Arc;
use tokenfuse_core::{Ledger, ModelPrice, Policy, PriceBook};
use tokenfuse_gateway::app;
use tokenfuse_gateway::provider::StubProvider;
use tokenfuse_gateway::state::AppState;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Illustrative prices ($/Mtok). Real prices ship as a versioned price book.
    let prices = PriceBook::new()
        .with(
            "claude-sonnet",
            ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
        )
        .with(
            "claude-haiku",
            ModelPrice::per_mtok_usd(0.80, 4.0, 0.08, 1.0),
        )
        .with("gpt", ModelPrice::per_mtok_usd(2.5, 10.0, 0.25, 3.125))
        .with_fallback(ModelPrice::per_mtok_usd(15.0, 75.0, 1.5, 18.75));

    let state = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(Policy::default()), // shadow by default
        Arc::new(StubProvider::default()),
        "default",
    );

    let addr = std::env::var("TOKENFUSE_ADDR").unwrap_or_else(|_| "127.0.0.1:4100".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");
    tracing::info!(%addr, "tokenfuse gateway listening (stub provider, shadow mode)");

    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
