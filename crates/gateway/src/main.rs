//! Tokenfuse gateway binary. Defaults are safe for a drop-in trial: in-process
//! ledger, an illustrative price book, and shadow-mode policy.
//!
//! Provider selection:
//! - `TOKENFUSE_UPSTREAM=<url>` forwards to a real endpoint (e.g.
//!   `https://api.anthropic.com/v1/messages`) with SSE passthrough;
//! - unset → the deterministic stub, so `cargo run` works offline.

use std::sync::Arc;
use tokenfuse_core::{AnomalyConfig, Growth, Ledger, ModelPrice, Policy, PriceBook, Window};
use tokenfuse_gateway::app;
use tokenfuse_gateway::provider::{HttpProvider, Provider, StubProvider};
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

    let provider: Arc<dyn Provider> = match std::env::var("TOKENFUSE_UPSTREAM") {
        Ok(url) if !url.is_empty() => {
            tracing::info!(%url, "forwarding to real upstream");
            Arc::new(HttpProvider::new(url))
        }
        _ => {
            tracing::info!("no TOKENFUSE_UPSTREAM set — using stub provider");
            Arc::new(StubProvider::default())
        }
    };

    // Shadow mode by default (safe to drop in) with loop detectors wired on, so
    // the running gateway surfaces "would block" without changing behavior.
    let policy = Policy {
        anomalies: AnomalyConfig {
            identical_tool_call: Some(Window {
                window: 10,
                threshold: 3,
            }),
            pingpong_pair: Some(Window {
                window: 8,
                threshold: 2,
            }),
            context_growth: Some(Growth {
                factor: 1.5,
                consecutive: 3,
            }),
        },
        ..Policy::default()
    };

    let state = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(policy),
        provider,
        "default",
    );

    let addr = std::env::var("TOKENFUSE_ADDR").unwrap_or_else(|_| "127.0.0.1:4100".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");
    tracing::info!(%addr, "tokenfuse gateway listening");

    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
