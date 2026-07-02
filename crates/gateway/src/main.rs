//! TokenFuse gateway binary. Defaults are safe for a drop-in trial: in-process
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
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        // `tokenfuse top` launches the live TUI.
        Some("top") => {
            let addr =
                std::env::var("TOKENFUSE_ADDR").unwrap_or_else(|_| "127.0.0.1:4100".to_string());
            let base = std::env::var("TOKENFUSE_URL").unwrap_or_else(|_| format!("http://{addr}"));
            if let Err(e) = tokenfuse_gateway::tui::run(base).await {
                eprintln!("tui error: {e}");
            }
        }
        // `tokenfuse sql "<query>"` queries the Parquet trace.
        Some("sql") => {
            let query = args.collect::<Vec<_>>().join(" ");
            if query.trim().is_empty() {
                eprintln!("usage: tokenfuse sql \"select ... from calls\"");
                return;
            }
            let dir = std::env::var("TOKENFUSE_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
            if let Err(e) = tokenfuse_gateway::sqlq::run(&query, &dir).await {
                eprintln!("sql error: {e}");
            }
        }
        // `tokenfuse backtest --budget … --max-steps …` replays a candidate
        // policy over the Parquet trace.
        Some("backtest") => {
            let rest: Vec<String> = args.collect();
            let dir = std::env::var("TOKENFUSE_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
            let policy = tokenfuse_gateway::backtestcli::parse_policy(&rest);
            if let Err(e) = tokenfuse_gateway::backtestcli::run(&dir, policy).await {
                eprintln!("backtest error: {e}");
            }
        }
        // Anything else starts the gateway.
        _ => serve().await,
    }
}

async fn serve() {
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

    let mut state = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(policy),
        provider,
        "default",
    );

    // Semantic cache: TOKENFUSE_CACHE = off | shadow | on (default shadow, which
    // records would-hits without serving them — safe to drop in).
    let cache_mode = match std::env::var("TOKENFUSE_CACHE").as_deref() {
        Ok("on") => tokenfuse_core::cache::CacheMode::On,
        Ok("off") => tokenfuse_core::cache::CacheMode::Off,
        _ => tokenfuse_core::cache::CacheMode::Shadow,
    };
    state = state.with_cache(Arc::new(tokenfuse_core::SemanticCache::new(
        tokenfuse_gateway::embedder::build(),
        tokenfuse_core::cache::CacheConfig {
            mode: cache_mode,
            ..Default::default()
        },
    )));
    tracing::info!(?cache_mode, "semantic cache");

    // Agent firewall: TOKENFUSE_FIREWALL = off | shadow | enforce (default off).
    let firewall = tokenfuse_gateway::firewall::from_env();
    tracing::info!(mode = ?firewall.mode, "agent firewall");
    state = state.with_firewall(Arc::new(firewall));

    // Opt in to the Parquet trace with TOKENFUSE_DATA_DIR; query it via
    // `tokenfuse sql "..."`. Without it, telemetry is a no-op.
    if let Ok(dir) = std::env::var("TOKENFUSE_DATA_DIR") {
        if !dir.is_empty() {
            match tokenfuse_gateway::sink::ParquetSink::new(&dir, 256) {
                Ok(sink) => {
                    tracing::info!(%dir, "recording trace to Parquet");
                    state = state.with_sink(Arc::new(sink));
                }
                Err(e) => tracing::warn!(%dir, "could not open trace dir: {e}"),
            }
        }
    }

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
