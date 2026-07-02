//! TokenFuse gateway binary. Defaults are safe for a drop-in trial: in-process
//! ledger, an illustrative price book, and shadow-mode policy.
//!
//! Provider selection:
//! - `TOKENFUSE_UPSTREAM=<url>` forwards to a real endpoint (e.g.
//!   `https://api.anthropic.com/v1/messages`) with SSE passthrough;
//! - unset → the deterministic stub, so `cargo run` works offline.

use std::sync::Arc;
use tokenfuse_core::{AnomalyConfig, Growth, Ledger, Mode, ModelPrice, Policy, PriceBook, Window};
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
        // `tokenfuse mcp-scan <tools.json> [--lock <file>] [--write-lock]`
        Some("mcp-scan") => {
            let rest: Vec<String> = args.collect();
            let tools_path = rest.iter().find(|a| !a.starts_with("--")).cloned();
            let lock_path = rest
                .iter()
                .position(|a| a == "--lock")
                .and_then(|i| rest.get(i + 1).cloned());
            let write_lock = rest.iter().any(|a| a == "--write-lock");
            match tools_path {
                Some(p) => {
                    if let Err(e) =
                        tokenfuse_gateway::mcpcli::run(&p, lock_path.as_deref(), write_lock)
                    {
                        eprintln!("mcp-scan error: {e}");
                    }
                }
                None => eprintln!(
                    "usage: tokenfuse mcp-scan <tools.json> [--lock <file>] [--write-lock]"
                ),
            }
        }
        // `tokenfuse mcp-broker` runs the MCP credential-broker proxy.
        Some("mcp-broker") => mcp_broker().await,
        // Anything else starts the gateway.
        _ => serve().await,
    }
}

/// Run the MCP credential-broker: an agent points its MCP client here; the broker
/// injects secret handles and scans tool listings before forwarding upstream.
async fn mcp_broker() {
    use std::sync::Arc;
    use tokenfuse_gateway::mcpbroker::{app, BrokerState, ScanMode};

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let upstream = std::env::var("TOKENFUSE_MCP_UPSTREAM").unwrap_or_default();
    if upstream.is_empty() {
        eprintln!("set TOKENFUSE_MCP_UPSTREAM=<real MCP server url>");
        return;
    }
    let vault = tokenfuse_core::SecretVault::from_pairs(
        &std::env::var("TOKENFUSE_MCP_SECRETS").unwrap_or_default(),
    );
    let scan = match std::env::var("TOKENFUSE_MCP_SCAN").as_deref() {
        Ok("off") => ScanMode::Off,
        Ok("block") => ScanMode::Block,
        _ => ScanMode::Warn,
    };
    let state = Arc::new(BrokerState {
        upstream: upstream.clone(),
        vault,
        scan,
        client: reqwest::Client::new(),
    });
    let addr = std::env::var("TOKENFUSE_MCP_ADDR").unwrap_or_else(|_| "127.0.0.1:4200".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");
    tracing::info!(%addr, %upstream, "mcp credential-broker listening");
    axum::serve(listener, app(state))
        .await
        .expect("server error");
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

    // Enforcement mode: TOKENFUSE_MODE = shadow | warn | enforce. Default is
    // shadow (safe to drop in — surfaces "would block" without changing
    // behavior); set enforce to actually return 402 and cut the circuit.
    let mode = match std::env::var("TOKENFUSE_MODE").as_deref() {
        Ok("enforce") => Mode::Enforce,
        Ok("warn") => Mode::Warn,
        _ => Mode::Shadow,
    };
    tracing::info!(?mode, "policy mode");
    let policy = Policy {
        mode,
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

    // DLP: TOKENFUSE_DLP = off | shadow | mask | block (default off).
    let dlp = match std::env::var("TOKENFUSE_DLP").as_deref() {
        Ok("shadow") => tokenfuse_core::DlpMode::Shadow,
        Ok("mask") => tokenfuse_core::DlpMode::Mask,
        Ok("block") => tokenfuse_core::DlpMode::Block,
        _ => tokenfuse_core::DlpMode::Off,
    };
    tracing::info!(?dlp, "secret scanning (DLP)");
    state = state.with_dlp(dlp);

    // Custom WASM policy (built with --features wasm): TOKENFUSE_WASM_POLICY=<path>.
    #[cfg(feature = "wasm")]
    if let Ok(path) = std::env::var("TOKENFUSE_WASM_POLICY") {
        if !path.is_empty() {
            match tokenfuse_gateway::wasmpolicy::WasmPolicy::from_file(&path) {
                Ok(p) => {
                    tracing::info!(%path, "loaded custom WASM policy");
                    state = state.with_wasm(Arc::new(p));
                }
                Err(e) => tracing::warn!(%path, "failed to load WASM policy: {e}"),
            }
        }
    }

    // Compose the event sink: Parquet trace (TOKENFUSE_DATA_DIR) and/or OTLP
    // spans (TOKENFUSE_OTLP_ENDPOINT). Both optional; default is a no-op.
    use tokenfuse_gateway::sink::{EventSink, NullSink, ParquetSink, TeeSink};
    let mut sink: Arc<dyn EventSink> = Arc::new(NullSink);
    if let Ok(dir) = std::env::var("TOKENFUSE_DATA_DIR") {
        if !dir.is_empty() {
            match ParquetSink::new(&dir, 256) {
                Ok(s) => {
                    tracing::info!(%dir, "recording trace to Parquet");
                    sink = Arc::new(s);
                }
                Err(e) => tracing::warn!(%dir, "could not open trace dir: {e}"),
            }
        }
    }
    if let Ok(endpoint) = std::env::var("TOKENFUSE_OTLP_ENDPOINT") {
        if !endpoint.is_empty() {
            tracing::info!(%endpoint, "exporting OTLP spans");
            let otel = Arc::new(tokenfuse_gateway::otel::OtelSink::new(&endpoint));
            sink = Arc::new(TeeSink {
                first: sink,
                second: otel,
            });
        }
    }
    // TokenFuse Cloud: push telemetry to a control plane for a cross-fleet view,
    // and pull operator kills back down. TOKENFUSE_CLOUD_URL is the control
    // plane base URL; TOKENFUSE_CLOUD_KEY is the org key.
    if let (Ok(base), Ok(key)) = (
        std::env::var("TOKENFUSE_CLOUD_URL"),
        std::env::var("TOKENFUSE_CLOUD_KEY"),
    ) {
        if !base.is_empty() && !key.is_empty() {
            tracing::info!(%base, "connected to TokenFuse Cloud");
            // Pull kills from the cloud and apply them to this gateway's runs.
            let st = state.clone();
            tokenfuse_gateway::cloudsink::spawn_kill_poller(
                base.clone(),
                key.clone(),
                move |run| st.kill(run),
            );
            // Pull centrally-managed budgets (override the client-supplied budget).
            let stb = state.clone();
            tokenfuse_gateway::cloudsink::spawn_budget_poller(
                base.clone(),
                key.clone(),
                move |map| {
                    let budgets = map
                        .into_iter()
                        .map(|(run, micros)| (run, tokenfuse_core::Microusd(micros)))
                        .collect();
                    stb.set_cloud_budgets(budgets);
                },
            );
            let cloud = Arc::new(tokenfuse_gateway::cloudsink::CloudSink::new(base, key));
            // Periodic flush so telemetry ships promptly, not only once a batch fills.
            let flusher = cloud.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
                loop {
                    tick.tick().await;
                    flusher.flush();
                }
            });
            sink = Arc::new(TeeSink {
                first: sink,
                second: cloud,
            });
        }
    }
    state = state.with_sink(sink);

    // HA: replace the in-process ledger with a raft-replicated one shared across
    // gateways (built with --features cluster; configured via TOKENFUSE_CLUSTER_*).
    #[cfg(feature = "cluster")]
    if let Some(rl) = cluster_ledger().await {
        tracing::info!("budget ledger is raft-replicated (HA cluster mode)");
        state = state.with_ledger(rl);
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

/// Build the raft-replicated ledger from `TOKENFUSE_CLUSTER_*` env, or `None` if
/// cluster mode isn't configured. Requires the `cluster` feature.
///
/// * `TOKENFUSE_CLUSTER_ID`    — this node's id (enables cluster mode)
/// * `TOKENFUSE_CLUSTER_ADDR`  — this node's raft HTTP addr (default 127.0.0.1:5000+id)
/// * `TOKENFUSE_CLUSTER_PEERS` — `1=http://host:port,2=http://…` (all members incl. self)
/// * `TOKENFUSE_CLUSTER_BOOTSTRAP` — set on exactly one node to initialize
#[cfg(feature = "cluster")]
async fn cluster_ledger() -> Option<Arc<dyn tokenfuse_gateway::ledger_backend::LedgerBackend>> {
    use std::collections::BTreeMap;
    let id: u64 = std::env::var("TOKENFUSE_CLUSTER_ID").ok()?.parse().ok()?;
    let addr = std::env::var("TOKENFUSE_CLUSTER_ADDR")
        .unwrap_or_else(|_| format!("127.0.0.1:{}", 5000 + id));
    let peers_spec = std::env::var("TOKENFUSE_CLUSTER_PEERS").unwrap_or_default();
    let mut peers = BTreeMap::new();
    for pair in peers_spec.split(',').filter(|s| !s.is_empty()) {
        if let Some((pid, url)) = pair.split_once('=') {
            if let Ok(pid) = pid.trim().parse::<u64>() {
                peers.insert(pid, url.trim().to_string());
            }
        }
    }
    if peers.is_empty() {
        peers.insert(id, format!("http://{addr}"));
    }
    let bootstrap = std::env::var("TOKENFUSE_CLUSTER_BOOTSTRAP").is_ok();
    let data_dir = std::env::var("TOKENFUSE_CLUSTER_DATA_DIR").ok();
    let token = std::env::var("TOKENFUSE_CLUSTER_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    let sock = match addr.parse() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(%addr, "bad TOKENFUSE_CLUSTER_ADDR: {e}");
            return None;
        }
    };
    match tokenfuse_gateway::raft_ledger::RaftLedger::start(
        id,
        sock,
        Arc::new(peers),
        bootstrap,
        data_dir,
        token,
    )
    .await
    {
        Ok(rl) => Some(rl),
        Err(e) => {
            // Cluster mode was explicitly requested (TOKENFUSE_CLUSTER_ID set).
            // Fail fast rather than silently degrade to a non-HA local ledger —
            // silently losing durability/HA is worse than a clear startup error.
            tracing::error!("failed to start cluster ledger: {e}");
            eprintln!("fatal: TOKENFUSE_CLUSTER_* set but the cluster ledger failed to start: {e}");
            std::process::exit(1);
        }
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
