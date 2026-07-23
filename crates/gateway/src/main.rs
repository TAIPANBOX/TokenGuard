//! TokenFuse gateway binary. Defaults are safe for a drop-in trial: in-process
//! ledger, an illustrative price book, and shadow-mode policy.
//!
//! Provider selection:
//! - `TOKENFUSE_UPSTREAM=<url>` forwards to a real endpoint (e.g.
//!   `https://api.anthropic.com/v1/messages`) with SSE passthrough;
//! - unset → the deterministic stub, so `cargo run` works offline.

use std::sync::Arc;
use tokenfuse_core::{AnomalyConfig, Growth, Ledger, Mode, Policy, Window};
use tokenfuse_gateway::app;
use tokenfuse_gateway::pricebook::default_price_book;
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
        // `tokenfuse savings` sums the avoided spend recorded at every
        // budget-protection block in the Parquet trace (the ROI of enforcement).
        Some("savings") => {
            let dir = std::env::var("TOKENFUSE_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
            if let Err(e) = tokenfuse_gateway::savingscli::run(&dir).await {
                eprintln!("savings error: {e}");
            }
        }
        // `tokenfuse compliance [--since <ms>] [--until <ms>] [--json]`
        //     `[--markdown] [--scan-report <file>]` projects the control catalog
        // against the Parquet trace into an auditor-ready evidence pack.
        Some("compliance") => {
            let rest: Vec<String> = args.collect();
            let dir = std::env::var("TOKENFUSE_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
            let cargs = tokenfuse_gateway::compliancecli::parse_args(&rest);
            if let Err(e) = tokenfuse_gateway::compliancecli::run(&dir, cargs).await {
                eprintln!("compliance error: {e}");
            }
        }
        // `tokenfuse mcp-scan <tools.json> [--lock <file>] [--write-lock]`
        //     `[--json] [--json-out <file>] [--sarif <file>] [--fail-on <severity>|none]`
        // `tokenfuse mcp-scan --url <endpoint> [--lock <file>] [--write-lock]`
        //     `[--json] [--json-out <file>] [--fail-on <severity>|none]`
        //     `[--skip-exposure] [--attempt-call --call-tool <name>]`
        Some("mcp-scan") => {
            let rest: Vec<String> = args.collect();
            let url_idx = rest.iter().position(|a| a == "--url");
            let url = url_idx.and_then(|i| rest.get(i + 1).cloned());
            let lock_idx = rest.iter().position(|a| a == "--lock");
            let lock_path = lock_idx.and_then(|i| rest.get(i + 1).cloned());
            let write_lock = rest.iter().any(|a| a == "--write-lock");
            let json_out_idx = rest.iter().position(|a| a == "--json-out");
            let json_out = json_out_idx.and_then(|i| rest.get(i + 1).cloned());
            let sarif_idx = rest.iter().position(|a| a == "--sarif");
            let sarif_out = sarif_idx.and_then(|i| rest.get(i + 1).cloned());
            let fail_on_idx = rest.iter().position(|a| a == "--fail-on");
            let fail_on_raw = fail_on_idx.and_then(|i| rest.get(i + 1).cloned());
            let call_tool_idx = rest.iter().position(|a| a == "--call-tool");
            let call_tool = call_tool_idx.and_then(|i| rest.get(i + 1).cloned());
            // Live-scan-only: exposure checks (unauth tools/list, plaintext
            // transport, wildcard CORS, SSRF-capable tools) run by default
            // against `--url` targets; `--skip-exposure` turns them off.
            // `--attempt-call` opts into the one invasive check (an
            // unauthenticated `tools/call`) — off by default because
            // invoking a stranger's tool is itself side-effecting. It
            // requires `--call-tool <name>`: the operator must name the
            // tool explicitly, since the server controls both the tool's
            // name and description and could describe a destructive tool as
            // "safe" to dodge an automatic keyword filter.
            let skip_exposure = rest.iter().any(|a| a == "--skip-exposure");
            let attempt_call = rest.iter().any(|a| a == "--attempt-call");
            let mode = if rest.iter().any(|a| a == "--json") {
                tokenfuse_gateway::mcpcli::OutputMode::Json
            } else {
                tokenfuse_gateway::mcpcli::OutputMode::Human
            };
            // `--fail-on` defaults to `high`; `none` disables failing.
            let threshold: Option<tokenfuse_core::Severity> = match fail_on_raw.as_deref() {
                None => Some(tokenfuse_core::Severity::High),
                Some("none") => None,
                Some(other) => match other.parse() {
                    Ok(s) => Some(s),
                    Err(e) => {
                        // A bad --fail-on is a config error: exit non-zero (2,
                        // distinct from 1 = findings) so a misconfigured CI
                        // pipeline fails loudly instead of silently passing.
                        eprintln!("mcp-scan error: {e}");
                        std::process::exit(2);
                    }
                },
            };
            // The bare positional tools-path arg: skip flags and the values
            // that belong to flags taking a value, so those don't get
            // mistaken for it.
            let flag_value_idx = [
                url_idx.map(|i| i + 1),
                lock_idx.map(|i| i + 1),
                json_out_idx.map(|i| i + 1),
                sarif_idx.map(|i| i + 1),
                fail_on_idx.map(|i| i + 1),
                call_tool_idx.map(|i| i + 1),
            ];
            let tools_path = rest
                .iter()
                .enumerate()
                .find(|(i, a)| !a.starts_with("--") && !flag_value_idx.contains(&Some(*i)))
                .map(|(_, a)| a.clone());
            let opts = tokenfuse_gateway::mcpcli::ScanOptions {
                lock_path,
                write_lock,
                mode,
                json_out,
                sarif_out,
                skip_exposure,
                attempt_call,
                call_tool,
            };
            // Ok(report) on a completed scan; Err(()) when the scan could not
            // run (bad args, a run/parse error, or nothing to scan). The Err
            // arms all `eprintln!` the reason so the operator sees it before
            // the non-zero exit below.
            let report: Result<tokenfuse_core::mcpreport::ScanReport, ()> = match (tools_path, url)
            {
                (Some(_), Some(_)) => {
                    eprintln!("mcp-scan error: pass either <tools.json> or --url, not both");
                    Err(())
                }
                (None, Some(url)) => tokenfuse_gateway::mcpcli::run_live(&url, &opts)
                    .await
                    .map_err(|e| eprintln!("mcp-scan error: {e}")),
                (Some(p), None) => {
                    // Exposure checks only make sense against a live server
                    // (`--url`); file mode has nothing to probe. Rather than
                    // silently ignoring a flag the caller took the trouble
                    // to pass, say so — a misused flag in a CI script should
                    // be visible, not a silent no-op.
                    if opts.skip_exposure || opts.attempt_call || opts.call_tool.is_some() {
                        eprintln!(
                            "mcp-scan: note: --skip-exposure/--attempt-call/--call-tool only apply to --url (live) scans; ignoring for file mode"
                        );
                    }
                    tokenfuse_gateway::mcpcli::run(&p, &opts)
                        .map_err(|e| eprintln!("mcp-scan error: {e}"))
                }
                (None, None) => {
                    eprintln!(
                        "usage: tokenfuse mcp-scan <tools.json> [--lock <file>] [--write-lock] [--json] [--json-out <file>] [--sarif <file>] [--fail-on <severity>|none]\n       tokenfuse mcp-scan --url <endpoint> [--lock <file>] [--write-lock] [--json] [--json-out <file>] [--sarif <file>] [--fail-on <severity>|none] [--skip-exposure] [--attempt-call --call-tool <name>]"
                    );
                    Err(())
                }
            };

            // Distinct exit codes so CI can distinguish outcomes: 2 = the scan
            // errored/never ran (above), 1 = findings ≥ threshold, 0 = clean.
            // A failed/never-run scan must NOT exit 0 (green) — that's the
            // whole point of the gate.
            let outcome = report.as_ref().map(|r| r.max_severity()).map_err(|_| ());
            let code = tokenfuse_core::mcpreport::scan_exit_code(&outcome, threshold);
            if let Ok(report) = &report {
                if mode == tokenfuse_gateway::mcpcli::OutputMode::Human {
                    let count = |s: tokenfuse_core::Severity| {
                        report.summary.get(s.as_str()).copied().unwrap_or(0)
                    };
                    let threshold_str = threshold.map(|t| t.as_str()).unwrap_or("none");
                    println!(
                        "RESULT: {} critical, {} high, {} medium, {} low — exit {code} (fail-on: {threshold_str})",
                        count(tokenfuse_core::Severity::Critical),
                        count(tokenfuse_core::Severity::High),
                        count(tokenfuse_core::Severity::Medium),
                        count(tokenfuse_core::Severity::Low),
                    );
                }
            }
            std::process::exit(code);
        }
        // `tokenfuse focus-export --traces <dir-or-glob> --out <file.csv>`
        //     `[--from <rfc3339>] [--to <rfc3339>]` exports the Parquet trace as
        // a FOCUS 1.2-style CSV (FinOps Open Cost & Usage Specification) so a
        // bank/FinOps team can load LLM agent spend into the same tooling they
        // use for cloud spend.
        Some("focus-export") => {
            let rest: Vec<String> = args.collect();
            let fargs = tokenfuse_gateway::focusexport::parse_args(&rest);
            if let Err(e) = tokenfuse_gateway::focusexport::run(&fargs).await {
                eprintln!("focus-export error: {e}");
                std::process::exit(1);
            }
        }
        // `tokenfuse outcomes --traces <dir-or-glob> [--from <rfc3339>]`
        //     `[--to <rfc3339>] [--json]` — unit economics per `X-Fuse-Outcome`
        // tag (P4): runs, total settled cost, mean cost per run, total calls,
        // and blocked calls, using the LAST non-empty tag per run.
        Some("outcomes") => {
            let rest: Vec<String> = args.collect();
            let oargs = tokenfuse_gateway::outcomescli::parse_args(&rest);
            if let Err(e) = tokenfuse_gateway::outcomescli::run(&oargs).await {
                eprintln!("outcomes error: {e}");
                std::process::exit(1);
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
    use tokenfuse_gateway::mcpbroker::{app, run_stdio, BrokerState, ScanMode};

    // stdio mode: `mcp-broker --stdio` or TOKENFUSE_MCP_STDIO — logs go to stderr
    // so stdout stays the JSON-RPC protocol channel.
    let stdio =
        std::env::args().any(|a| a == "--stdio") || std::env::var("TOKENFUSE_MCP_STDIO").is_ok();
    let builder = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    );
    if stdio {
        builder.with_writer(std::io::stderr).init();
    } else {
        builder.init();
    }

    let upstream = std::env::var("TOKENFUSE_MCP_UPSTREAM").unwrap_or_default();
    // Additional named upstreams: `TOKENFUSE_MCP_UPSTREAMS="name=url,name2=url2"`.
    // A request picks one by its `X-Fuse-Mcp-Upstream` header; an entry missing
    // its `=` is skipped with a warning rather than silently mis-parsed.
    let mut named_upstreams = std::collections::BTreeMap::new();
    for entry in std::env::var("TOKENFUSE_MCP_UPSTREAMS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        match entry.split_once('=') {
            Some((name, url)) if !name.trim().is_empty() && !url.trim().is_empty() => {
                named_upstreams.insert(name.trim().to_string(), url.trim().to_string());
            }
            _ => eprintln!(
                "TOKENFUSE_MCP_UPSTREAMS: ignoring malformed entry {entry:?} (want name=url)"
            ),
        }
    }
    if upstream.is_empty() && named_upstreams.is_empty() {
        eprintln!(
            "set TOKENFUSE_MCP_UPSTREAM=<real MCP server url> \
             (and/or TOKENFUSE_MCP_UPSTREAMS=name=url,... for named upstreams)"
        );
        return;
    }
    // If only named upstreams are configured, the first is the default an
    // un-named request forwards to, so the broker always has a fallback.
    let upstream = if upstream.is_empty() {
        named_upstreams
            .values()
            .next()
            .cloned()
            .expect("named_upstreams is non-empty here")
    } else {
        upstream
    };
    // The second PEP: the broker reuses the SAME Wardryx config the gateway
    // reads (TOKENFUSE_WARDRYX_*), so configuring Wardryx once gates both the
    // LLM path and MCP tool calls. Off unless TOKENFUSE_WARDRYX_MODE+URL are set.
    let wardryx = Arc::new(tokenfuse_gateway::wardryx::Wardryx::from_env());
    let vault = tokenfuse_core::SecretVault::from_pairs(
        &std::env::var("TOKENFUSE_MCP_SECRETS").unwrap_or_default(),
    );
    let scan = match std::env::var("TOKENFUSE_MCP_SCAN").as_deref() {
        Ok("off") => ScanMode::Off,
        Ok("block") => ScanMode::Block,
        _ => ScanMode::Warn,
    };
    let dlp = match std::env::var("TOKENFUSE_MCP_DLP").as_deref() {
        Ok("block") => tokenfuse_core::DlpMode::Block,
        Ok("off") => tokenfuse_core::DlpMode::Off,
        _ => tokenfuse_core::DlpMode::Shadow, // warn
    };
    // Optional rug-pull baseline: a JSON lockfile of pinned tool fingerprints.
    let lock = std::env::var("TOKENFUSE_MCP_LOCK").ok().and_then(|p| {
        std::fs::read_to_string(&p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    });
    // Agent-event NDJSON export (agent-passport SPEC.md §6): the mcp-broker is
    // its own process invocation, so it reads TOKENFUSE_EVENTS_PATH at its own
    // startup, same as the gateway does in `serve()`.
    let events = Arc::new(tokenfuse_gateway::events::from_env());
    let state = Arc::new(BrokerState {
        upstream: upstream.clone(),
        named_upstreams,
        vault,
        scan,
        dlp,
        lock,
        wardryx,
        client: reqwest::Client::new(),
        events,
    });
    if stdio {
        tracing::info!(%upstream, "mcp credential-broker on stdio");
        if let Err(e) = run_stdio(state).await {
            eprintln!("stdio error: {e}");
        }
        return;
    }
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

    // Default price book: illustrative generic entries plus exact entries for
    // the current Anthropic/OpenAI lineup. See pricebook.rs for the per-model
    // rates and units notes. Real prices ship as a versioned price book.
    let prices = default_price_book();

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

    // Who may call this gateway, and the stable `key_id` their spend is
    // attributed to. Unset leaves authentication off, exactly as before, so a
    // drop-in proxy stays drop-in on upgrade.
    //
    // Set-but-unusable exits instead of falling back to "off": that fallback
    // would leave the gateway open at precisely the moment an operator
    // believed they had just closed it, and a typo in an env var is not a
    // reason to serve unauthenticated traffic.
    let client_keys = match tokenfuse_gateway::clientkeys::ClientKeys::from_spec(
        &std::env::var("TOKENFUSE_CLIENT_KEYS").unwrap_or_default(),
    ) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("tokenfuse: {e}");
            std::process::exit(2);
        }
    };
    if client_keys.enabled() {
        println!(
            "client auth: ON ({} key(s)); metered calls must send the `{}` header",
            client_keys.len(),
            tokenfuse_gateway::clientkeys::CLIENT_KEY_HEADER
        );
    }

    // The declarative key<->agent<->unit identity map (docs/20). Unset leaves
    // identity off, exactly as before. Set-but-unusable exits instead of
    // falling back to "off", mirroring TOKENFUSE_CLIENT_KEYS above: a typo in
    // an env var must never silently disable what the operator believes is on.
    let identity_map = match std::env::var("TOKENFUSE_IDENTITY_MAP") {
        Ok(path) if !path.trim().is_empty() => {
            match tokenfuse_gateway::identitymap::IdentityMap::from_path(std::path::Path::new(
                path.trim(),
            )) {
                Ok(map) => map,
                Err(e) => {
                    eprintln!("tokenfuse: TOKENFUSE_IDENTITY_MAP: {e}");
                    std::process::exit(2);
                }
            }
        }
        _ => tokenfuse_gateway::identitymap::IdentityMap::default(),
    };
    // Strict mode governs ONLY the key<->agent binding check; unit budgets
    // follow TOKENFUSE_MODE like every other budget. An unknown value exits
    // (same posture as an unusable map: refuse, never guess).
    let identity_strict = {
        let raw = std::env::var("TOKENFUSE_IDENTITY_STRICT").unwrap_or_default();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            tokenfuse_gateway::identitymap::StrictMode::Off
        } else {
            match trimmed.parse::<tokenfuse_gateway::identitymap::StrictMode>() {
                Ok(mode) => mode,
                Err(_) => {
                    eprintln!(
                        "tokenfuse: TOKENFUSE_IDENTITY_STRICT must be off|warn|enforce, got `{trimmed}`"
                    );
                    std::process::exit(2);
                }
            }
        }
    };
    let units = Arc::new(tokenfuse_gateway::unitledger::UnitLedger::new(
        identity_map.unit_budgets(),
    ));
    if identity_map.enabled() {
        println!(
            "identity map: ON ({} unit(s), {} key binding(s)); strict={:?}",
            identity_map.unit_count(),
            identity_map.key_count(),
            identity_strict,
        );
        // A map key_id with no client key can never authenticate, so its
        // binding can never match live traffic. Warn, do not refuse: the two
        // env vars are legitimately staged independently.
        for id in identity_map.key_ids() {
            if !client_keys.key_ids().any(|k| k == id) {
                eprintln!(
                    "tokenfuse: identity map key_id `{id}` has no matching TOKENFUSE_CLIENT_KEYS entry; its binding cannot match live traffic"
                );
            }
        }
        if identity_strict != tokenfuse_gateway::identitymap::StrictMode::Off
            && !client_keys.enabled()
        {
            eprintln!(
                "tokenfuse: TOKENFUSE_IDENTITY_STRICT is set but TOKENFUSE_CLIENT_KEYS is not; nothing is authenticated to check, so binding checks stay idle and only prefix attribution applies"
            );
        }
    }

    let mut state = AppState::new(
        Arc::new(Ledger::new()),
        Arc::new(prices),
        Arc::new(policy),
        provider,
        "default",
    )
    .with_client_keys(Arc::new(client_keys))
    .with_identity(Arc::new(identity_map), identity_strict, units.clone());

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

    // Model router: TOKENFUSE_ROUTER = off | shadow | on (default off), rules
    // from TOKENFUSE_ROUTER_RULES (optional JSON path; built-in default
    // table otherwise). Picks the cheapest model that still meets a task's
    // required quality tier before the request is priced and forwarded --
    // see router.rs for the full contract.
    let router = tokenfuse_gateway::router::Router::from_env();
    tracing::info!(mode = ?router.mode, "model router");
    state = state.with_router(Arc::new(router));

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

    // Wardryx enforcement hook (a PEP): TOKENFUSE_WARDRYX_MODE = off | shadow
    // | enforce (default off), pointed at TOKENFUSE_WARDRYX_URL. An unset
    // URL keeps the hook off no matter what mode says, so there is nothing
    // to call and nothing to enforce. See wardryx.rs for the full contract
    // (fail-open/closed, the decision cache, etc.).
    let wardryx = tokenfuse_gateway::wardryx::Wardryx::from_env();
    tracing::info!(mode = ?wardryx.mode, "wardryx enforcement hook");
    state = state.with_wardryx(Arc::new(wardryx));

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
            // Pull centrally-managed per-unit monthly caps (docs/20). Only
            // when the identity map is on: an unconfigured gateway has no
            // units to apply them to, so it does not poll the endpoint.
            if state.identity.enabled() {
                let stu = units.clone();
                tokenfuse_gateway::cloudsink::spawn_unit_budget_poller(
                    base.clone(),
                    key.clone(),
                    move |map| {
                        let overrides = map
                            .into_iter()
                            .map(|(unit, micros)| (unit, tokenfuse_core::Microusd(micros)))
                            .collect();
                        stu.set_overrides(overrides);
                    },
                );
            }
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

    // Agent-event NDJSON export (agent-passport SPEC.md §6): TOKENFUSE_EVENTS_PATH,
    // read once here at startup — absent/empty keeps the exporter disabled
    // (zero per-request cost, see `tokenfuse_core::agent_event::Exporter`).
    state = state.with_events(Arc::new(tokenfuse_gateway::events::from_env()));

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
