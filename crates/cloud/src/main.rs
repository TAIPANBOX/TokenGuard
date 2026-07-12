//! Control-plane binary. Serves the read + ingest surface (A2/A3) with optional
//! durable persistence. Mutations, pairing, push and the OpenAPI contract arrive
//! in later PRs — see docs/14-mobile-companion.md.

use std::sync::Arc;
use std::time::Duration;

use tokenfuse_cloud::{
    app, openapi_spec, parse_keys, AppState, IncidentConfig, NullSender, OidcConfig, PushPipeline,
    PushSender, Store,
};

#[tokio::main]
async fn main() {
    // `tokenfuse-cloud --openapi` prints the API contract and exits — used by CI
    // to validate the spec and by client codegen (Swift, dashboard TS).
    if std::env::args().nth(1).as_deref() == Some("--openapi") {
        println!(
            "{}",
            serde_json::to_string_pretty(&openapi_spec()).expect("serialize openapi")
        );
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());

    // Auth keys. Fails CLOSED by default: an unset/empty/all-malformed
    // TOKENFUSE_CLOUD_KEYS yields an EMPTY key map (every request gets `401`,
    // nobody authenticates), rather than silently granting the hardcoded
    // `devkey` admin credential. That dev-convenience fallback exists only
    // for local/demo use and requires an explicit operator opt-in via
    // TOKENFUSE_CLOUD_ALLOW_DEVKEY=1 (see keys::parse_keys and
    // docs/13-security-hardening.md).
    let keys_spec = std::env::var("TOKENFUSE_CLOUD_KEYS").unwrap_or_default();
    let allow_devkey = env_flag("TOKENFUSE_CLOUD_ALLOW_DEVKEY");
    let keys = parse_keys(&keys_spec, allow_devkey);
    let key_count = keys.len();
    if key_count == 0 {
        tracing::error!(
            "no valid TOKENFUSE_CLOUD_KEYS configured and TOKENFUSE_CLOUD_ALLOW_DEVKEY not set: \
             the control plane will authenticate no one (every request gets 401). Set \
             TOKENFUSE_CLOUD_KEYS to a real key spec, or TOKENFUSE_CLOUD_ALLOW_DEVKEY=1 for \
             local dev only"
        );
    } else if allow_devkey && parse_keys(&keys_spec, false).is_empty() {
        // The insecure fallback only actually fired when the spec itself had
        // no valid entries: this check (re-parsed with the flag forced off)
        // distinguishes that from an operator who happens to have a real key
        // literally named "devkey" configured alongside the opt-in flag.
        tracing::warn!(
            "TOKENFUSE_CLOUD_ALLOW_DEVKEY is set and TOKENFUSE_CLOUD_KEYS has no valid entries: \
             the insecure `devkey` credential (org=default, role=admin) is ACTIVE. This must \
             never be used outside local dev"
        );
    }

    let alert_pct = std::env::var("TOKENFUSE_CLOUD_ALERT_PCT")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|p| *p > 0.0 && *p <= 1.0)
        .unwrap_or(0.8);

    // Incident-detector thresholds, mirroring the `TOKENFUSE_CLOUD_ALERT_PCT`
    // precedent: each env var overrides a documented default.
    let defaults = IncidentConfig::default();
    let incident_cfg = IncidentConfig {
        budget_blocks: env_u64(
            "TOKENFUSE_CLOUD_INCIDENT_BUDGET_BLOCKS",
            defaults.budget_blocks,
        ),
        loop_repeats: env_u64(
            "TOKENFUSE_CLOUD_INCIDENT_LOOP_REPEATS",
            defaults.loop_repeats,
        ),
        loop_window_ms: defaults.loop_window_ms,
        spend_per_min_micros: std::env::var("TOKENFUSE_CLOUD_INCIDENT_SPEND_PER_MIN_USD")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|p| *p > 0.0)
            .map(|usd| (usd * 1e6) as i64)
            .unwrap_or(defaults.spend_per_min_micros),
        fanout_runs: env_u64("TOKENFUSE_CLOUD_INCIDENT_FANOUT_RUNS", defaults.fanout_runs),
        fanout_window_ms: defaults.fanout_window_ms,
    };

    // Agent-event NDJSON export (agent-passport SPEC.md §6): TOKENFUSE_EVENTS_PATH,
    // read once here at startup (the control plane is its own process,
    // separate from any gateway that might also have it set) — absent/empty
    // keeps the exporter disabled (zero cost on the ingest hot path).
    let event_exporter = Arc::new(tokenfuse_core::agent_event::Exporter::from_env());
    if event_exporter.is_enabled() {
        tracing::info!("agent-event NDJSON export enabled");
    }

    // `alert_pct` is passed to the store too (not just `AppState`/
    // `PushPipeline`): C5's `MAX_RUNS_PER_ORG` eviction policy needs the SAME
    // threshold `/v1/alerts` uses to decide which runs it must not evict.
    let store =
        Arc::new(Store::with_config(incident_cfg, alert_pct).with_event_exporter(event_exporter));

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

    // Push pipeline: turn store change events into APNs pushes + Live Activity
    // updates. Without APNs configured it uses a no-op sender (fail-open).
    let sender: Arc<dyn PushSender> = build_push_sender();
    Arc::new(PushPipeline::new(Arc::clone(&store), sender, alert_pct)).spawn();

    // Optional offline OIDC/JWT bearer auth (WS4). Unconfigured ⇒ `None`, and
    // the auth chokepoints behave exactly as a keys-only deployment.
    let oidc = OidcConfig::from_env();
    if oidc.is_some() {
        tracing::info!("OIDC bearer auth enabled (offline JWKS)");
    }

    // Optional server P-256 key for signing audit manifests (P3 WS2).
    // Unconfigured ⇒ `None`, and `/v1/audit/manifest` reports not-configured;
    // the rest of the audit trail is unaffected.
    let audit_signing_key = tokenfuse_cloud::audit_signing_key_from_env();
    if audit_signing_key.is_some() {
        tracing::info!("audit manifest signing enabled (ES256)");
    }

    // Agent-event NDJSON replay source for `GET /v1/replay/{run}` (read-only,
    // additive: incident replay). Independent of `TOKENFUSE_EVENTS_PATH` above
    // (that's a gateway's own export path; this is what the control plane
    // reads from) so an operator can point it at the same file, a copy, or
    // leave it unset entirely (the endpoint still returns the store-derived
    // incidents/audit for a run, just zero events).
    let replay_events_path = std::env::var("TOKENFUSE_CLOUD_REPLAY_EVENTS").ok();
    if replay_events_path.as_deref().is_some_and(|p| !p.is_empty()) {
        tracing::info!("replay events configured for /v1/replay");
    }

    let state = AppState::new(Arc::clone(&store), Arc::new(keys), alert_pct)
        .with_oidc(oidc)
        .with_audit_signing_key(audit_signing_key)
        .with_replay_events_path(replay_events_path);

    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind control-plane address");
    tracing::info!("tokenfuse cloud control plane listening on {addr} ({key_count} org key(s))");
    axum::serve(listener, app(state))
        .await
        .expect("serve control plane");
}

/// Parse a positive `u64` env var, falling back to `default` when unset or
/// malformed.
fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(default)
}

/// Truthy env-var opt-in check: only `"1"` or `"true"` (case-insensitive)
/// count. Unset, empty, `"0"`, `"false"`, or a typo all fail closed (`false`):
/// a malformed opt-in must never silently enable the insecure `devkey`
/// fallback.
fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true"))
}

/// The APNs sender, if the `apns` feature is built and the environment is
/// configured; otherwise a no-op sender (push disabled, everything else works).
fn build_push_sender() -> Arc<dyn PushSender> {
    #[cfg(feature = "apns")]
    {
        match tokenfuse_cloud::apns::ApnsSender::from_env() {
            Some(sender) => {
                tracing::info!("APNs push enabled");
                return Arc::new(sender);
            }
            None => tracing::info!("APNs env not set — push disabled"),
        }
    }
    Arc::new(NullSender)
}
