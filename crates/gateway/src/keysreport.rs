//! `GET /v1/keys` (`docs/22-key-lifecycle.md`): a read-only key-lifecycle
//! report that correlates three sources of key identity into one response
//! the console (Genaryx) renders:
//!
//! 1. **Configured** - `TOKENFUSE_CLIENT_KEYS` (`crate::clientkeys`): which
//!    `key_id`s a secret currently resolves to.
//! 2. **Bound** - `TOKENFUSE_IDENTITY_MAP` `keys[]` (`crate::identitymap`):
//!    which `key_id`s have a unit binding, the agent patterns that
//!    constrain them, and the optional `created` field.
//! 3. **History** - the Parquet trace (`TOKENFUSE_DATA_DIR`), when set:
//!    every `key_id` that has ever made a call, folded into per-key
//!    counts and first/last-seen timestamps.
//!
//! Plus one in-process-only signal, `crate::keystats`'s since-startup
//! counters, which reset on restart and are reported separately from the
//! durable `history` fold.
//!
//! This module only assembles and serves; it never mints, rotates, revokes,
//! or enforces anything. See `docs/22-key-lifecycle.md` for the full wire
//! contract, the derived-status vocabulary the console computes from these
//! fields, and the honest limits.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::sqlq;
use crate::state::AppState;

/// How long a folded Parquet history scan is cached, keyed by the directory
/// it was computed for (`docs/22-key-lifecycle.md`): long enough that
/// console polling cannot turn this endpoint into a repeated full-directory
/// scan, short enough that the report still feels live.
const HISTORY_CACHE_TTL: Duration = Duration::from_secs(15);

/// Cached folded history: `(computed_at, dir_it_was_computed_for, fold)`.
/// Keying by directory (not just an unqualified "is it fresh" check) matters
/// because more than one directory can legitimately appear across the
/// lifetime of a test binary (each test builds its own temp dir) - without
/// the key, one call's cached fold could otherwise be served back for an
/// entirely different directory within the TTL window. In a real deployment
/// `TOKENFUSE_DATA_DIR` is fixed for the process's lifetime, so the key
/// simply never changes there.
type HistoryCacheSlot = (Instant, String, HashMap<String, HistoryFold>);
static HISTORY_CACHE: Mutex<Option<HistoryCacheSlot>> = Mutex::new(None);

/// Folded per-key history from the Parquet trace: call/mismatch counts and
/// first/last-seen timestamps. `Default` is the correct "zero rows for this
/// key" shape the wire contract calls for when history is available but a
/// given key never appears in it.
#[derive(Debug, Clone, Copy, Default)]
struct HistoryFold {
    calls: u64,
    identity_mismatches: u64,
    first_seen_millis: Option<i64>,
    last_seen_millis: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct KeysReport {
    pub strict_mode: &'static str,
    pub identity_map_configured: bool,
    pub history_available: bool,
    pub unauthorized_since_startup: UnauthorizedView,
    pub keys: Vec<KeyView>,
}

#[derive(Debug, Serialize)]
pub struct UnauthorizedView {
    pub attempts: u64,
    pub last_millis: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct KeyView {
    pub key_id: String,
    pub configured: bool,
    pub bound: bool,
    pub unit: Option<String>,
    pub agents: Vec<String>,
    pub created: Option<String>,
    pub since_startup: SinceStartupView,
    pub history: Option<HistoryView>,
}

#[derive(Debug, Serialize)]
pub struct SinceStartupView {
    pub calls: u64,
    pub identity_mismatches: u64,
    pub last_seen_millis: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct HistoryView {
    pub calls: u64,
    pub identity_mismatches: u64,
    pub first_seen_millis: Option<i64>,
    pub last_seen_millis: Option<i64>,
}

/// `GET /v1/keys`. Same (absent) auth posture as `GET /v1/runs`: this is
/// metadata (`key_id`s and counts), never a secret, and the gateway binds
/// loopback by default.
pub async fn list_keys(State(st): State<AppState>) -> Json<KeysReport> {
    let data_dir = std::env::var("TOKENFUSE_DATA_DIR").ok();
    Json(build_report(&st, data_dir.as_deref()).await)
}

/// Assembles the report. Takes the data directory as an explicit parameter
/// (rather than reading `TOKENFUSE_DATA_DIR` itself) so every scenario -
/// including "history available" - is directly testable without mutating
/// process-global environment state, which `cargo test`'s parallel threads
/// would otherwise race.
async fn build_report(st: &AppState, data_dir: Option<&str>) -> KeysReport {
    let dir = data_dir.map(str::trim).filter(|s| !s.is_empty());

    let (history_available, history) = match dir {
        Some(d) => match cached_history_fold(d).await {
            Ok(fold) => (true, fold),
            Err(e) => {
                // Never a 500 for a bad/unreadable trace directory: degrade
                // to "no history" and say so in the response
                // (`docs/22-key-lifecycle.md`'s honest-limits section).
                tracing::warn!(
                    dir = %d,
                    error = %e,
                    "GET /v1/keys: TOKENFUSE_DATA_DIR scan failed; serving history_available=false"
                );
                (false, HashMap::new())
            }
        },
        None => (false, HashMap::new()),
    };

    let stats = st.keystats.snapshot();
    let configured: HashSet<&str> = st.client_keys.key_ids().collect();
    let bound: HashSet<&str> = st.identity.key_ids().into_iter().collect();

    // Union of all three sources, sorted ascending by key_id.
    let mut key_ids: BTreeSet<String> = BTreeSet::new();
    key_ids.extend(configured.iter().map(|s| s.to_string()));
    key_ids.extend(bound.iter().map(|s| s.to_string()));
    key_ids.extend(history.keys().cloned());

    let keys = key_ids
        .into_iter()
        .map(|key_id| {
            let binding = st.identity.key_binding(&key_id);
            let since = stats.per_key.get(&key_id).copied().unwrap_or_default();
            let hist = history_available.then(|| history.get(&key_id).copied().unwrap_or_default());
            KeyView {
                configured: configured.contains(key_id.as_str()),
                bound: binding.is_some(),
                unit: binding.as_ref().map(|b| b.unit.clone()),
                agents: binding
                    .as_ref()
                    .map(|b| b.agents.clone())
                    .unwrap_or_default(),
                created: binding.and_then(|b| b.created),
                since_startup: SinceStartupView {
                    calls: since.calls,
                    identity_mismatches: since.identity_mismatches,
                    last_seen_millis: since.last_seen_millis,
                },
                history: hist.map(|h| HistoryView {
                    calls: h.calls,
                    identity_mismatches: h.identity_mismatches,
                    first_seen_millis: h.first_seen_millis,
                    last_seen_millis: h.last_seen_millis,
                }),
                key_id,
            }
        })
        .collect();

    KeysReport {
        strict_mode: st.identity_strict.as_wire_str(),
        identity_map_configured: st.identity.enabled(),
        history_available,
        unauthorized_since_startup: UnauthorizedView {
            attempts: stats.unauthorized.attempts,
            last_millis: stats.unauthorized.last_millis,
        },
        keys,
    }
}

/// Serves `history_fold(dir)`, cached for [`HISTORY_CACHE_TTL`] per
/// directory.
async fn cached_history_fold(
    dir: &str,
) -> Result<HashMap<String, HistoryFold>, Box<dyn std::error::Error>> {
    {
        let cache = HISTORY_CACHE.lock().unwrap();
        if let Some((at, cached_dir, fold)) = cache.as_ref() {
            if cached_dir == dir && at.elapsed() < HISTORY_CACHE_TTL {
                return Ok(fold.clone());
            }
        }
    }
    let fold = history_fold(dir).await?;
    *HISTORY_CACHE.lock().unwrap() = Some((Instant::now(), dir.to_string(), fold.clone()));
    Ok(fold)
}

/// Scans the Parquet trace in `dir` and folds it into per-`key_id` counts.
///
/// Follows the `sqlq.rs` precedent exactly: a flat `SELECT` (no `SQL GROUP
/// BY` - this repo deliberately folds in Rust, see
/// `sqlq.rs::mixed_pre_tool_calls_and_tool_calls_schema_files_read_with_defaults`)
/// of `(coalesce(key_id, ''), ts_millis, decision)`, filtered to rows that
/// genuinely have a `key_id` - pre-key_id-era rows (where the column is a
/// Parquet NULL, coalesced here to `''`) are excluded rather than folded
/// under an empty-string bucket.
async fn history_fold(
    dir: &str,
) -> Result<HashMap<String, HistoryFold>, Box<dyn std::error::Error>> {
    let batches = sqlq::query(
        "select coalesce(key_id, '') as key_id, ts_millis, decision from calls \
         where coalesce(key_id, '') <> ''",
        dir,
    )
    .await?;

    let mut folded: HashMap<String, HistoryFold> = HashMap::new();
    for batch in &batches {
        let ts_col = batch
            .column(1)
            .as_any()
            .downcast_ref::<datafusion::arrow::array::Int64Array>()
            .ok_or("ts_millis column type")?;
        for i in 0..batch.num_rows() {
            let key_id = sqlq::str_at(batch.column(0).as_ref(), i);
            let ts = ts_col.value(i);
            let decision = sqlq::str_at(batch.column(2).as_ref(), i);

            let entry = folded.entry(key_id).or_default();
            entry.calls += 1;
            if decision == "identity_mismatch" {
                entry.identity_mismatches += 1;
            }
            entry.first_seen_millis = Some(entry.first_seen_millis.map_or(ts, |f| f.min(ts)));
            entry.last_seen_millis = Some(entry.last_seen_millis.map_or(ts, |l| l.max(ts)));
        }
    }
    Ok(folded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clientkeys::ClientKeys;
    use crate::identitymap::{IdentityMap, StrictMode};
    use crate::provider::StubProvider;
    use crate::sink::{CallRecord, EventSink, ParquetSink};
    use crate::unitledger::UnitLedger;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tokenfuse_core::{Ledger, Mode, Policy, PriceBook};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn base_state() -> AppState {
        AppState::new(
            Arc::new(Ledger::new()),
            Arc::new(PriceBook::new()),
            Arc::new(Policy {
                mode: Mode::Enforce,
                ..Default::default()
            }),
            Arc::new(StubProvider::default()),
            "test-policy",
        )
    }

    /// Writes `json` to a fresh temp file and loads it as an `IdentityMap`,
    /// matching `proxy.rs`'s own `identity_state` test helper.
    fn map_from(json: &str) -> IdentityMap {
        let path = std::env::temp_dir().join(format!(
            "tf-keysreport-map-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, json).unwrap();
        let map = IdentityMap::from_path(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        map
    }

    fn call_record(key_id: &str, ts_millis: i64, decision: &str) -> CallRecord {
        CallRecord {
            ts_millis,
            run_id: "r".into(),
            model: "m".into(),
            decision: decision.into(),
            input_tokens: 0,
            output_tokens: 0,
            cost_microusd: 0,
            step: 1,
            agent_id: String::new(),
            saved_microusd: 0,
            parent_run_id: String::new(),
            on_behalf_of: String::new(),
            outcome: String::new(),
            key_id: key_id.into(),
            unit: String::new(),
            tool_calls: None,
        }
    }

    // -----------------------------------------------------------------
    // Assembly: union + sort, configured/bound/dangling, flags
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn empty_state_reports_no_keys_and_both_flags_off() {
        let st = base_state();
        let report = build_report(&st, None).await;
        assert_eq!(report.strict_mode, "off");
        assert!(!report.identity_map_configured);
        assert!(!report.history_available);
        assert_eq!(report.unauthorized_since_startup.attempts, 0);
        assert!(report.unauthorized_since_startup.last_millis.is_none());
        assert!(report.keys.is_empty());
    }

    #[tokio::test]
    async fn union_of_configured_and_bound_keys_is_sorted_ascending() {
        let mut st = base_state();
        st = st.with_client_keys(Arc::new(
            ClientKeys::from_spec("sk-a:zzz-agent,sk-b:aaa-agent").unwrap(),
        ));
        let map = map_from(
            r#"{
                "units": [{"id": "u"}],
                "keys": [
                    {"key_id": "aaa-agent", "unit": "u"},
                    {"key_id": "mmm-agent", "unit": "u"}
                ]
            }"#,
        );
        st = st.with_identity(
            Arc::new(map),
            StrictMode::Off,
            Arc::new(UnitLedger::default()),
        );

        let report = build_report(&st, None).await;
        let ids: Vec<&str> = report.keys.iter().map(|k| k.key_id.as_str()).collect();
        // "aaa-agent" appears in both sources but must be de-duplicated.
        assert_eq!(ids, vec!["aaa-agent", "mmm-agent", "zzz-agent"]);
    }

    #[tokio::test]
    async fn a_configured_only_key_is_unbound() {
        let mut st = base_state();
        st = st.with_client_keys(Arc::new(ClientKeys::from_spec("sk-a:solo").unwrap()));

        let report = build_report(&st, None).await;
        assert_eq!(report.keys.len(), 1);
        let k = &report.keys[0];
        assert_eq!(k.key_id, "solo");
        assert!(k.configured);
        assert!(!k.bound);
        assert_eq!(k.unit, None);
        assert!(k.agents.is_empty());
        assert_eq!(k.created, None);
        assert!(k.history.is_none());
    }

    #[tokio::test]
    async fn a_bound_only_key_is_dangling() {
        let mut st = base_state();
        let map = map_from(
            r#"{"units":[{"id":"u"}],
                "keys":[{"key_id":"dangling","unit":"u","agents":["a*"],"created":"2026-01-01"}]}"#,
        );
        st = st.with_identity(
            Arc::new(map),
            StrictMode::Off,
            Arc::new(UnitLedger::default()),
        );

        let report = build_report(&st, None).await;
        assert_eq!(report.keys.len(), 1);
        let k = &report.keys[0];
        assert_eq!(k.key_id, "dangling");
        assert!(
            !k.configured,
            "no TOKENFUSE_CLIENT_KEYS entry resolves here"
        );
        assert!(k.bound);
        assert_eq!(k.unit.as_deref(), Some("u"));
        assert_eq!(k.agents, vec!["a*".to_string()]);
        assert_eq!(k.created.as_deref(), Some("2026-01-01"));
    }

    #[tokio::test]
    async fn a_fully_populated_key_is_both_configured_and_bound() {
        let mut st = base_state();
        st = st.with_client_keys(Arc::new(ClientKeys::from_spec("sk-a:full").unwrap()));
        let map = map_from(r#"{"units":[{"id":"u"}],"keys":[{"key_id":"full","unit":"u"}]}"#);
        st = st.with_identity(
            Arc::new(map),
            StrictMode::Off,
            Arc::new(UnitLedger::default()),
        );

        let report = build_report(&st, None).await;
        assert_eq!(report.keys.len(), 1);
        assert!(report.keys[0].configured);
        assert!(report.keys[0].bound);
    }

    #[tokio::test]
    async fn identity_map_configured_flag_reflects_the_map() {
        let mut st = base_state();
        let map = map_from(r#"{"units":[{"id":"u"}]}"#);
        st = st.with_identity(
            Arc::new(map),
            StrictMode::Warn,
            Arc::new(UnitLedger::default()),
        );
        let report = build_report(&st, None).await;
        assert!(report.identity_map_configured);
        assert_eq!(report.strict_mode, "warn");
    }

    #[tokio::test]
    async fn per_key_since_startup_reflects_keystats() {
        let mut st = base_state();
        st = st.with_client_keys(Arc::new(ClientKeys::from_spec("sk-a:tracked").unwrap()));
        st.keystats.record_call("tracked");
        st.keystats.record_call("tracked");
        st.keystats.record_identity_mismatch("tracked");

        let report = build_report(&st, None).await;
        let k = &report.keys[0];
        assert_eq!(k.since_startup.calls, 2);
        assert_eq!(k.since_startup.identity_mismatches, 1);
        assert!(k.since_startup.last_seen_millis.is_some());
    }

    #[tokio::test]
    async fn unauthorized_since_startup_reflects_keystats() {
        let st = base_state();
        st.keystats.record_unauthorized();
        st.keystats.record_unauthorized();
        st.keystats.record_unauthorized();
        let report = build_report(&st, None).await;
        assert_eq!(report.unauthorized_since_startup.attempts, 3);
        assert!(report.unauthorized_since_startup.last_millis.is_some());
    }

    // -----------------------------------------------------------------
    // History wiring: zero-shape, unavailable, scan errors
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn history_is_null_on_every_key_when_unavailable() {
        let mut st = base_state();
        st = st.with_client_keys(Arc::new(ClientKeys::from_spec("sk-a:solo").unwrap()));
        let report = build_report(&st, None).await;
        assert!(!report.history_available);
        assert!(report.keys[0].history.is_none());
    }

    #[tokio::test]
    async fn history_zero_shape_when_available_but_the_key_has_no_rows() {
        let dir = std::env::temp_dir().join(format!("tf-keysreport-zero-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A row for a DIFFERENT key, so the directory is genuinely
        // scannable (history_available becomes true) while "solo" itself
        // has zero rows in it.
        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            sink.record(call_record("other-key", 1, "allow"));
        }

        let mut st = base_state();
        st = st.with_client_keys(Arc::new(ClientKeys::from_spec("sk-a:solo").unwrap()));

        let report = build_report(&st, Some(dir.to_str().unwrap())).await;
        assert!(report.history_available);
        let solo = report.keys.iter().find(|k| k.key_id == "solo").unwrap();
        let h = solo
            .history
            .as_ref()
            .expect("Some when history is available");
        assert_eq!(h.calls, 0);
        assert_eq!(h.identity_mismatches, 0);
        assert_eq!(h.first_seen_millis, None);
        assert_eq!(h.last_seen_millis, None);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_history_only_key_is_a_ghost() {
        let dir = std::env::temp_dir().join(format!("tf-keysreport-ghost-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            sink.record(call_record("removed-key", 10, "allow"));
        }

        // No client keys, no identity map: this key is not configured or
        // bound anywhere, only remembered by the trace.
        let st = base_state();
        let report = build_report(&st, Some(dir.to_str().unwrap())).await;
        assert_eq!(report.keys.len(), 1);
        let ghost = &report.keys[0];
        assert_eq!(ghost.key_id, "removed-key");
        assert!(!ghost.configured);
        assert!(!ghost.bound);
        let h = ghost.history.as_ref().unwrap();
        assert_eq!(h.calls, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_nonexistent_data_dir_serves_history_available_false() {
        // A mistyped/never-created TOKENFUSE_DATA_DIR: the scan must fail
        // (DataFusion cannot list a path whose parent does not exist), and
        // `build_report` must degrade rather than propagate the error - same
        // "clear error, not a panic" contract `focusexport.rs`'s and
        // `outcomescli.rs`'s own `missing_traces_dir_is_a_clear_error_not_a_panic`
        // tests already prove for `crate::sqlq::query` against a `/nonexistent/...`
        // path. (A plain, existing file with the wrong extension/content is NOT
        // an equivalent case: DataFusion's file-extension filter simply finds
        // zero matching files there and returns an empty, successful scan - not
        // an error - so it would not exercise this degrade path at all.)
        let dir = format!(
            "/nonexistent/tf-keysreport-not-a-source-{}",
            std::process::id()
        );

        let st = base_state();
        let report = build_report(&st, Some(&dir)).await;
        assert!(!report.history_available);
    }

    #[tokio::test]
    async fn a_blank_data_dir_is_treated_as_not_configured() {
        let st = base_state();
        for blank in ["", "   "] {
            let report = build_report(&st, Some(blank)).await;
            assert!(!report.history_available, "blank dir {blank:?}");
        }
    }

    // -----------------------------------------------------------------
    // history_fold: the Parquet fold itself
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn history_fold_computes_counts_and_first_last_seen_per_key() {
        let dir = std::env::temp_dir().join(format!("tf-keysreport-fold-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            sink.record(call_record("k1", 100, "allow"));
            sink.record(call_record("k1", 200, "identity_mismatch"));
            sink.record(call_record("k1", 50, "allow"));
            sink.record(call_record("k2", 500, "allow"));
        }

        let fold = history_fold(dir.to_str().unwrap())
            .await
            .expect("scan must succeed");

        assert_eq!(fold.len(), 2);
        let k1 = fold.get("k1").unwrap();
        assert_eq!(k1.calls, 3);
        assert_eq!(k1.identity_mismatches, 1);
        assert_eq!(k1.first_seen_millis, Some(50));
        assert_eq!(k1.last_seen_millis, Some(200));

        let k2 = fold.get("k2").unwrap();
        assert_eq!(k2.calls, 1);
        assert_eq!(k2.identity_mismatches, 0);
        assert_eq!(k2.first_seen_millis, Some(500));
        assert_eq!(k2.last_seen_millis, Some(500));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The pre-key_id-era proof, hand-writing a file exactly like
    /// `sqlq.rs`'s own mixed-schema tests do: a 12-column (P3) file
    /// genuinely lacking the `key_id` column must fold to a NULL, coalesced
    /// to `''`, and then be EXCLUDED by the `WHERE` clause - never counted
    /// under a synthetic `""` bucket.
    #[tokio::test]
    async fn history_fold_excludes_pre_key_id_era_rows() {
        use datafusion::arrow::array::{Int64Array, StringArray, UInt32Array, UInt64Array};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::parquet::arrow::ArrowWriter;

        let dir = std::env::temp_dir().join(format!(
            "tf-keysreport-fold-pre-key-id-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let pre_key_id_schema = Arc::new(Schema::new(vec![
            Field::new("ts_millis", DataType::Int64, false),
            Field::new("run_id", DataType::Utf8, false),
            Field::new("model", DataType::Utf8, false),
            Field::new("decision", DataType::Utf8, false),
            Field::new("input_tokens", DataType::UInt64, false),
            Field::new("output_tokens", DataType::UInt64, false),
            Field::new("cost_microusd", DataType::Int64, false),
            Field::new("step", DataType::UInt32, false),
            Field::new("agent_id", DataType::Utf8, false),
            Field::new("saved_microusd", DataType::Int64, false),
            Field::new("parent_run_id", DataType::Utf8, false),
            Field::new("on_behalf_of", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            pre_key_id_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1i64])),
                Arc::new(StringArray::from(vec!["pre-key-id-run"])),
                Arc::new(StringArray::from(vec!["m"])),
                Arc::new(StringArray::from(vec!["allow"])),
                Arc::new(UInt64Array::from(vec![0u64])),
                Arc::new(UInt64Array::from(vec![0u64])),
                Arc::new(Int64Array::from(vec![0i64])),
                Arc::new(UInt32Array::from(vec![1u32])),
                Arc::new(StringArray::from(vec![""])),
                Arc::new(Int64Array::from(vec![0i64])),
                Arc::new(StringArray::from(vec![""])),
                Arc::new(StringArray::from(vec![""])),
            ],
        )
        .unwrap();
        {
            let file = std::fs::File::create(dir.join("calls-pre-key-id.parquet")).unwrap();
            let mut w = ArrowWriter::try_new(file, pre_key_id_schema, None).unwrap();
            w.write(&batch).unwrap();
            w.close().unwrap();
        }

        // A real, current-schema file alongside it, so the directory mixes
        // eras the same way every sqlq.rs mixed-schema test does.
        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            sink.record(call_record("k1", 2, "allow"));
        }

        let fold = history_fold(dir.to_str().unwrap())
            .await
            .expect("mixed pre-key_id/key_id schema read must succeed");

        assert_eq!(
            fold.len(),
            1,
            "the pre-key_id row must be excluded, not folded under ''"
        );
        assert!(!fold.contains_key(""));
        assert_eq!(fold.get("k1").unwrap().calls, 1);

        std::fs::remove_dir_all(&dir).ok();
    }
}
