//! In-memory aggregation store: the per-organization fleet view built from the
//! call telemetry many gateways push in. A faithful port of the original Go
//! control plane's `store.go` (in-memory parts). Durable JSON snapshotting
//! (`Load`/`Save`/autosave) is added in a follow-up — see
//! docs/14-mobile-companion.md, PR A3.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::RwLock;

use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use tokenfuse_core::audit::{self, AuditEntry};
use tokio::sync::broadcast;
use utoipa::ToSchema;

use crate::devices::{Device, Pairing};

/// Anti-replay nonce ring size, per device (docs/14 §4.2).
const NONCE_CAP: usize = 4096;

/// How many recent samples to keep per org for the burn-rate series (in-memory,
/// not persisted — historical analytics live in the gateway's Parquet sink).
const SERIES_CAP: usize = 100_000;

/// Whether a call record represents a blocked decision (as opposed to a
/// settled call: `allow`/`cache_hit`). Blocked records are still stored and
/// counted, but their `cost_microusd` — an avoided-spend estimate, or 0 for
/// security blocks — must never be summed into real spend (see `ingest`).
fn is_blocked(decision: &str) -> bool {
    !matches!(decision, "allow" | "cache_hit")
}

/// One settled call, pushed by a gateway's `CloudSink`. The wire shape matches
/// `crates/gateway/src/sink.rs::CallRecord` (kept in sync by hand, exactly as
/// the Go plane did); a later cleanup can hoist the shared type into
/// `tokenfuse-core` so producer and consumer derive it from one definition.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct CallRecord {
    #[serde(default)]
    pub ts_millis: i64,
    pub run_id: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub decision: String,
    #[serde(default)]
    pub input_tokens: u64,
    #[serde(default)]
    pub output_tokens: u64,
    #[serde(default)]
    pub cost_microusd: i64,
    #[serde(default)]
    pub step: u32,
    /// Attribution: which logical agent made the call (P2). Accepted for
    /// forward-compat; aggregation (/v1/agents) lands in a later PR.
    #[serde(default)]
    pub agent_id: String,
    /// Cache-hit savings in microdollars (P2). Accepted for forward-compat;
    /// aggregation (/v1/savings) lands in a later PR.
    #[serde(default)]
    pub saved_microusd: i64,
}

/// The aggregated state of one run within an organization.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct RunAgg {
    pub run_id: String,
    pub model: String,
    /// Which logical agent this run is attributed to (P2). Empty when the
    /// gateway didn't tag the calls — folded into the "unattributed" bucket by
    /// [`Store::agents`]. `serde(default)` so pre-P2 snapshots still load.
    #[serde(default)]
    pub agent_id: String,
    pub spent_microusd: i64,
    pub calls: u64,
    pub cache_hits: u64,
    pub steps: u32,
    #[serde(rename = "last_seen_millis")]
    pub last_seen: i64,
    pub killed: bool,
}

/// Org-wide totals.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct Summary {
    pub runs: u64,
    pub calls: u64,
    pub spent_microusd: i64,
}

/// Per-agent spend rollup (P2), folded from an org's [`RunAgg`]s by `agent_id`.
/// The empty-string `agent_id` is kept as an explicit "unattributed" bucket.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct AgentAgg {
    /// The agent this bucket rolls up; `""` for unattributed runs.
    pub agent_id: String,
    /// Real spend (blocked/avoided-spend rows already excluded upstream).
    pub spent_microusd: i64,
    pub calls: u64,
    /// Distinct runs attributed to this agent.
    pub runs: u64,
    #[serde(rename = "last_seen_millis")]
    pub last_seen: i64,
}

/// Per-org FinOps savings summary (P2). `total_saved_microusd` is the marketing
/// headline: budget-protection blocked spend plus semantic-cache savings.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct SavingsSummary {
    /// Avoided spend from budget-protection blocks (runaway spend stopped).
    pub blocked_spend_microusd: i64,
    /// Dollars served for free by the semantic cache.
    pub cache_saved_microusd: i64,
    /// Distinct runs stopped by at least one budget-protection block.
    pub budget_breaks: u64,
    /// `blocked_spend_microusd + cache_saved_microusd`.
    pub total_saved_microusd: i64,
}

/// The live FinOps savings accumulator for one org, folded incrementally in
/// [`Store::ingest`] (the control plane is a live rollup, not a Parquet reader).
/// Persisted in the snapshot so totals survive a restart.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct SavingsAcc {
    blocked_spend_microusd: i64,
    cache_saved_microusd: i64,
    /// Distinct run ids that hit ≥1 budget-protection block — the set makes
    /// `budget_breaks` distinct-by-run even across restarts (it's persisted).
    #[serde(default)]
    breaks: HashSet<String>,
}

/// A run that has spent at or above a fraction of its central budget.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Alert {
    pub run_id: String,
    pub spent_microusd: i64,
    pub budget_micros: i64,
    pub fraction: f64,
    pub killed: bool,
}

/// One time bucket of the burn-rate series.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SeriesBucket {
    /// Bucket start, epoch millis.
    pub t: i64,
    pub cost_microusd: i64,
    pub calls: u64,
    pub blocked: u64,
}

/// An aggregated, first-class anomaly for an org (P2 incidents). Repeated or
/// severe detections are folded into one `Incident` keyed by a STABLE
/// [`incident_id`] (`"{kind}:{run_or_agent}"`) so later triggers bump
/// `occurrences`/`last_seen_millis` in place rather than piling up duplicates.
/// Persisted in the snapshot so open incidents — and the push-dedup clock
/// (`last_notified_millis`) — survive a restart.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Incident {
    /// Stable dedup id, `"{kind}:{run_or_agent}"`.
    pub id: String,
    pub org: String,
    /// The run this incident is scoped to, if run-scoped (`spend_spike` is
    /// org-scoped and leaves this `None`).
    pub run_id: Option<String>,
    /// The agent attributed at trip time, when the gateway tagged the run.
    pub agent_id: Option<String>,
    /// Detector kind: `budget_exhausted` | `sustained_loop` | `spend_spike` |
    /// `fanout_explosion`.
    pub kind: String,
    /// Reused from `tokenfuse_core` — rendered as a lowercase string in JSON.
    #[schema(value_type = String, example = "high")]
    pub severity: tokenfuse_core::Severity,
    pub first_seen_millis: i64,
    pub last_seen_millis: i64,
    /// How many times this incident's threshold has tripped.
    pub occurrences: u64,
    pub acknowledged: bool,
    /// Epoch millis of the last push fired for this incident — the SINGLE
    /// source of truth for push dedup (see `push.rs`). `0` until first notified.
    pub last_notified_millis: i64,
}

/// Thresholds for the incident detectors, mirroring the `alert_pct` env
/// precedent. Read from the environment at the composition root (see
/// `main::main`); [`Default`] carries the documented fallbacks.
#[derive(Debug, Clone)]
pub struct IncidentConfig {
    /// `budget_exhausted` trips at ≥ this many budget-protection blocks per run
    /// (`TOKENFUSE_CLOUD_INCIDENT_BUDGET_BLOCKS`).
    pub budget_blocks: u64,
    /// `sustained_loop` trips at ≥ this many `loop_detected` decisions for a run
    /// within `loop_window_ms` (`TOKENFUSE_CLOUD_INCIDENT_LOOP_REPEATS`).
    pub loop_repeats: u64,
    /// Window for the `sustained_loop` repeat count.
    pub loop_window_ms: i64,
    /// `spend_spike` trips when an org's last-minute burn reaches this rate
    /// (`TOKENFUSE_CLOUD_INCIDENT_SPEND_PER_MIN_USD`, stored as microdollars).
    pub spend_per_min_micros: i64,
    /// `fanout_explosion` trips when one `agent_id` drives ≥ this many DISTINCT
    /// runs within `fanout_window_ms` (`TOKENFUSE_CLOUD_INCIDENT_FANOUT_RUNS`).
    pub fanout_runs: u64,
    /// Window for the `fanout_explosion` distinct-run count.
    pub fanout_window_ms: i64,
}

impl Default for IncidentConfig {
    fn default() -> Self {
        Self {
            budget_blocks: 3,
            loop_repeats: 3,
            loop_window_ms: 600_000,
            spend_per_min_micros: 5_000_000,
            fanout_runs: 20,
            fanout_window_ms: 600_000,
        }
    }
}

/// Rolling window used to compute the `spend_spike` burn rate (matches the
/// per-minute framing of `TOKENFUSE_CLOUD_INCIDENT_SPEND_PER_MIN_USD`).
const SPIKE_WINDOW_MS: i64 = 60_000;

/// Cap on each per-(org,key) occurrence tracker deque, so a hot run can't grow
/// the tracker without bound (the incident itself is the durable record).
const INCIDENT_TRACKER_CAP: usize = 256;

/// A live change broadcast to `/v1/stream` subscribers. `org` routes the event
/// to the right subscriber and is not sent in the payload.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    RunUpdate {
        #[serde(skip)]
        org: String,
        run: RunAgg,
    },
    Kill {
        #[serde(skip)]
        org: String,
        run: String,
    },
    Budget {
        #[serde(skip)]
        org: String,
        run: String,
        budget_micros: i64,
    },
    /// A newly-tripped or re-tripped incident. Serialized flat (the internal
    /// `type` tag plus the incident's own fields, incl. its `org`).
    Incident(Incident),
}

impl StreamEvent {
    /// The org this event belongs to (used to filter per-subscriber).
    pub(crate) fn org(&self) -> &str {
        match self {
            Self::RunUpdate { org, .. } | Self::Kill { org, .. } | Self::Budget { org, .. } => org,
            Self::Incident(inc) => &inc.org,
        }
    }

    /// The SSE event name.
    pub(crate) fn event_name(&self) -> &'static str {
        match self {
            Self::RunUpdate { .. } => "run_update",
            Self::Kill { .. } => "kill",
            Self::Budget { .. } => "budget",
            Self::Incident(_) => "incident",
        }
    }
}

/// One recorded call, kept for the burn-rate series.
struct Sample {
    ts_millis: i64,
    run_id: String,
    cost_microusd: i64,
    blocked: bool,
}

#[derive(Default)]
struct Inner {
    /// org → run → aggregate
    orgs: HashMap<String, HashMap<String, RunAgg>>,
    /// org → run → killed
    killed: HashMap<String, HashMap<String, bool>>,
    /// org → run → central budget (microdollars)
    budgets: HashMap<String, HashMap<String, i64>>,
    /// org → bounded log of recent samples for the burn-rate series
    series: HashMap<String, VecDeque<Sample>>,
    /// org → live FinOps savings accumulator (persisted)
    savings: HashMap<String, SavingsAcc>,
    /// org → wire `decision` string → total occurrences (persisted). Folded in
    /// [`Store::ingest`] over EVERY record — including blocked ones, since a
    /// block is compliance *evidence* (the guard fired), not spend. Feeds the
    /// `/v1/compliance` evidence pack.
    decision_counts: HashMap<String, HashMap<String, u64>>,
    /// org → incident id → aggregated incident (persisted)
    incidents: HashMap<String, HashMap<String, Incident>>,
    /// org → append-only, hash-chained audit trail of control-plane mutations
    /// (persisted). Oldest entry first; the tip is the last element.
    audit: HashMap<String, Vec<AuditEntry>>,
    /// (org, "{kind}:{run_or_agent}") → recent trigger timestamps, bounded to
    /// [`INCIDENT_TRACKER_CAP`]; the small occurrence counter the detectors
    /// threshold against (ephemeral — the `Incident` is the durable record).
    incident_tracker: HashMap<(String, String), VecDeque<i64>>,
    /// (org, agent_id) → recent `(run_id, ts)` for the `fanout_explosion`
    /// detector, kept distinct-by-run and bounded to [`INCIDENT_TRACKER_CAP`];
    /// the windowed distinct-run count the detector thresholds against
    /// (ephemeral — the `Incident` is the durable record).
    fanout_tracker: HashMap<(String, String), VecDeque<(String, i64)>>,
    /// device_token → paired device (persisted)
    devices: HashMap<String, Device>,
    /// one-time pairing code → pending pairing (ephemeral)
    pairings: HashMap<String, Pairing>,
    /// device_id → recent nonces for replay defense (ephemeral)
    nonces: HashMap<String, VecDeque<String>>,
    /// org → run → Live Activity push tokens (ephemeral)
    activities: HashMap<String, HashMap<String, Vec<String>>>,
    /// set on any mutation, cleared by autosave — avoids writing an unchanged file
    dirty: bool,
}

/// On-disk snapshot of the whole store. Two shapes: a borrowing one for writing
/// (no clone) and an owning one for reading.
#[derive(Serialize)]
struct SnapshotRef<'a> {
    orgs: &'a HashMap<String, HashMap<String, RunAgg>>,
    killed: &'a HashMap<String, HashMap<String, bool>>,
    budgets: &'a HashMap<String, HashMap<String, i64>>,
    devices: &'a HashMap<String, Device>,
    savings: &'a HashMap<String, SavingsAcc>,
    decision_counts: &'a HashMap<String, HashMap<String, u64>>,
    incidents: &'a HashMap<String, HashMap<String, Incident>>,
    audit: &'a HashMap<String, Vec<AuditEntry>>,
}

#[derive(Default, Deserialize)]
struct SnapshotOwned {
    #[serde(default)]
    orgs: HashMap<String, HashMap<String, RunAgg>>,
    #[serde(default)]
    killed: HashMap<String, HashMap<String, bool>>,
    #[serde(default)]
    budgets: HashMap<String, HashMap<String, i64>>,
    #[serde(default)]
    devices: HashMap<String, Device>,
    /// Missing on pre-P2 snapshots — `default` yields an empty map, so
    /// `savings()` reports zeros until fresh telemetry accumulates.
    #[serde(default)]
    savings: HashMap<String, SavingsAcc>,
    /// Missing on pre-compliance snapshots — `default` loads empty, so
    /// `decision_counts()` reports zeros until fresh telemetry accumulates.
    #[serde(default)]
    decision_counts: HashMap<String, HashMap<String, u64>>,
    /// Missing on pre-incident snapshots — `default` loads to no open
    /// incidents (incl. their `last_notified_millis` push-dedup clock).
    #[serde(default)]
    incidents: HashMap<String, HashMap<String, Incident>>,
    /// Missing on pre-audit snapshots — `default` loads to empty chains, which
    /// [`audit::verify_chain`] treats as intact.
    #[serde(default)]
    audit: HashMap<String, Vec<AuditEntry>>,
}

/// A concurrency-safe aggregation keyed by org → run. A SQL/columnar backend
/// (Postgres/ClickHouse) for scale + retention is a drop-in follow-up behind
/// the same methods.
pub struct Store {
    inner: RwLock<Inner>,
    /// Live change bus for `/v1/stream` subscribers.
    events: broadcast::Sender<StreamEvent>,
    /// Incident-detector thresholds (env-configured at the composition root).
    incident_cfg: IncidentConfig,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub fn new() -> Self {
        Self::with_incident_config(IncidentConfig::default())
    }

    /// Build with explicit incident thresholds (used by `main` after reading the
    /// environment, and by unit tests that pin a threshold).
    pub fn with_incident_config(incident_cfg: IncidentConfig) -> Self {
        let (events, _) = broadcast::channel(1024);
        Self {
            inner: RwLock::new(Inner::default()),
            events,
            incident_cfg,
        }
    }

    /// Subscribe to live change events (per-org filtering is the caller's job).
    pub fn subscribe(&self) -> broadcast::Receiver<StreamEvent> {
        self.events.subscribe()
    }

    /// Fold a batch of records into an org's aggregates, append them to the
    /// burn-rate series, run incident detection, and broadcast a `run_update`
    /// per affected run plus an `incident` per tripped detector. Uses the store's
    /// own wall clock; see [`Store::ingest_at`] for the testable inner form.
    pub fn ingest(&self, org: &str, records: &[CallRecord]) {
        self.ingest_at(org, records, now_millis());
    }

    /// [`Store::ingest`] with an explicit `now_ms` (the same "now" `series`
    /// takes), so incident windows are deterministic in tests.
    pub(crate) fn ingest_at(&self, org: &str, records: &[CallRecord], now_ms: i64) {
        let mut updated: Vec<RunAgg> = Vec::new();
        let mut fired: HashMap<String, Incident> = HashMap::new();
        {
            let mut guard = self.inner.write().unwrap();
            guard.dirty = true;
            // Reborrow so `orgs` and `savings` can be borrowed as disjoint
            // fields inside the same loop (a live rollup accumulates both).
            let inner = &mut *guard;
            {
                let runs = inner.orgs.entry(org.to_string()).or_default();
                let sav = inner.savings.entry(org.to_string()).or_default();
                let dc = inner.decision_counts.entry(org.to_string()).or_default();
                for r in records {
                    let agg = runs.entry(r.run_id.clone()).or_insert_with(|| RunAgg {
                        run_id: r.run_id.clone(),
                        ..Default::default()
                    });
                    // Compliance evidence: count EVERY record's decision,
                    // including blocked ones (a block is a guard firing, not
                    // spend). `/v1/compliance` reads this per-org tally.
                    *dc.entry(r.decision.clone()).or_insert(0) += 1;
                    // Blocked calls are stored and counted, but their
                    // cost_microusd (avoided spend, or 0 for security blocks)
                    // must not inflate the org's real spend total.
                    if !is_blocked(&r.decision) {
                        agg.spent_microusd += r.cost_microusd;
                    }
                    agg.calls += 1;
                    if r.decision == "cache_hit" {
                        agg.cache_hits += 1;
                    }
                    if !r.model.is_empty() {
                        agg.model = r.model.clone();
                    }
                    if !r.agent_id.is_empty() {
                        agg.agent_id = r.agent_id.clone();
                    }
                    if r.step > agg.steps {
                        agg.steps = r.step;
                    }
                    if r.ts_millis > agg.last_seen {
                        agg.last_seen = r.ts_millis;
                    }
                    // FinOps savings, folded in the same pass. Only the
                    // budget-protection subset counts as blocked (avoided)
                    // spend — dlp/taint blocks are security value, not dollars
                    // (and carry cost 0 anyway). Cache savings sum
                    // unconditionally: `saved_microusd` is 0 off cache hits.
                    if tokenfuse_core::savings::is_budget_protection(&r.decision) {
                        sav.blocked_spend_microusd += r.cost_microusd;
                        sav.breaks.insert(r.run_id.clone());
                    }
                    sav.cache_saved_microusd += r.saved_microusd;
                }
            }
            {
                let log = inner.series.entry(org.to_string()).or_default();
                for r in records {
                    log.push_back(Sample {
                        ts_millis: r.ts_millis,
                        run_id: r.run_id.clone(),
                        cost_microusd: r.cost_microusd,
                        blocked: is_blocked(&r.decision),
                    });
                }
                while log.len() > SERIES_CAP {
                    log.pop_front();
                }
            }
            // Snapshot each affected run's new aggregate for the stream.
            if let Some(runs) = inner.orgs.get(org) {
                let mut seen = HashSet::new();
                for r in records {
                    if seen.insert(r.run_id.as_str()) {
                        if let Some(a) = runs.get(&r.run_id) {
                            updated.push(a.clone());
                        }
                    }
                }
            }

            // --- Incident detection (same pass, on the just-updated state) ---
            let cfg = &self.incident_cfg;
            for r in records {
                // Effective event time: the record's own stamp, or `now` when
                // the gateway didn't set one (keeps loop windows sane in tests).
                let ts = if r.ts_millis > 0 { r.ts_millis } else { now_ms };
                let agent = (!r.agent_id.is_empty()).then(|| r.agent_id.clone());

                // budget_exhausted (High): ≥ N budget-protection blocks per run.
                if tokenfuse_core::savings::is_budget_protection(&r.decision) {
                    let n = bump_tracker(
                        &mut inner.incident_tracker,
                        org,
                        "budget_exhausted",
                        &r.run_id,
                        ts,
                        None,
                    );
                    if n >= cfg.budget_blocks {
                        let inc = upsert_incident(
                            &mut inner.incidents,
                            org,
                            "budget_exhausted",
                            tokenfuse_core::Severity::High,
                            &r.run_id,
                            Some(r.run_id.clone()),
                            agent.clone(),
                            ts,
                        );
                        fired.insert(inc.id.clone(), inc);
                    }
                }

                // sustained_loop (Medium): ≥ N loop_detected for a run in-window.
                if r.decision == "loop_detected" {
                    let n = bump_tracker(
                        &mut inner.incident_tracker,
                        org,
                        "sustained_loop",
                        &r.run_id,
                        ts,
                        Some((now_ms, cfg.loop_window_ms)),
                    );
                    if n >= cfg.loop_repeats {
                        let inc = upsert_incident(
                            &mut inner.incidents,
                            org,
                            "sustained_loop",
                            tokenfuse_core::Severity::Medium,
                            &r.run_id,
                            Some(r.run_id.clone()),
                            agent.clone(),
                            ts,
                        );
                        fired.insert(inc.id.clone(), inc);
                    }
                }

                // fanout_explosion (High): one agent driving ≥ N distinct runs
                // in-window. Only attributed records count — a blank agent_id
                // isn't "one agent fanning out", so unattributed runs are skipped.
                if let Some(a) = &agent {
                    let n = bump_fanout_tracker(
                        &mut inner.fanout_tracker,
                        org,
                        a,
                        &r.run_id,
                        ts,
                        now_ms,
                        cfg.fanout_window_ms,
                    );
                    if n >= cfg.fanout_runs {
                        let inc = upsert_incident(
                            &mut inner.incidents,
                            org,
                            "fanout_explosion",
                            tokenfuse_core::Severity::High,
                            a,
                            None,
                            Some(a.clone()),
                            ts,
                        );
                        fired.insert(inc.id.clone(), inc);
                    }
                }
            }

            // spend_spike (High): org burn over the last minute, summed from the
            // SAME sample log `series()` buckets — not a second time-series.
            let burn = inner
                .series
                .get(org)
                .map(|log| burn_since(log, now_ms - SPIKE_WINDOW_MS, now_ms))
                .unwrap_or(0);
            if burn >= cfg.spend_per_min_micros {
                let inc = upsert_incident(
                    &mut inner.incidents,
                    org,
                    "spend_spike",
                    tokenfuse_core::Severity::High,
                    "",
                    None,
                    None,
                    now_ms,
                );
                fired.insert(inc.id.clone(), inc);
            }
        }
        for run in updated {
            let _ = self.events.send(StreamEvent::RunUpdate {
                org: org.to_string(),
                run,
            });
        }
        for (_, inc) in fired {
            let _ = self.events.send(StreamEvent::Incident(inc));
        }
    }

    /// Burn-rate buckets for a scope (whole org, or one `run`) over `window_ms`,
    /// `step_ms` wide, ending at `now_ms`.
    pub fn series(
        &self,
        org: &str,
        run: Option<&str>,
        window_ms: i64,
        step_ms: i64,
        now_ms: i64,
    ) -> Vec<SeriesBucket> {
        let step = step_ms.max(1);
        let window = window_ms.max(step);
        let start = now_ms - window;
        let n = (window / step).max(1) as usize;
        let mut buckets: Vec<SeriesBucket> = (0..n)
            .map(|i| SeriesBucket {
                t: start + i as i64 * step,
                cost_microusd: 0,
                calls: 0,
                blocked: 0,
            })
            .collect();
        let inner = self.inner.read().unwrap();
        if let Some(log) = inner.series.get(org) {
            for s in log {
                if s.ts_millis < start || s.ts_millis > now_ms {
                    continue;
                }
                if run.is_some_and(|rid| s.run_id != rid) {
                    continue;
                }
                let idx = (((s.ts_millis - start) / step) as usize).min(n - 1);
                let b = &mut buckets[idx];
                b.cost_microusd += s.cost_microusd;
                b.calls += 1;
                if s.blocked {
                    b.blocked += 1;
                }
            }
        }
        buckets
    }

    /// An org's run aggregates (order unspecified; the client sorts). The
    /// `killed` flag is resolved at read time from the kill set.
    pub fn runs(&self, org: &str) -> Vec<RunAgg> {
        let inner = self.inner.read().unwrap();
        let killed = inner.killed.get(org);
        let mut out = Vec::new();
        if let Some(runs) = inner.orgs.get(org) {
            for agg in runs.values() {
                let mut a = agg.clone();
                a.killed = killed
                    .and_then(|k| k.get(&a.run_id))
                    .copied()
                    .unwrap_or(false);
                out.push(a);
            }
        }
        out
    }

    /// Org-wide totals.
    pub fn summary(&self, org: &str) -> Summary {
        let inner = self.inner.read().unwrap();
        let mut sum = Summary::default();
        if let Some(runs) = inner.orgs.get(org) {
            for agg in runs.values() {
                sum.runs += 1;
                sum.calls += agg.calls;
                sum.spent_microusd += agg.spent_microusd;
            }
        }
        sum
    }

    /// An org's per-agent spend rollup, highest spend first. Folds the org's
    /// [`RunAgg`]s by `agent_id`; the empty-string agent is kept as its own
    /// (unattributed) bucket. Spend already excludes blocked rows (that gate is
    /// applied when folding calls into `RunAgg::spent_microusd`).
    pub fn agents(&self, org: &str) -> Vec<AgentAgg> {
        let inner = self.inner.read().unwrap();
        let mut by_agent: HashMap<String, AgentAgg> = HashMap::new();
        if let Some(runs) = inner.orgs.get(org) {
            for agg in runs.values() {
                let a = by_agent
                    .entry(agg.agent_id.clone())
                    .or_insert_with(|| AgentAgg {
                        agent_id: agg.agent_id.clone(),
                        ..Default::default()
                    });
                a.spent_microusd += agg.spent_microusd;
                a.calls += agg.calls;
                a.runs += 1;
                if agg.last_seen > a.last_seen {
                    a.last_seen = agg.last_seen;
                }
            }
        }
        let mut out: Vec<AgentAgg> = by_agent.into_values().collect();
        out.sort_by_key(|a| std::cmp::Reverse(a.spent_microusd));
        out
    }

    /// An org's live FinOps savings totals (blocked/avoided spend + cache
    /// savings). Accumulated incrementally in [`Store::ingest`] and persisted.
    pub fn savings(&self, org: &str) -> SavingsSummary {
        let inner = self.inner.read().unwrap();
        let acc = inner.savings.get(org);
        let blocked = acc.map(|a| a.blocked_spend_microusd).unwrap_or(0);
        let cache = acc.map(|a| a.cache_saved_microusd).unwrap_or(0);
        let breaks = acc.map(|a| a.breaks.len() as u64).unwrap_or(0);
        SavingsSummary {
            blocked_spend_microusd: blocked,
            cache_saved_microusd: cache,
            budget_breaks: breaks,
            total_saved_microusd: blocked + cache,
        }
    }

    /// An org's per-`decision` occurrence tally (every ingested record's wire
    /// `decision`, blocked or not). The compliance evidence pack projects the
    /// control catalog against this. Empty for an org with no telemetry.
    pub fn decision_counts(&self, org: &str) -> BTreeMap<String, u64> {
        let inner = self.inner.read().unwrap();
        inner
            .decision_counts
            .get(org)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .unwrap_or_default()
    }

    /// An org's open incidents folded by `kind` (one count per distinct
    /// incident, matching how `incidents()` aggregates them). Feeds the
    /// incident evidence column of the compliance report.
    pub fn incident_kind_counts(&self, org: &str) -> BTreeMap<String, u64> {
        let inner = self.inner.read().unwrap();
        let mut out: BTreeMap<String, u64> = BTreeMap::new();
        if let Some(m) = inner.incidents.get(org) {
            for inc in m.values() {
                *out.entry(inc.kind.clone()).or_insert(0) += 1;
            }
        }
        out
    }

    /// An org's open incidents, most-recently-seen first.
    pub fn incidents(&self, org: &str) -> Vec<Incident> {
        let inner = self.inner.read().unwrap();
        let mut out: Vec<Incident> = inner
            .incidents
            .get(org)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        out.sort_by_key(|i| std::cmp::Reverse(i.last_seen_millis));
        out
    }

    /// Acknowledge an incident (admin action). Returns whether it existed.
    pub fn ack_incident(&self, org: &str, id: &str) -> bool {
        let mut inner = self.inner.write().unwrap();
        let mut found = false;
        if let Some(inc) = inner.incidents.get_mut(org).and_then(|m| m.get_mut(id)) {
            inc.acknowledged = true;
            found = true;
        }
        if found {
            inner.dirty = true;
        }
        found
    }

    /// Atomically decide whether to push for an incident and, if so, stamp its
    /// `last_notified_millis`. This makes that field the SINGLE source of truth
    /// for push dedup (see `push.rs`): returns `true` only when more than
    /// `window_ms` has passed since the last push (and then records `now_ms`).
    pub fn mark_incident_notified(&self, org: &str, id: &str, now_ms: i64, window_ms: i64) -> bool {
        let mut inner = self.inner.write().unwrap();
        let mut notify = false;
        if let Some(inc) = inner.incidents.get_mut(org).and_then(|m| m.get_mut(id)) {
            if now_ms - inc.last_notified_millis > window_ms {
                inc.last_notified_millis = now_ms;
                notify = true;
            }
        }
        if notify {
            inner.dirty = true;
        }
        notify
    }

    /// Append a control-plane mutation to `org`'s tamper-evident audit chain,
    /// linking it to the current tip and stamping it with the store's wall
    /// clock. In-memory and infallible: callers log the action *after* the
    /// mutation succeeds, and an append never fails the mutation.
    pub fn audit_append(&self, org: &str, actor: &str, action: &str, subject: &str, detail: &str) {
        let mut inner = self.inner.write().unwrap();
        inner.dirty = true;
        let chain = inner.audit.entry(org.to_string()).or_default();
        let entry = audit::append(chain.last(), now_millis(), actor, action, subject, detail);
        chain.push(entry);
    }

    /// `org`'s audit chain, oldest first (append order). Empty when the org has
    /// logged no mutations.
    pub fn audit(&self, org: &str) -> Vec<AuditEntry> {
        self.inner
            .read()
            .unwrap()
            .audit
            .get(org)
            .cloned()
            .unwrap_or_default()
    }

    /// Verify `org`'s audit chain end-to-end. `Ok(())` if intact (or empty);
    /// `Err(index)` at the first broken link.
    pub fn audit_verify(&self, org: &str) -> Result<(), usize> {
        let inner = self.inner.read().unwrap();
        match inner.audit.get(org) {
            Some(chain) => audit::verify_chain(chain),
            None => Ok(()),
        }
    }

    /// A cryptographically-signed manifest over `org`'s audit chain tip, signed
    /// with `key` and stamped `now_ms`. Derived on demand from the persisted
    /// chain (nothing new is stored); an empty chain still yields a valid signed
    /// zero-tip manifest. See [`crate::audit_sign::build_signed_manifest`].
    pub fn audit_manifest(
        &self,
        org: &str,
        key: &SigningKey,
        now_ms: i64,
    ) -> crate::audit_sign::AuditManifest {
        let inner = self.inner.read().unwrap();
        let empty = Vec::new();
        let chain = inner.audit.get(org).unwrap_or(&empty);
        crate::audit_sign::build_signed_manifest(org, chain, key, now_ms)
    }

    /// Mark a run killed for an org; gateways poll this and hard-stop it.
    pub fn kill(&self, org: &str, run: &str) {
        {
            let mut inner = self.inner.write().unwrap();
            inner.dirty = true;
            inner
                .killed
                .entry(org.to_string())
                .or_default()
                .insert(run.to_string(), true);
        }
        let _ = self.events.send(StreamEvent::Kill {
            org: org.to_string(),
            run: run.to_string(),
        });
    }

    /// The run ids an org has killed.
    pub fn kills(&self, org: &str) -> Vec<String> {
        let inner = self.inner.read().unwrap();
        inner
            .killed
            .get(org)
            .map(|m| {
                m.iter()
                    .filter(|(_, &k)| k)
                    .map(|(run, _)| run.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Set a centrally-managed budget (microdollars) for a run; gateways poll
    /// this and apply it over the client-supplied budget.
    pub fn set_budget(&self, org: &str, run: &str, micros: i64) {
        {
            let mut inner = self.inner.write().unwrap();
            inner.dirty = true;
            inner
                .budgets
                .entry(org.to_string())
                .or_default()
                .insert(run.to_string(), micros);
        }
        let _ = self.events.send(StreamEvent::Budget {
            org: org.to_string(),
            run: run.to_string(),
            budget_micros: micros,
        });
    }

    /// An org's run → budget-micros overrides.
    pub fn budgets(&self, org: &str) -> HashMap<String, i64> {
        let inner = self.inner.read().unwrap();
        inner.budgets.get(org).cloned().unwrap_or_default()
    }

    /// Runs whose spend has reached `pct` (0..1) of a set budget. Only runs with
    /// a central budget override (> 0) are considered.
    pub fn alerts(&self, org: &str, pct: f64) -> Vec<Alert> {
        let inner = self.inner.read().unwrap();
        let mut out = Vec::new();
        let Some(budgets) = inner.budgets.get(org) else {
            return out;
        };
        let runs = inner.orgs.get(org);
        let killed = inner.killed.get(org);
        for (run, &budget) in budgets {
            if budget <= 0 {
                continue;
            }
            let spent = runs
                .and_then(|m| m.get(run))
                .map(|a| a.spent_microusd)
                .unwrap_or(0);
            let fraction = spent as f64 / budget as f64;
            if fraction >= pct {
                out.push(Alert {
                    run_id: run.clone(),
                    spent_microusd: spent,
                    budget_micros: budget,
                    fraction,
                    killed: killed.and_then(|k| k.get(run)).copied().unwrap_or(false),
                });
            }
        }
        out
    }

    /// Atomically write a JSON snapshot to `path` (private tmp file + rename).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let data = {
            let inner = self.inner.read().unwrap();
            let snap = SnapshotRef {
                orgs: &inner.orgs,
                killed: &inner.killed,
                budgets: &inner.budgets,
                devices: &inner.devices,
                savings: &inner.savings,
                decision_counts: &inner.decision_counts,
                incidents: &inner.incidents,
                audit: &inner.audit,
            };
            serde_json::to_vec(&snap)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        };
        let tmp = path.with_extension("tmp");
        write_file_private(&tmp, &data)?;
        std::fs::rename(&tmp, path)
    }

    /// Load a snapshot from `path` into the store. A missing file is a clean
    /// start, not an error.
    pub fn load(&self, path: &Path) -> std::io::Result<()> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let snap: SnapshotOwned = serde_json::from_slice(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut inner = self.inner.write().unwrap();
        inner.orgs = snap.orgs;
        inner.killed = snap.killed;
        inner.budgets = snap.budgets;
        inner.devices = snap.devices;
        inner.savings = snap.savings;
        inner.decision_counts = snap.decision_counts;
        inner.incidents = snap.incidents;
        inner.audit = snap.audit;
        Ok(())
    }

    /// Register a pending one-time pairing code (fixing the device's org/role).
    pub fn create_pairing(&self, code: &str, org: &str, role: &str, expires_unix: i64) {
        let mut inner = self.inner.write().unwrap();
        inner.pairings.insert(
            code.to_string(),
            Pairing {
                org: org.to_string(),
                role: role.to_string(),
                expires_unix,
            },
        );
    }

    /// Redeem a pairing code (one-time): if it exists and is unexpired, register
    /// a device keyed by `token` and return it. `None` for an unknown/expired
    /// code — the code is consumed either way if present.
    #[allow(clippy::too_many_arguments)]
    pub fn redeem_pairing(
        &self,
        code: &str,
        now_unix: i64,
        device_id: String,
        token: String,
        pubkey_b64: String,
        name: String,
        platform: String,
    ) -> Option<Device> {
        let mut inner = self.inner.write().unwrap();
        let pairing = inner.pairings.remove(code)?;
        if pairing.expires_unix < now_unix {
            return None;
        }
        let device = Device {
            device_id,
            org: pairing.org,
            role: pairing.role,
            name,
            platform,
            pubkey_b64,
            apns_token: None,
        };
        inner.dirty = true;
        inner.devices.insert(token, device.clone());
        Some(device)
    }

    /// The device a bearer `token` maps to, if any.
    pub fn device_by_token(&self, token: &str) -> Option<Device> {
        self.inner.read().unwrap().devices.get(token).cloned()
    }

    /// Record a nonce for a device; returns `false` if it was already seen
    /// (replay). Keeps the most recent [`NONCE_CAP`] per device.
    pub fn check_and_record_nonce(&self, device_id: &str, nonce: &str) -> bool {
        let mut inner = self.inner.write().unwrap();
        let seen = inner.nonces.entry(device_id.to_string()).or_default();
        if seen.iter().any(|n| n == nonce) {
            return false;
        }
        seen.push_back(nonce.to_string());
        while seen.len() > NONCE_CAP {
            seen.pop_front();
        }
        true
    }

    /// All devices belonging to an org (for fan-out push).
    pub fn devices_for_org(&self, org: &str) -> Vec<Device> {
        self.inner
            .read()
            .unwrap()
            .devices
            .values()
            .filter(|d| d.org == org)
            .cloned()
            .collect()
    }

    /// Set a device's APNs token (looked up by `device_id`). Returns whether the
    /// device was found.
    pub fn set_apns_token(&self, device_id: &str, token: &str) -> bool {
        let mut inner = self.inner.write().unwrap();
        let mut found = false;
        for d in inner.devices.values_mut() {
            if d.device_id == device_id {
                d.apns_token = Some(token.to_string());
                found = true;
                break;
            }
        }
        if found {
            inner.dirty = true;
        }
        found
    }

    /// Register a Live Activity push token for a run.
    pub fn register_activity(&self, org: &str, run: &str, activity_token: &str) {
        let mut inner = self.inner.write().unwrap();
        inner
            .activities
            .entry(org.to_string())
            .or_default()
            .entry(run.to_string())
            .or_default()
            .push(activity_token.to_string());
    }

    /// The Live Activity push tokens registered for a run.
    pub fn activities_for_run(&self, org: &str, run: &str) -> Vec<String> {
        self.inner
            .read()
            .unwrap()
            .activities
            .get(org)
            .and_then(|m| m.get(run))
            .cloned()
            .unwrap_or_default()
    }

    /// Directly insert a device keyed by token — test helper.
    #[cfg(test)]
    pub(crate) fn insert_device_for_test(&self, token: &str, device: Device) {
        self.inner
            .write()
            .unwrap()
            .devices
            .insert(token.to_string(), device);
    }

    /// Read and clear the dirty flag; an autosave loop saves only when `true`.
    pub fn take_dirty(&self) -> bool {
        let mut inner = self.inner.write().unwrap();
        let d = inner.dirty;
        inner.dirty = false;
        d
    }
}

/// The store's wall clock in epoch millis — the "now" `ingest` feeds detection
/// (mirrors the `now_ms` `series` is called with by the HTTP layer).
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The stable incident id / dedup key, `"{kind}:{run_or_agent}"`. Org-scoped
/// detectors (e.g. `spend_spike`) pass an empty scope.
fn incident_id(kind: &str, scope: &str) -> String {
    format!("{kind}:{scope}")
}

/// Push `ts` onto the per-(org,key) occurrence tracker, bound it, and — when a
/// `(now, window_ms)` is given — drop timestamps older than the window. Returns
/// the current count the detector thresholds against.
fn bump_tracker(
    tracker: &mut HashMap<(String, String), VecDeque<i64>>,
    org: &str,
    kind: &str,
    scope: &str,
    ts: i64,
    window: Option<(i64, i64)>,
) -> u64 {
    let dq = tracker
        .entry((org.to_string(), incident_id(kind, scope)))
        .or_default();
    dq.push_back(ts);
    while dq.len() > INCIDENT_TRACKER_CAP {
        dq.pop_front();
    }
    if let Some((now, window_ms)) = window {
        let cutoff = now - window_ms;
        while dq.front().is_some_and(|&t| t < cutoff) {
            dq.pop_front();
        }
    }
    dq.len() as u64
}

/// Record `(run_id, ts)` on the per-(org,agent) fanout tracker and return the
/// number of DISTINCT runs seen in-window. Refreshes an existing run's stamp
/// rather than logging a duplicate (so the deque holds distinct runs and a hot
/// run can't evict its peers), bounds it to [`INCIDENT_TRACKER_CAP`], and drops
/// entries older than `window_ms` before `now`.
fn bump_fanout_tracker(
    tracker: &mut HashMap<(String, String), VecDeque<(String, i64)>>,
    org: &str,
    agent: &str,
    run_id: &str,
    ts: i64,
    now: i64,
    window_ms: i64,
) -> u64 {
    let dq = tracker
        .entry((org.to_string(), agent.to_string()))
        .or_default();
    dq.retain(|(r, _)| r != run_id);
    dq.push_back((run_id.to_string(), ts));
    while dq.len() > INCIDENT_TRACKER_CAP {
        dq.pop_front();
    }
    let cutoff = now - window_ms;
    dq.retain(|(_, t)| *t >= cutoff);
    dq.len() as u64
}

/// Upsert the incident for `(org, kind, scope)`: create it on first trip, else
/// bump `occurrences`/`last_seen_millis` in place. Returns the current state.
#[allow(clippy::too_many_arguments)]
fn upsert_incident(
    incidents: &mut HashMap<String, HashMap<String, Incident>>,
    org: &str,
    kind: &str,
    severity: tokenfuse_core::Severity,
    scope: &str,
    run_id: Option<String>,
    agent_id: Option<String>,
    ts: i64,
) -> Incident {
    let id = incident_id(kind, scope);
    let per_org = incidents.entry(org.to_string()).or_default();
    let inc = per_org.entry(id.clone()).or_insert_with(|| Incident {
        id: id.clone(),
        org: org.to_string(),
        run_id: run_id.clone(),
        agent_id: agent_id.clone(),
        kind: kind.to_string(),
        severity,
        first_seen_millis: ts,
        last_seen_millis: ts,
        occurrences: 0,
        acknowledged: false,
        last_notified_millis: 0,
    });
    inc.occurrences += 1;
    if ts > inc.last_seen_millis {
        inc.last_seen_millis = ts;
    }
    // Keep the attributed agent fresh if a later trigger carries one.
    if inc.agent_id.is_none() {
        if let Some(a) = agent_id {
            inc.agent_id = Some(a);
        }
    }
    inc.clone()
}

/// Sum sample cost over `[start, now]` for the org's burn series (the same
/// accumulation `series()` does within one bucket) — the `spend_spike` rate.
fn burn_since(log: &VecDeque<Sample>, start: i64, now: i64) -> i64 {
    log.iter()
        .filter(|s| s.ts_millis >= start && s.ts_millis <= now)
        .map(|s| s.cost_microusd)
        .sum()
}

/// Write `data` to `path` with owner-only permissions on unix (the snapshot can
/// hold budget/kill state), a plain write elsewhere.
fn write_file_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(run: &str, cost: i64) -> CallRecord {
        CallRecord {
            run_id: run.into(),
            decision: "allow".into(),
            cost_microusd: cost,
            ..Default::default()
        }
    }

    #[test]
    fn ingest_aggregates() {
        let s = Store::new();
        s.ingest(
            "acme",
            &[
                CallRecord {
                    run_id: "r1".into(),
                    model: "claude".into(),
                    decision: "allow".into(),
                    cost_microusd: 1000,
                    step: 1,
                    ts_millis: 100,
                    ..Default::default()
                },
                CallRecord {
                    run_id: "r1".into(),
                    model: "claude".into(),
                    decision: "cache_hit".into(),
                    cost_microusd: 0,
                    step: 2,
                    ts_millis: 200,
                    ..Default::default()
                },
                CallRecord {
                    run_id: "r2".into(),
                    model: "gpt".into(),
                    decision: "allow".into(),
                    cost_microusd: 500,
                    step: 1,
                    ts_millis: 150,
                    ..Default::default()
                },
            ],
        );

        let runs = s.runs("acme");
        assert_eq!(runs.len(), 2);
        let r1 = runs.iter().find(|r| r.run_id == "r1").expect("r1 missing");
        assert_eq!(r1.spent_microusd, 1000);
        assert_eq!(r1.calls, 2);
        assert_eq!(r1.cache_hits, 1);
        assert_eq!(r1.steps, 2);
        assert_eq!(r1.last_seen, 200);

        let sum = s.summary("acme");
        assert_eq!(sum.runs, 2);
        assert_eq!(sum.calls, 3);
        assert_eq!(sum.spent_microusd, 1500);
    }

    /// A blocked record's `cost_microusd` (avoided-spend estimate, or 0 for
    /// security blocks) must be counted/stored but never summed into real
    /// spend — see `Store::ingest`'s `is_blocked` gate.
    #[test]
    fn ingest_excludes_blocked_spend_from_totals() {
        let s = Store::new();
        s.ingest(
            "acme",
            &[
                CallRecord {
                    run_id: "r1".into(),
                    model: "claude".into(),
                    decision: "allow".into(),
                    cost_microusd: 1000,
                    step: 1,
                    ts_millis: 100,
                    ..Default::default()
                },
                CallRecord {
                    run_id: "r1".into(),
                    model: "claude".into(),
                    decision: "budget_exceeded".into(),
                    cost_microusd: 750_000, // avoided estimate — not real spend
                    step: 2,
                    ts_millis: 200,
                    ..Default::default()
                },
                CallRecord {
                    run_id: "r1".into(),
                    model: "claude".into(),
                    decision: "taint_blocked".into(),
                    cost_microusd: 0,
                    step: 3,
                    ts_millis: 300,
                    ..Default::default()
                },
            ],
        );

        let runs = s.runs("acme");
        assert_eq!(runs.len(), 1);
        let r1 = &runs[0];
        // Only the "allow" record's cost counts toward spend.
        assert_eq!(r1.spent_microusd, 1000);
        // But every record — blocked or not — is counted and moves `steps`.
        assert_eq!(r1.calls, 3);
        assert_eq!(r1.steps, 3);
        assert_eq!(r1.last_seen, 300);

        let sum = s.summary("acme");
        assert_eq!(sum.runs, 1);
        assert_eq!(sum.calls, 3);
        assert_eq!(sum.spent_microusd, 1000);
    }

    #[test]
    fn orgs_are_isolated() {
        let s = Store::new();
        s.ingest("acme", &[rec("r1", 100)]);
        s.ingest("globex", &[rec("r1", 999)]);
        assert_eq!(s.summary("acme").spent_microusd, 100);
        assert_eq!(s.summary("globex").spent_microusd, 999);
        assert!(s.runs("unknown").is_empty());
    }

    #[test]
    fn killed_flag_surfaces_in_runs() {
        let s = Store::new();
        s.ingest("acme", &[rec("r1", 100)]);
        assert!(!s.runs("acme")[0].killed);
        s.kill("acme", "r1");
        assert!(s.runs("acme")[0].killed);
        assert_eq!(s.kills("acme"), vec!["r1".to_string()]);
    }

    #[test]
    fn alerts_fire_only_over_threshold_with_a_budget() {
        let s = Store::new();
        s.ingest("acme", &[rec("r1", 900), rec("r2", 100)]);
        s.set_budget("acme", "r1", 1000); // 90% spent
        s.set_budget("acme", "r2", 1000); // 10% spent
        let alerts = s.alerts("acme", 0.8);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].run_id, "r1");
        assert!((alerts[0].fraction - 0.9).abs() < 1e-9);
    }

    #[test]
    fn agents_roll_up_by_agent_id() {
        let s = Store::new();
        let r = |run: &str, agent: &str, decision: &str, cost: i64, ts: i64| CallRecord {
            run_id: run.into(),
            agent_id: agent.into(),
            decision: decision.into(),
            cost_microusd: cost,
            ts_millis: ts,
            ..Default::default()
        };
        s.ingest(
            "acme",
            &[
                r("r1", "planner", "allow", 1000, 10),
                r("r2", "planner", "allow", 2000, 20),
                // A budget-protection block for coder — its avoided cost must
                // NOT count toward the agent's real spend.
                r("r3", "coder", "allow", 500, 30),
                r("r3", "coder", "budget_exceeded", 999_999, 40),
                // Unattributed run (empty agent_id) is kept as its own bucket.
                r("r4", "", "allow", 250, 50),
            ],
        );

        let agents = s.agents("acme");
        assert_eq!(agents.len(), 3);
        // Sorted by spend desc: planner (3000) > coder (500) > "" (250).
        assert_eq!(agents[0].agent_id, "planner");
        assert_eq!(agents[0].spent_microusd, 3000);
        assert_eq!(agents[0].calls, 2);
        assert_eq!(agents[0].runs, 2);
        assert_eq!(agents[0].last_seen, 20);

        assert_eq!(agents[1].agent_id, "coder");
        // Blocked/avoided spend excluded — only the $0.0005 allow counts.
        assert_eq!(agents[1].spent_microusd, 500);
        assert_eq!(agents[1].calls, 2);
        assert_eq!(agents[1].runs, 1);

        assert_eq!(agents[2].agent_id, "");
        assert_eq!(agents[2].spent_microusd, 250);
        assert_eq!(agents[2].runs, 1);
    }

    #[test]
    fn savings_accumulate_across_reasons() {
        let s = Store::new();
        let r = |run: &str, decision: &str, cost: i64, saved: i64| CallRecord {
            run_id: run.into(),
            decision: decision.into(),
            cost_microusd: cost,
            saved_microusd: saved,
            ..Default::default()
        };
        s.ingest(
            "acme",
            &[
                r("r1", "allow", 1000, 0),
                r("r1", "budget_exceeded", 500_000, 0), // avoided spend
                r("r2", "loop_detected", 200_000, 0),   // avoided spend, 2nd run
                r("r1", "cache_hit", 0, 30_000),        // cache savings
                r("r3", "dlp_blocked", 9_000_000, 0),   // security — excluded
            ],
        );

        let sav = s.savings("acme");
        // Only budget-protection cost counts; dlp is excluded.
        assert_eq!(sav.blocked_spend_microusd, 700_000);
        assert_eq!(sav.cache_saved_microusd, 30_000);
        // Distinct blocked runs: r1 and r2 (r3's dlp doesn't count).
        assert_eq!(sav.budget_breaks, 2);
        assert_eq!(sav.total_saved_microusd, 730_000);
    }

    #[test]
    fn savings_breaks_are_distinct_by_run() {
        let s = Store::new();
        let r = |run: &str| CallRecord {
            run_id: run.into(),
            decision: "budget_exceeded".into(),
            cost_microusd: 1_000_000,
            ..Default::default()
        };
        // Same run blocked twice → one break; blocked_spend still sums both.
        s.ingest("acme", &[r("r1"), r("r1")]);
        let sav = s.savings("acme");
        assert_eq!(sav.budget_breaks, 1);
        assert_eq!(sav.blocked_spend_microusd, 2_000_000);
    }

    #[test]
    fn savings_persist_round_trip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tf-cloud-{}-savings.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let s = Store::new();
        s.ingest(
            "acme",
            &[
                CallRecord {
                    run_id: "r1".into(),
                    decision: "budget_exceeded".into(),
                    cost_microusd: 400_000,
                    ..Default::default()
                },
                CallRecord {
                    run_id: "r2".into(),
                    decision: "cache_hit".into(),
                    saved_microusd: 60_000,
                    ..Default::default()
                },
            ],
        );
        s.save(&path).expect("save");

        // Totals — including distinct budget_breaks — survive a reload.
        let s2 = Store::new();
        s2.load(&path).expect("load");
        let sav = s2.savings("acme");
        assert_eq!(sav.blocked_spend_microusd, 400_000);
        assert_eq!(sav.cache_saved_microusd, 60_000);
        assert_eq!(sav.budget_breaks, 1);
        assert_eq!(sav.total_saved_microusd, 460_000);

        // An old snapshot with no `savings` field loads to zeros, not an error.
        let old = dir.join(format!("tf-cloud-{}-oldsnap.json", std::process::id()));
        std::fs::write(
            &old,
            br#"{"orgs":{},"killed":{},"budgets":{},"devices":{}}"#,
        )
        .expect("write old snapshot");
        let s3 = Store::new();
        s3.load(&old).expect("load old snapshot");
        assert_eq!(s3.savings("acme").total_saved_microusd, 0);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&old);
    }

    #[test]
    fn decision_counts_accumulate_and_persist() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tf-cloud-{}-decisions.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let s = Store::new();
        s.ingest(
            "acme",
            &[
                block_at("r1", "allow", 1000, 10),
                block_at("r1", "budget_exceeded", 0, 20),
                block_at("r2", "budget_exceeded", 0, 30),
                block_at("r2", "loop_detected", 0, 40),
                block_at("r3", "allow", 500, 50),
            ],
        );
        // Every decision — blocked or not — is tallied.
        let dc = s.decision_counts("acme");
        assert_eq!(dc.get("allow").copied(), Some(2));
        assert_eq!(dc.get("budget_exceeded").copied(), Some(2));
        assert_eq!(dc.get("loop_detected").copied(), Some(1));
        // Orgs are isolated.
        assert!(s.decision_counts("other").is_empty());

        s.save(&path).expect("save");
        let s2 = Store::new();
        s2.load(&path).expect("load");
        let dc2 = s2.decision_counts("acme");
        assert_eq!(dc2.get("budget_exceeded").copied(), Some(2));
        assert_eq!(dc2.get("loop_detected").copied(), Some(1));

        // An old snapshot with no `decision_counts` field loads to empty.
        let old = dir.join(format!("tf-cloud-{}-olddc.json", std::process::id()));
        std::fs::write(
            &old,
            br#"{"orgs":{},"killed":{},"budgets":{},"devices":{}}"#,
        )
        .expect("write old snapshot");
        let s3 = Store::new();
        s3.load(&old).expect("load old snapshot");
        assert!(s3.decision_counts("acme").is_empty());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&old);
    }

    #[test]
    fn incident_kind_counts_fold_by_kind() {
        let s = Store::new();
        let now = 1_000_000;
        // Three budget-protection blocks on one run trip a budget_exhausted.
        s.ingest_at(
            "acme",
            &[
                block_at("r1", "budget_exceeded", 1000, now - 2),
                block_at("r1", "budget_exceeded", 1000, now - 1),
                block_at("r1", "budget_exceeded", 1000, now),
            ],
            now,
        );
        let counts = s.incident_kind_counts("acme");
        assert_eq!(counts.get("budget_exhausted").copied(), Some(1));
        assert!(s.incident_kind_counts("other").is_empty());
    }

    #[test]
    fn persistence_round_trip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tf-cloud-{}-persist.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let s = Store::new();
        s.ingest(
            "acme",
            &[CallRecord {
                run_id: "r1".into(),
                model: "claude".into(),
                decision: "allow".into(),
                cost_microusd: 1500,
                step: 2,
                ts_millis: 100,
                ..Default::default()
            }],
        );
        s.kill("acme", "r1");
        s.set_budget("acme", "r1", 500_000);
        s.save(&path).expect("save");

        // A fresh store loads the snapshot and sees everything.
        let s2 = Store::new();
        s2.load(&path).expect("load");
        let runs = s2.runs("acme");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].spent_microusd, 1500);
        assert!(runs[0].killed);
        assert_eq!(s2.budgets("acme")["r1"], 500_000);

        // A missing file is a clean start, not an error.
        let missing = dir.join(format!("tf-cloud-{}-nope.json", std::process::id()));
        Store::new()
            .load(&missing)
            .expect("missing file should be ok");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn audit_chain_persists_and_verifies() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tf-cloud-{}-audit.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let s = Store::new();
        s.audit_append("acme", "key:abc123", "control.kill", "r1", "mode=hard");
        s.audit_append(
            "acme",
            "key:abc123",
            "control.set_budget",
            "r1",
            "budget_micros=2500000",
        );
        assert_eq!(s.audit("acme").len(), 2);
        assert_eq!(s.audit_verify("acme"), Ok(()));
        s.save(&path).expect("save");

        // Reload: the chain (and its integrity) survives a restart.
        let s2 = Store::new();
        s2.load(&path).expect("load");
        let chain = s2.audit("acme");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].seq, 0);
        assert_eq!(chain[0].action, "control.kill");
        assert_eq!(chain[1].seq, 1);
        assert_eq!(chain[1].action, "control.set_budget");
        // The second entry links to the first's hash.
        assert_eq!(chain[1].prev_hash, chain[0].entry_hash);
        assert_eq!(s2.audit_verify("acme"), Ok(()));

        // An old snapshot with no `audit` field loads to an empty (valid) chain.
        let old = dir.join(format!("tf-cloud-{}-audit-old.json", std::process::id()));
        std::fs::write(
            &old,
            br#"{"orgs":{},"killed":{},"budgets":{},"devices":{}}"#,
        )
        .expect("write old snapshot");
        let s3 = Store::new();
        s3.load(&old).expect("load old snapshot");
        assert!(s3.audit("acme").is_empty());
        assert_eq!(s3.audit_verify("acme"), Ok(()));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&old);
    }

    #[test]
    fn dirty_flag_tracks_mutations() {
        let s = Store::new();
        assert!(!s.take_dirty(), "fresh store is clean");
        s.ingest("acme", &[rec("r1", 1)]);
        assert!(s.take_dirty(), "ingest marks dirty");
        assert!(!s.take_dirty(), "take clears the flag");
    }

    fn rec_at(run: &str, cost: i64, ts: i64) -> CallRecord {
        CallRecord {
            run_id: run.into(),
            decision: "allow".into(),
            cost_microusd: cost,
            ts_millis: ts,
            ..Default::default()
        }
    }

    #[test]
    fn series_buckets_sum_to_totals() {
        let s = Store::new();
        let now = 10_000;
        s.ingest(
            "acme",
            &[
                rec_at("r1", 100, now - 500),
                rec_at("r1", 200, now - 100),
                rec_at("r2", 50, now - 50),
            ],
        );
        let buckets = s.series("acme", None, 1000, 100, now);
        let cost: i64 = buckets.iter().map(|b| b.cost_microusd).sum();
        let calls: u64 = buckets.iter().map(|b| b.calls).sum();
        // Sum over the window equals the org total.
        assert_eq!(cost, 350);
        assert_eq!(calls, 3);
        assert_eq!(cost, s.summary("acme").spent_microusd);

        // Scoped to one run.
        let r1: i64 = s
            .series("acme", Some("r1"), 1000, 100, now)
            .iter()
            .map(|b| b.cost_microusd)
            .sum();
        assert_eq!(r1, 300);

        // Samples outside the window are excluded.
        let none: i64 = s
            .series("acme", None, 100, 50, now + 100_000)
            .iter()
            .map(|b| b.cost_microusd)
            .sum();
        assert_eq!(none, 0);
    }

    #[test]
    fn stream_emits_run_update_on_ingest() {
        let s = Store::new();
        let mut rx = s.subscribe();
        s.ingest("acme", &[rec("r1", 5)]);
        match rx.try_recv() {
            Ok(StreamEvent::RunUpdate { org, run }) => {
                assert_eq!(org, "acme");
                assert_eq!(run.run_id, "r1");
                assert_eq!(run.spent_microusd, 5);
            }
            other => panic!("expected run_update, got {other:?}"),
        }
    }

    #[test]
    fn stream_emits_kill() {
        let s = Store::new();
        let mut rx = s.subscribe();
        s.kill("acme", "r1");
        assert!(matches!(
            rx.try_recv(),
            Ok(StreamEvent::Kill { org, run }) if org == "acme" && run == "r1"
        ));
    }

    // ---- incidents ----------------------------------------------------------

    fn block_at(run: &str, decision: &str, cost: i64, ts: i64) -> CallRecord {
        CallRecord {
            run_id: run.into(),
            decision: decision.into(),
            cost_microusd: cost,
            ts_millis: ts,
            ..Default::default()
        }
    }

    #[test]
    fn budget_exhausted_fires_at_threshold_not_under() {
        let s = Store::new(); // default budget_blocks = 3
        let now = 1_000_000;
        // Two budget-protection blocks: under threshold → nothing yet.
        s.ingest_at(
            "acme",
            &[
                block_at("r1", "budget_exceeded", 1000, now - 2),
                block_at("r1", "budget_exceeded", 1000, now - 1),
            ],
            now,
        );
        assert!(s.incidents("acme").is_empty(), "under threshold");

        // The third block trips it.
        s.ingest_at("acme", &[block_at("r1", "budget_exceeded", 1000, now)], now);
        let incs = s.incidents("acme");
        assert_eq!(incs.len(), 1);
        assert_eq!(incs[0].id, "budget_exhausted:r1");
        assert_eq!(incs[0].kind, "budget_exhausted");
        assert_eq!(incs[0].severity, tokenfuse_core::Severity::High);
        assert_eq!(incs[0].run_id.as_deref(), Some("r1"));
        assert_eq!(incs[0].occurrences, 1);
        assert_eq!(incs[0].first_seen_millis, now);

        // A further block upserts in place (bumps occurrences, no duplicate).
        s.ingest_at(
            "acme",
            &[block_at("r1", "budget_exceeded", 1000, now + 5)],
            now + 5,
        );
        let incs = s.incidents("acme");
        assert_eq!(incs.len(), 1, "same incident, not a duplicate");
        assert_eq!(incs[0].occurrences, 2);
        assert_eq!(incs[0].last_seen_millis, now + 5);
    }

    #[test]
    fn sustained_loop_fires_within_window() {
        let s = Store::new(); // default loop_repeats = 3, window 10 min
        let now = 1_000_000;
        s.ingest_at(
            "acme",
            &[
                block_at("r1", "loop_detected", 0, now - 2),
                block_at("r1", "loop_detected", 0, now - 1),
            ],
            now,
        );
        assert!(
            s.incidents("acme")
                .iter()
                .all(|i| i.kind != "sustained_loop"),
            "under threshold"
        );

        s.ingest_at("acme", &[block_at("r1", "loop_detected", 0, now)], now);
        let inc = s
            .incidents("acme")
            .into_iter()
            .find(|i| i.kind == "sustained_loop")
            .expect("sustained_loop incident");
        assert_eq!(inc.id, "sustained_loop:r1");
        assert_eq!(inc.severity, tokenfuse_core::Severity::Medium);
        assert_eq!(inc.run_id.as_deref(), Some("r1"));
    }

    #[test]
    fn sustained_loop_window_prunes_stale_repeats() {
        let s = Store::new();
        let now = 10_000_000;
        // Two loops far outside the 10-minute window, one now → count prunes to 1.
        s.ingest_at(
            "acme",
            &[
                block_at("r1", "loop_detected", 0, now - 5_000_000),
                block_at("r1", "loop_detected", 0, now - 4_000_000),
                block_at("r1", "loop_detected", 0, now),
            ],
            now,
        );
        assert!(
            s.incidents("acme")
                .iter()
                .all(|i| i.kind != "sustained_loop"),
            "stale repeats pruned, under threshold"
        );
    }

    #[test]
    fn spend_spike_fires_over_burn_rate() {
        let s = Store::new(); // default 5 USD/min = 5_000_000 micros
        let now = 1_000_000;
        // 4 USD in the last minute — under the rate.
        s.ingest_at("acme", &[block_at("r1", "allow", 4_000_000, now)], now);
        assert!(s.incidents("acme").iter().all(|i| i.kind != "spend_spike"));

        // Another $2 tips the minute's burn over 5 USD.
        s.ingest_at(
            "acme",
            &[block_at("r1", "allow", 2_000_000, now + 1)],
            now + 1,
        );
        let inc = s
            .incidents("acme")
            .into_iter()
            .find(|i| i.kind == "spend_spike")
            .expect("spend_spike incident");
        assert_eq!(inc.id, "spend_spike:", "org-scoped, empty run scope");
        assert_eq!(inc.severity, tokenfuse_core::Severity::High);
        assert!(inc.run_id.is_none());
    }

    #[test]
    fn stream_emits_incident_on_trip() {
        let s = Store::new();
        let mut rx = s.subscribe();
        let now = 1_000_000;
        s.ingest_at(
            "acme",
            &[
                block_at("r1", "budget_exceeded", 1000, now - 2),
                block_at("r1", "budget_exceeded", 1000, now - 1),
                block_at("r1", "budget_exceeded", 1000, now),
            ],
            now,
        );
        let mut saw = false;
        while let Ok(ev) = rx.try_recv() {
            if let StreamEvent::Incident(inc) = ev {
                assert_eq!(inc.id, "budget_exhausted:r1");
                saw = true;
            }
        }
        assert!(saw, "expected an incident event on the bus");
    }

    #[test]
    fn incidents_persist_round_trip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tf-cloud-{}-incidents.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let s = Store::new();
        let now = 1_000_000;
        s.ingest_at(
            "acme",
            &[
                block_at("r1", "budget_exceeded", 1000, now - 2),
                block_at("r1", "budget_exceeded", 1000, now - 1),
                block_at("r1", "budget_exceeded", 1000, now),
            ],
            now,
        );
        // Stamp a notify time so we can prove it survives the round-trip.
        assert!(s.mark_incident_notified("acme", "budget_exhausted:r1", now, 600_000));
        s.save(&path).expect("save");

        let s2 = Store::new();
        s2.load(&path).expect("load");
        let incs = s2.incidents("acme");
        assert_eq!(incs.len(), 1);
        assert_eq!(incs[0].id, "budget_exhausted:r1");
        assert_eq!(incs[0].occurrences, 1);
        assert_eq!(incs[0].last_notified_millis, now, "dedup clock persists");
        // The persisted clock still dedups after a restart.
        assert!(!s2.mark_incident_notified("acme", "budget_exhausted:r1", now + 1000, 600_000));

        // An old snapshot with no `incidents` field loads to empty, not an error.
        let old = dir.join(format!("tf-cloud-{}-oldinc.json", std::process::id()));
        std::fs::write(
            &old,
            br#"{"orgs":{},"killed":{},"budgets":{},"devices":{}}"#,
        )
        .expect("write old snapshot");
        let s3 = Store::new();
        s3.load(&old).expect("load old snapshot");
        assert!(s3.incidents("acme").is_empty());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&old);
    }

    #[test]
    fn ack_marks_incident_acknowledged() {
        let s = Store::new();
        let now = 1_000_000;
        s.ingest_at(
            "acme",
            &[
                block_at("r1", "budget_exceeded", 1000, now - 2),
                block_at("r1", "budget_exceeded", 1000, now - 1),
                block_at("r1", "budget_exceeded", 1000, now),
            ],
            now,
        );
        assert!(!s.incidents("acme")[0].acknowledged);
        assert!(s.ack_incident("acme", "budget_exhausted:r1"));
        assert!(s.incidents("acme")[0].acknowledged);
        // Unknown id → false.
        assert!(!s.ack_incident("acme", "nope"));
    }

    /// One `agent_id` fanning out across many DISTINCT runs opens an
    /// agent-scoped `fanout_explosion`; a smaller fan-out opens nothing.
    #[test]
    fn fanout_explosion_fires_over_distinct_run_threshold() {
        let cfg = IncidentConfig {
            fanout_runs: 4,
            ..Default::default()
        };
        let s = Store::with_incident_config(cfg);
        let now = 1_000_000;
        let fan = |agent: &str, run: &str, ts: i64| CallRecord {
            run_id: run.into(),
            agent_id: agent.into(),
            decision: "allow".into(),
            ts_millis: ts,
            ..Default::default()
        };

        // Three distinct runs for one agent — under the threshold of 4.
        s.ingest_at(
            "acme",
            &[
                fan("orchestrator", "r1", now - 3),
                fan("orchestrator", "r2", now - 2),
                fan("orchestrator", "r3", now - 1),
            ],
            now,
        );
        assert!(
            s.incidents("acme")
                .iter()
                .all(|i| i.kind != "fanout_explosion"),
            "under distinct-run threshold"
        );

        // A fourth distinct run trips it.
        s.ingest_at("acme", &[fan("orchestrator", "r4", now)], now);
        let inc = s
            .incidents("acme")
            .into_iter()
            .find(|i| i.kind == "fanout_explosion")
            .expect("fanout_explosion incident");
        assert_eq!(inc.id, "fanout_explosion:orchestrator");
        assert_eq!(inc.severity, tokenfuse_core::Severity::High);
        assert!(inc.run_id.is_none(), "agent-scoped, no run");
        assert_eq!(inc.agent_id.as_deref(), Some("orchestrator"));

        // Re-driving the SAME run adds no NEW distinct run (the count stays at
        // 4, not 5), yet still upserts the one incident in place — proving the
        // tracker is distinct-by-run and dedups rather than piling up.
        s.ingest_at("acme", &[fan("orchestrator", "r4", now + 1)], now + 1);
        let fanouts: Vec<_> = s
            .incidents("acme")
            .into_iter()
            .filter(|i| i.kind == "fanout_explosion")
            .collect();
        assert_eq!(fanouts.len(), 1, "same incident, not a duplicate");
        assert_eq!(fanouts[0].occurrences, 2);
        assert_eq!(fanouts[0].last_seen_millis, now + 1);
    }

    /// Distinct runs older than `fanout_window_ms` are pruned and don't count
    /// toward the threshold (mirrors `sustained_loop_window_prunes_stale_repeats`).
    #[test]
    fn fanout_window_prunes_stale_runs() {
        let cfg = IncidentConfig {
            fanout_runs: 3,
            ..Default::default()
        };
        let s = Store::with_incident_config(cfg);
        let now = 10_000_000;
        let fan = |run: &str, ts: i64| CallRecord {
            run_id: run.into(),
            agent_id: "orchestrator".into(),
            decision: "allow".into(),
            ts_millis: ts,
            ..Default::default()
        };
        // Two distinct runs far outside the 10-minute window, one now → the
        // in-window distinct count prunes to 1, well under the threshold of 3.
        s.ingest_at(
            "acme",
            &[
                fan("r1", now - 5_000_000),
                fan("r2", now - 4_000_000),
                fan("r3", now),
            ],
            now,
        );
        assert!(
            s.incidents("acme")
                .iter()
                .all(|i| i.kind != "fanout_explosion"),
            "stale runs pruned, under threshold"
        );
    }

    /// Records with an empty `agent_id` never open a fanout incident — a blank
    /// agent isn't a single agent fanning out.
    #[test]
    fn fanout_ignores_unattributed_runs() {
        let cfg = IncidentConfig {
            fanout_runs: 3,
            ..Default::default()
        };
        let s = Store::with_incident_config(cfg);
        let now = 1_000_000;
        let unattributed = |run: &str, ts: i64| CallRecord {
            run_id: run.into(),
            agent_id: "".into(),
            decision: "allow".into(),
            ts_millis: ts,
            ..Default::default()
        };
        // Five distinct unattributed runs — far over the threshold, but blank
        // agent_id must never fan out.
        s.ingest_at(
            "acme",
            &[
                unattributed("r1", now - 4),
                unattributed("r2", now - 3),
                unattributed("r3", now - 2),
                unattributed("r4", now - 1),
                unattributed("r5", now),
            ],
            now,
        );
        assert!(
            s.incidents("acme")
                .iter()
                .all(|i| i.kind != "fanout_explosion"),
            "unattributed runs never fan out"
        );
    }

    /// A test P-256 signing key (fixed scalar, no RNG).
    fn test_signing_key() -> SigningKey {
        SigningKey::from_slice(&[0x22u8; 32]).expect("valid scalar")
    }

    #[test]
    fn audit_manifest_pins_the_current_tip() {
        let s = Store::new();
        let key = test_signing_key();
        s.audit_append("acme", "key:a", "control.kill", "r1", "mode=hard");
        s.audit_append(
            "acme",
            "key:a",
            "control.set_budget",
            "r1",
            "budget_micros=1",
        );

        let chain = s.audit("acme");
        let m = s.audit_manifest("acme", &key, 1_700_000_000_000);
        assert_eq!(m.org, "acme");
        assert_eq!(m.algorithm, "ES256");
        assert_eq!(m.entry_count, 2);
        assert_eq!(m.tip_seq, 1);
        // The manifest pins the actual current chain tip.
        assert_eq!(m.tip_hash, chain[1].entry_hash);
        assert_eq!(m.signed_at_millis, 1_700_000_000_000);
        assert!(!m.signature_b64.is_empty());
        assert!(!m.public_key_b64.is_empty());
    }

    #[test]
    fn audit_manifest_over_empty_chain_is_the_zero_tip() {
        let s = Store::new();
        let key = test_signing_key();
        let m = s.audit_manifest("noorg", &key, 42);
        assert_eq!(m.tip_seq, 0);
        assert_eq!(m.entry_count, 0);
        assert_eq!(m.tip_hash, "");
        assert_eq!(m.algorithm, "ES256");
        assert!(!m.signature_b64.is_empty());
    }

    #[test]
    fn a_signed_manifest_catches_a_re_hashed_forge() {
        let s = Store::new();
        let key = test_signing_key();
        s.audit_append("acme", "key:a", "control.kill", "r1", "mode=hard");
        s.audit_append(
            "acme",
            "key:a",
            "control.set_budget",
            "r1",
            "budget_micros=1",
        );
        // An auditor holds this manifest, pinning the intact tip.
        let signed = s.audit_manifest("acme", &key, 1);
        assert_eq!(s.audit_verify("acme"), Ok(()));

        // A forger edits entry 0 and RE-HASHES the whole chain so the plain
        // hash-chain check passes again — this is exactly the attack the signed
        // tip defends against (the store alone cannot detect it).
        {
            let mut inner = s.inner.write().unwrap();
            let chain = inner.audit.get_mut("acme").unwrap();
            let mut forged: Vec<AuditEntry> = Vec::new();
            for (i, e) in chain.iter().enumerate() {
                let detail = if i == 0 {
                    "mode=soft"
                } else {
                    e.detail.as_str()
                };
                forged.push(audit::append(
                    forged.last(),
                    e.ts_millis,
                    e.actor.clone(),
                    e.action.clone(),
                    e.subject.clone(),
                    detail,
                ));
            }
            *chain = forged;
        }
        // The re-hashed forge passes the hash-chain check...
        assert_eq!(s.audit_verify("acme"), Ok(()));
        // ...but re-hashing moved the tip, which the forger cannot re-sign: the
        // recomputed tip_hash no longer matches the signed manifest's.
        let after = s.audit_manifest("acme", &key, 2);
        assert_ne!(after.tip_hash, signed.tip_hash);
    }
}
