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

/// Hard cap on the number of buckets [`Store::series`] will ever allocate,
/// regardless of the requested `window`/`step`. Without this, any
/// authenticated viewer (`/v1/series` only requires `FleetReads`, so a viewer
/// key on a Paid org qualifies) could request e.g. `window=2592000s&step=1ms`
/// and force a ~80GB `Vec` allocation, crashing the shared process for every
/// org. Enforced here — not just in the HTTP query parsing — so the store is
/// safe regardless of what calls it.
const MAX_SERIES_BUCKETS: usize = 10_000;

/// Whether a call record represents a blocked decision (as opposed to a
/// settled call: `allow`/`cache_hit`). Blocked records are still stored and
/// counted, but their `cost_microusd` — an avoided-spend estimate, or 0 for
/// security blocks — must never be summed into real spend (see `ingest`).
fn is_blocked(decision: &str) -> bool {
    !matches!(decision, "allow" | "cache_hit")
}

/// True for wire `decision` values ingest evidence is trusted for: the two
/// non-blocking outcomes (`"allow"`, `"cache_hit"`) plus every
/// `tokenfuse_core::BreakerReason::as_wire_str()` value (`budget_exceeded`,
/// `policy_violation`, `loop_detected`, `killed`, `wasm_policy`,
/// `taint_blocked`, `dlp_blocked` — see `crates/core/src/breaker.rs`).
///
/// `/v1/ingest` is intentionally ungated: ANY authenticated org principal,
/// including a read-only viewer key, may POST a batch (ADR-3, so a gateway
/// never loses telemetry over a stale/rotated key). That means the
/// `decision` string in a record is untrusted input from whichever principal
/// is calling — not necessarily the gateway's own guard firing. Without this
/// allow-list, a viewer key could POST a fabricated `decision` (e.g.
/// `"pwned"`) to inflate/pollute `/v1/compliance`'s `decision_counts` or, were
/// a detector ever loosened to match on an arbitrary string, forge an
/// incident. An unrecognized decision still updates the run's `calls` (and,
/// via the existing `is_blocked` gate, is treated as non-spend) so a gateway
/// shipping a not-yet-adopted decision kind doesn't silently lose accounting
/// — it just never becomes compliance/incident evidence until this list is
/// extended for it. This also bounds `decision_counts` to ~9 keys per org.
///
/// Hardcoded rather than iterating the enum (Rust has no built-in enum
/// iteration) — mirrors the same tradeoff `compliance.rs::ALL_REASONS` makes
/// in `tokenfuse-core`; see `known_decisions_cover_every_breaker_reason` below
/// for the test that keeps this list honest against `BreakerReason`.
fn is_known_decision(decision: &str) -> bool {
    matches!(
        decision,
        "allow"
            | "cache_hit"
            | "budget_exceeded"
            | "policy_violation"
            | "loop_detected"
            | "killed"
            | "wasm_policy"
            | "taint_blocked"
            | "dlp_blocked"
    )
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

/// Org-wide totals. `calls`/`spent_microusd` are exact across the org's
/// entire ingest history; `runs` is the currently-retained distinct run
/// count, bounded by `MAX_RUNS_PER_ORG` — see `Store::summary`.
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

/// Per-org running totals, folded on EVERY ingested record — independent of
/// which [`RunAgg`]s remain in [`Inner::orgs`] after LRU eviction (see
/// [`MAX_RUNS_PER_ORG`]). [`Store::summary`] reads `calls`/`spent_microusd`
/// from here (rather than summing the possibly-evicted run map) so eviction
/// never undercounts an org's totals. Persisted so totals survive a restart;
/// see [`Store::load`]'s backfill for snapshots that predate this field.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct OrgTotals {
    /// Every ingested record increments this by one — mirrors `RunAgg::calls`
    /// summed across ALL runs ever seen for the org, evicted or not.
    calls: u64,
    /// Real spend only (blocked/avoided-spend rows excluded — the same gate
    /// `RunAgg::spent_microusd` uses; see `is_blocked`).
    spent_microusd: i64,
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

/// Hard cap on the number of distinct run_ids retained per org in
/// [`Inner::orgs`]. `/v1/ingest` is intentionally ungated (ADR-3 — any
/// authenticated org principal, including a read-only viewer key, may push a
/// batch), so without this a low-privilege credential could grow this map
/// without bound by posting records with unique `run_id`s. On overflow the
/// least-recently-touched run is evicted (see [`RecencyIndex`]); eviction
/// only drops that run's OWN per-run aggregate from `/v1/runs` — the org's
/// running totals are unaffected (see [`OrgTotals`] / [`Store::summary`]).
const MAX_RUNS_PER_ORG: usize = 50_000;

/// Hard cap on the number of distinct keys retained in EACH of
/// `incident_tracker` and `fanout_tracker` (enforced independently per
/// tracker). Both are keyed by attacker-influenceable `run_id`/`agent_id`
/// values reachable through the same ungated `/v1/ingest` path as
/// [`MAX_RUNS_PER_ORG`]. These trackers are ephemeral detector state (not
/// persisted); evicting a long-dormant key just means it won't
/// retroactively re-trip a detector — the durable [`Incident`] record, once
/// tripped, lives in a separate map and is never evicted by this.
const MAX_TRACKER_KEYS: usize = 20_000;

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

/// A least-recently-used index over a set of keys, used to bound the
/// cardinality of a map: [`RecencyIndex::touch`] records/refreshes a key's
/// recency in O(log n), and [`RecencyIndex::evict_oldest`] removes and
/// returns the least-recently-touched key in O(log n). Kept as a small side
/// index (rather than threading recency through the maps it bounds) so the
/// same structure works for `Inner::orgs`' per-org run map and the flat
/// `incident_tracker` / `fanout_tracker` maps alike. Not persisted — see call
/// sites for how each user rebuilds or tolerates a cold index after a
/// restart.
struct RecencyIndex<K: Ord + Clone + std::hash::Hash + Eq> {
    /// seq (monotonic touch order) → key, ascending — the front is the
    /// least-recently-touched.
    by_seq: BTreeMap<u64, K>,
    /// key → its current seq, so a re-touch can find and drop its stale
    /// `by_seq` entry before re-inserting at the back.
    seq_of: HashMap<K, u64>,
    next_seq: u64,
}

impl<K: Ord + Clone + std::hash::Hash + Eq> Default for RecencyIndex<K> {
    fn default() -> Self {
        Self {
            by_seq: BTreeMap::new(),
            seq_of: HashMap::new(),
            next_seq: 0,
        }
    }
}

impl<K: Ord + Clone + std::hash::Hash + Eq> RecencyIndex<K> {
    /// Record `key` as just-touched (most recent), moving it to the back of
    /// the eviction order if already present.
    fn touch(&mut self, key: K) {
        if let Some(old_seq) = self.seq_of.remove(&key) {
            self.by_seq.remove(&old_seq);
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.by_seq.insert(seq, key.clone());
        self.seq_of.insert(key, seq);
    }

    /// Remove and return the least-recently-touched key, if any.
    fn evict_oldest(&mut self) -> Option<K> {
        let seq = *self.by_seq.keys().next()?;
        let key = self.by_seq.remove(&seq)?;
        self.seq_of.remove(&key);
        Some(key)
    }
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
    /// org → running totals, unaffected by `orgs` eviction (persisted) — see
    /// [`OrgTotals`].
    org_totals: HashMap<String, OrgTotals>,
    /// org → LRU recency index over `orgs[org]`'s run_ids, bounding it to
    /// [`MAX_RUNS_PER_ORG`]. Ephemeral: best-effort rebuilt from each
    /// `RunAgg::last_seen` on load (see `Store::load`), so recency across a
    /// restart isn't exact, only a reasonable approximation.
    run_recency: HashMap<String, RecencyIndex<String>>,
    /// Recency index over `incident_tracker`'s keys, bounding it to
    /// [`MAX_TRACKER_KEYS`]. Ephemeral, like the tracker itself.
    tracker_recency: RecencyIndex<(String, String)>,
    /// Recency index over `fanout_tracker`'s keys, bounding it to
    /// [`MAX_TRACKER_KEYS`]. Ephemeral, like the tracker itself.
    fanout_recency: RecencyIndex<(String, String)>,
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
    org_totals: &'a HashMap<String, OrgTotals>,
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
    /// Missing on snapshots that predate `MAX_RUNS_PER_ORG` eviction —
    /// `default` loads empty, and [`Store::load`] backfills each org's totals
    /// by summing its (never-evicted, on those old snapshots) `orgs` map, so
    /// pre-existing installs recover EXACT historical totals rather than
    /// zeros.
    #[serde(default)]
    org_totals: HashMap<String, OrgTotals>,
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
    ///
    /// Honesty note: `/v1/ingest` authenticates the ORG CREDENTIAL presented on
    /// the request (any role — an org's own viewer key qualifies, ADR-3), not
    /// the gateway process cryptographically. There is currently no
    /// gateway-specific credential, so this store cannot distinguish "the real
    /// gateway pushed this" from "some holder of an org key pushed this" — a
    /// gateway-specific credential is future work. `decision` is accordingly
    /// treated as untrusted per-record input and gated through
    /// [`is_known_decision`] before it can become compliance/incident evidence.
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
                let totals = inner.org_totals.entry(org.to_string()).or_default();
                let recency = inner.run_recency.entry(org.to_string()).or_default();
                for r in records {
                    // Bound `runs`' cardinality (see `MAX_RUNS_PER_ORG`):
                    // evict the least-recently-touched run before inserting a
                    // genuinely NEW run_id that would exceed the cap. This
                    // only drops that run's own `RunAgg` — `totals` below
                    // already captured its contribution and is never
                    // affected by eviction (see `Store::summary`).
                    if !runs.contains_key(&r.run_id) && runs.len() >= MAX_RUNS_PER_ORG {
                        if let Some(evict_id) = recency.evict_oldest() {
                            runs.remove(&evict_id);
                        } else if let Some(any_id) = runs.keys().next().cloned() {
                            // Defensive fallback: `recency` and `runs` are
                            // kept in lock-step below, so this should be
                            // unreachable — but never let an out-of-sync
                            // index leave the cap unenforced.
                            runs.remove(&any_id);
                        }
                    }
                    let agg = runs.entry(r.run_id.clone()).or_insert_with(|| RunAgg {
                        run_id: r.run_id.clone(),
                        ..Default::default()
                    });
                    recency.touch(r.run_id.clone());
                    // Compliance evidence: count every KNOWN record decision
                    // (see `is_known_decision`), including blocked ones (a
                    // block is a guard firing, not spend). `/v1/compliance`
                    // reads this per-org tally; an unrecognized decision is
                    // untrusted input (ingest is ungated — any org principal
                    // can push a batch) and must not land here.
                    if is_known_decision(&r.decision) {
                        *dc.entry(r.decision.clone()).or_insert(0) += 1;
                    }
                    // Blocked calls are stored and counted, but their
                    // cost_microusd (avoided spend, or 0 for security blocks)
                    // must not inflate the org's real spend total. `totals`
                    // mirrors the same gate so it stays exact regardless of
                    // `runs` eviction.
                    if !is_blocked(&r.decision) {
                        agg.spent_microusd += r.cost_microusd;
                        totals.spent_microusd += r.cost_microusd;
                    }
                    agg.calls += 1;
                    totals.calls += 1;
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

                // budget_exhausted (High): ≥ N budget-protection blocks per
                // run. Gated on `is_known_decision` (belt-and-braces:
                // `is_budget_protection`'s set is already a subset of known
                // decisions, but this keeps the detector explicitly immune to
                // an unrecognized/fabricated decision string).
                if is_known_decision(&r.decision)
                    && tokenfuse_core::savings::is_budget_protection(&r.decision)
                {
                    let n = bump_tracker(
                        &mut inner.incident_tracker,
                        &mut inner.tracker_recency,
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

                // sustained_loop (Medium): ≥ N loop_detected for a run
                // in-window. `is_known_decision` guard for the same reason as
                // `budget_exhausted` above.
                if is_known_decision(&r.decision) && r.decision == "loop_detected" {
                    let n = bump_tracker(
                        &mut inner.incident_tracker,
                        &mut inner.tracker_recency,
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
                        &mut inner.fanout_recency,
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
        // Capped so a caller can never force an unbounded allocation (see
        // `MAX_SERIES_BUCKETS`); an absurd window/step combo just yields a
        // truncated series rather than crashing the process.
        let n = ((window / step).max(1) as usize).min(MAX_SERIES_BUCKETS);
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

    /// Org-wide totals. `calls`/`spent_microusd` are read from the running
    /// [`OrgTotals`] accumulator (exact over the org's full ingest history,
    /// unaffected by [`MAX_RUNS_PER_ORG`] eviction); `runs` reflects the
    /// currently-RETAINED run count (bounded by the same cap — see
    /// `Store::runs` for the live set).
    pub fn summary(&self, org: &str) -> Summary {
        let inner = self.inner.read().unwrap();
        let mut sum = Summary::default();
        if let Some(runs) = inner.orgs.get(org) {
            sum.runs = runs.len() as u64;
        }
        if let Some(totals) = inner.org_totals.get(org) {
            sum.calls = totals.calls;
            sum.spent_microusd = totals.spent_microusd;
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

    /// [`Store::ack_incident`] plus its `control.incident_ack` audit entry,
    /// folded into ONE write-lock acquisition (see [`append_audit_locked`]'s
    /// doc) — the HTTP `ack_incident` handler uses this instead of two separate
    /// locked calls. Preserves the not-found → `false` behavior: no audit entry
    /// is written for an unknown incident id.
    pub fn ack_incident_audited(&self, org: &str, id: &str, actor: &str) -> bool {
        let mut inner = self.inner.write().unwrap();
        let mut found = false;
        if let Some(inc) = inner.incidents.get_mut(org).and_then(|m| m.get_mut(id)) {
            inc.acknowledged = true;
            found = true;
        }
        if found {
            inner.dirty = true;
            append_audit_locked(&mut inner, org, actor, "control.incident_ack", id, "");
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
    ///
    /// Calling this as a SEPARATE step after a mutation (two lock
    /// acquisitions) leaves a window where a crash, or the periodic autosave,
    /// can persist the mutation with no matching audit entry — undercutting
    /// the "tamper-evident audit of every mutation" contract. The HTTP
    /// mutation handlers (`kill`, `set_budget`, `ack_incident`, `pair`) use the
    /// `*_audited` store methods below instead, which do the mutation and this
    /// append under ONE write-lock acquisition. This method remains for
    /// standalone audit writes (and tests) that have no paired mutation.
    pub fn audit_append(&self, org: &str, actor: &str, action: &str, subject: &str, detail: &str) {
        let mut inner = self.inner.write().unwrap();
        inner.dirty = true;
        append_audit_locked(&mut inner, org, actor, action, subject, detail);
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

    /// [`Store::kill`] plus its `control.kill` audit entry, folded into ONE
    /// write-lock acquisition (see [`append_audit_locked`]'s doc) — the HTTP
    /// `kill` handler uses this instead of calling `kill` then `audit_append` as
    /// two separate locked sections.
    pub fn kill_audited(&self, org: &str, run: &str, actor: &str) {
        {
            let mut inner = self.inner.write().unwrap();
            inner.dirty = true;
            inner
                .killed
                .entry(org.to_string())
                .or_default()
                .insert(run.to_string(), true);
            append_audit_locked(&mut inner, org, actor, "control.kill", run, "mode=hard");
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

    /// [`Store::set_budget`] plus its `control.set_budget` audit entry, folded
    /// into ONE write-lock acquisition (see [`append_audit_locked`]'s doc) — the
    /// HTTP `set_budget` handler uses this instead of two separate locked calls.
    pub fn set_budget_audited(&self, org: &str, run: &str, micros: i64, actor: &str) {
        {
            let mut inner = self.inner.write().unwrap();
            inner.dirty = true;
            inner
                .budgets
                .entry(org.to_string())
                .or_default()
                .insert(run.to_string(), micros);
            append_audit_locked(
                &mut inner,
                org,
                actor,
                "control.set_budget",
                run,
                &format!("budget_micros={micros}"),
            );
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
                org_totals: &inner.org_totals,
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

        // Pre-existing snapshots (from before MAX_RUNS_PER_ORG eviction
        // landed) have no `org_totals` entry for an org; since their `orgs`
        // map was never evicted, summing it recovers EXACT historical totals
        // — a strictly better default than zero. Post-fix snapshots already
        // carry an accurate `org_totals` per org (accumulated independently
        // of eviction, see `ingest_at`) and are used as-is.
        let mut org_totals = snap.org_totals;
        for (org, runs) in &inner.orgs {
            org_totals.entry(org.clone()).or_insert_with(|| {
                let mut t = OrgTotals::default();
                for agg in runs.values() {
                    t.calls += agg.calls;
                    t.spent_microusd += agg.spent_microusd;
                }
                t
            });
        }
        inner.org_totals = org_totals;

        // Seed the run-recency index (ephemeral, not persisted) from the
        // loaded runs, ordered by each RunAgg's own `last_seen`, so an
        // eviction shortly after a restart still prefers the actually-oldest
        // run rather than an arbitrary HashMap iteration order. Best effort:
        // `last_seen` is the record's own (client-supplied) timestamp, not a
        // perfect proxy for server-side touch order, but far better than no
        // ordering at all.
        let seed: Vec<(String, Vec<String>)> = inner
            .orgs
            .iter()
            .map(|(org, runs)| {
                let mut ids: Vec<(String, i64)> = runs
                    .values()
                    .map(|a| (a.run_id.clone(), a.last_seen))
                    .collect();
                ids.sort_by_key(|(_, last_seen)| *last_seen);
                (org.clone(), ids.into_iter().map(|(id, _)| id).collect())
            })
            .collect();
        inner.run_recency.clear();
        for (org, ids) in seed {
            let idx = inner.run_recency.entry(org).or_default();
            for id in ids {
                idx.touch(id);
            }
        }
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

    /// [`Store::redeem_pairing`] plus its `control.pair` audit entry, folded
    /// into ONE write-lock acquisition (see [`append_audit_locked`]'s doc) — the
    /// HTTP `pair` handler uses this instead of a separate `audit_append` call.
    /// The device self-redeemed (no bearer auth — the code was the credential,
    /// checked at `pair/new`), so the audit actor is the device itself.
    #[allow(clippy::too_many_arguments)]
    pub fn redeem_pairing_audited(
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
        let actor = format!("device:{}", device.device_id);
        let detail = format!("role={};platform={}", device.role, device.platform);
        append_audit_locked(
            &mut inner,
            &device.org,
            &actor,
            "control.pair",
            &device.device_id,
            &detail,
        );
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

/// Append an audit entry to `org`'s chain given an already-held write guard —
/// the shared building block for [`Store::audit_append`] and the `*_audited`
/// mutation methods, which fold a mutation and its audit record into ONE lock
/// acquisition so the two can never be observed/persisted independently.
fn append_audit_locked(
    inner: &mut Inner,
    org: &str,
    actor: &str,
    action: &str,
    subject: &str,
    detail: &str,
) {
    let chain = inner.audit.entry(org.to_string()).or_default();
    let entry = audit::append(chain.last(), now_millis(), actor, action, subject, detail);
    chain.push(entry);
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
///
/// Also bounds the number of DISTINCT `(org,key)` entries in `tracker` to
/// [`MAX_TRACKER_KEYS`], evicting the least-recently-touched entry (per
/// `recency`) when a genuinely NEW key would exceed the cap — an existing
/// key's repeat trigger is never dropped by this.
fn bump_tracker(
    tracker: &mut HashMap<(String, String), VecDeque<i64>>,
    recency: &mut RecencyIndex<(String, String)>,
    org: &str,
    kind: &str,
    scope: &str,
    ts: i64,
    window: Option<(i64, i64)>,
) -> u64 {
    let key = (org.to_string(), incident_id(kind, scope));
    if !tracker.contains_key(&key) && tracker.len() >= MAX_TRACKER_KEYS {
        if let Some(evict_key) = recency.evict_oldest() {
            tracker.remove(&evict_key);
        }
    }
    recency.touch(key.clone());
    let dq = tracker.entry(key).or_default();
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
///
/// Also bounds the number of DISTINCT `(org,agent)` entries in `tracker` to
/// [`MAX_TRACKER_KEYS`], evicting the least-recently-touched entry (per
/// `recency`) when a genuinely NEW key would exceed the cap.
#[allow(clippy::too_many_arguments)]
fn bump_fanout_tracker(
    tracker: &mut HashMap<(String, String), VecDeque<(String, i64)>>,
    recency: &mut RecencyIndex<(String, String)>,
    org: &str,
    agent: &str,
    run_id: &str,
    ts: i64,
    now: i64,
    window_ms: i64,
) -> u64 {
    let key = (org.to_string(), agent.to_string());
    if !tracker.contains_key(&key) && tracker.len() >= MAX_TRACKER_KEYS {
        if let Some(evict_key) = recency.evict_oldest() {
            tracker.remove(&evict_key);
        }
    }
    recency.touch(key.clone());
    let dq = tracker.entry(key).or_default();
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

    /// `is_known_decision` must accept every real `BreakerReason` wire string
    /// plus `allow`/`cache_hit`, and reject the rest — the exact list a
    /// fabricated `decision` (see `ingest_ignores_fabricated_decisions` below)
    /// must fail to join.
    #[test]
    fn known_decisions_cover_every_breaker_reason() {
        use tokenfuse_core::BreakerReason;
        // Mirrors `compliance.rs::ALL_REASONS` in `tokenfuse-core`: hardcoded
        // so a new `BreakerReason` variant doesn't silently slip past this
        // list unnoticed (it still compiles either way, but a reviewer diffing
        // this array against the enum will catch it).
        const ALL: [BreakerReason; 7] = [
            BreakerReason::BudgetExceeded,
            BreakerReason::PolicyViolation,
            BreakerReason::LoopDetected,
            BreakerReason::Killed,
            BreakerReason::WasmPolicy,
            BreakerReason::TaintBlocked,
            BreakerReason::DlpBlocked,
        ];
        for r in ALL {
            assert!(
                is_known_decision(r.as_wire_str()),
                "{} missing from the allow-list",
                r.as_wire_str()
            );
        }
        assert!(is_known_decision("allow"));
        assert!(is_known_decision("cache_hit"));
        assert!(!is_known_decision("pwned"));
        assert!(!is_known_decision(""));
    }

    /// A viewer key (or any org principal — `/v1/ingest` is intentionally
    /// ungated) POSTing a fabricated `decision` string must not be able to
    /// pollute `/v1/compliance` evidence or forge an incident. A real
    /// `budget_exceeded`, by contrast, must still do both.
    #[test]
    fn ingest_ignores_fabricated_decisions_for_compliance_and_incidents() {
        let s = Store::new();
        let now = 1_000_000;

        // A fabricated decision: counted toward calls, but must not appear in
        // decision_counts or drive any detector.
        s.ingest_at("acme", &[block_at("r1", "pwned", 0, now)], now);
        assert!(
            !s.decision_counts("acme").contains_key("pwned"),
            "fabricated decision must not appear in decision_counts"
        );
        assert!(
            s.incidents("acme").is_empty(),
            "fabricated decision must not create an incident"
        );
        assert_eq!(s.runs("acme")[0].calls, 1, "calls still accounted for");

        // The real budget_exceeded reason, three times, still trips
        // budget_exhausted AND lands in decision_counts — proving the
        // allow-list doesn't just silently swallow everything.
        s.ingest_at(
            "acme",
            &[
                block_at("r2", "budget_exceeded", 1000, now),
                block_at("r2", "budget_exceeded", 1000, now),
                block_at("r2", "budget_exceeded", 1000, now),
            ],
            now,
        );
        assert_eq!(
            s.decision_counts("acme").get("budget_exceeded").copied(),
            Some(3)
        );
        assert!(
            s.incidents("acme")
                .iter()
                .any(|i| i.id == "budget_exhausted:r2"),
            "real budget_exceeded must still trip an incident"
        );
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

    /// The `*_audited` methods fold a mutation and its audit entry into ONE
    /// write-lock acquisition, so the two are never observable independently —
    /// unlike the plain `kill`/`set_budget`/`ack_incident` + a separate
    /// `audit_append`, which leaves a window where a crash or the periodic
    /// autosave could persist the mutation with no matching audit entry. This
    /// proves the mutation effect and its audit entry are always observed (and
    /// persisted) TOGETHER: after a kill and a set_budget, exactly the expected
    /// two audit entries exist, the chain verifies, and a single saved snapshot
    /// carries both the mutation state and the matching audit entries.
    #[test]
    fn audited_mutations_are_atomic_with_their_audit_entry() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tf-cloud-{}-atomic.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let s = Store::new();
        s.kill_audited("acme", "r1", "key:abc123");
        s.set_budget_audited("acme", "r1", 2_500_000, "key:abc123");

        // The mutation effects are live...
        assert!(s.runs("acme").is_empty(), "no telemetry ingested yet");
        assert_eq!(s.kills("acme"), vec!["r1".to_string()]);
        assert_eq!(s.budgets("acme")["r1"], 2_500_000);

        // ...and exactly the expected audit entries exist, chained and
        // verifiable — nothing extra, nothing missing.
        let chain = s.audit("acme");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].action, "control.kill");
        assert_eq!(chain[0].subject, "r1");
        assert_eq!(chain[0].actor, "key:abc123");
        assert_eq!(chain[1].action, "control.set_budget");
        assert_eq!(chain[1].detail, "budget_micros=2500000");
        assert_eq!(chain[1].prev_hash, chain[0].entry_hash);
        assert_eq!(s.audit_verify("acme"), Ok(()));

        // The point: a single snapshot (one save, one load — no window for the
        // mutation and its audit record to diverge) carries BOTH the mutation
        // state and its audit entries together.
        s.save(&path).expect("save");
        let s2 = Store::new();
        s2.load(&path).expect("load");
        assert_eq!(s2.kills("acme"), vec!["r1".to_string()]);
        assert_eq!(s2.budgets("acme")["r1"], 2_500_000);
        assert_eq!(s2.audit("acme").len(), 2);
        assert_eq!(s2.audit_verify("acme"), Ok(()));

        let _ = std::fs::remove_file(&path);
    }

    /// [`Store::ack_incident_audited`] preserves the not-found → `false`
    /// behavior of the plain `ack_incident`, and — unlike a separate
    /// mutate-then-`audit_append` pair — never writes an audit entry for an
    /// unknown incident id (there is no mutation to pair it with).
    #[test]
    fn ack_incident_audited_writes_no_audit_entry_when_not_found() {
        let s = Store::new();
        assert!(!s.ack_incident_audited("acme", "nope", "key:abc123"));
        assert!(s.audit("acme").is_empty(), "no mutation, no audit entry");
    }

    /// [`Store::redeem_pairing_audited`] registers the device AND appends the
    /// `control.pair` audit entry atomically — both observable together.
    #[test]
    fn redeem_pairing_audited_registers_device_and_audits_together() {
        let s = Store::new();
        s.create_pairing("code-1", "acme", "admin", 9_999_999_999);
        let dev = s
            .redeem_pairing_audited(
                "code-1",
                0,
                "dev-1".into(),
                "tok-1".into(),
                "pubkey".into(),
                "iphone".into(),
                "ios".into(),
            )
            .expect("pairing redeemed");
        assert_eq!(dev.org, "acme");

        let chain = s.audit("acme");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].action, "control.pair");
        assert_eq!(chain[0].subject, "dev-1");
        assert_eq!(chain[0].actor, "device:dev-1");
        assert_eq!(chain[0].detail, "role=admin;platform=ios");
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

    /// A huge window paired with a tiny step must never allocate more than
    /// [`MAX_SERIES_BUCKETS`] — the DoS this guards against (`?window=2592000s
    /// &step=1ms` would otherwise ask for ~2.6 billion buckets).
    #[test]
    fn series_bucket_count_is_capped() {
        let s = Store::new();
        let now = 10_000;
        let buckets = s.series("acme", None, 2_592_000_000, 1, now);
        assert_eq!(buckets.len(), MAX_SERIES_BUCKETS);
        assert!(buckets.len() <= MAX_SERIES_BUCKETS);
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

    // ---- LRU bounds (MAX_RUNS_PER_ORG / MAX_TRACKER_KEYS) -------------------

    /// A low-privilege credential POSTing records with unique `run_id`s
    /// (`/v1/ingest` is intentionally ungated) must not be able to grow
    /// `orgs[org]` without bound. Ingesting far more than `MAX_RUNS_PER_ORG`
    /// distinct runs keeps the retained map capped AND retains the
    /// most-recently-touched runs — but MUST NOT lose any spend: `summary()`
    /// still reflects the full ingested total via the `OrgTotals`
    /// accumulator, which eviction never touches.
    #[test]
    fn run_map_is_capped_but_totals_stay_exact() {
        let s = Store::new();
        let extra = 25;
        let total_records = MAX_RUNS_PER_ORG + extra;
        let mut expected_spend: i64 = 0;
        let mut records: Vec<CallRecord> = Vec::with_capacity(total_records);
        for i in 0..total_records {
            let cost = (i % 7) as i64 + 1; // varied, small, nonzero cost
            expected_spend += cost;
            records.push(CallRecord {
                run_id: format!("run-{i}"),
                decision: "allow".into(),
                cost_microusd: cost,
                ts_millis: i as i64,
                ..Default::default()
            });
        }
        // One big batch, ingested in order — mirrors a burst from a gateway
        // (or an attacker) pushing many distinct run_ids.
        s.ingest_at("acme", &records, total_records as i64);

        let runs = s.runs("acme");
        assert!(
            runs.len() <= MAX_RUNS_PER_ORG,
            "run map must stay capped, got {}",
            runs.len()
        );

        // Eviction did NOT lose any spend or calls: the summary total still
        // reflects EVERY ingested record, even though most individual
        // RunAggs were evicted.
        let sum = s.summary("acme");
        assert_eq!(sum.spent_microusd, expected_spend);
        assert_eq!(sum.calls, total_records as u64);

        // LRU: the most-recently-touched runs (the tail of the batch) are the
        // ones retained; the oldest (the head) were evicted. Check via a
        // HashSet rather than re-scanning `runs` per id — this loop covers
        // `total_records` ids and a linear `.iter().any(..)` per id would be
        // O(n^2) (n ~ 50,000, so ~2.5 billion comparisons).
        let retained: HashSet<&str> = runs.iter().map(|r| r.run_id.as_str()).collect();
        for i in extra..total_records {
            let id = format!("run-{i}");
            assert!(
                retained.contains(id.as_str()),
                "{id} should still be retained"
            );
        }
        for i in 0..extra {
            let id = format!("run-{i}");
            assert!(
                !retained.contains(id.as_str()),
                "{id} should have been evicted"
            );
        }
    }

    /// `incident_tracker` and `fanout_tracker` are ephemeral detector state
    /// keyed by attacker-influenceable `run_id`/`agent_id` values (same
    /// ungated ingest path as `MAX_RUNS_PER_ORG`). Pushing far more than
    /// `MAX_TRACKER_KEYS` distinct keys through each must keep both maps
    /// bounded.
    #[test]
    fn trackers_are_bounded() {
        let s = Store::new();
        let now = 1_000_000;
        let extra = 25;
        let total = MAX_TRACKER_KEYS + extra;

        // incident_tracker: one distinct (org, "budget_exhausted:run_id") key
        // per record (a single budget-protection block each — not enough on
        // its own to trip an incident, so this only exercises the tracker's
        // key cardinality bound, not the detector).
        let budget_records: Vec<CallRecord> = (0..total)
            .map(|i| CallRecord {
                run_id: format!("run-{i}"),
                decision: "budget_exceeded".into(),
                cost_microusd: 1,
                ts_millis: now,
                ..Default::default()
            })
            .collect();
        s.ingest_at("acme", &budget_records, now);

        // fanout_tracker: one distinct (org, agent_id) key per record.
        let fanout_records: Vec<CallRecord> = (0..total)
            .map(|i| CallRecord {
                run_id: format!("fr-{i}"),
                agent_id: format!("agent-{i}"),
                decision: "allow".into(),
                ts_millis: now,
                ..Default::default()
            })
            .collect();
        s.ingest_at("acme", &fanout_records, now);

        let inner = s.inner.read().unwrap();
        assert!(
            inner.incident_tracker.len() <= MAX_TRACKER_KEYS,
            "incident_tracker must stay bounded, got {}",
            inner.incident_tracker.len()
        );
        assert!(
            inner.fanout_tracker.len() <= MAX_TRACKER_KEYS,
            "fanout_tracker must stay bounded, got {}",
            inner.fanout_tracker.len()
        );
    }

    /// The `OrgTotals` accumulator round-trips through save/load exactly, and
    /// a snapshot from before this field existed (whose `orgs` map was, by
    /// definition, never evicted) backfills sane — exact, not zero — totals
    /// by summing that map.
    #[test]
    fn org_totals_persist_and_old_snapshots_backfill_from_runs() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tf-cloud-{}-orgtotals.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let s = Store::new();
        s.ingest(
            "acme",
            &[
                CallRecord {
                    run_id: "r1".into(),
                    decision: "allow".into(),
                    cost_microusd: 1000,
                    ..Default::default()
                },
                CallRecord {
                    run_id: "r2".into(),
                    decision: "allow".into(),
                    cost_microusd: 2500,
                    ..Default::default()
                },
            ],
        );
        s.save(&path).expect("save");

        let s2 = Store::new();
        s2.load(&path).expect("load");
        let sum = s2.summary("acme");
        assert_eq!(sum.spent_microusd, 3500);
        assert_eq!(sum.calls, 2);

        // A pre-existing snapshot with no `org_totals` field, but a
        // populated (never-evicted, as every pre-fix snapshot's is) `orgs`
        // map, backfills its totals by summing that map.
        let old = dir.join(format!("tf-cloud-{}-oldorgtotals.json", std::process::id()));
        std::fs::write(
            &old,
            br#"{"orgs":{"acme":{"r1":{"run_id":"r1","model":"","agent_id":"","spent_microusd":700,"calls":4,"cache_hits":0,"steps":0,"last_seen_millis":10,"killed":false}}},"killed":{},"budgets":{},"devices":{}}"#,
        )
        .expect("write old snapshot");
        let s3 = Store::new();
        s3.load(&old).expect("load old snapshot");
        let sum3 = s3.summary("acme");
        assert_eq!(sum3.spent_microusd, 700, "backfilled from the orgs map");
        assert_eq!(sum3.calls, 4);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&old);
    }
}
