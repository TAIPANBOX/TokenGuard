//! In-memory aggregation store: the per-organization fleet view built from the
//! call telemetry many gateways push in. A faithful port of the original Go
//! control plane's `store.go` (in-memory parts). Durable JSON snapshotting
//! (`Load`/`Save`/autosave) is added in a follow-up — see
//! docs/14-mobile-companion.md, PR A3.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
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
}

impl StreamEvent {
    /// The org this event belongs to (used to filter per-subscriber).
    pub(crate) fn org(&self) -> &str {
        match self {
            Self::RunUpdate { org, .. } | Self::Kill { org, .. } | Self::Budget { org, .. } => org,
        }
    }

    /// The SSE event name.
    pub(crate) fn event_name(&self) -> &'static str {
        match self {
            Self::RunUpdate { .. } => "run_update",
            Self::Kill { .. } => "kill",
            Self::Budget { .. } => "budget",
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
}

/// A concurrency-safe aggregation keyed by org → run. A SQL/columnar backend
/// (Postgres/ClickHouse) for scale + retention is a drop-in follow-up behind
/// the same methods.
pub struct Store {
    inner: RwLock<Inner>,
    /// Live change bus for `/v1/stream` subscribers.
    events: broadcast::Sender<StreamEvent>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(1024);
        Self {
            inner: RwLock::new(Inner::default()),
            events,
        }
    }

    /// Subscribe to live change events (per-org filtering is the caller's job).
    pub fn subscribe(&self) -> broadcast::Receiver<StreamEvent> {
        self.events.subscribe()
    }

    /// Fold a batch of records into an org's aggregates, append them to the
    /// burn-rate series, and broadcast a `run_update` per affected run.
    pub fn ingest(&self, org: &str, records: &[CallRecord]) {
        let mut updated: Vec<RunAgg> = Vec::new();
        {
            let mut guard = self.inner.write().unwrap();
            guard.dirty = true;
            // Reborrow so `orgs` and `savings` can be borrowed as disjoint
            // fields inside the same loop (a live rollup accumulates both).
            let inner = &mut *guard;
            {
                let runs = inner.orgs.entry(org.to_string()).or_default();
                let sav = inner.savings.entry(org.to_string()).or_default();
                for r in records {
                    let agg = runs.entry(r.run_id.clone()).or_insert_with(|| RunAgg {
                        run_id: r.run_id.clone(),
                        ..Default::default()
                    });
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
        }
        for run in updated {
            let _ = self.events.send(StreamEvent::RunUpdate {
                org: org.to_string(),
                run,
            });
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
}
