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

/// Whether a call record represents a blocked decision. Gateways currently only
/// ingest settled calls (`allow`/`cache_hit`); anything else is reserved for
/// future block telemetry.
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
}

/// The aggregated state of one run within an organization.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct RunAgg {
    pub run_id: String,
    pub model: String,
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
    /// device_token → paired device (persisted)
    devices: HashMap<String, Device>,
    /// one-time pairing code → pending pairing (ephemeral)
    pairings: HashMap<String, Pairing>,
    /// device_id → recent nonces for replay defense (ephemeral)
    nonces: HashMap<String, VecDeque<String>>,
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
            let mut inner = self.inner.write().unwrap();
            inner.dirty = true;
            {
                let runs = inner.orgs.entry(org.to_string()).or_default();
                for r in records {
                    let agg = runs.entry(r.run_id.clone()).or_insert_with(|| RunAgg {
                        run_id: r.run_id.clone(),
                        ..Default::default()
                    });
                    agg.spent_microusd += r.cost_microusd;
                    agg.calls += 1;
                    if r.decision == "cache_hit" {
                        agg.cache_hits += 1;
                    }
                    if !r.model.is_empty() {
                        agg.model = r.model.clone();
                    }
                    if r.step > agg.steps {
                        agg.steps = r.step;
                    }
                    if r.ts_millis > agg.last_seen {
                        agg.last_seen = r.ts_millis;
                    }
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
