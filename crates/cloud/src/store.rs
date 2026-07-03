//! In-memory aggregation store: the per-organization fleet view built from the
//! call telemetry many gateways push in. A faithful port of the original Go
//! control plane's `store.go` (in-memory parts). Durable JSON snapshotting
//! (`Load`/`Save`/autosave) is added in a follow-up — see
//! docs/14-mobile-companion.md, PR A3.

use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// One settled call, pushed by a gateway's `CloudSink`. The wire shape matches
/// `crates/gateway/src/sink.rs::CallRecord` (kept in sync by hand, exactly as
/// the Go plane did); a later cleanup can hoist the shared type into
/// `tokenfuse-core` so producer and consumer derive it from one definition.
#[derive(Debug, Clone, Default, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub runs: u64,
    pub calls: u64,
    pub spent_microusd: i64,
}

/// A run that has spent at or above a fraction of its central budget.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub run_id: String,
    pub spent_microusd: i64,
    pub budget_micros: i64,
    pub fraction: f64,
    pub killed: bool,
}

#[derive(Default)]
struct Inner {
    /// org → run → aggregate
    orgs: HashMap<String, HashMap<String, RunAgg>>,
    /// org → run → killed
    killed: HashMap<String, HashMap<String, bool>>,
    /// org → run → central budget (microdollars)
    budgets: HashMap<String, HashMap<String, i64>>,
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
}

#[derive(Default, Deserialize)]
struct SnapshotOwned {
    #[serde(default)]
    orgs: HashMap<String, HashMap<String, RunAgg>>,
    #[serde(default)]
    killed: HashMap<String, HashMap<String, bool>>,
    #[serde(default)]
    budgets: HashMap<String, HashMap<String, i64>>,
}

/// A concurrency-safe aggregation keyed by org → run. A SQL/columnar backend
/// (Postgres/ClickHouse) for scale + retention is a drop-in follow-up behind
/// the same methods.
#[derive(Default)]
pub struct Store {
    inner: RwLock<Inner>,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold a batch of records into an org's aggregates.
    pub fn ingest(&self, org: &str, records: &[CallRecord]) {
        let mut inner = self.inner.write().unwrap();
        inner.dirty = true;
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
        let mut inner = self.inner.write().unwrap();
        inner.dirty = true;
        inner
            .killed
            .entry(org.to_string())
            .or_default()
            .insert(run.to_string(), true);
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
        let mut inner = self.inner.write().unwrap();
        inner.dirty = true;
        inner
            .budgets
            .entry(org.to_string())
            .or_default()
            .insert(run.to_string(), micros);
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
        Ok(())
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
}
