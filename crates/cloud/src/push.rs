//! Push delivery + the event→push pipeline (docs/14 §4.3). Delivery is a trait
//! so the default build and tests use a no-op / recording sender; the real APNs
//! client lives behind the `apns` feature (see `apns.rs`). The pipeline turns
//! store change events (the same broadcast bus that feeds `/v1/stream`) into
//! alert pushes and Live Activity updates, deduplicated per (org, run, reason).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::store::{Store, StreamEvent};

/// An alert push to one device.
#[derive(Clone, Debug, PartialEq)]
pub struct Push {
    pub device_apns_token: String,
    pub title: String,
    pub body: String,
    pub run_id: String,
    pub reason: String,
}

/// A Live Activity update to one activity.
#[derive(Clone, Debug, PartialEq)]
pub struct ActivityUpdate {
    pub activity_token: String,
    pub run_id: String,
    pub spent_microusd: i64,
    pub budget_micros: Option<i64>,
    pub ended: bool,
}

/// Where pushes go. Fire-and-forget — real impls spawn the network call.
pub trait PushSender: Send + Sync {
    fn send(&self, push: Push);
    fn update_activity(&self, update: ActivityUpdate);
}

/// Default when APNs isn't configured — pushes are dropped (fail-open).
pub struct NullSender;

impl PushSender for NullSender {
    fn send(&self, _: Push) {}
    fn update_activity(&self, _: ActivityUpdate) {}
}

/// Records what would be sent — for tests.
#[derive(Default)]
pub struct RecordingSender {
    pub pushes: Mutex<Vec<Push>>,
    pub activities: Mutex<Vec<ActivityUpdate>>,
}

impl PushSender for RecordingSender {
    fn send(&self, push: Push) {
        self.pushes.lock().unwrap().push(push);
    }
    fn update_activity(&self, update: ActivityUpdate) {
        self.activities.lock().unwrap().push(update);
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Dedup window: at most one push per (org, run, reason) per 10 minutes.
const DEDUP_SECS: i64 = 600;

/// Turns store change events into pushes + Live Activity updates.
pub struct PushPipeline {
    store: Arc<Store>,
    sender: Arc<dyn PushSender>,
    alert_pct: f64,
    dedup: Mutex<HashMap<(String, String, String), i64>>,
}

impl PushPipeline {
    pub fn new(store: Arc<Store>, sender: Arc<dyn PushSender>, alert_pct: f64) -> Self {
        Self {
            store,
            sender,
            alert_pct,
            dedup: Mutex::new(HashMap::new()),
        }
    }

    /// Subscribe to the store's change bus and process events until it closes.
    pub fn spawn(self: Arc<Self>) {
        let mut rx = self.store.subscribe();
        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                self.handle(event);
            }
        });
    }

    /// Process one change event (sync — senders are fire-and-forget).
    pub fn handle(&self, event: StreamEvent) {
        match event {
            StreamEvent::Kill { org, run } => {
                self.alert(
                    &org,
                    &run,
                    "kill",
                    "Run killed",
                    &format!("Agent run {run} was killed"),
                );
                for token in self.store.activities_for_run(&org, &run) {
                    self.sender.update_activity(ActivityUpdate {
                        activity_token: token,
                        run_id: run.clone(),
                        spent_microusd: 0,
                        budget_micros: None,
                        ended: true,
                    });
                }
            }
            StreamEvent::RunUpdate { org, run } => {
                let budget = self.store.budgets(&org).get(&run.run_id).copied();
                if let Some(b) = budget {
                    if b > 0 && run.spent_microusd as f64 / b as f64 >= self.alert_pct {
                        let pct = (run.spent_microusd as f64 / b as f64 * 100.0) as i64;
                        self.alert(
                            &org,
                            &run.run_id,
                            "budget",
                            "Budget alert",
                            &format!("Run {} at {pct}% of budget", run.run_id),
                        );
                    }
                }
                for token in self.store.activities_for_run(&org, &run.run_id) {
                    self.sender.update_activity(ActivityUpdate {
                        activity_token: token,
                        run_id: run.run_id.clone(),
                        spent_microusd: run.spent_microusd,
                        budget_micros: budget,
                        ended: false,
                    });
                }
            }
            StreamEvent::Budget { .. } => {}
        }
    }

    fn alert(&self, org: &str, run: &str, reason: &str, title: &str, body: &str) {
        if !self.should_send(org, run, reason) {
            return;
        }
        for device in self.store.devices_for_org(org) {
            if let Some(token) = device.apns_token {
                self.sender.send(Push {
                    device_apns_token: token,
                    title: title.to_string(),
                    body: body.to_string(),
                    run_id: run.to_string(),
                    reason: reason.to_string(),
                });
            }
        }
    }

    /// True if this (org, run, reason) hasn't fired within the dedup window.
    fn should_send(&self, org: &str, run: &str, reason: &str) -> bool {
        let now = now_unix();
        let key = (org.to_string(), run.to_string(), reason.to_string());
        let mut dedup = self.dedup.lock().unwrap();
        if let Some(&last) = dedup.get(&key) {
            if now - last < DEDUP_SECS {
                return false;
            }
        }
        dedup.insert(key, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::Device;
    use crate::store::CallRecord;

    fn device(id: &str, org: &str, role: &str, apns: Option<&str>) -> Device {
        Device {
            device_id: id.into(),
            org: org.into(),
            role: role.into(),
            name: String::new(),
            platform: "ios".into(),
            pubkey_b64: String::new(),
            apns_token: apns.map(str::to_string),
        }
    }

    fn pipeline_with(store: Arc<Store>) -> (Arc<PushPipeline>, Arc<RecordingSender>) {
        let rec = Arc::new(RecordingSender::default());
        let pipe = Arc::new(PushPipeline::new(store, rec.clone(), 0.8));
        (pipe, rec)
    }

    #[test]
    fn kill_pushes_to_org_devices_with_a_token() {
        let store = Arc::new(Store::new());
        store.insert_device_for_test("tok-a", device("d1", "acme", "admin", Some("apns-1")));
        store.insert_device_for_test("tok-b", device("d2", "acme", "admin", None)); // no token
        store.insert_device_for_test("tok-c", device("d3", "other", "admin", Some("apns-x"))); // other org
        let (pipe, rec) = pipeline_with(store);

        pipe.handle(StreamEvent::Kill {
            org: "acme".into(),
            run: "r1".into(),
        });

        let pushes = rec.pushes.lock().unwrap();
        assert_eq!(pushes.len(), 1, "only the acme device with a token");
        assert_eq!(pushes[0].device_apns_token, "apns-1");
        assert_eq!(pushes[0].reason, "kill");
        assert_eq!(pushes[0].run_id, "r1");
    }

    #[test]
    fn duplicate_events_are_deduped() {
        let store = Arc::new(Store::new());
        store.insert_device_for_test("t", device("d1", "acme", "admin", Some("apns-1")));
        let (pipe, rec) = pipeline_with(store);

        for _ in 0..3 {
            pipe.handle(StreamEvent::Kill {
                org: "acme".into(),
                run: "r1".into(),
            });
        }
        assert_eq!(rec.pushes.lock().unwrap().len(), 1, "deduped within window");
    }

    #[test]
    fn budget_alert_fires_only_over_threshold() {
        let store = Arc::new(Store::new());
        store.insert_device_for_test("t", device("d1", "acme", "admin", Some("apns-1")));
        store.set_budget("acme", "r1", 1000);
        let (pipe, rec) = pipeline_with(store.clone());

        // 50% — no alert.
        store.ingest("acme", &[rec_at("r1", 500)]);
        pipe.handle(StreamEvent::RunUpdate {
            org: "acme".into(),
            run: run_agg("r1", 500),
        });
        assert_eq!(rec.pushes.lock().unwrap().len(), 0);

        // 90% — alert.
        pipe.handle(StreamEvent::RunUpdate {
            org: "acme".into(),
            run: run_agg("r1", 900),
        });
        let pushes = rec.pushes.lock().unwrap();
        assert_eq!(pushes.len(), 1);
        assert_eq!(pushes[0].reason, "budget");
    }

    #[test]
    fn live_activity_updates_on_run_and_ends_on_kill() {
        let store = Arc::new(Store::new());
        store.register_activity("acme", "r1", "act-1");
        let (pipe, rec) = pipeline_with(store);

        pipe.handle(StreamEvent::RunUpdate {
            org: "acme".into(),
            run: run_agg("r1", 250),
        });
        pipe.handle(StreamEvent::Kill {
            org: "acme".into(),
            run: "r1".into(),
        });

        let acts = rec.activities.lock().unwrap();
        assert_eq!(acts.len(), 2);
        assert_eq!(acts[0].spent_microusd, 250);
        assert!(!acts[0].ended);
        assert!(acts[1].ended, "kill ends the activity");
    }

    fn rec_at(run: &str, cost: i64) -> CallRecord {
        CallRecord {
            run_id: run.into(),
            cost_microusd: cost,
            ..Default::default()
        }
    }

    fn run_agg(run: &str, spent: i64) -> crate::store::RunAgg {
        crate::store::RunAgg {
            run_id: run.into(),
            spent_microusd: spent,
            ..Default::default()
        }
    }
}
