//! `CloudSink` — ships settled-call telemetry to the TokenFuse Cloud control
//! plane, so many gateways roll up into one cross-fleet view.
//!
//! It batches records and POSTs them asynchronously (fire-and-forget) so the
//! request path is never blocked on the network; a failed push is dropped, not
//! retried — the local Parquet trace remains the source of truth. Enable with
//! `TOKENFUSE_CLOUD_URL` + `TOKENFUSE_CLOUD_KEY`; composes with other sinks via
//! `TeeSink`.

use std::sync::Mutex;

use serde::Serialize;

use crate::sink::{CallRecord, EventSink};

/// How many records to buffer before an automatic flush.
const BATCH: usize = 20;

pub struct CloudSink {
    url: String,
    key: String,
    client: reqwest::Client,
    buf: Mutex<Vec<CallRecord>>,
}

#[derive(Serialize)]
struct Batch<'a> {
    records: &'a [CallRecord],
}

impl CloudSink {
    /// `base` is the control plane's base URL (e.g. `http://control-plane:8080`);
    /// telemetry is POSTed to `{base}/v1/ingest`. `key` is the org API key.
    pub fn new(base: impl Into<String>, key: impl Into<String>) -> Self {
        let base = base.into();
        let url = format!("{}/v1/ingest", base.trim_end_matches('/'));
        CloudSink {
            url,
            key: key.into(),
            client: reqwest::Client::new(),
            buf: Mutex::new(Vec::new()),
        }
    }

    /// POST a batch in the background. Best-effort: errors are logged, not retried.
    fn ship(&self, records: Vec<CallRecord>) {
        if records.is_empty() {
            return;
        }
        let (client, url, key) = (self.client.clone(), self.url.clone(), self.key.clone());
        tokio::spawn(async move {
            let payload = match serde_json::to_vec(&Batch { records: &records }) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!("cloud telemetry encode failed: {e}");
                    return;
                }
            };
            let req = client
                .post(&url)
                .bearer_auth(&key)
                .header("content-type", "application/json")
                .body(payload);
            if let Err(e) = req.send().await {
                tracing::debug!("cloud telemetry push failed: {e}");
            }
        });
    }

    fn take_if_full(&self) -> Option<Vec<CallRecord>> {
        let mut buf = self.buf.lock().unwrap();
        if buf.len() >= BATCH {
            Some(std::mem::take(&mut *buf))
        } else {
            None
        }
    }
}

impl EventSink for CloudSink {
    fn record(&self, rec: CallRecord) {
        self.buf.lock().unwrap().push(rec);
        if let Some(batch) = self.take_if_full() {
            self.ship(batch);
        }
    }

    fn flush(&self) {
        let batch = std::mem::take(&mut *self.buf.lock().unwrap());
        self.ship(batch);
    }
}

/// Poll the control plane's per-run budget overrides and hand them to `apply`
/// (run id → µUSD), so an operator can set/tighten budgets centrally and every
/// gateway of the org enforces them. Best-effort; runs until the process exits.
pub fn spawn_budget_poller<F>(base: String, key: String, apply: F)
where
    F: Fn(std::collections::HashMap<String, i64>) + Send + Sync + 'static,
{
    let url = format!("{}/v1/budgets", base.trim_end_matches('/'));
    let client = reqwest::Client::new();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3));
        loop {
            tick.tick().await;
            let resp = match client.get(&url).bearer_auth(&key).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("cloud budget poll failed: {e}");
                    continue;
                }
            };
            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Ok(map) =
                serde_json::from_slice::<std::collections::HashMap<String, i64>>(&bytes)
            {
                apply(map);
            }
        }
    });
}

/// Poll the control plane's kill list and apply each killed run id locally, so an
/// operator's "Kill" in the Cloud dashboard propagates to every gateway of the
/// org (which then hard-stops that run — `402 killed`). Best-effort; runs until
/// the process exits.
pub fn spawn_kill_poller<F>(base: String, key: String, apply: F)
where
    F: Fn(&str) + Send + Sync + 'static,
{
    let url = format!("{}/v1/kills", base.trim_end_matches('/'));
    let client = reqwest::Client::new();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3));
        loop {
            tick.tick().await;
            let resp = match client.get(&url).bearer_auth(&key).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("cloud kill poll failed: {e}");
                    continue;
                }
            };
            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Ok(runs) = serde_json::from_slice::<Vec<String>>(&bytes) {
                for run in runs {
                    apply(&run);
                }
            }
        }
    });
}
