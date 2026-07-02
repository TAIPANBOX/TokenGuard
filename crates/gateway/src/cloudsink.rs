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
    /// `url` is the control plane's ingest endpoint (e.g.
    /// `http://control-plane:8080/v1/ingest`); `key` is the org API key.
    pub fn new(url: impl Into<String>, key: impl Into<String>) -> Self {
        CloudSink {
            url: url.into(),
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
