//! OpenTelemetry export (W9): emit one span per settled call over OTLP/JSON.
//!
//! We integrate with the user's existing observability stack rather than compete
//! with it. Each call becomes a span with GenAI semantic-convention attributes
//! (`gen_ai.*`) plus TokenFuse's own (`tokenfuse.*`); all calls of a run share a
//! trace id, so a run shows up as one trace in Grafana/Datadog/Honeycomb.
//!
//! Implemented directly against the OTLP/HTTP JSON endpoint (`/v1/traces`) using
//! the HTTP client we already have — no heavy OTel crate tree, and it's a no-op
//! unless `TOKENFUSE_OTLP_ENDPOINT` is set.

use std::hash::{Hash, Hasher};

use crate::sink::{CallRecord, EventSink};

pub struct OtelSink {
    client: reqwest::Client,
    /// Full traces URL, e.g. `http://localhost:4318/v1/traces`.
    url: String,
    service: String,
}

impl OtelSink {
    pub fn new(endpoint: &str) -> Self {
        let base = endpoint.trim_end_matches('/');
        let url = if base.ends_with("/v1/traces") {
            base.to_string()
        } else {
            format!("{base}/v1/traces")
        };
        OtelSink {
            client: reqwest::Client::new(),
            url,
            service: "tokenfuse".to_string(),
        }
    }
}

fn hash64(parts: &[&str]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for p in parts {
        p.hash(&mut h);
    }
    let v = h.finish();
    if v == 0 {
        1
    } else {
        v
    }
}

/// Build the OTLP/JSON payload for a single call. Pure — unit-tested.
pub fn otlp_json(rec: &CallRecord, service: &str) -> serde_json::Value {
    // A run maps to one trace; each step is a span within it.
    let trace_id = format!(
        "{:016x}{:016x}",
        hash64(&[&rec.run_id]),
        hash64(&["trace", &rec.run_id])
    );
    let span_id = format!("{:016x}", hash64(&[&rec.run_id, &rec.step.to_string()]));
    let start_nanos = (rec.ts_millis.max(0) as i128 * 1_000_000).to_string();

    let attr_s = |k: &str, v: &str| serde_json::json!({ "key": k, "value": { "stringValue": v } });
    let attr_i =
        |k: &str, v: i64| serde_json::json!({ "key": k, "value": { "intValue": v.to_string() } });
    let attr_d = |k: &str, v: f64| serde_json::json!({ "key": k, "value": { "doubleValue": v } });

    serde_json::json!({
        "resourceSpans": [{
            "resource": { "attributes": [ attr_s("service.name", service) ] },
            "scopeSpans": [{
                "scope": { "name": "tokenfuse" },
                "spans": [{
                    "traceId": trace_id,
                    "spanId": span_id,
                    "name": "llm.call",
                    "kind": 3, // CLIENT
                    "startTimeUnixNano": start_nanos,
                    "endTimeUnixNano": start_nanos,
                    "attributes": [
                        attr_s("gen_ai.request.model", &rec.model),
                        attr_i("gen_ai.usage.input_tokens", rec.input_tokens as i64),
                        attr_i("gen_ai.usage.output_tokens", rec.output_tokens as i64),
                        attr_s("tokenfuse.run_id", &rec.run_id),
                        attr_i("tokenfuse.step", rec.step as i64),
                        attr_s("tokenfuse.decision", &rec.decision),
                        attr_d("tokenfuse.cost_usd", rec.cost_microusd as f64 / 1e6),
                    ]
                }]
            }]
        }]
    })
}

impl EventSink for OtelSink {
    fn record(&self, rec: CallRecord) {
        let payload = otlp_json(&rec, &self.service).to_string();
        let client = self.client.clone();
        let url = self.url.clone();
        // Best-effort, fire-and-forget; never blocks the request path.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = client
                    .post(&url)
                    .header("content-type", "application/json")
                    .body(payload)
                    .send()
                    .await;
            });
        }
    }
    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> CallRecord {
        CallRecord {
            ts_millis: 1_700_000_000_000,
            run_id: "run-1".into(),
            model: "claude-sonnet".into(),
            decision: "allow".into(),
            input_tokens: 1000,
            output_tokens: 500,
            cost_microusd: 10_500,
            step: 2,
            agent_id: String::new(),
            saved_microusd: 0,
            parent_run_id: String::new(),
            on_behalf_of: String::new(),
            outcome: String::new(),
            key_id: String::new(),
            unit: String::new(),
        }
    }

    #[test]
    fn endpoint_normalization() {
        assert_eq!(
            OtelSink::new("http://h:4318").url,
            "http://h:4318/v1/traces"
        );
        assert_eq!(
            OtelSink::new("http://h:4318/").url,
            "http://h:4318/v1/traces"
        );
        assert_eq!(
            OtelSink::new("http://h:4318/v1/traces").url,
            "http://h:4318/v1/traces"
        );
    }

    #[test]
    fn otlp_payload_shape() {
        let v = otlp_json(&rec(), "tokenfuse");
        let span = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["name"], "llm.call");
        assert_eq!(span["traceId"].as_str().unwrap().len(), 32);
        assert_eq!(span["spanId"].as_str().unwrap().len(), 16);
        let attrs = span["attributes"].as_array().unwrap();
        let has = |k: &str| attrs.iter().any(|a| a["key"] == k);
        assert!(has("gen_ai.request.model"));
        assert!(has("gen_ai.usage.input_tokens"));
        assert!(has("tokenfuse.run_id"));
        assert!(has("tokenfuse.cost_usd"));
    }

    #[test]
    fn same_run_shares_trace_id() {
        let mut a = rec();
        a.step = 1;
        let mut b = rec();
        b.step = 2;
        let ta = otlp_json(&a, "s")["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"]
            .as_str()
            .unwrap()
            .to_string();
        let tb = otlp_json(&b, "s")["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(ta, tb); // one trace per run
    }
}
