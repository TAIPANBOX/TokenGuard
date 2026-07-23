//! OpenTelemetry export (W9): emit one span per settled call over OTLP/JSON.
//!
//! We integrate with the user's existing observability stack rather than compete
//! with it. Each call becomes a span with GenAI semantic-convention attributes
//! (`gen_ai.*`) plus TokenFuse's own (`tokenfuse.*`); all calls of a run share a
//! trace id, so a run shows up as one trace in Grafana/Datadog/Honeycomb.
//!
//! Implemented directly against the OTLP/HTTP JSON endpoint (`/v1/traces`) using
//! the HTTP client we already have - no heavy OTel crate tree, and it's a no-op
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

/// The OTel GenAI `gen_ai.system` value for a model, by well-known name
/// prefix, or `None` when the provider can't be told from the model name.
/// Returning `None` (so the attribute is omitted) is deliberate: TokenFuse is
/// provider-agnostic and records only the model string, so guessing a
/// `gen_ai.system` for an unrecognized model would be a fabricated attribute,
/// which "honesty is a feature" forbids. The values are the semantic-convention
/// registry's own (`anthropic`, `openai`, `gcp.gemini`, `cohere`, `mistral_ai`,
/// `deepseek`, `groq`).
fn gen_ai_system(model: &str) -> Option<&'static str> {
    let m = model.to_ascii_lowercase();
    if m.starts_with("claude") {
        Some("anthropic")
    } else if m.starts_with("gpt")
        || m.starts_with("o1")
        || m.starts_with("o3")
        || m.starts_with("o4")
    {
        Some("openai")
    } else if m.starts_with("gemini") {
        Some("gcp.gemini")
    } else if m.starts_with("command") || m.starts_with("cohere") {
        Some("cohere")
    } else if m.starts_with("mistral") || m.starts_with("codestral") {
        Some("mistral_ai")
    } else if m.starts_with("deepseek") {
        Some("deepseek")
    } else if m.starts_with("groq") {
        Some("groq")
    } else {
        None
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

/// Build the OTLP/JSON payload for a single call. Pure - unit-tested.
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

    // GenAI semantic-convention attributes first, then TokenFuse's own. Built as
    // a Vec so `gen_ai.system` can be omitted when the provider is unknown (see
    // `gen_ai_system`), rather than emitting a guessed value.
    let mut attributes = vec![
        // `operation.name` is `chat`: the gateway proxies the chat/messages
        // completion operation, which is a constant here, not a per-call guess.
        attr_s("gen_ai.operation.name", "chat"),
        attr_s("gen_ai.request.model", &rec.model),
        // The model that actually served the call. TokenFuse records the model
        // used, so response and request model are the same value here; both are
        // emitted so a semconv-aware backend sees the standard pair.
        attr_s("gen_ai.response.model", &rec.model),
        attr_i("gen_ai.usage.input_tokens", rec.input_tokens as i64),
        attr_i("gen_ai.usage.output_tokens", rec.output_tokens as i64),
    ];
    if let Some(system) = gen_ai_system(&rec.model) {
        attributes.push(attr_s("gen_ai.system", system));
    }
    attributes.extend([
        attr_s("tokenfuse.run_id", &rec.run_id),
        attr_i("tokenfuse.step", rec.step as i64),
        attr_s("tokenfuse.decision", &rec.decision),
        attr_d("tokenfuse.cost_usd", rec.cost_microusd as f64 / 1e6),
    ]);

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
                    "attributes": attributes
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
            tool_calls: None,
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
        let val = |k: &str| {
            attrs
                .iter()
                .find(|a| a["key"] == k)
                .map(|a| a["value"]["stringValue"].as_str().unwrap().to_string())
        };
        assert!(has("gen_ai.request.model"));
        assert!(has("gen_ai.usage.input_tokens"));
        assert!(has("tokenfuse.run_id"));
        assert!(has("tokenfuse.cost_usd"));
        // GenAI semconv additions.
        assert_eq!(val("gen_ai.operation.name").as_deref(), Some("chat"));
        assert_eq!(
            val("gen_ai.response.model").as_deref(),
            Some("claude-sonnet")
        );
        assert_eq!(
            val("gen_ai.system").as_deref(),
            Some("anthropic"),
            "a claude model maps to gen_ai.system=anthropic"
        );
    }

    #[test]
    fn gen_ai_system_is_omitted_for_an_unknown_model() {
        // Honesty: an unrecognized model name yields no gen_ai.system rather
        // than a guessed provider.
        assert_eq!(gen_ai_system("my-private-finetune-v3"), None);
        let mut r = rec();
        r.model = "my-private-finetune-v3".into();
        let v = otlp_json(&r, "tokenfuse");
        let attrs = v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
            .as_array()
            .unwrap();
        assert!(
            !attrs.iter().any(|a| a["key"] == "gen_ai.system"),
            "no gen_ai.system for an unrecognized model"
        );
        // The operation and request model are still emitted.
        assert!(attrs.iter().any(|a| a["key"] == "gen_ai.operation.name"));
    }

    #[test]
    fn gen_ai_system_maps_known_providers() {
        assert_eq!(gen_ai_system("gpt-4o"), Some("openai"));
        assert_eq!(gen_ai_system("o3-mini"), Some("openai"));
        assert_eq!(gen_ai_system("gemini-2.0-flash"), Some("gcp.gemini"));
        assert_eq!(gen_ai_system("mistral-large"), Some("mistral_ai"));
        assert_eq!(gen_ai_system("command-r-plus"), Some("cohere"));
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
