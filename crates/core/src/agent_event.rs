//! Agent-event NDJSON envelope and exporter (agent-passport SPEC.md §6,
//! schema `taipanbox.dev/agent-event/v0.1`).
//!
//! Lives in `tokenfuse-core` (not the gateway) because TokenFuse's existing
//! incident taxonomy is raised from TWO different deployables that both
//! depend on this crate but not on each other:
//!   - `crates/gateway` — per-request enforcement (`breaker_tripped`,
//!     `dlp_block`, `taint_block`) and the MCP broker (`mcp_drift`).
//!   - `crates/cloud` — the fleet-aggregate incident detectors added in P2
//!     (`budget_exhausted`, `sustained_loop`, `spend_spike`,
//!     `fanout_explosion`), which need a cross-run/cross-org window neither
//!     a single gateway process nor `tokenfuse-core` (I/O-free, single-call
//!     scope) can compute alone.
//!
//! Putting the envelope + severity mapping + NDJSON line serialization + the
//! fail-open file writer here — using nothing but `std::fs`/`std::io` and the
//! `serde`/`serde_json` this crate already depends on — lets both products
//! share ONE implementation without a dependency inversion (`cloud` and
//! `gateway` are siblings) and without adding a crate dependency. Each
//! product still owns its OWN call sites, its own `TOKENFUSE_EVENTS_PATH`
//! read at its own process startup, and its own `Exporter` instance — see
//! `crates/gateway/src/events.rs` and `crates/cloud/src/store.rs`.

use serde::Serialize;

use crate::timefmt::ts_millis_to_rfc3339_millis;

/// `schema` field value (agent-passport SPEC.md §8.4 — final for v0.1).
pub const SCHEMA: &str = "taipanbox.dev/agent-event/v0.1";
/// `source` field value: every event this crate builds is TokenFuse's own.
pub const SOURCE: &str = "tokenfuse";

/// `severity` enum (SPEC.md §6.1: `info` | `low` | `medium` | `high` |
/// `critical`). Re-exported from [`crate::mcpreport`], which already defines
/// exactly this set (used for `mcp-scan` findings and, today, cloud incident
/// severity) — one severity vocabulary for the whole crate rather than a
/// second copy.
pub use crate::mcpreport::Severity;

/// TokenFuse's event-type taxonomy (agent-passport SPEC.md §6.2, `source =
/// "tokenfuse"` row): the four existing P2 incident kinds plus the four new
/// per-call kinds this phase wires up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Existing cloud incident (P2, PR #90): raised in
    /// `crates/cloud/src/store.rs::ingest_at` when a run hits ≥ N
    /// budget-protection blocks.
    BudgetExhausted,
    /// Existing cloud incident (P2, PR #90): raised when a run repeats
    /// `loop_detected` ≥ N times in-window.
    SustainedLoop,
    /// Existing cloud incident (P2, PR #90): raised when an org's burn rate
    /// crosses the configured per-minute threshold.
    SpendSpike,
    /// Existing cloud incident (P2, PR #90): raised when one `agent_id`
    /// drives ≥ N distinct runs in-window.
    FanoutExplosion,
    /// New: any Breaker 402 (`tokenfuse_core::breaker::BreakerReason`) —
    /// budget, policy, loop, kill, or WASM-policy trip. Raised at the
    /// gateway's `breaker_error_response` call sites.
    BreakerTripped,
    /// New: a DLP (secret-scanning) 403 block. Raised at the gateway's
    /// `dlp_block` call site.
    DlpBlock,
    /// New: an agent-firewall (taint) 403 block. Raised at the gateway's
    /// `firewall_block` call site.
    TaintBlock,
    /// New: the MCP broker's live rug-pull check found a
    /// `tokenfuse_core::mcp::Drift::Changed` entry against the pinned lock.
    McpDrift,
}

impl EventType {
    /// The exact `type` wire string (agent-passport SPEC.md §6.2 — these are
    /// TokenFuse's registry entries verbatim, zero renaming for the four P2
    /// incident kinds).
    pub fn as_wire_str(self) -> &'static str {
        match self {
            EventType::BudgetExhausted => "budget_exhausted",
            EventType::SustainedLoop => "sustained_loop",
            EventType::SpendSpike => "spend_spike",
            EventType::FanoutExplosion => "fanout_explosion",
            EventType::BreakerTripped => "breaker_tripped",
            EventType::DlpBlock => "dlp_block",
            EventType::TaintBlock => "taint_block",
            EventType::McpDrift => "mcp_drift",
        }
    }

    /// Fixed severity per event type — NOT caller-supplied, so no emission
    /// site can misclassify an event. Mapping (from the phase spec):
    /// `budget_exhausted` / `mcp_drift` / `breaker_tripped` = `critical`;
    /// `sustained_loop` / `spend_spike` / `fanout_explosion` / `dlp_block` /
    /// `taint_block` = `high`.
    ///
    /// Note this is deliberately independent of `cloud::store::Incident`'s
    /// own `severity` field (used for `/v1/incidents` today, e.g.
    /// `sustained_loop` is `Medium` there) — that field predates this
    /// envelope and this phase does not change it; the envelope's severity is
    /// its own, newly-specified mapping.
    pub fn severity(self) -> Severity {
        match self {
            EventType::BudgetExhausted | EventType::McpDrift | EventType::BreakerTripped => {
                Severity::Critical
            }
            EventType::SustainedLoop
            | EventType::SpendSpike
            | EventType::FanoutExplosion
            | EventType::DlpBlock
            | EventType::TaintBlock => Severity::High,
        }
    }
}

/// One agent-event envelope (agent-passport SPEC.md §6). Field order matches
/// the spec's example exactly, which `serde_json` preserves on serialize
/// (struct fields are emitted in declaration order, not sorted).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AgentEvent {
    pub schema: &'static str,
    pub ts: String,
    pub source: &'static str,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub severity: Severity,
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
}

/// Build one envelope, or `None` when `agent_id` is absent/empty.
///
/// The envelope schema REQUIRES `agent_id` (SPEC.md §6.1); rather than
/// fabricate a placeholder, the caller must skip the event entirely and count
/// the skip (see `Exporter::emit`, which does exactly that). This function is
/// the single place that enforces the rule, so no call site can accidentally
/// emit an event with a synthesized identity.
///
/// `on_behalf_of`: `None`/empty is treated as "omit" (SPEC.md §5: "An
/// empty/absent chain means the agent acts autonomously" — distinct from
/// serializing an empty JSON array).
///
/// `prev_hash` is a raw pass-through — see `crates/gateway/src/events.rs` and
/// `crates/cloud/src/store.rs` module docs for why this phase omits it at
/// every current call site (no existing sha256 chain covers the
/// enforcement/incident stream; see `tokenfuse_core::audit`'s own scope note).
#[allow(clippy::too_many_arguments)]
pub fn build(
    event_type: EventType,
    ts_millis: i64,
    agent_id: Option<&str>,
    run_id: Option<&str>,
    on_behalf_of: Option<&[String]>,
    data: serde_json::Value,
    prev_hash: Option<&str>,
) -> Option<AgentEvent> {
    let agent_id = agent_id.filter(|s| !s.is_empty())?;
    Some(AgentEvent {
        schema: SCHEMA,
        ts: ts_millis_to_rfc3339_millis(ts_millis),
        source: SOURCE,
        kind: event_type.as_wire_str(),
        severity: event_type.severity(),
        agent_id: agent_id.to_string(),
        run_id: run_id.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        on_behalf_of: on_behalf_of
            .filter(|chain| !chain.is_empty())
            .map(|chain| chain.to_vec()),
        data: if data.is_null() { None } else { Some(data) },
        prev_hash: prev_hash.filter(|s| !s.is_empty()).map(|s| s.to_string()),
    })
}

/// Serialize one envelope as a single NDJSON line (no trailing newline).
/// `serde_json::to_string` over this struct cannot fail in practice (no
/// non-UTF8 map keys, no non-finite floats produced by this module's own
/// callers) — an error is treated as "nothing to write" rather than a panic,
/// keeping this on the same fail-open footing as [`Exporter::emit`].
pub fn to_ndjson_line(event: &AgentEvent) -> Option<String> {
    serde_json::to_string(event).ok()
}

/// The env var every product reads, ONCE, at process startup, to enable the
/// exporter (absent/empty ⇒ disabled, zero per-request cost).
pub const EVENTS_PATH_ENV: &str = "TOKENFUSE_EVENTS_PATH";

/// Fail-open NDJSON append-only exporter. `disabled()` is the zero-cost
/// default (no file handle, `emit` returns immediately); `from_env` opens
/// `TOKENFUSE_EVENTS_PATH` once and keeps the handle for the process
/// lifetime. Every write is best-effort: an I/O error is logged (by the
/// caller — this module has no logging dependency, see `emit`'s return value)
/// and dropped, never surfaced as a request failure.
#[derive(Debug)]
pub struct Exporter {
    file: Option<std::sync::Mutex<std::fs::File>>,
    skipped: std::sync::atomic::AtomicU64,
    write_errors: std::sync::atomic::AtomicU64,
}

/// The outcome of one [`Exporter::emit`] call, for the caller to log (this
/// module intentionally has no `tracing`/logging dependency of its own).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitOutcome {
    /// Disabled (no path configured) — the common case, zero cost.
    Disabled,
    /// Wrote one NDJSON line.
    Written,
    /// Skipped: no `agent_id` was available. Carries the running total.
    SkippedNoAgentId { skipped_total: u64 },
    /// The file write failed (fail-open: the request is unaffected). Carries
    /// the running total and a message for the caller to log.
    WriteError { errors_total: u64, message: String },
}

impl Exporter {
    /// The always-off exporter: no file, `emit` is a single branch away from
    /// a no-op, so a disabled exporter costs nothing on the hot path.
    pub fn disabled() -> Self {
        Exporter {
            file: None,
            skipped: std::sync::atomic::AtomicU64::new(0),
            write_errors: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Open `path` for append. Returns `Err` with a message the caller should
    /// log (and then fall back to [`Exporter::disabled`]) — opening the file
    /// is a one-time startup concern, not a per-request one, so this is the
    /// one place allowed to return a hard error.
    pub fn open(path: &str) -> Result<Self, String> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("could not open '{path}': {e}"))?;
        Ok(Exporter {
            file: Some(std::sync::Mutex::new(file)),
            skipped: std::sync::atomic::AtomicU64::new(0),
            write_errors: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Read [`EVENTS_PATH_ENV`] ONCE and open it, or return the disabled
    /// exporter when absent/empty. On an open error, ALSO returns the
    /// disabled exporter (fail-open at startup too) — the caller should log
    /// the `Err` case's message via the `Result`-returning [`Exporter::open`]
    /// directly if it wants a startup warning; `from_env` is the convenience
    /// path for callers that just want "on or off, never a crash".
    pub fn from_env() -> Self {
        match std::env::var(EVENTS_PATH_ENV) {
            Ok(path) if !path.is_empty() => Self::open(&path).unwrap_or_else(|_| Self::disabled()),
            _ => Self::disabled(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.file.is_some()
    }

    /// Build and (best-effort) write one event. Returns what happened so the
    /// caller can log it (this crate has no logging dependency); every branch
    /// is fail-open — this call NEVER returns an error the caller must
    /// propagate.
    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        &self,
        event_type: EventType,
        ts_millis: i64,
        agent_id: Option<&str>,
        run_id: Option<&str>,
        on_behalf_of: Option<&[String]>,
        data: serde_json::Value,
        prev_hash: Option<&str>,
    ) -> EmitOutcome {
        let Some(file) = &self.file else {
            return EmitOutcome::Disabled;
        };
        let Some(event) = build(
            event_type,
            ts_millis,
            agent_id,
            run_id,
            on_behalf_of,
            data,
            prev_hash,
        ) else {
            let n = self
                .skipped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            return EmitOutcome::SkippedNoAgentId { skipped_total: n };
        };
        let Some(mut line) = to_ndjson_line(&event) else {
            // Unreachable in practice (see `to_ndjson_line`'s doc); treat as a
            // write error rather than panicking on the hot path.
            let n = self
                .write_errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            return EmitOutcome::WriteError {
                errors_total: n,
                message: "event serialization failed".to_string(),
            };
        };
        line.push('\n');
        use std::io::Write;
        let result = file.lock().unwrap().write_all(line.as_bytes());
        match result {
            Ok(()) => EmitOutcome::Written,
            Err(e) => {
                let n = self
                    .write_errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                EmitOutcome::WriteError {
                    errors_total: n,
                    message: e.to_string(),
                }
            }
        }
    }

    pub fn skipped_count(&self) -> u64 {
        self.skipped.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn write_error_count(&self) -> u64 {
        self.write_errors.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- severity mapping --------------------------------------------------

    #[test]
    fn severity_mapping_matches_the_documented_table() {
        for t in [
            EventType::BudgetExhausted,
            EventType::McpDrift,
            EventType::BreakerTripped,
        ] {
            assert_eq!(t.severity(), Severity::Critical, "{t:?}");
        }
        for t in [
            EventType::SustainedLoop,
            EventType::SpendSpike,
            EventType::FanoutExplosion,
            EventType::DlpBlock,
            EventType::TaintBlock,
        ] {
            assert_eq!(t.severity(), Severity::High, "{t:?}");
        }
    }

    #[test]
    fn wire_strings_match_the_spec_registry_verbatim() {
        let cases = [
            (EventType::BudgetExhausted, "budget_exhausted"),
            (EventType::SustainedLoop, "sustained_loop"),
            (EventType::SpendSpike, "spend_spike"),
            (EventType::FanoutExplosion, "fanout_explosion"),
            (EventType::BreakerTripped, "breaker_tripped"),
            (EventType::DlpBlock, "dlp_block"),
            (EventType::TaintBlock, "taint_block"),
            (EventType::McpDrift, "mcp_drift"),
        ];
        for (t, s) in cases {
            assert_eq!(t.as_wire_str(), s);
        }
    }

    // -- build() / envelope shape -------------------------------------------

    #[test]
    fn build_returns_none_without_agent_id() {
        assert!(build(
            EventType::BreakerTripped,
            0,
            None,
            Some("run-1"),
            None,
            serde_json::Value::Null,
            None,
        )
        .is_none());
        assert!(build(
            EventType::BreakerTripped,
            0,
            Some(""),
            Some("run-1"),
            None,
            serde_json::Value::Null,
            None,
        )
        .is_none());
    }

    #[test]
    fn build_full_envelope_matches_spec_shape() {
        let ev = build(
            EventType::BudgetExhausted,
            1_783_566_764_100, // 2026-07-09T03:12:44.100Z
            Some("agent://acme-bank.example/support/tier1-bot"),
            Some("run-8842"),
            Some(&["user://acme-bank.example/j.doe".to_string()]),
            serde_json::json!({ "budget_usd": 2.00, "spent_usd": 2.00, "action": "blocked_402" }),
            None,
        )
        .unwrap();
        assert_eq!(ev.schema, SCHEMA);
        assert_eq!(ev.ts, "2026-07-09T03:12:44.100Z");
        assert_eq!(ev.source, "tokenfuse");
        assert_eq!(ev.kind, "budget_exhausted");
        assert_eq!(ev.severity, Severity::Critical);
        assert_eq!(ev.agent_id, "agent://acme-bank.example/support/tier1-bot");
        assert_eq!(ev.run_id.as_deref(), Some("run-8842"));
        assert_eq!(
            ev.on_behalf_of,
            Some(vec!["user://acme-bank.example/j.doe".to_string()])
        );
        assert!(ev.prev_hash.is_none());
    }

    #[test]
    fn build_omits_on_behalf_of_when_absent_or_empty() {
        let ev = build(
            EventType::McpDrift,
            0,
            Some("agent://acme.example/bot"),
            None,
            None,
            serde_json::Value::Null,
            None,
        )
        .unwrap();
        assert!(ev.on_behalf_of.is_none());

        let ev2 = build(
            EventType::McpDrift,
            0,
            Some("agent://acme.example/bot"),
            None,
            Some(&[]),
            serde_json::Value::Null,
            None,
        )
        .unwrap();
        assert!(ev2.on_behalf_of.is_none());
    }

    // -- NDJSON line golden shape --------------------------------------------

    #[test]
    fn ndjson_line_golden_shape_and_key_order() {
        let ev = build(
            EventType::BreakerTripped,
            1_783_566_764_100,
            Some("agent://acme-bank.example/support/tier1-bot"),
            Some("run-8842"),
            None,
            serde_json::json!({ "reason": "budget_exceeded" }),
            None,
        )
        .unwrap();
        let line = to_ndjson_line(&ev).unwrap();
        let want = concat!(
            r#"{"schema":"taipanbox.dev/agent-event/v0.1","#,
            r#""ts":"2026-07-09T03:12:44.100Z","#,
            r#""source":"tokenfuse","#,
            r#""type":"breaker_tripped","#,
            r#""severity":"critical","#,
            r#""agent_id":"agent://acme-bank.example/support/tier1-bot","#,
            r#""run_id":"run-8842","#,
            r#""data":{"reason":"budget_exceeded"}}"#,
        );
        assert_eq!(line, want);
        // Valid, single-line JSON (NDJSON contract): parses back and round-trips
        // the required fields the JSON Schema (agent-event.schema.json) checks.
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["schema"], "taipanbox.dev/agent-event/v0.1");
        assert!(v.get("ts").is_some());
        assert_eq!(v["source"], "tokenfuse");
        assert_eq!(v["type"], "breaker_tripped");
        assert!(v.get("agent_id").is_some());
        assert!(!line.contains('\n'));
    }

    #[test]
    fn ndjson_line_omits_null_optionals() {
        let ev = build(
            EventType::TaintBlock,
            0,
            Some("agent://acme.example/bot"),
            None,
            None,
            serde_json::Value::Null,
            None,
        )
        .unwrap();
        let line = to_ndjson_line(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(v.get("run_id").is_none());
        assert!(v.get("on_behalf_of").is_none());
        assert!(v.get("data").is_none());
        assert!(v.get("prev_hash").is_none());
    }

    // -- Exporter: disabled / skip / write -----------------------------------

    #[test]
    fn disabled_exporter_is_a_pure_no_op() {
        let exp = Exporter::disabled();
        assert!(!exp.is_enabled());
        let outcome = exp.emit(
            EventType::BreakerTripped,
            0,
            Some("agent://acme.example/bot"),
            None,
            None,
            serde_json::Value::Null,
            None,
        );
        assert_eq!(outcome, EmitOutcome::Disabled);
        assert_eq!(exp.skipped_count(), 0);
    }

    #[test]
    fn from_env_is_disabled_when_var_unset() {
        std::env::remove_var(EVENTS_PATH_ENV);
        let exp = Exporter::from_env();
        assert!(!exp.is_enabled());
    }

    #[test]
    fn emit_without_agent_id_is_skipped_and_counted() {
        let dir = std::env::temp_dir().join(format!("tf-agent-event-{}-a", std::process::id()));
        let path = dir.join("events.ndjson");
        std::fs::create_dir_all(&dir).unwrap();
        let exp = Exporter::open(path.to_str().unwrap()).unwrap();

        let outcome = exp.emit(
            EventType::DlpBlock,
            0,
            None,
            Some("run-1"),
            None,
            serde_json::Value::Null,
            None,
        );
        assert_eq!(outcome, EmitOutcome::SkippedNoAgentId { skipped_total: 1 });
        assert_eq!(exp.skipped_count(), 1);
        // Nothing written to the file for a skipped event.
        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(contents, "");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn emit_appends_one_ndjson_line_per_call() {
        let dir = std::env::temp_dir().join(format!("tf-agent-event-{}-b", std::process::id()));
        let path = dir.join("events.ndjson");
        std::fs::create_dir_all(&dir).unwrap();
        let exp = Exporter::open(path.to_str().unwrap()).unwrap();

        for i in 0..3 {
            let outcome = exp.emit(
                EventType::TaintBlock,
                i,
                Some("agent://acme.example/bot"),
                Some("run-1"),
                None,
                serde_json::Value::Null,
                None,
            );
            assert_eq!(outcome, EmitOutcome::Written);
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["type"], "taint_block");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_nonexistent_directory_errors_cleanly() {
        let err = Exporter::open("/nonexistent/tf-agent-event-dir-xyz/events.ndjson").unwrap_err();
        assert!(err.contains("nonexistent"), "{err}");
    }
}
