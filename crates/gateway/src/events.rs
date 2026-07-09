//! Agent-event NDJSON exporter wiring for the gateway (agent-passport
//! SPEC.md §6). The envelope, severity mapping, NDJSON serialization, and the
//! fail-open file writer all live in `tokenfuse_core::agent_event` — see that
//! module's doc for why (short version: the OTHER four event kinds this
//! phase wires up, `budget_exhausted`/`sustained_loop`/`spend_spike`/
//! `fanout_explosion`, are raised in `crates/cloud/src/store.rs`, a sibling
//! crate that can't depend on `gateway`, so the shared mechanics had to live
//! in `tokenfuse-core`, which both depend on).
//!
//! This module is the gateway's OWN piece: reading `TOKENFUSE_EVENTS_PATH`
//! once at gateway startup (never per-request — see [`from_env`]) and the
//! call sites that are only observable from inside a running gateway
//! process:
//!   - `crate::proxy` — `breaker_tripped` (all five Breaker 402 sites, via
//!     `emit_breaker_event`), `dlp_block`, `taint_block`.
//!   - `crate::mcpbroker` — `mcp_drift` (the live rug-pull check).
//!
//! `crates/cloud/src/store.rs` wires its own four incident kinds directly
//! against `tokenfuse_core::agent_event::Exporter`, reading the SAME
//! `TOKENFUSE_EVENTS_PATH` env var at ITS OWN process startup (the gateway
//! and the Cloud control plane are separate deployables, each opens its own
//! file handle).
//!
//! Fail-open, end to end: `TOKENFUSE_EVENTS_PATH` unset ⇒ [`EventExporter`]
//! is `disabled()` and `emit` is a single branch, no I/O, no allocation — the
//! stated design goal ("zero cost on the hot path" when off). When enabled, a
//! write error is logged and dropped by the call site (see `crate::proxy`),
//! never surfaced as a request failure.

pub use tokenfuse_core::agent_event::{EmitOutcome, EventType, Exporter as EventExporter};

/// Read [`tokenfuse_core::agent_event::EVENTS_PATH_ENV`] once and build the
/// exporter, logging the outcome. Call this exactly once, at gateway startup
/// (`crate::main`) — never per-request.
pub fn from_env() -> EventExporter {
    match std::env::var(tokenfuse_core::agent_event::EVENTS_PATH_ENV) {
        Ok(path) if !path.is_empty() => match EventExporter::open(&path) {
            Ok(exp) => {
                tracing::info!(%path, "agent-event NDJSON export enabled");
                exp
            }
            Err(e) => {
                tracing::warn!(%path, "could not open TOKENFUSE_EVENTS_PATH: {e}");
                EventExporter::disabled()
            }
        },
        _ => EventExporter::disabled(),
    }
}

/// Log the outcome of an [`EventExporter::emit`] call. Every call site in
/// `crate::proxy`/`crate::mcpbroker` routes through this so skip/error
/// counts are logged uniformly (this crate has `tracing`; `tokenfuse-core`
/// deliberately does not, see its Cargo.toml).
pub fn log_outcome(event_type: EventType, outcome: EmitOutcome) {
    match outcome {
        EmitOutcome::Disabled | EmitOutcome::Written => {}
        EmitOutcome::SkippedNoAgentId { skipped_total } => {
            tracing::warn!(
                event = event_type.as_wire_str(),
                skipped_total,
                "agent-event skipped: no agent_id on the request"
            );
        }
        EmitOutcome::WriteError {
            errors_total,
            message,
        } => {
            tracing::warn!(
                event = event_type.as_wire_str(),
                errors_total,
                "agent-event NDJSON write failed: {message}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_disabled_when_unset() {
        std::env::remove_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV);
        let exp = from_env();
        assert!(!exp.is_enabled());
    }

    #[test]
    fn from_env_enabled_when_set_to_a_writable_path() {
        let dir = std::env::temp_dir().join(format!("tf-gw-events-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.ndjson");
        std::env::set_var(
            tokenfuse_core::agent_event::EVENTS_PATH_ENV,
            path.to_str().unwrap(),
        );
        let exp = from_env();
        assert!(exp.is_enabled());
        std::env::remove_var(tokenfuse_core::agent_event::EVENTS_PATH_ENV);
        std::fs::remove_dir_all(&dir).ok();
    }
}
