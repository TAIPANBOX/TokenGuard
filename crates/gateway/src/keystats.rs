//! Since-startup, in-process counters for client-key activity
//! (`docs/22-key-lifecycle.md`): how many calls each `key_id` has made, how
//! many of those hit an identity-map mismatch, and an aggregate count of
//! `401 unauthorized` responses.
//!
//! ## Why this exists
//!
//! `crate::clientkeys` and `crate::identitymap` know how keys are
//! *configured*; the Parquet trace (`crate::sink`/`crate::sqlq`) knows how
//! they have been used *historically*, but only when `TOKENFUSE_DATA_DIR` is
//! set. Neither answers "is this key still alive right now" cheaply. This
//! module is the third, always-on signal `crate::keysreport` folds together
//! with the other two: a plain in-memory tally, updated on the request path
//! that already runs today.
//!
//! ## NO persistence, NO per-secret data
//!
//! Every number here resets to zero on restart - there is no snapshot, no
//! file, nothing durable. That is a deliberate, stated limitation (see
//! `docs/22-key-lifecycle.md`), not an oversight: the durable, cross-restart
//! view is the Parquet history fold in `crate::keysreport`, and it exists
//! only when the operator has opted into `TOKENFUSE_DATA_DIR`.
//!
//! Nothing in this module ever stores a secret, a header value, or anything
//! that could distinguish *why* a request was unauthorized. The aggregate
//! [`KeyStats::record_unauthorized`] counter exists precisely so the `401`
//! response's deliberate indistinguishability (`crate::clientkeys`,
//! `crate::proxy::unauthorized`) is preserved: this counts THAT an attempt
//! happened, never anything about it.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::sink::now_millis;

/// Per-key counters since process startup.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyCounters {
    pub calls: u64,
    pub identity_mismatches: u64,
    pub last_seen_millis: Option<i64>,
}

/// Aggregate `401 unauthorized` counters. Never keyed by anything
/// caller-supplied - see the module doc.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnauthorizedCounters {
    pub attempts: u64,
    pub last_millis: Option<i64>,
}

/// A read-only copy of every counter, for `crate::keysreport`'s assembly
/// step. Taken under the lock and then handed out by value, so the caller
/// never holds `KeyStats`'s mutex while it builds a response.
#[derive(Debug, Clone, Default)]
pub struct KeyStatsSnapshot {
    pub per_key: HashMap<String, KeyCounters>,
    pub unauthorized: UnauthorizedCounters,
}

#[derive(Debug, Default)]
struct Inner {
    per_key: HashMap<String, KeyCounters>,
    unauthorized: UnauthorizedCounters,
}

/// Since-startup, in-process counters for client-key activity. A plain
/// `std::sync::Mutex` around a `HashMap` is enough at gateway request rates
/// (the same shape `AppState`'s `history`/`killed`/`taint` fields already
/// use) - this is not a hot inner loop like the budget ledger.
#[derive(Debug, Default)]
pub struct KeyStats {
    inner: Mutex<Inner>,
}

impl KeyStats {
    /// Record one request whose client credential resolved to `key_id`
    /// (including `""`, when client keys are not configured at all - see
    /// `crate::proxy::resolve_client_key`). Called exactly once per request
    /// that reaches this point, regardless of what happens downstream
    /// (success, a `402` Breaker trip, a `403` identity block): see the
    /// call site in `crate::proxy::messages`.
    ///
    /// A blank `key_id` is a no-op: it means client keys are off entirely,
    /// there is no real key for the report to ever show, and tracking it
    /// would just be a dead entry no union in `crate::keysreport` ever
    /// surfaces (a `key_id` this blank is also rejected at identity-map load
    /// time, so it can never appear there either).
    pub fn record_call(&self, key_id: &str) {
        if key_id.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let entry = inner.per_key.entry(key_id.to_string()).or_default();
        entry.calls += 1;
        entry.last_seen_millis = Some(now_millis());
    }

    /// Record an identity-map mismatch DETECTED for `key_id`
    /// (`docs/20-identity-map.md`). Called from both the `warn` and
    /// `enforce` strict-mode paths in `crate::proxy::messages` - `warn`
    /// still counts here, even though the call itself is allowed through,
    /// because the mismatch genuinely happened (`docs/22-key-lifecycle.md`).
    /// Not called from the `off` path: nothing consults the mismatch there,
    /// so nothing counts it either.
    pub fn record_identity_mismatch(&self, key_id: &str) {
        if key_id.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        inner
            .per_key
            .entry(key_id.to_string())
            .or_default()
            .identity_mismatches += 1;
    }

    /// Record one `401 unauthorized` response. Aggregate only, by design -
    /// see the module doc's note on the response's deliberate
    /// indistinguishability. Called from `crate::proxy::unauthorized`
    /// itself, so every call site of that function gets this for free.
    pub fn record_unauthorized(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.unauthorized.attempts += 1;
        inner.unauthorized.last_millis = Some(now_millis());
    }

    /// A read-only snapshot of every counter, for `crate::keysreport`.
    #[must_use]
    pub fn snapshot(&self) -> KeyStatsSnapshot {
        let inner = self.inner.lock().unwrap();
        KeyStatsSnapshot {
            per_key: inner.per_key.clone(),
            unauthorized: inner.unauthorized,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_and_last_seen_increment_per_key() {
        let stats = KeyStats::default();
        stats.record_call("k1");
        stats.record_call("k1");
        stats.record_call("k2");
        let snap = stats.snapshot();
        assert_eq!(snap.per_key.get("k1").unwrap().calls, 2);
        assert_eq!(snap.per_key.get("k2").unwrap().calls, 1);
        assert!(snap.per_key.get("k1").unwrap().last_seen_millis.is_some());
    }

    #[test]
    fn an_empty_key_id_is_never_tracked() {
        let stats = KeyStats::default();
        stats.record_call("");
        stats.record_identity_mismatch("");
        let snap = stats.snapshot();
        assert!(
            snap.per_key.is_empty(),
            "no client keys configured means nothing real to track"
        );
    }

    #[test]
    fn identity_mismatch_increments_independently_of_calls() {
        let stats = KeyStats::default();
        stats.record_call("k1");
        stats.record_identity_mismatch("k1");
        stats.record_identity_mismatch("k1");
        let snap = stats.snapshot();
        let k1 = snap.per_key.get("k1").unwrap();
        assert_eq!(k1.calls, 1);
        assert_eq!(k1.identity_mismatches, 2);
    }

    #[test]
    fn a_mismatch_with_no_prior_call_still_creates_the_entry() {
        // Defensive: proxy.rs always calls `record_call` first in practice,
        // but this module must not assume call ordering.
        let stats = KeyStats::default();
        stats.record_identity_mismatch("k1");
        let snap = stats.snapshot();
        let k1 = snap.per_key.get("k1").unwrap();
        assert_eq!(k1.calls, 0);
        assert_eq!(k1.identity_mismatches, 1);
    }

    #[test]
    fn unauthorized_counter_is_aggregate_only() {
        let stats = KeyStats::default();
        stats.record_unauthorized();
        stats.record_unauthorized();
        let snap = stats.snapshot();
        assert_eq!(snap.unauthorized.attempts, 2);
        assert!(snap.unauthorized.last_millis.is_some());
        assert!(
            snap.per_key.is_empty(),
            "unauthorized attempts never key by anything"
        );
    }

    #[test]
    fn a_fresh_key_stats_reports_nothing() {
        let snap = KeyStats::default().snapshot();
        assert!(snap.per_key.is_empty());
        assert_eq!(snap.unauthorized.attempts, 0);
        assert!(snap.unauthorized.last_millis.is_none());
    }

    #[test]
    fn snapshot_is_a_copy_not_a_live_view() {
        let stats = KeyStats::default();
        stats.record_call("k1");
        let snap = stats.snapshot();
        stats.record_call("k1");
        assert_eq!(
            snap.per_key.get("k1").unwrap().calls,
            1,
            "a snapshot already taken must not see later increments"
        );
    }
}
