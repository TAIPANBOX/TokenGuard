//! Outcome-tag unit economics (P4 — "what does one resolved case cost").
//!
//! `crates/gateway/src/proxy.rs` captures an opaque `X-Fuse-Outcome` tag per
//! call, verbatim, into the trace (`sink::CallRecord::outcome`) — capture
//! only, no run-level state is built in the proxy (the hot path stays
//! untouched). This module is the read side: given the flat per-call rows
//! loaded from the Parquet trace, it answers "for each outcome tag, how many
//! runs, how much did they cost, how many calls did it take". Mirrors
//! [`crate::savings`] in shape: pure aggregation over a `Call` list, no I/O.
//!
//! ## Outcome semantics: last non-empty tag per run wins
//!
//! An agent typically tags only its FINAL call of a run (e.g. `case_resolved`
//! once the ticket is closed), but any call in the run may carry the header,
//! and a later call's tag should override an earlier one (an agent that
//! re-tags a run from `escalated` to `case_resolved` as the situation
//! resolves). So a run's outcome is defined as: the LAST non-empty `outcome`
//! value recorded for its `run_id`, in call order (`step` is the per-run
//! sequence counter the gateway assigns — see `sink::CallRecord::step` — so
//! it, not `ts_millis`, is the reliable per-run ordering key: multiple calls
//! of a fast local run can share a millisecond, but never a step). A run that
//! never sent the header at all is `(untagged)`.
//!
//! ## Why post-processing, not SQL
//!
//! [`compute_outcomes`] takes the "last non-empty per run" winner and the
//! per-outcome rollup as two passes of plain Rust over an already-loaded
//! `Vec<Call>`, rather than expressing "last non-null value per group" as a
//! DataFusion window query. A `LAST_VALUE(...) IGNORE NULLS OVER (PARTITION
//! BY run_id ORDER BY step)` query is expressible but adds a second,
//! harder-to-test SQL surface for logic that is a handful of lines of
//! straightforward Rust — and it would need its own reasoning about NULL vs.
//! `''` (the trace's actual "unset" sentinel, per the schema-evolution
//! COALESCE convention — see `sink::CallRecord`). Loading once and folding in
//! Rust keeps the winner-selection logic in one place, next to its tests,
//! consistent with how `compute_savings` favors a pure aggregation over a
//! wider SQL query.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::breaker::BreakerReason;

/// One recorded call from the trace, the input unit of an outcomes
/// projection.
#[derive(Debug, Clone)]
pub struct Call {
    pub run_id: String,
    /// The wire decision string recorded for this call (e.g. `allow`,
    /// `cache_hit`, `budget_exceeded`, `dlp_blocked`).
    pub decision: String,
    pub cost_microusd: i64,
    /// Raw, per-call `X-Fuse-Outcome` value (`""` when unset).
    pub outcome: String,
    /// Per-run sequence counter (`sink::CallRecord::step`) — the ordering key
    /// used to find each run's LAST non-empty outcome tag.
    pub step: u32,
}

/// The Breaker block reasons - read off [`BreakerReason`] so this
/// mirrors `gateway::focusexport::is_blocked_decision` from the single
/// canonical source rather than hand-copying wire strings a second time.
/// Includes the identity-map pair (docs/20).
const BLOCKED_DECISIONS: [BreakerReason; 9] = [
    BreakerReason::BudgetExceeded,
    BreakerReason::PolicyViolation,
    BreakerReason::LoopDetected,
    BreakerReason::Killed,
    BreakerReason::WasmPolicy,
    BreakerReason::TaintBlocked,
    BreakerReason::DlpBlocked,
    BreakerReason::UnitBudgetExceeded,
    BreakerReason::IdentityMismatch,
];

/// Whether a decision string is one of the Breaker block reasons (vs.
/// an allow or a cache hit). A blocked row's `cost_microusd` holds the
/// avoided estimate, never a real settled charge (see `proxy.rs`), so
/// [`compute_outcomes`] excludes these rows from the cost total but still
/// counts them as calls and as blocked calls.
pub fn is_blocked_decision(decision: &str) -> bool {
    BLOCKED_DECISIONS
        .iter()
        .any(|r| r.as_wire_str() == decision)
}

/// One row of a per-outcome-tag unit-economics report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutcomeRow {
    /// The outcome tag, or `None` for runs whose last non-empty tag is
    /// absent (they never sent `X-Fuse-Outcome`, or every occurrence was
    /// over the header's sanity cap and got ignored). Callers render this as
    /// `(untagged)`.
    pub outcome: Option<String>,
    /// Number of distinct runs whose winning tag is `outcome`.
    pub runs: usize,
    /// Sum of settled cost (microdollars) across every call belonging to
    /// those runs. Blocked-decision rows contribute `0` here (their
    /// `cost_microusd` is an avoided estimate, not real spend — see
    /// [`is_blocked_decision`]).
    pub total_cost_microusd: i64,
    /// Total call rows (settled AND blocked) across those runs.
    pub calls: usize,
    /// Blocked-decision call rows across those runs.
    pub blocked_calls: usize,
}

impl OutcomeRow {
    /// Mean settled cost per run, in microdollars. `0` when `runs == 0`
    /// (never actually produced by [`compute_outcomes`], which only emits
    /// rows for tags that have at least one run — kept total for callers
    /// that persist/reconstruct rows independently).
    pub fn mean_cost_microusd(&self) -> i64 {
        if self.runs == 0 {
            0
        } else {
            self.total_cost_microusd / self.runs as i64
        }
    }
}

/// Aggregate `calls` into one [`OutcomeRow`] per outcome tag (last non-empty
/// per run wins — see the module docs), plus an untagged (`outcome: None`)
/// row for runs that never set one. Rows are sorted by tag name, with the
/// untagged row last (a `BTreeMap<Option<String>, _>` would instead put
/// `None` FIRST, since `None < Some(_)` — not the reading order a report
/// wants).
pub fn compute_outcomes(calls: &[Call]) -> Vec<OutcomeRow> {
    // Pass 1: each run's LAST non-empty outcome tag, scanning in per-run call
    // order (`step`). Later non-empty values overwrite earlier ones, so
    // whatever's in the map after the scan is exactly the last-non-empty
    // winner — this is why sorting by `step` (not merely grouping) matters.
    let mut ordered: Vec<&Call> = calls.iter().collect();
    ordered.sort_by(|a, b| a.run_id.cmp(&b.run_id).then(a.step.cmp(&b.step)));
    let mut winner: BTreeMap<&str, &str> = BTreeMap::new();
    for c in &ordered {
        if !c.outcome.is_empty() {
            winner.insert(c.run_id.as_str(), c.outcome.as_str());
        }
    }

    // Pass 2: fold every call into its run's winning-tag bucket.
    #[derive(Default)]
    struct Acc {
        runs: BTreeSet<String>,
        cost_microusd: i64,
        calls: usize,
        blocked_calls: usize,
    }
    let mut buckets: BTreeMap<Option<String>, Acc> = BTreeMap::new();
    for c in calls {
        let tag = winner.get(c.run_id.as_str()).map(|s| s.to_string());
        let acc = buckets.entry(tag).or_default();
        acc.runs.insert(c.run_id.clone());
        acc.calls += 1;
        if is_blocked_decision(&c.decision) {
            acc.blocked_calls += 1;
        } else {
            acc.cost_microusd += c.cost_microusd;
        }
    }

    let mut rows: Vec<OutcomeRow> = buckets
        .into_iter()
        .map(|(outcome, acc)| OutcomeRow {
            outcome,
            runs: acc.runs.len(),
            total_cost_microusd: acc.cost_microusd,
            calls: acc.calls,
            blocked_calls: acc.blocked_calls,
        })
        .collect();
    rows.sort_by(|a, b| match (&a.outcome, &b.outcome) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(x), Some(y)) => x.cmp(y),
    });
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(run: &str, decision: &str, cost: i64, outcome: &str, step: u32) -> Call {
        Call {
            run_id: run.into(),
            decision: decision.into(),
            cost_microusd: cost,
            outcome: outcome.into(),
            step,
        }
    }

    #[test]
    fn empty_trace_is_empty_report() {
        assert_eq!(compute_outcomes(&[]), Vec::new());
    }

    #[test]
    fn single_run_tagged_on_final_call() {
        let calls = vec![
            call("r1", "allow", 1_000_000, "", 1),
            call("r1", "allow", 2_000_000, "case_resolved", 2),
        ];
        let rows = compute_outcomes(&calls);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outcome.as_deref(), Some("case_resolved"));
        assert_eq!(rows[0].runs, 1);
        assert_eq!(rows[0].total_cost_microusd, 3_000_000);
        assert_eq!(rows[0].calls, 2);
        assert_eq!(rows[0].blocked_calls, 0);
    }

    #[test]
    fn conflicting_tags_last_non_empty_by_step_wins() {
        // Same run tagged twice with DIFFERENT values — the later step's tag
        // must win, proving last-wins is keyed off call order, not just "any
        // non-empty tag found".
        let calls = vec![
            call("r1", "allow", 1_000_000, "escalated", 1),
            call("r1", "allow", 1_000_000, "case_resolved", 2),
        ];
        let rows = compute_outcomes(&calls);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outcome.as_deref(), Some("case_resolved"));
    }

    #[test]
    fn later_empty_tag_does_not_erase_an_earlier_non_empty_one() {
        // The final call of the run does NOT set the header (empty) — the
        // earlier non-empty tag must still be the run's winner (an agent
        // isn't required to repeat the tag on every call).
        let calls = vec![
            call("r1", "allow", 1_000_000, "in_progress", 1),
            call("r1", "allow", 1_000_000, "", 2),
        ];
        let rows = compute_outcomes(&calls);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outcome.as_deref(), Some("in_progress"));
    }

    #[test]
    fn untagged_run_lands_in_the_none_bucket() {
        let calls = vec![call("r1", "allow", 1_000_000, "", 1)];
        let rows = compute_outcomes(&calls);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outcome, None);
        assert_eq!(rows[0].runs, 1);
    }

    #[test]
    fn blocked_calls_are_counted_but_excluded_from_cost() {
        let calls = vec![
            call("r1", "allow", 1_000_000, "case_resolved", 1),
            call("r1", "budget_exceeded", 9_000_000, "", 2),
        ];
        let rows = compute_outcomes(&calls);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].calls, 2);
        assert_eq!(rows[0].blocked_calls, 1);
        // The blocked row's 9_000_000 avoided-estimate must NOT count as cost.
        assert_eq!(rows[0].total_cost_microusd, 1_000_000);
    }

    #[test]
    fn multiple_runs_group_by_winning_tag() {
        let calls = vec![
            call("a", "allow", 1_000_000, "case_resolved", 1),
            call("b", "allow", 2_000_000, "case_resolved", 1),
            call("c", "allow", 500_000, "escalated", 1),
        ];
        let rows = compute_outcomes(&calls);
        assert_eq!(rows.len(), 2);
        let resolved = rows
            .iter()
            .find(|r| r.outcome.as_deref() == Some("case_resolved"))
            .unwrap();
        assert_eq!(resolved.runs, 2);
        assert_eq!(resolved.total_cost_microusd, 3_000_000);
        let escalated = rows
            .iter()
            .find(|r| r.outcome.as_deref() == Some("escalated"))
            .unwrap();
        assert_eq!(escalated.runs, 1);
        assert_eq!(escalated.total_cost_microusd, 500_000);
    }

    #[test]
    fn rows_sort_by_tag_with_untagged_last() {
        let calls = vec![
            call("a", "allow", 1, "zzz_last_tag", 1),
            call("b", "allow", 1, "", 1),
            call("c", "allow", 1, "aaa_first_tag", 1),
        ];
        let rows = compute_outcomes(&calls);
        let labels: Vec<Option<&str>> = rows.iter().map(|r| r.outcome.as_deref()).collect();
        assert_eq!(
            labels,
            vec![Some("aaa_first_tag"), Some("zzz_last_tag"), None]
        );
    }

    #[test]
    fn mean_cost_microusd_divides_total_by_runs() {
        let row = OutcomeRow {
            outcome: Some("case_resolved".into()),
            runs: 4,
            total_cost_microusd: 1_000_000,
            calls: 4,
            blocked_calls: 0,
        };
        assert_eq!(row.mean_cost_microusd(), 250_000);
    }

    #[test]
    fn mean_cost_microusd_is_zero_for_zero_runs() {
        let row = OutcomeRow {
            outcome: None,
            runs: 0,
            total_cost_microusd: 0,
            calls: 0,
            blocked_calls: 0,
        };
        assert_eq!(row.mean_cost_microusd(), 0);
    }

    #[test]
    fn is_blocked_decision_matches_the_seven_breaker_reasons() {
        for d in [
            "budget_exceeded",
            "policy_violation",
            "loop_detected",
            "killed",
            "wasm_policy",
            "taint_blocked",
            "dlp_blocked",
        ] {
            assert!(is_blocked_decision(d), "{d} should be blocked");
        }
        assert!(!is_blocked_decision("allow"));
        assert!(!is_blocked_decision("cache_hit"));
    }
}
