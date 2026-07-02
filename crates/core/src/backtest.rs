//! Policy backtesting (W6 — "the time machine").
//!
//! Replays a candidate budget policy over the recorded call trace and reports
//! what it *would* have blocked and saved — so a policy can be tested on real
//! history before it is enforced, instead of guessed at.
//!
//! Pure logic: it operates on a flat list of [`Call`]s (loaded from the Parquet
//! trace by the gateway). Only budget/step rules are backtestable from the trace
//! today; loop detection needs per-call tool signatures, which the trace does
//! not yet carry.

use std::collections::BTreeMap;

/// One recorded call, the input unit of a backtest.
#[derive(Debug, Clone)]
pub struct Call {
    pub run_id: String,
    pub step: u32,
    pub cost_microusd: i64,
}

/// A candidate policy to evaluate (limits in microdollars).
#[derive(Debug, Clone, Default)]
pub struct BacktestPolicy {
    pub budget_per_run_micro: Option<i64>,
    pub budget_per_step_micro: Option<i64>,
    pub max_steps: Option<u32>,
}

impl BacktestPolicy {
    pub fn is_empty(&self) -> bool {
        self.budget_per_run_micro.is_none()
            && self.budget_per_step_micro.is_none()
            && self.max_steps.is_none()
    }
}

/// What the candidate policy would have done to the trace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BacktestReport {
    pub runs_total: u64,
    pub runs_affected: u64,
    pub calls_total: u64,
    pub calls_blocked: u64,
    /// Total spend that actually happened in the trace.
    pub spent_microusd: i64,
    /// Spend the candidate policy would have prevented.
    pub saved_microusd: i64,
}

impl BacktestReport {
    /// Spend that would remain after applying the candidate policy.
    pub fn projected_microusd(&self) -> i64 {
        self.spent_microusd - self.saved_microusd
    }
}

/// Replay `policy` over `calls` and report the outcome.
///
/// A per-run budget or max-steps breach stops the run: that call and every later
/// call in the run are counted as blocked (an agent that gets a 402 stops). A
/// per-step breach blocks only that one call — the run continues.
pub fn backtest(calls: &[Call], policy: &BacktestPolicy) -> BacktestReport {
    let mut by_run: BTreeMap<&str, Vec<&Call>> = BTreeMap::new();
    for c in calls {
        by_run.entry(c.run_id.as_str()).or_default().push(c);
    }

    let mut report = BacktestReport {
        runs_total: by_run.len() as u64,
        calls_total: calls.len() as u64,
        spent_microusd: calls.iter().map(|c| c.cost_microusd).sum(),
        ..Default::default()
    };

    for (_run, mut list) in by_run {
        list.sort_by_key(|c| c.step);
        let mut running = 0i64;
        let mut steps = 0u32;
        let mut stopped = false;
        let mut affected = false;

        for c in list {
            if stopped {
                report.calls_blocked += 1;
                report.saved_microusd += c.cost_microusd;
                affected = true;
                continue;
            }
            // max steps → stop the run
            if let Some(max) = policy.max_steps {
                if steps >= max {
                    stopped = true;
                    report.calls_blocked += 1;
                    report.saved_microusd += c.cost_microusd;
                    affected = true;
                    continue;
                }
            }
            // per-run budget → stop the run
            if let Some(b) = policy.budget_per_run_micro {
                if running + c.cost_microusd > b {
                    stopped = true;
                    report.calls_blocked += 1;
                    report.saved_microusd += c.cost_microusd;
                    affected = true;
                    continue;
                }
            }
            // per-step budget → block just this call
            if let Some(s) = policy.budget_per_step_micro {
                if c.cost_microusd > s {
                    report.calls_blocked += 1;
                    report.saved_microusd += c.cost_microusd;
                    affected = true;
                    continue;
                }
            }
            running += c.cost_microusd;
            steps += 1;
        }
        if affected {
            report.runs_affected += 1;
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(run: &str, step: u32, cost: i64) -> Call {
        Call {
            run_id: run.into(),
            step,
            cost_microusd: cost,
        }
    }

    #[test]
    fn per_run_budget_blocks_run_onward() {
        // run r: $1, $1, $1 with a $2 budget → 3rd call blocked.
        let calls = vec![
            call("r", 1, 1_000_000),
            call("r", 2, 1_000_000),
            call("r", 3, 1_000_000),
        ];
        let report = backtest(
            &calls,
            &BacktestPolicy {
                budget_per_run_micro: Some(2_000_000),
                ..Default::default()
            },
        );
        assert_eq!(report.calls_total, 3);
        assert_eq!(report.calls_blocked, 1);
        assert_eq!(report.runs_affected, 1);
        assert_eq!(report.saved_microusd, 1_000_000);
        assert_eq!(report.projected_microusd(), 2_000_000);
    }

    #[test]
    fn max_steps_stops_the_run() {
        let calls = vec![
            call("r", 1, 500_000),
            call("r", 2, 500_000),
            call("r", 3, 500_000),
            call("r", 4, 500_000),
        ];
        let report = backtest(
            &calls,
            &BacktestPolicy {
                max_steps: Some(2),
                ..Default::default()
            },
        );
        // steps 3 and 4 are blocked.
        assert_eq!(report.calls_blocked, 2);
        assert_eq!(report.saved_microusd, 1_000_000);
    }

    #[test]
    fn per_step_blocks_only_the_expensive_call() {
        let calls = vec![
            call("r", 1, 100_000),
            call("r", 2, 9_000_000), // over the per-step cap
            call("r", 3, 100_000),
        ];
        let report = backtest(
            &calls,
            &BacktestPolicy {
                budget_per_step_micro: Some(1_000_000),
                ..Default::default()
            },
        );
        // Only the expensive call is blocked; the run continues.
        assert_eq!(report.calls_blocked, 1);
        assert_eq!(report.saved_microusd, 9_000_000);
    }

    #[test]
    fn independent_runs_are_isolated() {
        let calls = vec![
            call("a", 1, 3_000_000),
            call("b", 1, 500_000),
            call("b", 2, 500_000),
        ];
        let report = backtest(
            &calls,
            &BacktestPolicy {
                budget_per_run_micro: Some(1_000_000),
                ..Default::default()
            },
        );
        // Run a's single $3 call exceeds $1 → blocked. Run b stays under.
        assert_eq!(report.runs_total, 2);
        assert_eq!(report.runs_affected, 1);
        assert_eq!(report.calls_blocked, 1);
        assert_eq!(report.saved_microusd, 3_000_000);
    }

    #[test]
    fn empty_policy_blocks_nothing() {
        let calls = vec![call("r", 1, 1_000_000)];
        let report = backtest(&calls, &BacktestPolicy::default());
        assert_eq!(report.calls_blocked, 0);
        assert_eq!(report.saved_microusd, 0);
        assert_eq!(report.spent_microusd, 1_000_000);
    }
}
