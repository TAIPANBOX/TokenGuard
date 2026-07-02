//! Policy evaluation for non-budget limits and the rollout mode.
//!
//! Division of responsibility (single source of truth per rule):
//! - The **per-run budget** is enforced atomically by the [`crate::ledger`] on
//!   `reserve`, so it is not re-checked here.
//! - Everything else — per-step cost cap, max steps, and (later) loop detection
//!   — is evaluated here against a [`RunSnapshot`].
//!
//! Rollout modes let a team adopt enforcement safely: `Shadow` observes and
//! records what it *would* block without changing behavior; `Warn` surfaces the
//! violation but still allows; `Enforce` blocks.

use crate::ledger::RunSnapshot;
use crate::loops::AnomalyConfig;
use crate::money::Microusd;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Shadow,
    Warn,
    Enforce,
}

/// A policy is a selector-matched bundle of limits plus a rollout mode. The
/// selector lives at a higher layer; this is the evaluable core.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub mode: Mode,
    /// Per-run budget. Informational here — enforced by the ledger — but kept
    /// on the policy so it is the thing that *sets* the ledger budget.
    #[serde(default)]
    pub budget_per_run: Option<Microusd>,
    #[serde(default)]
    pub budget_per_step: Option<Microusd>,
    #[serde(default)]
    pub max_steps: Option<u32>,
    /// Loop / runaway detectors. Evaluated by the gateway via `crate::loops`.
    #[serde(default)]
    pub anomalies: AnomalyConfig,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            mode: Mode::Shadow,
            budget_per_run: None,
            budget_per_step: None,
            max_steps: None,
            anomalies: AnomalyConfig::default(),
        }
    }
}

/// The action the gateway should take for a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Warn { reason: String },
    Block { reason: String },
}

impl Decision {
    pub fn is_blocking(&self) -> bool {
        matches!(self, Decision::Block { .. })
    }
}

/// The result of evaluating a policy: the action to take *and* the rule that
/// tripped (if any), independent of mode. The `violated` field lets the gateway
/// log "would have blocked: <reason>" while in shadow mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub decision: Decision,
    pub violated: Option<String>,
}

/// Evaluate `policy` for a next call of `estimate` cost against `snapshot`.
pub fn evaluate(policy: &Policy, snapshot: &RunSnapshot, estimate: Microusd) -> Evaluation {
    let violated = first_violation(policy, snapshot, estimate);

    let decision = match &violated {
        None => Decision::Allow,
        Some(reason) => match policy.mode {
            Mode::Shadow => Decision::Allow,
            Mode::Warn => Decision::Warn {
                reason: reason.clone(),
            },
            Mode::Enforce => Decision::Block {
                reason: reason.clone(),
            },
        },
    };

    Evaluation { decision, violated }
}

/// Return the first violated rule's human-readable reason, or `None` if the call
/// is within all limits. Order defines precedence.
fn first_violation(policy: &Policy, snapshot: &RunSnapshot, estimate: Microusd) -> Option<String> {
    if let Some(max) = policy.max_steps {
        // `steps` counts reservations already made; the next call would be
        // step (steps + 1).
        if snapshot.steps >= max {
            return Some(format!(
                "max steps reached: {} of {max} already taken",
                snapshot.steps
            ));
        }
    }

    if let Some(cap) = policy.budget_per_step {
        if estimate > cap {
            return Some(format!(
                "per-step budget exceeded: estimate {estimate} over cap {cap}"
            ));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(steps: u32) -> RunSnapshot {
        RunSnapshot {
            budget: Microusd::from_usd(5.0),
            reserved: Microusd::ZERO,
            spent: Microusd::ZERO,
            steps,
        }
    }

    #[test]
    fn allows_when_within_all_limits() {
        let policy = Policy {
            mode: Mode::Enforce,
            max_steps: Some(10),
            budget_per_step: Some(Microusd::from_usd(1.0)),
            ..Default::default()
        };
        let eval = evaluate(&policy, &snap(3), Microusd::from_usd(0.5));
        assert_eq!(eval.decision, Decision::Allow);
        assert!(eval.violated.is_none());
    }

    #[test]
    fn enforce_blocks_on_max_steps() {
        let policy = Policy {
            mode: Mode::Enforce,
            max_steps: Some(5),
            ..Default::default()
        };
        let eval = evaluate(&policy, &snap(5), Microusd::from_usd(0.1));
        assert!(eval.decision.is_blocking());
        assert!(eval.violated.unwrap().contains("max steps"));
    }

    #[test]
    fn shadow_allows_but_records_would_block() {
        let policy = Policy {
            mode: Mode::Shadow,
            max_steps: Some(5),
            ..Default::default()
        };
        let eval = evaluate(&policy, &snap(5), Microusd::from_usd(0.1));
        // Shadow never blocks...
        assert_eq!(eval.decision, Decision::Allow);
        // ...but it still reports what it would have blocked.
        assert!(eval.violated.is_some());
    }

    #[test]
    fn warn_surfaces_reason_but_allows() {
        let policy = Policy {
            mode: Mode::Warn,
            budget_per_step: Some(Microusd::from_usd(0.5)),
            ..Default::default()
        };
        let eval = evaluate(&policy, &snap(1), Microusd::from_usd(2.0));
        match eval.decision {
            Decision::Warn { reason } => assert!(reason.contains("per-step")),
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    #[test]
    fn max_steps_takes_precedence_over_per_step_cost() {
        let policy = Policy {
            mode: Mode::Enforce,
            max_steps: Some(2),
            budget_per_step: Some(Microusd::from_usd(0.5)),
            ..Default::default()
        };
        // Both rules would trip; max_steps is checked first.
        let eval = evaluate(&policy, &snap(2), Microusd::from_usd(9.0));
        assert!(eval.violated.unwrap().contains("max steps"));
    }
}
