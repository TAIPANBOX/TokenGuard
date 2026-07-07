//! Breaker: a facade that unifies TokenFuse's seven existing block reasons
//! (budget, policy, loop, kill, WASM policy, taint, DLP) behind one type.
//!
//! Adoption is partial. The 402 budget-family block sites in
//! `crates/gateway/src/proxy.rs` (budget, policy, loop, kill, WASM policy) now
//! build a `BreakerVerdict` and render their response through this facade
//! (`breaker_error_response`). The 403 sites — `dlp_block` and `firewall_block`
//! (DLP/taint) — do NOT go through it yet; they still build their JSON
//! directly. The facade mirrors the wire contract proxy.rs produces
//! (`budget_error`, `dlp_block`, `firewall_block`) so those remaining sites can
//! migrate later without a wire change.

use serde::Serialize;

/// The seven reasons the Breaker can trip a run, one per existing wire
/// `"type"` string emitted by the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerReason {
    BudgetExceeded,
    PolicyViolation,
    LoopDetected,
    Killed,
    WasmPolicy,
    TaintBlocked,
    DlpBlocked,
}

impl BreakerReason {
    /// The exact `error.type` string the gateway puts on the wire today.
    /// See `crates/gateway/src/proxy.rs`: `budget_error` (kind param),
    /// `dlp_block` ("dlp_blocked"), `firewall_block` ("taint_blocked").
    pub fn as_wire_str(self) -> &'static str {
        match self {
            BreakerReason::BudgetExceeded => "budget_exceeded",
            BreakerReason::PolicyViolation => "policy_violation",
            BreakerReason::LoopDetected => "loop_detected",
            BreakerReason::Killed => "killed",
            BreakerReason::WasmPolicy => "wasm_policy",
            BreakerReason::TaintBlocked => "taint_blocked",
            BreakerReason::DlpBlocked => "dlp_blocked",
        }
    }

    /// The HTTP status the gateway returns for this reason today.
    /// `dlp_block`/`firewall_block` in proxy.rs return `403 FORBIDDEN`;
    /// `budget_error` (used for budget/policy/loop/kill/wasm) returns
    /// `402 PAYMENT_REQUIRED`.
    pub fn http_status(self) -> u16 {
        match self {
            BreakerReason::TaintBlocked | BreakerReason::DlpBlocked => 403,
            BreakerReason::BudgetExceeded
            | BreakerReason::PolicyViolation
            | BreakerReason::LoopDetected
            | BreakerReason::Killed
            | BreakerReason::WasmPolicy => 402,
        }
    }
}

/// The wire shape of the `error` object, mirroring the `serde_json::json!`
/// bodies built in `proxy.rs`. Optional fields are omitted (not `null`) when
/// absent, matching `dlp_block`/`firewall_block` (no budget/spent/policy_id)
/// vs. `budget_error` (always includes them).
#[derive(Serialize)]
struct WireError<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    run_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    budget_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spent_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_id: Option<&'a str>,
    reason: &'a str,
    retryable: bool,
}

/// The outcome of evaluating whether a run should be broken (stopped).
/// Unifies the seven existing block reasons without touching the
/// enforcement path.
#[derive(Debug, Clone, Default)]
pub struct BreakerVerdict {
    pub tripped: bool,
    pub reason: Option<BreakerReason>,
    pub detail: Option<String>,
    pub budget_usd: Option<f64>,
    pub spent_usd: Option<f64>,
    pub policy_id: Option<String>,
    /// True when the run *would* have tripped the Breaker but the policy is
    /// in shadow/warn mode, so the request was allowed through anyway.
    pub would_trip_only: bool,
}

impl BreakerVerdict {
    /// A verdict for a run that did not trip the Breaker.
    pub fn allow() -> Self {
        BreakerVerdict {
            tripped: false,
            reason: None,
            detail: None,
            budget_usd: None,
            spent_usd: None,
            policy_id: None,
            would_trip_only: false,
        }
    }

    /// Render the gateway's stable error-body JSON for this verdict, byte-
    /// compatible with what `proxy.rs`'s `budget_error`/`dlp_block`/
    /// `firewall_block` produce today.
    pub fn to_error_json(&self, run_id: &str) -> serde_json::Value {
        let kind = self.reason.map(BreakerReason::as_wire_str).unwrap_or("");
        let wire = WireError {
            kind,
            run_id,
            budget_usd: self.budget_usd,
            spent_usd: self.spent_usd,
            policy_id: self.policy_id.as_deref(),
            reason: self.detail.as_deref().unwrap_or(""),
            retryable: false,
        };
        serde_json::json!({ "error": wire })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_str_budget_exceeded() {
        assert_eq!(
            BreakerReason::BudgetExceeded.as_wire_str(),
            "budget_exceeded"
        );
    }

    #[test]
    fn wire_str_policy_violation() {
        assert_eq!(
            BreakerReason::PolicyViolation.as_wire_str(),
            "policy_violation"
        );
    }

    #[test]
    fn wire_str_loop_detected() {
        assert_eq!(BreakerReason::LoopDetected.as_wire_str(), "loop_detected");
    }

    #[test]
    fn wire_str_killed() {
        assert_eq!(BreakerReason::Killed.as_wire_str(), "killed");
    }

    #[test]
    fn wire_str_wasm_policy() {
        assert_eq!(BreakerReason::WasmPolicy.as_wire_str(), "wasm_policy");
    }

    #[test]
    fn wire_str_taint_blocked() {
        assert_eq!(BreakerReason::TaintBlocked.as_wire_str(), "taint_blocked");
    }

    #[test]
    fn wire_str_dlp_blocked() {
        assert_eq!(BreakerReason::DlpBlocked.as_wire_str(), "dlp_blocked");
    }

    #[test]
    fn http_status_403_for_taint_and_dlp() {
        // Matches proxy.rs dlp_block/firewall_block: StatusCode::FORBIDDEN.
        assert_eq!(BreakerReason::TaintBlocked.http_status(), 403);
        assert_eq!(BreakerReason::DlpBlocked.http_status(), 403);
    }

    #[test]
    fn http_status_402_for_the_rest() {
        // Matches proxy.rs budget_error: StatusCode::PAYMENT_REQUIRED.
        for reason in [
            BreakerReason::BudgetExceeded,
            BreakerReason::PolicyViolation,
            BreakerReason::LoopDetected,
            BreakerReason::Killed,
            BreakerReason::WasmPolicy,
        ] {
            assert_eq!(reason.http_status(), 402);
        }
    }

    #[test]
    fn allow_is_not_tripped() {
        let v = BreakerVerdict::allow();
        assert!(!v.tripped);
        assert!(v.reason.is_none());
        assert!(!v.would_trip_only);
    }

    #[test]
    fn budget_json_matches_proxy_budget_error_shape() {
        // Mirrors crates/gateway/src/proxy.rs `budget_error()` (~line 577):
        //   json!({ "error": { "type": kind, "run_id": run_id,
        //     "budget_usd": budget.as_usd(), "spent_usd": spent.as_usd(),
        //     "policy_id": policy_id, "reason": reason, "retryable": false } })
        let verdict = BreakerVerdict {
            tripped: true,
            reason: Some(BreakerReason::BudgetExceeded),
            detail: Some("per-run budget exceeded".to_string()),
            budget_usd: Some(5.0),
            spent_usd: Some(5.25),
            policy_id: Some("default".to_string()),
            would_trip_only: false,
        };
        let got = verdict.to_error_json("run-1");
        let want = serde_json::json!({
            "error": {
                "type": "budget_exceeded",
                "run_id": "run-1",
                "budget_usd": 5.0,
                "spent_usd": 5.25,
                "policy_id": "default",
                "reason": "per-run budget exceeded",
                "retryable": false,
            }
        });
        assert_eq!(got, want);
    }

    #[test]
    fn killed_json_matches_proxy_budget_error_shape() {
        // `killed` is also produced via budget_error() (proxy.rs messages(),
        // ~line 74), so it carries budget_usd/spent_usd/policy_id too.
        let verdict = BreakerVerdict {
            tripped: true,
            reason: Some(BreakerReason::Killed),
            detail: Some("run killed by operator".to_string()),
            budget_usd: Some(10.0),
            spent_usd: Some(1.5),
            policy_id: Some("default".to_string()),
            would_trip_only: false,
        };
        let got = verdict.to_error_json("run-2");
        let want = serde_json::json!({
            "error": {
                "type": "killed",
                "run_id": "run-2",
                "budget_usd": 10.0,
                "spent_usd": 1.5,
                "policy_id": "default",
                "reason": "run killed by operator",
                "retryable": false,
            }
        });
        assert_eq!(got, want);
    }

    #[test]
    fn dlp_json_matches_proxy_dlp_block_shape_and_omits_budget_fields() {
        // Mirrors crates/gateway/src/proxy.rs `dlp_block()` (~line 482):
        //   json!({ "error": { "type": "dlp_blocked", "run_id": run_id,
        //     "reason": summary, "retryable": false } })
        // Note: no budget_usd/spent_usd/policy_id keys at all (not even null).
        let verdict = BreakerVerdict {
            tripped: true,
            reason: Some(BreakerReason::DlpBlocked),
            detail: Some("1 secret (aws_key)".to_string()),
            budget_usd: None,
            spent_usd: None,
            policy_id: None,
            would_trip_only: false,
        };
        let got = verdict.to_error_json("run-3");
        let want = serde_json::json!({
            "error": {
                "type": "dlp_blocked",
                "run_id": "run-3",
                "reason": "1 secret (aws_key)",
                "retryable": false,
            }
        });
        assert_eq!(got, want);
        assert!(got["error"].get("budget_usd").is_none());
        assert!(got["error"].get("spent_usd").is_none());
        assert!(got["error"].get("policy_id").is_none());
    }

    #[test]
    fn taint_json_matches_proxy_firewall_block_shape() {
        // Mirrors crates/gateway/src/proxy.rs `firewall_block()` (~line 502):
        //   json!({ "error": { "type": "taint_blocked", "run_id": run_id,
        //     "reason": reason, "retryable": false } })
        let verdict = BreakerVerdict {
            tripped: true,
            reason: Some(BreakerReason::TaintBlocked),
            detail: Some("exec denied after web taint".to_string()),
            budget_usd: None,
            spent_usd: None,
            policy_id: None,
            would_trip_only: false,
        };
        let got = verdict.to_error_json("run-4");
        let want = serde_json::json!({
            "error": {
                "type": "taint_blocked",
                "run_id": "run-4",
                "reason": "exec denied after web taint",
                "retryable": false,
            }
        });
        assert_eq!(got, want);
    }

    #[test]
    fn wasm_policy_json_matches_proxy_budget_error_shape() {
        let verdict = BreakerVerdict {
            tripped: true,
            reason: Some(BreakerReason::WasmPolicy),
            detail: Some("blocked by custom wasm policy".to_string()),
            budget_usd: Some(2.0),
            spent_usd: Some(0.1),
            policy_id: Some("default".to_string()),
            would_trip_only: false,
        };
        let got = verdict.to_error_json("run-5");
        assert_eq!(got["error"]["type"], "wasm_policy");
        assert_eq!(got["error"]["retryable"], false);
        assert_eq!(got["error"]["budget_usd"], 2.0);
    }
}
