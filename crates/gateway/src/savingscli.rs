//! `tokenfuse savings` — sum the avoided spend recorded at every
//! budget-protection BLOCK site in the Parquet trace and print the ROI.
//!
//! This is the read side of P2: the gateway records a block row (with the
//! avoided cost estimate) per prevented call, and this command aggregates them
//! via [`tokenfuse_core::savings::compute_savings`]. It mirrors
//! [`crate::backtestcli`]'s shape — a thin loader over [`crate::sqlq::query`]
//! plus a human summary.

use tokenfuse_core::savings::compute_savings;
use tokenfuse_core::Microusd;

use crate::sqlq::load_calls;

/// Load the trace, aggregate the savings, and print the report.
///
/// A missing or empty trace directory is not an error: it prints a friendly
/// hint and exits 0, so `tokenfuse savings` is safe to wire into a dashboard or
/// CI step before any traffic has been recorded.
pub async fn run(dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    // A missing dir (nothing recorded yet) makes DataFusion error on register;
    // treat that the same as an empty trace rather than surfacing a stack of
    // Parquet internals to someone who just hasn't sent traffic yet.
    let calls = match load_calls(dir, None, None).await {
        Ok(calls) => calls,
        Err(_) => {
            print_empty(dir);
            return Ok(());
        }
    };
    if calls.is_empty() {
        print_empty(dir);
        return Ok(());
    }

    let report = compute_savings(&calls);
    let money = |m: i64| Microusd(m).to_string();

    println!("TokenFuse savings — from {dir}");
    println!(
        "  runaway spend stopped:   {}   ({} blocked call(s) across {} budget break(s))",
        money(report.blocked_spend_microusd),
        report.blocked_calls,
        report.budget_breaks_prevented,
    );
    // Cache savings are a distinct ROI (spend served for free), reported on its
    // own line rather than folded into the runaway-spend headline.
    println!(
        "  cache saved:             {}",
        money(report.cache_saved_microusd)
    );
    // Per-reason breakdown, when anything was blocked, so the headline number is
    // attributable (which protection did the saving).
    for (reason, spend) in &report.by_reason_microusd {
        println!("    {reason:<16} {}", money(*spend));
    }
    Ok(())
}

fn print_empty(dir: &str) {
    println!("TokenFuse savings — no trace yet at {dir}");
    println!("  set TOKENFUSE_DATA_DIR and run some traffic, then try again.");
}

#[cfg(test)]
mod tests {
    use tokenfuse_core::savings::compute_savings;
    use tokenfuse_core::savings::Call;

    fn call(run: &str, decision: &str, cost: i64) -> Call {
        Call {
            run_id: run.into(),
            decision: decision.into(),
            cost_microusd: cost,
            saved_microusd: 0,
        }
    }

    #[test]
    fn computes_savings_over_a_mixed_trace() {
        // The pure path the CLI runs after loading: allows + a security block are
        // ignored; only the budget-protection blocks are summed, and cache hits
        // contribute their avoided spend on the separate cache-saved line.
        let calls = vec![
            call("a", "allow", 500_000),
            call("a", "budget_exceeded", 1_000_000),
            call("b", "killed", 2_000_000),
            call("b", "dlp_blocked", 9_000_000),
            Call {
                run_id: "b".into(),
                decision: "cache_hit".into(),
                cost_microusd: 0,
                saved_microusd: 750_000,
            },
        ];
        let report = compute_savings(&calls);
        assert_eq!(report.blocked_spend_microusd, 3_000_000);
        assert_eq!(report.blocked_calls, 2);
        assert_eq!(report.budget_breaks_prevented, 2);
        assert_eq!(report.cache_saved_microusd, 750_000);
    }
}
