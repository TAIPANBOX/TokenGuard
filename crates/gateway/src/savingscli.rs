//! `tokenfuse savings` — sum the avoided spend recorded at every
//! budget-protection BLOCK site in the Parquet trace and print the ROI.
//!
//! This is the read side of P2: the gateway records a block row (with the
//! avoided cost estimate) per prevented call, and this command aggregates them
//! via [`tokenfuse_core::savings::compute_savings`]. It mirrors
//! [`crate::backtestcli`]'s shape — a thin loader over [`crate::sqlq::query`]
//! plus a human summary.

use datafusion::arrow::array::{Array, Int64Array, StringArray, StringViewArray};
use tokenfuse_core::savings::{compute_savings, Call};
use tokenfuse_core::Microusd;

use crate::sqlq::query;

/// Read a string cell whether the column is `Utf8` or `Utf8View` (DataFusion
/// picks the view type by default).
fn str_at(col: &dyn Array, i: usize) -> String {
    if let Some(a) = col.as_any().downcast_ref::<StringArray>() {
        return a.value(i).to_string();
    }
    if let Some(a) = col.as_any().downcast_ref::<StringViewArray>() {
        return a.value(i).to_string();
    }
    String::new()
}

/// Load the trace, aggregate the savings, and print the report.
///
/// A missing or empty trace directory is not an error: it prints a friendly
/// hint and exits 0, so `tokenfuse savings` is safe to wire into a dashboard or
/// CI step before any traffic has been recorded.
pub async fn run(dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    // A missing dir (nothing recorded yet) makes DataFusion error on register;
    // treat that the same as an empty trace rather than surfacing a stack of
    // Parquet internals to someone who just hasn't sent traffic yet.
    let calls = match load_calls(dir).await {
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

/// Load the `run_id`, `decision`, and `cost_microusd` columns from the trace.
///
/// Mirrors [`crate::backtestcli`]'s loader but reads `decision` (not `step`),
/// since savings keys off the block reason. Both read the same `calls` table.
async fn load_calls(dir: &str) -> Result<Vec<Call>, Box<dyn std::error::Error>> {
    let batches = query(
        "select run_id, decision, cast(cost_microusd as bigint) as cost from calls",
        dir,
    )
    .await?;
    let mut calls = Vec::new();
    for b in &batches {
        let cost = b
            .column(2)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("cost column type")?;
        for i in 0..b.num_rows() {
            calls.push(Call {
                run_id: str_at(b.column(0).as_ref(), i),
                decision: str_at(b.column(1).as_ref(), i),
                cost_microusd: cost.value(i),
            });
        }
    }
    Ok(calls)
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
        }
    }

    #[test]
    fn computes_savings_over_a_mixed_trace() {
        // The pure path the CLI runs after loading: allows + a security block are
        // ignored; only the budget-protection blocks are summed.
        let calls = vec![
            call("a", "allow", 500_000),
            call("a", "budget_exceeded", 1_000_000),
            call("b", "killed", 2_000_000),
            call("b", "dlp_blocked", 9_000_000),
        ];
        let report = compute_savings(&calls);
        assert_eq!(report.blocked_spend_microusd, 3_000_000);
        assert_eq!(report.blocked_calls, 2);
        assert_eq!(report.budget_breaks_prevented, 2);
    }
}
