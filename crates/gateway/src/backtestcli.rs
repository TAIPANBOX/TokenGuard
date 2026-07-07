//! `tokenfuse backtest` — replay a candidate policy over the Parquet trace and
//! print what it would have blocked and saved.

use datafusion::arrow::array::Int64Array;
use tokenfuse_core::backtest::{backtest, BacktestPolicy, Call};

use crate::sqlq::{query, str_at};

/// Load the trace, run the backtest, and print the report.
pub async fn run(dir: &str, policy: BacktestPolicy) -> Result<(), Box<dyn std::error::Error>> {
    if policy.is_empty() {
        eprintln!("no candidate policy given. Try: tokenfuse backtest --budget 2.0 --max-steps 20");
        return Ok(());
    }

    let calls = load_calls(dir).await?;
    if calls.is_empty() {
        println!("no calls in the trace at {dir}");
        return Ok(());
    }

    let report = backtest(&calls, &policy);
    let usd = |m: i64| m as f64 / 1e6;
    let pct = if report.spent_microusd > 0 {
        report.saved_microusd as f64 / report.spent_microusd as f64 * 100.0
    } else {
        0.0
    };

    println!("TokenFuse backtest");
    println!("  candidate policy   : {}", describe(&policy));
    println!(
        "  runs               : {} ({} affected)",
        report.runs_total, report.runs_affected
    );
    println!(
        "  calls              : {} ({} would be blocked)",
        report.calls_total, report.calls_blocked
    );
    println!("  spend in trace     : ${:.6}", usd(report.spent_microusd));
    println!(
        "  would have saved   : ${:.6} ({pct:.1}%)",
        usd(report.saved_microusd)
    );
    println!(
        "  projected spend    : ${:.6}",
        usd(report.projected_microusd())
    );
    Ok(())
}

fn describe(p: &BacktestPolicy) -> String {
    let mut parts = Vec::new();
    if let Some(b) = p.budget_per_run_micro {
        parts.push(format!("budget/run ${:.4}", b as f64 / 1e6));
    }
    if let Some(s) = p.budget_per_step_micro {
        parts.push(format!("budget/step ${:.4}", s as f64 / 1e6));
    }
    if let Some(m) = p.max_steps {
        parts.push(format!("max_steps {m}"));
    }
    parts.join(", ")
}

async fn load_calls(dir: &str) -> Result<Vec<Call>, Box<dyn std::error::Error>> {
    // Cast the numeric columns to bigint so both come back as Int64Array.
    let batches = query(
        "select run_id, cast(step as bigint) as step, cast(cost_microusd as bigint) as cost \
         from calls",
        dir,
    )
    .await?;
    let mut calls = Vec::new();
    for b in &batches {
        let step = b
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("step column type")?;
        let cost = b
            .column(2)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("cost column type")?;
        for i in 0..b.num_rows() {
            calls.push(Call {
                run_id: str_at(b.column(0).as_ref(), i),
                step: step.value(i).max(0) as u32,
                cost_microusd: cost.value(i),
            });
        }
    }
    Ok(calls)
}

/// Parse `--budget <usd>`, `--budget-per-step <usd>`, `--max-steps <n>`.
pub fn parse_policy(args: &[String]) -> BacktestPolicy {
    let mut p = BacktestPolicy::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--budget" => {
                if let Some(v) = it.next().and_then(|x| x.parse::<f64>().ok()) {
                    p.budget_per_run_micro = Some((v * 1e6) as i64);
                }
            }
            "--budget-per-step" => {
                if let Some(v) = it.next().and_then(|x| x.parse::<f64>().ok()) {
                    p.budget_per_step_micro = Some((v * 1e6) as i64);
                }
            }
            "--max-steps" => {
                if let Some(v) = it.next().and_then(|x| x.parse::<u32>().ok()) {
                    p.max_steps = Some(v);
                }
            }
            _ => {}
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flags() {
        let args = vec![
            "--budget".to_string(),
            "2.5".to_string(),
            "--max-steps".to_string(),
            "20".to_string(),
        ];
        let p = parse_policy(&args);
        assert_eq!(p.budget_per_run_micro, Some(2_500_000));
        assert_eq!(p.max_steps, Some(20));
        assert!(p.budget_per_step_micro.is_none());
    }
}
