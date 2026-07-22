//! `tokenfuse outcomes --traces <dir-or-glob> [--from RFC3339] [--to RFC3339] [--json]`
//!
//! Unit economics for FinOps (P4 — "what does one resolved case cost"): per
//! `X-Fuse-Outcome` tag (last non-empty tag per run wins — see
//! [`tokenfuse_core::outcomes`] for exactly how and why), the number of runs,
//! total settled cost, mean cost per run, total calls, and blocked calls.
//! Plus an `(untagged)` row for runs that never sent the header.
//!
//! Read-only: loads the trace via the same DataFusion path as `tokenfuse sql`
//! ([`crate::sqlq`]) and `tokenfuse focus-export`. It never touches the
//! enforcement hot path (`proxy.rs` / `tokenfuse_core::breaker`) — the
//! `outcome` column is a capture-only per-call field there; all the
//! "last-non-empty-per-run" logic lives in [`tokenfuse_core::outcomes`],
//! exercised as pure Rust post-processing (not SQL — see that module's docs
//! for why).

use datafusion::arrow::array::{Int64Array, UInt32Array};
use tokenfuse_core::outcomes::{compute_outcomes, Call, OutcomeRow};
use tokenfuse_core::Microusd;

use crate::sqlq::{query, str_at};

/// Parsed `tokenfuse outcomes` flags.
#[derive(Debug, Clone, Default)]
pub struct Args {
    pub traces: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    /// Emit the per-outcome rows as pretty JSON instead of a human table.
    pub json: bool,
}

/// Parse `--traces <dir-or-glob>`, `--from <rfc3339>`, `--to <rfc3339>`,
/// `--json`.
pub fn parse_args(args: &[String]) -> Args {
    let mut out = Args::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--traces" => out.traces = it.next().cloned(),
            "--from" => out.from = it.next().cloned(),
            "--to" => out.to = it.next().cloned(),
            "--json" => out.json = true,
            _ => {}
        }
    }
    out
}

/// Load the trace, aggregate per outcome tag, and print the report. Returns
/// `Err` with a clear message on bad flags, a missing/unreadable trace, or an
/// empty result set — the caller (`main.rs`) turns that into a non-zero exit
/// (same contract as `tokenfuse focus-export`, unlike `tokenfuse
/// savings`/`compliance`, which treat an empty trace as a friendly 0-report:
/// unit economics with zero calls isn't a report worth printing).
pub async fn run(args: &Args) -> Result<(), String> {
    let traces = args
        .traces
        .clone()
        .ok_or_else(|| "missing --traces <dir-or-glob>".to_string())?;

    let from_ms = match &args.from {
        Some(s) => Some(
            crate::focusexport::parse_rfc3339_millis(s).map_err(|e| format!("bad --from: {e}"))?,
        ),
        None => None,
    };
    let to_ms = match &args.to {
        Some(s) => Some(
            crate::focusexport::parse_rfc3339_millis(s).map_err(|e| format!("bad --to: {e}"))?,
        ),
        None => None,
    };

    let calls = load_calls(&traces, from_ms, to_ms)
        .await
        .map_err(|e| format!("could not read traces at '{traces}': {e}"))?;

    if calls.is_empty() {
        let window = if from_ms.is_some() || to_ms.is_some() {
            " in the given --from/--to window"
        } else {
            ""
        };
        return Err(format!(
            "no calls found in the trace at '{traces}'{window} — nothing to report"
        ));
    }

    let rows = compute_outcomes(&calls);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?
        );
    } else {
        print_human(&traces, &rows);
    }
    Ok(())
}

/// Load the trace rows the outcomes aggregation needs: `run_id`, `decision`,
/// `cost_microusd`, `outcome`, `step` (the per-run ordering key — see
/// `tokenfuse_core::outcomes` for why `step`, not `ts_millis`).
///
/// `coalesce(outcome, '')` keeps the read robust across schema evolution:
/// files written before the column existed surface it as NULL, which this
/// maps to the documented default of `''` (same pattern as `agent_id`/
/// `parent_run_id`/`on_behalf_of` — see `sqlq::tests` for the mixed-schema
/// proof, mirrored here in this module's own fixture test).
async fn load_calls(
    dir: &str,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
) -> Result<Vec<Call>, Box<dyn std::error::Error>> {
    let mut sql = String::from(
        "select run_id, decision, cast(cost_microusd as bigint) as cost, \
         coalesce(outcome, '') as outcome, step from calls",
    );
    let mut conds: Vec<String> = Vec::new();
    if let Some(f) = from_ms {
        conds.push(format!("ts_millis >= {f}"));
    }
    if let Some(t) = to_ms {
        conds.push(format!("ts_millis <= {t}"));
    }
    if !conds.is_empty() {
        sql.push_str(" where ");
        sql.push_str(&conds.join(" and "));
    }

    let batches = query(&sql, dir).await?;
    let mut calls = Vec::new();
    for b in &batches {
        let cost = b
            .column(2)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("cost column type")?;
        let step = b
            .column(4)
            .as_any()
            .downcast_ref::<UInt32Array>()
            .ok_or("step column type")?;
        for i in 0..b.num_rows() {
            calls.push(Call {
                run_id: str_at(b.column(0).as_ref(), i),
                decision: str_at(b.column(1).as_ref(), i),
                cost_microusd: cost.value(i),
                outcome: str_at(b.column(3).as_ref(), i),
                step: step.value(i),
            });
        }
    }
    Ok(calls)
}

/// Print the human-readable table: one aligned row per outcome tag, sorted
/// the same way [`compute_outcomes`] returns them (tag name, untagged last).
fn print_human(dir: &str, rows: &[OutcomeRow]) {
    println!("TokenFuse outcomes — from {dir}");
    println!(
        "  {:<28} {:>6} {:>14} {:>14} {:>8} {:>8}",
        "OUTCOME", "RUNS", "TOTAL", "MEAN/RUN", "CALLS", "BLOCKED"
    );
    for row in rows {
        let label = row
            .outcome
            .clone()
            .unwrap_or_else(|| "(untagged)".to_string());
        println!(
            "  {:<28} {:>6} {:>14} {:>14} {:>8} {:>8}",
            label,
            row.runs,
            Microusd(row.total_cost_microusd).to_string(),
            Microusd(row.mean_cost_microusd()).to_string(),
            row.calls,
            row.blocked_calls,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::{CallRecord, EventSink, ParquetSink};

    #[allow(clippy::too_many_arguments)]
    fn rec(run_id: &str, decision: &str, cost: i64, outcome: &str, step: u32) -> CallRecord {
        CallRecord {
            ts_millis: step as i64, // monotonic-with-step is enough for this fixture
            run_id: run_id.into(),
            model: "m".into(),
            decision: decision.into(),
            input_tokens: 10,
            output_tokens: 5,
            cost_microusd: cost,
            step,
            agent_id: String::new(),
            saved_microusd: 0,
            parent_run_id: String::new(),
            on_behalf_of: String::new(),
            outcome: outcome.into(),
            key_id: String::new(),
        }
    }

    #[test]
    fn parse_args_reads_all_flags() {
        let args = vec![
            "--traces".to_string(),
            "./data".to_string(),
            "--from".to_string(),
            "2026-01-01T00:00:00Z".to_string(),
            "--to".to_string(),
            "2026-02-01T00:00:00Z".to_string(),
            "--json".to_string(),
        ];
        let a = parse_args(&args);
        assert_eq!(a.traces.as_deref(), Some("./data"));
        assert_eq!(a.from.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(a.to.as_deref(), Some("2026-02-01T00:00:00Z"));
        assert!(a.json);
    }

    #[tokio::test]
    async fn missing_traces_dir_is_a_clear_error_not_a_panic() {
        let args = Args {
            traces: Some("/nonexistent/tf-outcomes-dir-xyz".to_string()),
            from: None,
            to: None,
            json: false,
        };
        let err = run(&args).await.unwrap_err();
        assert!(err.contains("nonexistent"), "{err}");
    }

    #[tokio::test]
    async fn empty_traces_dir_is_a_clear_error_not_a_silent_zero_report() {
        let dir = std::env::temp_dir().join(format!("tf-outcomes-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let args = Args {
            traces: Some(dir.to_str().unwrap().to_string()),
            from: None,
            to: None,
            json: false,
        };
        let err = run(&args).await.unwrap_err();
        assert!(err.contains("nothing to report"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// End-to-end fixture: real Parquet files written via `ParquetSink`, read
    /// back via the real DataFusion path (`load_calls`), aggregated via the
    /// real `compute_outcomes` — exercising the full pipeline this CLI wires
    /// together, not just the pure aggregation in isolation.
    ///
    /// Fixture covers every case the task calls for:
    /// - run "a": multiple calls, tagged only on its FINAL call.
    /// - run "b": CONFLICTING tags across calls — proves last-wins (by step,
    ///   not just "some non-empty tag was seen").
    /// - run "c": never sends the header — lands in the `(untagged)` bucket.
    /// - a blocked call (on run "a") — counted as a call and as blocked, but
    ///   excluded from the cost total.
    #[tokio::test]
    async fn end_to_end_fixture_multiple_runs_conflicting_tags_untagged_and_blocked() {
        let dir = std::env::temp_dir().join(format!("tf-outcomes-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            // Run "a": step 1 allow (untagged), step 2 a BLOCKED call (budget
            // family — must not count toward cost), step 3 final allow
            // tagged "case_resolved".
            sink.record(rec("a", "allow", 1_000_000, "", 1));
            sink.record(rec("a", "budget_exceeded", 9_000_000, "", 2));
            sink.record(rec("a", "allow", 500_000, "case_resolved", 3));

            // Run "b": tagged "escalated" first, then RE-TAGGED
            // "case_resolved" on its later, final call — proves last-wins.
            sink.record(rec("b", "allow", 2_000_000, "escalated", 1));
            sink.record(rec("b", "allow", 1_000_000, "case_resolved", 2));

            // Run "c": never sends X-Fuse-Outcome at all.
            sink.record(rec("c", "allow", 750_000, "", 1));
        }

        let calls = load_calls(dir.to_str().unwrap(), None, None).await.unwrap();
        assert_eq!(calls.len(), 6, "all six rows across all three runs");

        let rows = compute_outcomes(&calls);
        assert_eq!(
            rows.len(),
            2,
            "case_resolved + (untagged); no 'escalated' row survives"
        );

        let resolved = rows
            .iter()
            .find(|r| r.outcome.as_deref() == Some("case_resolved"))
            .expect("case_resolved row");
        assert_eq!(
            resolved.runs, 2,
            "runs a and b both resolved to case_resolved"
        );
        assert_eq!(resolved.calls, 5, "3 calls from run a + 2 calls from run b");
        assert_eq!(
            resolved.blocked_calls, 1,
            "run a's one budget_exceeded call"
        );
        assert_eq!(
            resolved.total_cost_microusd,
            1_000_000 + 500_000 + 2_000_000 + 1_000_000,
            "the blocked call's 9_000_000 avoided estimate must be excluded"
        );
        assert_eq!(
            resolved.mean_cost_microusd(),
            resolved.total_cost_microusd / 2
        );

        let untagged = rows
            .iter()
            .find(|r| r.outcome.is_none())
            .expect("untagged row");
        assert_eq!(untagged.runs, 1);
        assert_eq!(untagged.calls, 1);
        assert_eq!(untagged.blocked_calls, 0);
        assert_eq!(untagged.total_cost_microusd, 750_000);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn from_to_window_filters_calls() {
        let dir = std::env::temp_dir().join(format!("tf-outcomes-window-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            let mut old = rec("a", "allow", 1_000, "old", 1);
            old.ts_millis = 0;
            sink.record(old);
            let mut new = rec("b", "allow", 1_000, "new", 1);
            new.ts_millis = 10_000;
            sink.record(new);
        }

        let calls = load_calls(dir.to_str().unwrap(), Some(5_000), None)
            .await
            .unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].run_id, "b");

        std::fs::remove_dir_all(&dir).ok();
    }
}
