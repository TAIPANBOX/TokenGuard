//! `tokenfuse compliance` — project the honest control catalog
//! ([`tokenfuse_core::compliance::CATALOG`]) against the recorded Parquet trace
//! (and, optionally, an `mcp-scan` report) into an auditor-ready evidence pack.
//!
//! This is the read side of P3: it loads the same `calls` rows as
//! [`crate::savingscli`] (reusing [`tokenfuse_core::savings::Call`] verbatim),
//! optionally attaches finding evidence from a [`ScanReport`] JSON produced by
//! `tokenfuse mcp-scan --json-out`, and aggregates via
//! [`tokenfuse_core::compliance::compute_compliance`]. Nothing here is a
//! certification — see the disclaimer emitted with every report.

use datafusion::arrow::array::{Array, Int64Array, StringArray, StringViewArray};
use tokenfuse_core::compliance::{compute_compliance, ComplianceReport, ControlEvidence};
use tokenfuse_core::mcpreport::{Finding, ScanReport};
use tokenfuse_core::savings::Call;
use tokenfuse_core::{Enforcement, CATALOG};

use crate::sqlq::query;

/// Parsed `tokenfuse compliance` flags.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Only count trace rows with `ts_millis >= since` (epoch millis).
    pub since: Option<i64>,
    /// Only count trace rows with `ts_millis <= until` (epoch millis).
    pub until: Option<i64>,
    /// Emit the [`ComplianceReport`] as pretty JSON.
    pub json: bool,
    /// Emit an auditor-ready Markdown table.
    pub markdown: bool,
    /// Path to a `ScanReport` JSON (from `mcp-scan --json-out`) whose findings
    /// are attached as finding evidence. Absent → no finding evidence.
    pub scan_report: Option<String>,
}

/// Parse `--since <ms>`, `--until <ms>`, `--json`, `--markdown`,
/// `--scan-report <file>`.
pub fn parse_args(args: &[String]) -> Args {
    let mut out = Args::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--since" => out.since = it.next().and_then(|x| x.parse().ok()),
            "--until" => out.until = it.next().and_then(|x| x.parse().ok()),
            "--json" => out.json = true,
            "--markdown" => out.markdown = true,
            "--scan-report" => out.scan_report = it.next().cloned(),
            _ => {}
        }
    }
    out
}

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

/// Load the trace, attach any scan-report findings, and emit the report.
///
/// A missing/empty trace is not an error: unlike a savings figure, a compliance
/// report is still meaningful with zero traffic (preventive Enforced guards are
/// covered by being active, and any `--scan-report` findings still attach), so
/// we always produce the report and, in human mode, note the empty trace rather
/// than bailing.
pub async fn run(dir: &str, args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let findings = match &args.scan_report {
        Some(path) => load_findings(path)?,
        None => Vec::new(),
    };

    // A missing dir (nothing recorded yet) makes DataFusion error on register;
    // treat that the same as an empty trace.
    let calls = load_calls(dir, args.since, args.until)
        .await
        .unwrap_or_default();

    let report = compute_compliance(CATALOG, &calls, &findings);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if args.markdown {
        print_markdown(&report);
    } else {
        if calls.is_empty() && findings.is_empty() {
            println!("TokenFuse compliance — no trace yet at {dir}");
            println!(
                "  showing the controls TokenFuse enforces; run some traffic (and optionally pass"
            );
            println!(
                "  --scan-report <mcp-scan.json>) to attach runtime evidence, then try again."
            );
            println!();
        }
        print_human(dir, &report);
    }
    Ok(())
}

/// Load the findings from a `ScanReport` JSON (as written by
/// `mcp-scan --json-out`).
fn load_findings(path: &str) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let report: ScanReport =
        serde_json::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))?;
    Ok(report.findings)
}

/// Load `run_id`, `decision`, `cost_microusd`, `saved_microusd` from the trace,
/// optionally filtered to a `[since, until]` `ts_millis` window. Mirrors
/// [`crate::savingscli`]'s loader (same `Call` rows) plus the time filter.
async fn load_calls(
    dir: &str,
    since: Option<i64>,
    until: Option<i64>,
) -> Result<Vec<Call>, Box<dyn std::error::Error>> {
    // `coalesce(saved_microusd, 0)` keeps the read robust across schema
    // evolution (pre-P2 files lack the column). `since`/`until` are parsed i64
    // literals, so inlining them into the WHERE clause is injection-safe.
    let mut sql = String::from(
        "select run_id, decision, cast(cost_microusd as bigint) as cost, \
         cast(coalesce(saved_microusd, 0) as bigint) as saved from calls",
    );
    let mut conds: Vec<String> = Vec::new();
    if let Some(s) = since {
        conds.push(format!("ts_millis >= {s}"));
    }
    if let Some(u) = until {
        conds.push(format!("ts_millis <= {u}"));
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
        let saved = b
            .column(3)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("saved column type")?;
        for i in 0..b.num_rows() {
            calls.push(Call {
                run_id: str_at(b.column(0).as_ref(), i),
                decision: str_at(b.column(1).as_ref(), i),
                cost_microusd: cost.value(i),
                saved_microusd: saved.value(i),
            });
        }
    }
    Ok(calls)
}

/// The enforcement label used in both human and Markdown output.
fn enf_label(enf: Enforcement) -> &'static str {
    match enf {
        Enforcement::Enforced => "enforced",
        Enforcement::Partial => "partial",
        Enforcement::Documented => "documented",
    }
}

/// A compact `key=count, key=count` evidence string for one control (watched
/// keys are always shown, even at 0, so the report documents what is watched).
fn evidence_summary(c: &ControlEvidence) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (k, v) in &c.decision_counts {
        parts.push(format!("{k}={v}"));
    }
    for (k, v) in &c.finding_counts {
        parts.push(format!("{k}={v}"));
    }
    if c.incident_count > 0 {
        parts.push(format!("incidents={}", c.incident_count));
    }
    if parts.is_empty() {
        "—".to_string()
    } else {
        parts.join(", ")
    }
}

/// Distinct framework ids a control maps to, joined for display. Looked up from
/// [`CATALOG`] by id (the report keeps the projection lean).
fn frameworks_for(control_id: &str) -> String {
    CATALOG
        .iter()
        .find(|c| c.control_id == control_id)
        .map(|c| {
            let mut ids: Vec<&str> = Vec::new();
            for (id, _) in c.frameworks {
                if !ids.contains(id) {
                    ids.push(id);
                }
            }
            ids.join(", ")
        })
        .unwrap_or_default()
}

/// Default human print: per-control coverage grouped by enforcement, then the
/// disclaimer line and the framework-versions footer.
fn print_human(dir: &str, report: &ComplianceReport) {
    println!("TokenFuse compliance — from {dir}");
    println!(
        "  {} decision(s) and {} finding(s) in scope",
        report.decisions_total, report.findings_total
    );
    println!();

    for enf in [
        Enforcement::Enforced,
        Enforcement::Partial,
        Enforcement::Documented,
    ] {
        let group: Vec<&ControlEvidence> = report
            .controls
            .iter()
            .filter(|c| c.enforcement == enf)
            .collect();
        if group.is_empty() {
            continue;
        }
        println!("{}:", enf_label(enf).to_uppercase());
        for c in group {
            // covered+events, covered+quiet, or not covered.
            let mark = match (c.covered, c.evidence_seen) {
                (true, true) => "[x]",
                (true, false) => "[~]",
                (false, _) => "[ ]",
            };
            println!("  {mark} {:<16} {}", c.control_id, c.title);
            println!("        evidence: {}", evidence_summary(c));
        }
        println!();
    }

    println!(
        "Legend: [x] covered, evidence seen  ·  [~] active guard, no events  ·  [ ] not covered"
    );
    println!();
    println!("{}", report.generated_note);
    println!();
    println!("Frameworks (versions pinned at mapping time):");
    for (id, name, ver) in report.framework_versions {
        println!("  {id:<14} {name} — {ver}");
    }
}

/// Auditor-ready Markdown table: control | enforcement | frameworks | evidence
/// | covered, followed by the disclaimer.
fn print_markdown(report: &ComplianceReport) {
    println!("| Control | Enforcement | Frameworks | Evidence | Covered |");
    println!("| --- | --- | --- | --- | --- |");
    for c in &report.controls {
        let covered = match (c.covered, c.evidence_seen) {
            (true, true) => "yes",
            (true, false) => "yes (no events)",
            (false, _) => "no",
        };
        println!(
            "| `{}` {} | {} | {} | {} | {} |",
            c.control_id,
            c.title,
            enf_label(c.enforcement),
            frameworks_for(c.control_id),
            evidence_summary(c),
            covered,
        );
    }
    println!();
    println!("_{}_", report.generated_note);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenfuse_core::mcpreport::{Finding, Severity};
    use tokenfuse_core::savings::Call;

    fn call(run: &str, decision: &str) -> Call {
        Call {
            run_id: run.into(),
            decision: decision.into(),
            cost_microusd: 0,
            saved_microusd: 0,
        }
    }

    #[test]
    fn parses_flags() {
        let args = vec![
            "--since".to_string(),
            "1000".to_string(),
            "--until".to_string(),
            "2000".to_string(),
            "--markdown".to_string(),
            "--scan-report".to_string(),
            "scan.json".to_string(),
        ];
        let a = parse_args(&args);
        assert_eq!(a.since, Some(1000));
        assert_eq!(a.until, Some(2000));
        assert!(a.markdown);
        assert!(!a.json);
        assert_eq!(a.scan_report.as_deref(), Some("scan.json"));
    }

    #[test]
    fn computes_compliance_over_a_mixed_trace() {
        // The pure path the CLI runs after loading: budget/loop decisions land on
        // their controls; the poisoning finding lands on the scanner control.
        let calls = vec![
            call("a", "allow"),
            call("a", "budget_exceeded"),
            call("b", "loop_detected"),
        ];
        let findings = vec![Finding {
            kind: "poisoning".into(),
            severity: Severity::High,
            tool: Some("evil".into()),
            message: "x".into(),
        }];
        let report = compute_compliance(CATALOG, &calls, &findings);
        assert_eq!(report.decisions_total, 3);
        assert_eq!(report.findings_total, 1);

        let budget = report
            .controls
            .iter()
            .find(|c| c.control_id == "TF.BUDGET")
            .unwrap();
        assert_eq!(
            budget.decision_counts.get("budget_exceeded").copied(),
            Some(1)
        );
        assert!(budget.covered);

        let poison = report
            .controls
            .iter()
            .find(|c| c.control_id == "TF.MCP.POISON")
            .unwrap();
        assert_eq!(poison.finding_counts.get("poisoning").copied(), Some(1));
        assert!(poison.covered);
    }

    #[test]
    fn frameworks_for_dedups_and_finds() {
        // TF.LOOP maps NIST twice (SC-6 and SI-4); the display list dedups ids.
        let fw = frameworks_for("TF.LOOP");
        assert!(fw.contains("NIST-800-53r5"));
        assert_eq!(fw.matches("NIST-800-53r5").count(), 1);
        assert_eq!(frameworks_for("does.not.exist"), "");
    }

    #[test]
    fn markdown_and_evidence_summary_render() {
        let report = compute_compliance(CATALOG, &[call("a", "killed")], &[]);
        let kill = report
            .controls
            .iter()
            .find(|c| c.control_id == "TF.KILL")
            .unwrap();
        assert_eq!(evidence_summary(kill), "killed=1");
    }
}
