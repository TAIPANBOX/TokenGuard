//! `tokenfuse mcp-scan` — scan an MCP server's `tools/list` for poisoning and
//! for drift against a pinned lockfile (rug-pull detection).
//!
//! Two ways to get the `tools/list` payload: a saved JSON file ([`run`]) or a
//! live Streamable HTTP fetch against a running MCP server ([`run_live`]).
//! Both share the same scan/diff/print/report logic once the JSON value is
//! in hand, and both return a [`ScanReport`] so the caller (`main.rs`) can
//! decide the process exit code from `--fail-on`.

use std::fs;
use tokenfuse_core::mcp::{diff, parse_tools, scan_injection, Drift, Lock, McpTool};
use tokenfuse_core::mcpexposure::{exposure_findings, ssrf_capable_findings};
use tokenfuse_core::mcpreport::ScanReport;

use crate::mcpclient::{fetch_tools_list, McpClientConfig};
use crate::mcpexposure_probe::run_exposure_probe;

/// How to render the scan results. `Human` preserves the existing tree
/// output exactly (default, behavior-preserving); `Json` prints the
/// [`ScanReport`] as pretty JSON instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputMode {
    #[default]
    Human,
    Json,
}

/// Scan `tools_path` (a saved `tools/list` JSON). Optionally diff against
/// `lock_path`, and optionally (over)write the lock. Prints per `mode` and
/// optionally also writes the JSON report to `json_out`. Returns the
/// [`ScanReport`] so the caller can decide the exit code.
pub fn run(
    tools_path: &str,
    lock_path: Option<&str>,
    write_lock: bool,
    mode: OutputMode,
    json_out: Option<&str>,
) -> Result<ScanReport, String> {
    let raw = fs::read_to_string(tools_path).map_err(|e| format!("read {tools_path}: {e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {tools_path}: {e}"))?;
    let tools = parse_tools(&value);
    if mode == OutputMode::Human {
        println!("MCP scan — {} tool(s) in {tools_path}", tools.len());
    }
    let report = build_scan_report(&tools, lock_path, write_lock, mode)?;
    emit_report(&report, mode, json_out)?;
    Ok(report)
}

/// Scan a live MCP server at `url` over Streamable HTTP. Twin of [`run`]: same
/// injection scan / lock-diff / print / report logic, fed by a live
/// `tools/list` fetch instead of a file on disk. Additionally, unless
/// `skip_exposure` is set, runs the server-exposure checks (unauthenticated
/// `tools/list`, plaintext transport, wildcard CORS, SSRF-capable tools, and
/// — opt-in via `attempt_call` — an unauthenticated `tools/call`) and merges
/// their findings into the same report. File-mode scans ([`run`]) have no
/// live server to probe, so exposure checks only run here.
pub async fn run_live(
    url: &str,
    lock_path: Option<&str>,
    write_lock: bool,
    mode: OutputMode,
    json_out: Option<&str>,
    skip_exposure: bool,
    attempt_call: bool,
) -> Result<ScanReport, String> {
    let cfg = McpClientConfig::new(url);
    let value = fetch_tools_list(&cfg).await.map_err(|e| e.to_string())?;
    let tools = parse_tools(&value);
    if mode == OutputMode::Human {
        println!("MCP scan — {} tool(s) live from {url}", tools.len());
    }
    let mut report = build_scan_report(&tools, lock_path, write_lock, mode)?;

    if !skip_exposure {
        let outcome = run_exposure_probe(url, &tools, attempt_call).await;
        let mut extra = exposure_findings(&outcome);
        extra.extend(ssrf_capable_findings(&tools));
        if mode == OutputMode::Human {
            if extra.is_empty() {
                println!("  exposure scan: clean");
            } else {
                println!("  exposure scan: {} issue(s)", extra.len());
                for f in &extra {
                    match &f.tool {
                        Some(tool) => println!("    ⚠ [{}] {}: {}", f.kind, tool, f.message),
                        None => println!("    ⚠ [{}] {}", f.kind, f.message),
                    }
                }
            }
        }
        report.push_findings(extra);
    } else if mode == OutputMode::Human {
        println!("  exposure scan: skipped (--skip-exposure)");
    }

    emit_report(&report, mode, json_out)?;
    Ok(report)
}

/// Shared post-parse logic for [`run`] and [`run_live`]: injection scan, plus
/// optional lock write/diff, then build (but don't yet emit) the report —
/// [`run_live`] needs to merge exposure findings in before printing/writing
/// JSON, so emission is split out into [`emit_report`].
fn build_scan_report(
    tools: &[McpTool],
    lock_path: Option<&str>,
    write_lock: bool,
    mode: OutputMode,
) -> Result<ScanReport, String> {
    let findings = scan_injection(tools);
    if mode == OutputMode::Human {
        if findings.is_empty() {
            println!("  injection scan: clean");
        } else {
            println!("  injection scan: {} issue(s)", findings.len());
            for f in &findings {
                println!("    ⚠ {}: {}", f.tool, f.issue);
            }
        }
    }

    let mut drifts: Vec<Drift> = Vec::new();

    if let Some(lock_path) = lock_path {
        if write_lock {
            let lock = Lock::from_tools(tools);
            let json = serde_json::to_string_pretty(&lock).map_err(|e| e.to_string())?;
            fs::write(lock_path, json).map_err(|e| format!("write {lock_path}: {e}"))?;
            if mode == OutputMode::Human {
                println!(
                    "  lock: wrote {} tool fingerprints to {lock_path}",
                    tools.len()
                );
            }
        } else {
            let lock_raw =
                fs::read_to_string(lock_path).map_err(|e| format!("read {lock_path}: {e}"))?;
            let lock: Lock =
                serde_json::from_str(&lock_raw).map_err(|e| format!("parse {lock_path}: {e}"))?;
            drifts = diff(tools, &lock);
            if mode == OutputMode::Human {
                if drifts.is_empty() {
                    println!("  lock: no drift — matches {lock_path}");
                } else {
                    println!("  lock: {} change(s) vs {lock_path}", drifts.len());
                    for d in &drifts {
                        match d {
                            Drift::Changed(n) => {
                                println!("    ⛔ RUG PULL: tool '{n}' description/schema changed")
                            }
                            Drift::Added(n) => println!("    + new tool '{n}' (not in lock)"),
                            Drift::Removed(n) => println!("    - tool '{n}' removed"),
                        }
                    }
                }
            }
        }
    }

    Ok(ScanReport::from_scan(tools, &findings, &drifts))
}

/// Print `report` as JSON (if `mode` is [`OutputMode::Json`]) and/or write it
/// to `json_out`, if given. Split out of [`build_scan_report`] so
/// [`run_live`] can merge exposure findings into the report before either
/// happens.
fn emit_report(report: &ScanReport, mode: OutputMode, json_out: Option<&str>) -> Result<(), String> {
    if mode == OutputMode::Json {
        let json = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
        println!("{json}");
    }

    if let Some(path) = json_out {
        let json = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
        fs::write(path, json).map_err(|e| format!("write {path}: {e}"))?;
    }

    Ok(())
}
