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
use tokenfuse_core::mcpreport::ScanReport;

use crate::mcpclient::{fetch_tools_list, McpClientConfig};

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
    scan_and_report(&tools, lock_path, write_lock, mode, json_out)
}

/// Scan a live MCP server at `url` over Streamable HTTP. Twin of [`run`]: same
/// injection scan / lock-diff / print / report logic, fed by a live
/// `tools/list` fetch instead of a file on disk.
pub async fn run_live(
    url: &str,
    lock_path: Option<&str>,
    write_lock: bool,
    mode: OutputMode,
    json_out: Option<&str>,
) -> Result<ScanReport, String> {
    let cfg = McpClientConfig::new(url);
    let value = fetch_tools_list(&cfg).await.map_err(|e| e.to_string())?;
    let tools = parse_tools(&value);
    if mode == OutputMode::Human {
        println!("MCP scan — {} tool(s) live from {url}", tools.len());
    }
    scan_and_report(&tools, lock_path, write_lock, mode, json_out)
}

/// Shared post-parse logic for [`run`] and [`run_live`]: injection scan, plus
/// optional lock write/diff, then build and emit the report.
fn scan_and_report(
    tools: &[McpTool],
    lock_path: Option<&str>,
    write_lock: bool,
    mode: OutputMode,
    json_out: Option<&str>,
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

    let report = ScanReport::from_scan(tools, &findings, &drifts);

    if mode == OutputMode::Json {
        let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
        println!("{json}");
    }

    if let Some(path) = json_out {
        let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
        fs::write(path, json).map_err(|e| format!("write {path}: {e}"))?;
    }

    Ok(report)
}
