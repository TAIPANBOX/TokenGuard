//! `tokenfuse focus-export --traces <dir-or-glob> --out <file.csv> [--from RFC3339] [--to RFC3339]`
//!
//! Exports the Parquet call trace as a FOCUS 1.2-style CSV (FinOps Open Cost &
//! Usage Specification) — one row per LLM call — so a bank/FinOps team can load
//! LLM agent spend into the same tooling they already use for cloud spend.
//!
//! Read-only: this reads the already-written trace via the same DataFusion path
//! as `tokenfuse sql` ([`crate::sqlq`]). It never touches the enforcement hot
//! path (`proxy.rs` / `tokenfuse_core::breaker`).
//!
//! ## Column sourcing
//!
//! Every column is derived from the ACTUAL `calls` Parquet schema
//! ([`crate::sink::ParquetSink`]) — nothing is invented. A few FOCUS-shaped
//! columns have no matching source field today and are always emitted empty,
//! rather than synthesized:
//!   - `x_parent_run_id`: sourced from `CallRecord.parent_run_id` (P3,
//!     agent-passport SPEC.md §3.2) — the run's `X-Fuse-Parent-Run-Id`
//!     header, now written to the trace (see `crate::sink::CallRecord`).
//!     `COALESCE(parent_run_id, '')` in [`load_records`] keeps this `""` for
//!     rows from a pre-P3 trace file that lacks the column (schema
//!     evolution, same pattern as `agent_id` below) as well as for rows that
//!     genuinely had no parent.
//!   - `x_outcome`: sourced from `CallRecord.outcome` (P4, unit economics) —
//!     the raw, per-call `X-Fuse-Outcome` value. `""` for rows from a pre-P4
//!     trace file (schema evolution, same `COALESCE` pattern) as well as for
//!     calls that never set the header. This is the raw per-call capture, not
//!     the "last non-empty per run" aggregation `tokenfuse outcomes` computes
//!     — see `tokenfuse_core::outcomes`.
//!   - `x_unit`: sourced from `CallRecord.unit` (docs/20-identity-map.md
//!     section 4) - the business unit resolved server-side from the identity
//!     map. `""` for rows from a pre-unit trace file (schema evolution, same
//!     `COALESCE` pattern) as well as for calls the map did not match.
//!   - `ChargePeriodStart` / `ChargePeriodEnd`: the trace records exactly one
//!     timestamp per call (`ts_millis`, the settle time) — there is no
//!     separate call-start timestamp — so both columns get the SAME instant.
//!
//! `ProviderName` / `PublisherName` / `InvoiceIssuerName` also have no direct
//! source: the trace has no per-call upstream/provider field
//! (`TOKENFUSE_UPSTREAM` is a gateway-wide setting, not recorded per row), so
//! the provider is inferred from the `model` string via
//! [`provider_from_model`]. This is a derivation from real data, not an
//! invention, but it is a heuristic — an unrecognized model name falls back to
//! `"Unknown"`.
//!
//! ## Cost basis and `x_blocked`
//!
//! A call's `decision` column already tells us whether the Breaker tripped
//! (the seven reasons in [`tokenfuse_core::BreakerReason`]) — see
//! [`is_blocked_decision`]. For a blocked row `cost_microusd` holds the
//! *reserved estimate* that was never actually charged (see `proxy.rs`), so
//! `BilledCost`/`EffectiveCost` are forced to `0` and `x_cost_basis` is
//! `"blocked"` — that zero-cost row, kept rather than dropped, IS the savings
//! story a bank's FinOps team wants to see.
//!
//! For an allowed call, `cost_microusd` is normally the real settled cost
//! (parsed usage × price). One edge case: `SettleGuard`'s `Drop` path (client
//! cancel / upstream error mid-stream, see `settle.rs`) settles with the
//! *reserved fallback* when no usage was parsed — recorded with `decision =
//! "allow"` but `input_tokens = output_tokens = 0`. We detect that shape
//! (zero tokens, non-zero cost) and mark it `x_cost_basis = "estimated"`;
//! everything else lands on `"settled"`.

use crate::sqlq::{query, str_at};
use datafusion::arrow::array::Int64Array;
use tokenfuse_core::timefmt::{days_from_civil, ts_millis_to_rfc3339};
use tokenfuse_core::{BreakerReason, Microusd};

/// Parsed `tokenfuse focus-export` flags.
#[derive(Debug, Clone, Default)]
pub struct Args {
    pub traces: Option<String>,
    pub out: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// Parse `--traces <dir-or-glob>`, `--out <file.csv>`, `--from <rfc3339>`,
/// `--to <rfc3339>`.
pub fn parse_args(args: &[String]) -> Args {
    let mut out = Args::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--traces" => out.traces = it.next().cloned(),
            "--out" => out.out = it.next().cloned(),
            "--from" => out.from = it.next().cloned(),
            "--to" => out.to = it.next().cloned(),
            _ => {}
        }
    }
    out
}

/// One `calls` row as loaded from the trace, before FOCUS projection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FocusRecord {
    ts_millis: i64,
    run_id: String,
    model: String,
    decision: String,
    input_tokens: u64,
    output_tokens: u64,
    cost_microusd: i64,
    agent_id: String,
    parent_run_id: String,
    outcome: String,
    unit: String,
}

/// The FOCUS 1.2-style column header, in the order the architect specified.
const HEADER: [&str; 25] = [
    "BilledCost",
    "EffectiveCost",
    "BillingCurrency",
    "ChargePeriodStart",
    "ChargePeriodEnd",
    "ChargeDescription",
    "ProviderName",
    "PublisherName",
    "InvoiceIssuerName",
    "ServiceName",
    "ServiceCategory",
    "ResourceId",
    "ResourceName",
    "SubAccountId",
    "SubAccountName",
    "x_run_id",
    "x_parent_run_id",
    "x_agent_id",
    "x_model",
    "x_tokens_in",
    "x_tokens_out",
    "x_blocked",
    "x_cost_basis",
    "x_outcome",
    "x_unit",
];

/// Load, project, and write the FOCUS CSV. Returns `Err` with a clear message
/// on bad flags, a missing/unreadable trace, or an empty result set — the
/// caller (`main.rs`) turns that into a non-zero exit.
pub async fn run(args: &Args) -> Result<(), String> {
    let traces = args
        .traces
        .clone()
        .ok_or_else(|| "missing --traces <dir-or-glob>".to_string())?;
    let out_path = args
        .out
        .clone()
        .ok_or_else(|| "missing --out <file.csv>".to_string())?;

    let from_ms = match &args.from {
        Some(s) => Some(parse_rfc3339_millis(s).map_err(|e| format!("bad --from: {e}"))?),
        None => None,
    };
    let to_ms = match &args.to {
        Some(s) => Some(parse_rfc3339_millis(s).map_err(|e| format!("bad --to: {e}"))?),
        None => None,
    };

    let records = load_records(&traces, from_ms, to_ms)
        .await
        .map_err(|e| format!("could not read traces at '{traces}': {e}"))?;

    if records.is_empty() {
        let window = if from_ms.is_some() || to_ms.is_some() {
            " in the given --from/--to window"
        } else {
            ""
        };
        return Err(format!(
            "no calls found in the trace at '{traces}'{window} — nothing to export"
        ));
    }

    let csv = render_csv(&records);
    std::fs::write(&out_path, &csv).map_err(|e| format!("could not write '{out_path}': {e}"))?;

    println!(
        "tokenfuse focus-export: wrote {} row(s) to {out_path}",
        records.len()
    );
    Ok(())
}

/// Load the trace rows FOCUS needs, oldest first (ties broken by `run_id` —
/// the trace has no per-row sequence number to break ties further).
async fn load_records(
    dir: &str,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
) -> Result<Vec<FocusRecord>, Box<dyn std::error::Error>> {
    let mut sql = String::from(
        "select ts_millis, run_id, model, decision, \
         cast(input_tokens as bigint) as input_tokens, \
         cast(output_tokens as bigint) as output_tokens, \
         cast(cost_microusd as bigint) as cost_microusd, \
         coalesce(agent_id, '') as agent_id, \
         coalesce(parent_run_id, '') as parent_run_id, \
         coalesce(outcome, '') as outcome, \
         coalesce(unit, '') as unit \
         from calls",
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
    sql.push_str(" order by ts_millis, run_id");

    let batches = query(&sql, dir).await?;
    let mut out = Vec::new();
    for b in &batches {
        let ts = b
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("ts_millis column type")?;
        let input_tokens = b
            .column(4)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("input_tokens column type")?;
        let output_tokens = b
            .column(5)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("output_tokens column type")?;
        let cost = b
            .column(6)
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("cost_microusd column type")?;
        for i in 0..b.num_rows() {
            out.push(FocusRecord {
                ts_millis: ts.value(i),
                run_id: str_at(b.column(1).as_ref(), i),
                model: str_at(b.column(2).as_ref(), i),
                decision: str_at(b.column(3).as_ref(), i),
                input_tokens: input_tokens.value(i).max(0) as u64,
                output_tokens: output_tokens.value(i).max(0) as u64,
                cost_microusd: cost.value(i),
                agent_id: str_at(b.column(7).as_ref(), i),
                parent_run_id: str_at(b.column(8).as_ref(), i),
                outcome: str_at(b.column(9).as_ref(), i),
                unit: str_at(b.column(10).as_ref(), i),
            });
        }
    }
    Ok(out)
}

/// The Breaker block reasons, read off [`tokenfuse_core::BreakerReason`]
/// so this stays in sync with core's canonical list rather than duplicating
/// the wire strings by hand. Includes the identity-map pair (docs/20):
/// `unit_budget_exceeded` rows carry the avoided estimate and
/// `identity_mismatch` rows carry zero cost; both stay $0 `x_blocked` rows.
fn is_blocked_decision(decision: &str) -> bool {
    [
        BreakerReason::BudgetExceeded,
        BreakerReason::PolicyViolation,
        BreakerReason::LoopDetected,
        BreakerReason::Killed,
        BreakerReason::WasmPolicy,
        BreakerReason::TaintBlocked,
        BreakerReason::DlpBlocked,
        BreakerReason::UnitBudgetExceeded,
        BreakerReason::IdentityMismatch,
    ]
    .iter()
    .any(|r| r.as_wire_str() == decision)
}

/// Infer a provider display name from the model string. The trace has no
/// per-call upstream field, so this is the best real-data-driven signal
/// available; unrecognized names fall back to `"Unknown"` rather than
/// guessing further.
fn provider_from_model(model: &str) -> &'static str {
    let m = model.to_ascii_lowercase();
    if m.contains("claude") {
        "Anthropic"
    } else if m.contains("gpt")
        || m.contains("chatgpt")
        || m.starts_with("o1")
        || m.starts_with("o3")
        || m.starts_with("o4")
    {
        "OpenAI"
    } else if m.contains("gemini") {
        "Google"
    } else if m.contains("llama") {
        "Meta"
    } else if m.contains("mistral") {
        "Mistral AI"
    } else {
        "Unknown"
    }
}

/// Render `microusd` as a plain (no `$`) fixed-point USD string, matching the
/// microdollar precision the ledger stores.
fn usd_string(microusd: i64) -> String {
    format!("{:.6}", Microusd(microusd).as_usd())
}

/// Project one trace row into the 25 FOCUS column values, in [`HEADER`] order.
fn to_row(rec: &FocusRecord) -> [String; 25] {
    let blocked = is_blocked_decision(&rec.decision);
    let (cost_microusd, cost_basis) = if blocked {
        (0i64, "blocked")
    } else if rec.input_tokens == 0 && rec.output_tokens == 0 && rec.cost_microusd != 0 {
        (rec.cost_microusd, "estimated")
    } else {
        (rec.cost_microusd, "settled")
    };
    let billed = usd_string(cost_microusd);
    let ts = ts_millis_to_rfc3339(rec.ts_millis);
    let provider = provider_from_model(&rec.model).to_string();

    [
        billed.clone(),                          // BilledCost
        billed,                                  // EffectiveCost
        "USD".to_string(),                       // BillingCurrency
        ts.clone(),                              // ChargePeriodStart
        ts,                                      // ChargePeriodEnd
        format!("LLM call model={}", rec.model), // ChargeDescription
        provider.clone(),                        // ProviderName
        provider.clone(),                        // PublisherName
        provider,                                // InvoiceIssuerName
        "LLM inference".to_string(),             // ServiceName
        "AI and Machine Learning".to_string(),   // ServiceCategory
        rec.agent_id.clone(),                    // ResourceId
        rec.agent_id.clone(),                    // ResourceName
        rec.run_id.clone(),                      // SubAccountId
        rec.run_id.clone(),                      // SubAccountName
        rec.run_id.clone(),                      // x_run_id
        rec.parent_run_id.clone(),               // x_parent_run_id
        rec.agent_id.clone(),                    // x_agent_id
        rec.model.clone(),                       // x_model
        rec.input_tokens.to_string(),            // x_tokens_in
        rec.output_tokens.to_string(),           // x_tokens_out
        blocked.to_string(),                     // x_blocked
        cost_basis.to_string(),                  // x_cost_basis
        rec.outcome.clone(),                     // x_outcome
        rec.unit.clone(),                        // x_unit
    ]
}

/// RFC 4180 field quoting: quote (doubling embedded quotes) whenever the field
/// contains a comma, a double quote, or a line break; leave everything else
/// bare.
fn csv_quote(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn csv_row<S: AsRef<str>>(fields: &[S]) -> String {
    fields
        .iter()
        .map(|f| csv_quote(f.as_ref()))
        .collect::<Vec<_>>()
        .join(",")
}

fn render_csv(records: &[FocusRecord]) -> String {
    let mut out = String::new();
    out.push_str(&csv_row(&HEADER));
    out.push('\n');
    for rec in records {
        out.push_str(&csv_row(&to_row(rec)));
        out.push('\n');
    }
    out
}

/// Parse a minimal RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SS[.fff]Z`) into
/// epoch milliseconds, for `--from`/`--to`. Deliberately narrow — no
/// non-`Z` timezone offsets — good enough for CLI filter flags without a
/// date-parsing dependency.
///
/// `pub(crate)` so `tokenfuse outcomes` ([`crate::outcomescli`]) can reuse the
/// exact same `--from`/`--to` parsing instead of duplicating it.
pub(crate) fn parse_rfc3339_millis(s: &str) -> Result<i64, String> {
    let s = s.trim();
    let bad = || format!("expected RFC3339 like 2026-01-02T15:04:05Z, got '{s}'");
    let body = s.strip_suffix('Z').ok_or_else(bad)?;
    let (date, time) = body.split_once('T').ok_or_else(bad)?;

    let mut dp = date.split('-');
    let y: i64 = dp.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let m: u32 = dp.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let d: u32 = dp.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if dp.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(bad());
    }

    // Fractional seconds (if any) aren't needed at second precision.
    let time = time.split('.').next().unwrap_or(time);
    let mut tp = time.split(':');
    let hh: i64 = tp.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let mm: i64 = tp.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let ss: i64 = tp.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if tp.next().is_some()
        || !(0..24).contains(&hh)
        || !(0..60).contains(&mm)
        || !(0..60).contains(&ss)
    {
        return Err(bad());
    }

    let days = days_from_civil(y, m, d);
    Ok(days * 86_400_000 + hh * 3_600_000 + mm * 60_000 + ss * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::{CallRecord, EventSink, ParquetSink};

    // -- CSV quoting -----------------------------------------------------

    #[test]
    fn csv_quote_leaves_plain_fields_bare() {
        assert_eq!(csv_quote("claude-sonnet"), "claude-sonnet");
        assert_eq!(csv_quote(""), "");
    }

    #[test]
    fn csv_quote_wraps_and_escapes_commas_and_quotes() {
        assert_eq!(csv_quote("a,b"), "\"a,b\"");
        assert_eq!(csv_quote("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_quote("a, \"b\""), "\"a, \"\"b\"\"\"");
    }

    #[test]
    fn csv_quote_wraps_newlines() {
        assert_eq!(csv_quote("a\nb"), "\"a\nb\"");
        assert_eq!(csv_quote("a\rb"), "\"a\rb\"");
    }

    // -- provider inference ------------------------------------------------

    #[test]
    fn provider_from_model_recognizes_known_families() {
        assert_eq!(provider_from_model("claude-sonnet"), "Anthropic");
        assert_eq!(provider_from_model("claude-3-5-haiku"), "Anthropic");
        assert_eq!(provider_from_model("gpt-4o"), "OpenAI");
        assert_eq!(provider_from_model("o3-mini"), "OpenAI");
        assert_eq!(provider_from_model("gemini-1.5-pro"), "Google");
        assert_eq!(provider_from_model("llama-3-70b"), "Meta");
        assert_eq!(provider_from_model("mistral-large"), "Mistral AI");
        assert_eq!(provider_from_model("some-custom-model"), "Unknown");
    }

    // -- blocked-decision set ------------------------------------------------

    #[test]
    fn is_blocked_decision_matches_the_seven_breaker_reasons() {
        for d in [
            "budget_exceeded",
            "policy_violation",
            "loop_detected",
            "killed",
            "wasm_policy",
            "taint_blocked",
            "dlp_blocked",
        ] {
            assert!(is_blocked_decision(d), "{d} should be blocked");
        }
        assert!(!is_blocked_decision("allow"));
        assert!(!is_blocked_decision("cache_hit"));
    }

    // -- RFC 3339 timestamp round-trip ------------------------------------

    #[test]
    fn ts_millis_to_rfc3339_known_values() {
        assert_eq!(ts_millis_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(ts_millis_to_rfc3339(1_000), "1970-01-01T00:00:01Z");
        assert_eq!(ts_millis_to_rfc3339(86_400_000), "1970-01-02T00:00:00Z");
        assert_eq!(
            ts_millis_to_rfc3339(1_704_067_200_000),
            "2024-01-01T00:00:00Z"
        );
        // Leap day.
        assert_eq!(
            ts_millis_to_rfc3339(1_709_208_000_000),
            "2024-02-29T12:00:00Z"
        );
    }

    #[test]
    fn parse_rfc3339_millis_known_values() {
        assert_eq!(parse_rfc3339_millis("1970-01-01T00:00:00Z"), Ok(0));
        assert_eq!(
            parse_rfc3339_millis("2024-01-01T00:00:00Z"),
            Ok(1_704_067_200_000)
        );
        assert_eq!(
            parse_rfc3339_millis("2024-02-29T12:00:00Z"),
            Ok(1_709_208_000_000)
        );
        // Fractional seconds are accepted and truncated.
        assert_eq!(
            parse_rfc3339_millis("2024-01-01T00:00:00.999Z"),
            Ok(1_704_067_200_000)
        );
    }

    #[test]
    fn parse_rfc3339_millis_rejects_malformed_input() {
        assert!(parse_rfc3339_millis("not-a-date").is_err());
        assert!(parse_rfc3339_millis("2024-01-01 00:00:00").is_err()); // no 'T'/'Z'
        assert!(parse_rfc3339_millis("2024-13-01T00:00:00Z").is_err()); // bad month
        assert!(parse_rfc3339_millis("2024-01-01T25:00:00Z").is_err()); // bad hour
    }

    #[test]
    fn rfc3339_round_trips_over_a_range_of_days() {
        use tokenfuse_core::timefmt::civil_from_days;
        // civil_from_days / days_from_civil must be exact inverses across a
        // span that includes multiple leap years and century boundaries.
        for days in -1000..1000 {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{y:04}-{m:02}-{d:02}");
        }
    }

    // -- golden end-to-end export -----------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn rec(
        ts_millis: i64,
        run_id: &str,
        model: &str,
        decision: &str,
        input_tokens: u64,
        output_tokens: u64,
        cost_microusd: i64,
        agent_id: &str,
    ) -> CallRecord {
        rec_with_parent_and_outcome(
            ts_millis,
            run_id,
            model,
            decision,
            input_tokens,
            output_tokens,
            cost_microusd,
            agent_id,
            "",
            "",
            "",
        )
    }

    /// Like [`rec`], but also sets `parent_run_id` (P3), `outcome` (P4), and
    /// `unit` (docs/20-identity-map.md) - exercises `x_parent_run_id`,
    /// `x_outcome`, and `x_unit` sourcing together (see
    /// `exports_a_fixture_trace_to_the_exact_expected_csv`).
    #[allow(clippy::too_many_arguments)]
    fn rec_with_parent_and_outcome(
        ts_millis: i64,
        run_id: &str,
        model: &str,
        decision: &str,
        input_tokens: u64,
        output_tokens: u64,
        cost_microusd: i64,
        agent_id: &str,
        parent_run_id: &str,
        outcome: &str,
        unit: &str,
    ) -> CallRecord {
        CallRecord {
            ts_millis,
            run_id: run_id.into(),
            model: model.into(),
            decision: decision.into(),
            input_tokens,
            output_tokens,
            cost_microusd,
            step: 1,
            agent_id: agent_id.into(),
            saved_microusd: 0,
            parent_run_id: parent_run_id.into(),
            on_behalf_of: String::new(),
            outcome: outcome.into(),
            key_id: String::new(),
            unit: unit.into(),
        }
    }

    #[tokio::test]
    async fn exports_a_fixture_trace_to_the_exact_expected_csv() {
        let dir = std::env::temp_dir().join(format!("tf-focus-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = dir.join("focus.csv");

        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            // A: a normal settled allow (real parsed usage), WITH a parent run,
            // an outcome tag, AND a resolved unit - exercises P3's
            // x_parent_run_id sourcing, P4's x_outcome sourcing, and unit
            // identity's x_unit sourcing together.
            sink.record(rec_with_parent_and_outcome(
                0,
                "run-a",
                "claude-sonnet",
                "allow",
                100,
                50,
                345_000,
                "agent-1",
                "run-parent-a",
                "case_resolved",
                "treasury",
            ));
            // B: SettleGuard-drop-without-complete edge case — allow, zero
            // tokens, non-zero cost (the reserved fallback) -> "estimated".
            sink.record(rec(1_000, "run-a", "gpt-4o", "allow", 0, 0, 1_000_000, ""));
            // C: a genuine $0 cache hit -> "settled", not "estimated".
            sink.record(rec(
                2_000,
                "run-b",
                "claude-haiku",
                "cache_hit",
                0,
                0,
                0,
                "agent-2",
            ));
            // D: a Breaker block, with a comma AND a quote in the model name
            // and a comma in the agent id, to exercise RFC 4180 quoting.
            sink.record(rec(
                3_000,
                "run-b",
                "claude-sonnet, pro\"tier",
                "budget_exceeded",
                0,
                0,
                250_000,
                "agent://team,ops",
            ));
        }

        let args = Args {
            traces: Some(dir.to_str().unwrap().to_string()),
            out: Some(out.to_str().unwrap().to_string()),
            from: None,
            to: None,
        };
        run(&args).await.expect("export should succeed");

        let got = std::fs::read_to_string(&out).unwrap();
        let want = concat!(
            "BilledCost,EffectiveCost,BillingCurrency,ChargePeriodStart,ChargePeriodEnd,",
            "ChargeDescription,ProviderName,PublisherName,InvoiceIssuerName,ServiceName,",
            "ServiceCategory,ResourceId,ResourceName,SubAccountId,SubAccountName,x_run_id,",
            "x_parent_run_id,x_agent_id,x_model,x_tokens_in,x_tokens_out,x_blocked,x_cost_basis,",
            "x_outcome,x_unit\n",
            "0.345000,0.345000,USD,1970-01-01T00:00:00Z,1970-01-01T00:00:00Z,",
            "LLM call model=claude-sonnet,Anthropic,Anthropic,Anthropic,LLM inference,",
            "AI and Machine Learning,agent-1,agent-1,run-a,run-a,run-a,run-parent-a,agent-1,",
            "claude-sonnet,100,50,false,settled,case_resolved,treasury\n",
            "1.000000,1.000000,USD,1970-01-01T00:00:01Z,1970-01-01T00:00:01Z,",
            "LLM call model=gpt-4o,OpenAI,OpenAI,OpenAI,LLM inference,AI and Machine Learning,",
            ",,run-a,run-a,run-a,,,gpt-4o,0,0,false,estimated,,\n",
            "0.000000,0.000000,USD,1970-01-01T00:00:02Z,1970-01-01T00:00:02Z,",
            "LLM call model=claude-haiku,Anthropic,Anthropic,Anthropic,LLM inference,",
            "AI and Machine Learning,agent-2,agent-2,run-b,run-b,run-b,,agent-2,claude-haiku,",
            "0,0,false,settled,,\n",
            "0.000000,0.000000,USD,1970-01-01T00:00:03Z,1970-01-01T00:00:03Z,",
            "\"LLM call model=claude-sonnet, pro\"\"tier\",Anthropic,Anthropic,Anthropic,",
            "LLM inference,AI and Machine Learning,\"agent://team,ops\",\"agent://team,ops\",",
            "run-b,run-b,run-b,,\"agent://team,ops\",\"claude-sonnet, pro\"\"tier\",0,0,true,",
            "blocked,,\n",
        );
        assert_eq!(got, want);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn from_to_window_filters_rows() {
        let dir =
            std::env::temp_dir().join(format!("tf-focus-export-window-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = dir.join("focus.csv");

        {
            let sink = ParquetSink::new(&dir, 1).unwrap();
            sink.record(rec(0, "run-a", "m", "allow", 1, 1, 1_000, ""));
            sink.record(rec(10_000, "run-b", "m", "allow", 1, 1, 1_000, ""));
        }

        let args = Args {
            traces: Some(dir.to_str().unwrap().to_string()),
            out: Some(out.to_str().unwrap().to_string()),
            from: Some("1970-01-01T00:00:05Z".to_string()),
            to: None,
        };
        run(&args).await.expect("export should succeed");
        let got = std::fs::read_to_string(&out).unwrap();
        assert_eq!(got.lines().count(), 2); // header + run-b only
        assert!(got.contains("run-b"));
        assert!(!got.contains("run-a"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn missing_traces_dir_is_a_clear_error_not_a_panic() {
        let args = Args {
            traces: Some("/nonexistent/tf-focus-export-dir-xyz".to_string()),
            out: Some("/tmp/should-not-be-written.csv".to_string()),
            from: None,
            to: None,
        };
        let err = run(&args).await.unwrap_err();
        assert!(err.contains("nonexistent"), "{err}");
    }

    #[test]
    fn parse_args_reads_all_flags() {
        let args = vec![
            "--traces".to_string(),
            "./data".to_string(),
            "--out".to_string(),
            "focus.csv".to_string(),
            "--from".to_string(),
            "2026-01-01T00:00:00Z".to_string(),
            "--to".to_string(),
            "2026-02-01T00:00:00Z".to_string(),
        ];
        let a = parse_args(&args);
        assert_eq!(a.traces.as_deref(), Some("./data"));
        assert_eq!(a.out.as_deref(), Some("focus.csv"));
        assert_eq!(a.from.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(a.to.as_deref(), Some("2026-02-01T00:00:00Z"));
    }
}
