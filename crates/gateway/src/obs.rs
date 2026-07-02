//! Observability endpoints: list active runs and kill a runaway.
//!
//! These back the `tokenfuse top` TUI and the Slack kill-button. Everything is
//! metadata (ids, budgets, spend, steps) — no prompt contents.

use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;

/// A run as shown in the dashboard / TUI. Money is rendered in USD at the edge.
#[derive(Serialize)]
pub struct RunView {
    pub run_id: String,
    pub budget_usd: f64,
    pub spent_usd: f64,
    pub reserved_usd: f64,
    pub remaining_usd: f64,
    pub steps: u32,
    pub pct_used: f64,
    pub killed: bool,
}

/// `GET /v1/runs` — all known runs, most-spent first.
pub async fn list_runs(State(st): State<AppState>) -> Json<Vec<RunView>> {
    let mut views: Vec<RunView> = st
        .ledger
        .list_runs()
        .await
        .into_iter()
        .map(|(run_id, s)| {
            let budget = s.budget.as_usd();
            let spent = s.spent.as_usd();
            RunView {
                killed: st.is_killed(&run_id),
                run_id,
                budget_usd: budget,
                spent_usd: spent,
                reserved_usd: s.reserved.as_usd(),
                remaining_usd: s.remaining().as_usd(),
                steps: s.steps,
                pct_used: if budget > 0.0 {
                    (s.in_flight().as_usd() / budget) * 100.0
                } else {
                    0.0
                },
            }
        })
        .collect();
    views.sort_by(|a, b| {
        b.spent_usd
            .partial_cmp(&a.spent_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Json(views)
}

/// `POST /v1/runs/{id}/kill` — hard-stop a run; subsequent calls get 402.
pub async fn kill_run(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    st.kill(&id);
    Json(serde_json::json!({ "killed": id }))
}
