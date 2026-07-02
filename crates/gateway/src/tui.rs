//! `tokenfuse top` — a live, htop-style terminal view of running agents.
//!
//! Polls the gateway's `GET /v1/runs` and renders a table of runs with spend,
//! budget usage, and step counts. Keys: ↑/↓ or j/k select, `k`/Enter kill the
//! selected run, `r` refresh now, `q`/Esc quit.

use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, TableState};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RunRow {
    pub run_id: String,
    pub budget_usd: f64,
    pub spent_usd: f64,
    #[serde(default)]
    pub reserved_usd: f64,
    pub steps: u32,
    pub pct_used: f64,
    pub killed: bool,
}

/// Format a USD amount compactly for the table.
pub fn fmt_usd(v: f64) -> String {
    if v >= 100.0 {
        format!("${v:.0}")
    } else if v >= 1.0 {
        format!("${v:.2}")
    } else {
        format!("${v:.4}")
    }
}

/// A text progress bar of `width` cells for a 0–100(+)% value.
pub fn bar(pct: f64, width: usize) -> String {
    let clamped = pct.clamp(0.0, 100.0) / 100.0;
    let filled = (clamped * width as f64).round() as usize;
    let filled = filled.min(width);
    let mut s = String::with_capacity(width);
    for i in 0..width {
        s.push(if i < filled { '█' } else { '░' });
    }
    s
}

fn pct_color(pct: f64, killed: bool) -> Color {
    if killed {
        Color::DarkGray
    } else if pct >= 100.0 {
        Color::Red
    } else if pct >= 85.0 {
        Color::Yellow
    } else {
        Color::Green
    }
}

async fn fetch(client: &reqwest::Client, base: &str) -> Result<Vec<RunRow>, String> {
    let url = format!("{base}/v1/runs");
    let text = client
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

async fn kill(client: &reqwest::Client, base: &str, run_id: &str) {
    let url = format!("{base}/v1/runs/{run_id}/kill");
    let _ = client.post(&url).send().await;
}

/// Run the TUI against the gateway at `base_url` until the user quits.
pub async fn run(base_url: String) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let mut terminal = ratatui::init();
    let mut state = TableState::default();
    // `action` (last operator action) persists across refreshes; `conn` is
    // recomputed each loop from the fetch result.
    let mut action: Option<String> = None;

    let result = loop {
        let (runs, conn) = match fetch(&client, &base_url).await {
            Ok(r) => {
                let conn = format!("connected · {} run(s)", r.len());
                (r, conn)
            }
            Err(e) => (
                Vec::new(),
                format!("gateway unreachable at {base_url}: {e}"),
            ),
        };

        // Keep the selection in range.
        if runs.is_empty() {
            state.select(None);
        } else {
            let sel = state.selected().unwrap_or(0).min(runs.len() - 1);
            state.select(Some(sel));
        }

        if let Err(e) =
            terminal.draw(|frame| draw(frame, &runs, &mut state, &conn, action.as_deref()))
        {
            break Err(e.into());
        }

        // Input with a poll timeout so the table refreshes ~2x/second.
        match event::poll(Duration::from_millis(500)) {
            Ok(true) => {
                if let Ok(Event::Key(key)) = event::read() {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                        KeyCode::Down | KeyCode::Char('j') => {
                            if !runs.is_empty() {
                                let next =
                                    state.selected().map(|i| (i + 1) % runs.len()).unwrap_or(0);
                                state.select(Some(next));
                            }
                        }
                        KeyCode::Up => {
                            if !runs.is_empty() {
                                let prev = state
                                    .selected()
                                    .map(|i| (i + runs.len() - 1) % runs.len())
                                    .unwrap_or(0);
                                state.select(Some(prev));
                            }
                        }
                        KeyCode::Char('k') | KeyCode::Enter => {
                            if let Some(i) = state.selected() {
                                if let Some(r) = runs.get(i) {
                                    kill(&client, &base_url, &r.run_id).await;
                                    action = Some(format!("killed {}", r.run_id));
                                }
                            }
                        }
                        KeyCode::Char('r') => {} // loop refetches immediately
                        _ => {}
                    }
                }
            }
            Ok(false) => {}
            Err(e) => break Err(e.into()),
        }
    };

    ratatui::restore();
    result
}

fn draw(
    frame: &mut ratatui::Frame,
    runs: &[RunRow],
    state: &mut TableState,
    conn: &str,
    action: Option<&str>,
) {
    let areas = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(frame.area());

    let total: f64 = runs.iter().map(|r| r.spent_usd).sum();
    let title = Line::from(format!(
        " tokenfuse top — {} run(s) · total spend {} ",
        runs.len(),
        fmt_usd(total)
    ))
    .bold();
    frame.render_widget(Paragraph::new(title), areas[0]);

    let header = Row::new(vec!["run", "spend / budget", "usage", "%", "steps", ""])
        .style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED));

    let rows: Vec<Row> = runs
        .iter()
        .map(|r| {
            let color = pct_color(r.pct_used, r.killed);
            let money = format!("{} / {}", fmt_usd(r.spent_usd), fmt_usd(r.budget_usd));
            let flag = if r.killed { "KILLED" } else { "" };
            Row::new(vec![
                Cell::from(r.run_id.clone()),
                Cell::from(money),
                Cell::from(bar(r.pct_used, 16)).style(Style::default().fg(color)),
                Cell::from(format!("{:.0}%", r.pct_used)),
                Cell::from(r.steps.to_string()),
                Cell::from(flag).style(Style::default().fg(Color::Red)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Min(16),
        Constraint::Length(18),
        Constraint::Length(18),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::bordered().title(" runs "))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, areas[1], state);

    let action = action.map(|a| format!(" · {a}")).unwrap_or_default();
    let help = Line::from(format!(
        " {conn}{action}   │   ↑/↓ select · k/Enter kill · r refresh · q quit "
    ))
    .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(Paragraph::new(help), areas[2]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_fills_proportionally() {
        assert_eq!(bar(0.0, 4), "░░░░");
        assert_eq!(bar(100.0, 4), "████");
        assert_eq!(bar(50.0, 4), "██░░");
        // Over 100% clamps to full.
        assert_eq!(bar(250.0, 4), "████");
    }

    #[test]
    fn usd_scales_precision() {
        assert_eq!(fmt_usd(0.0105), "$0.0105");
        assert_eq!(fmt_usd(4.25), "$4.25");
        assert_eq!(fmt_usd(1847.0), "$1847");
    }

    #[test]
    fn color_thresholds() {
        assert_eq!(pct_color(10.0, false), Color::Green);
        assert_eq!(pct_color(90.0, false), Color::Yellow);
        assert_eq!(pct_color(120.0, false), Color::Red);
        assert_eq!(pct_color(50.0, true), Color::DarkGray);
    }

    #[test]
    fn run_row_parses_from_endpoint_json() {
        let json = r#"[{"run_id":"r1","budget_usd":5.0,"spent_usd":1.25,"reserved_usd":0.0,"remaining_usd":3.75,"steps":3,"pct_used":25.0,"killed":false}]"#;
        let rows: Vec<RunRow> = serde_json::from_str(json).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].run_id, "r1");
        assert_eq!(rows[0].steps, 3);
    }
}
