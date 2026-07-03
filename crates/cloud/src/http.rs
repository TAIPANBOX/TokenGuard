//! HTTP surface for the control plane: `/healthz` + `/v1/ingest` (A2), the read
//! endpoints `/v1/runs`, `/v1/summary`, `/v1/alerts` + browser CORS (A3), and
//! the admin-only mutations `kill` / `budget` with their poll endpoints
//! `/v1/kills`, `/v1/budgets` (A4). The OpenAPI contract lands in a later PR —
//! see docs/14-mobile-companion.md.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::keys::Principal;
use crate::store::{CallRecord, Store};

/// Shared application state. `Clone` is cheap — everything is behind an `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub keys: Arc<HashMap<String, Principal>>,
    /// Budget fraction at which a run is flagged by `/v1/alerts` (default 0.8).
    pub alert_pct: f64,
}

impl AppState {
    pub fn new(store: Arc<Store>, keys: Arc<HashMap<String, Principal>>, alert_pct: f64) -> Self {
        Self {
            store,
            keys,
            alert_pct,
        }
    }

    /// Resolve the bearer token to its principal. Accepts the token with or
    /// without the `Bearer ` prefix, matching the Go plane.
    fn principal_for(&self, headers: &HeaderMap) -> Option<&Principal> {
        let raw = headers.get("authorization")?.to_str().ok()?;
        let token = raw.strip_prefix("Bearer ").unwrap_or(raw).trim();
        if token.is_empty() {
            return None;
        }
        self.keys.get(token)
    }

    /// Resolve the bearer token to an org (any role), or `None` if unauthorized.
    fn org_for(&self, headers: &HeaderMap) -> Option<String> {
        self.principal_for(headers).map(|p| p.org.clone())
    }

    /// Authorize a mutation: the org for an `admin` principal, otherwise an
    /// [`AuthError`] — `401` for an unknown key, `403` for a non-admin.
    fn admin_org(&self, headers: &HeaderMap) -> Result<String, AuthError> {
        match self.principal_for(headers) {
            None => Err(AuthError::Unauthorized),
            Some(p) if p.role != "admin" => Err(AuthError::Forbidden),
            Some(p) => Ok(p.org.clone()),
        }
    }
}

/// A mutation authorization failure, small so it doesn't bloat handler `Result`s.
enum AuthError {
    Unauthorized,
    Forbidden,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::Unauthorized => unauthorized(),
            AuthError::Forbidden => forbidden(),
        }
    }
}

/// Build the control-plane router.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/healthz", get(healthz))
        .route("/v1/ingest", post(ingest))
        .route("/v1/runs", get(runs))
        .route("/v1/summary", get(summary))
        .route("/v1/alerts", get(alerts))
        .route("/v1/runs/{run}/kill", post(kill))
        .route("/v1/kills", get(kills))
        .route("/v1/runs/{run}/budget", post(set_budget))
        .route("/v1/budgets", get(budgets))
        .layer(middleware::from_fn(cors))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

/// `GET /` — the embedded zero-deploy dashboard (a self-contained vanilla
/// HTML/JS page that calls the API with relative paths).
async fn dashboard() -> Html<&'static str> {
    Html(include_str!("../index.html"))
}

#[derive(Deserialize)]
struct IngestBody {
    #[serde(default)]
    records: Vec<CallRecord>,
}

/// `POST /v1/ingest` — a gateway pushes a batch of settled calls for its org.
async fn ingest(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    let parsed: IngestBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad json"}))).into_response()
        }
    };
    let accepted = parsed.records.len();
    st.store.ingest(&org, &parsed.records);
    (StatusCode::OK, Json(json!({ "accepted": accepted }))).into_response()
}

/// `GET /v1/runs` — the caller org's aggregated runs.
async fn runs(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.runs(&org))).into_response()
}

/// `GET /v1/summary` — org-wide totals.
async fn summary(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.summary(&org))).into_response()
}

#[derive(Deserialize)]
struct AlertQuery {
    pct: Option<f64>,
}

/// `GET /v1/alerts` — runs at or above the alert threshold of their budget. The
/// threshold defaults to the configured `alert_pct` and can be overridden with
/// `?pct=` (0..1).
async fn alerts(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AlertQuery>,
) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    let pct = q
        .pct
        .filter(|p| *p > 0.0 && *p <= 1.0)
        .unwrap_or(st.alert_pct);
    (StatusCode::OK, Json(st.store.alerts(&org, pct))).into_response()
}

/// `POST /v1/runs/{run}/kill` — mark a run killed (admin only). Gateways poll
/// `/v1/kills` and hard-stop it across the org fleet.
async fn kill(State(st): State<AppState>, headers: HeaderMap, Path(run): Path<String>) -> Response {
    let org = match st.admin_org(&headers) {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    st.store.kill(&org, &run);
    (StatusCode::OK, Json(json!({ "killed": run }))).into_response()
}

/// `GET /v1/kills` — run ids this org has killed (gateways poll this).
async fn kills(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.kills(&org))).into_response()
}

#[derive(Deserialize)]
struct BudgetBody {
    budget_usd: f64,
}

/// `POST /v1/runs/{run}/budget` — set a central budget for a run (admin only),
/// overriding the client-supplied budget. Gateways poll `/v1/budgets`.
async fn set_budget(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(run): Path<String>,
    body: Bytes,
) -> Response {
    let org = match st.admin_org(&headers) {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    let parsed: BudgetBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad json"}))).into_response()
        }
    };
    let micros = (parsed.budget_usd * 1e6) as i64;
    st.store.set_budget(&org, &run, micros);
    (
        StatusCode::OK,
        Json(json!({ "run": run, "budget_micros": micros })),
    )
        .into_response()
}

/// `GET /v1/budgets` — this org's run → budget-micros overrides (gateways poll).
async fn budgets(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.budgets(&org))).into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "invalid api key"})),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": "admin role required"})),
    )
        .into_response()
}

/// Allow the standalone (Next.js) dashboard, served from another origin, to call
/// the API from the browser. Auth is a Bearer token (not cookies), so a wildcard
/// origin is safe. Ported from the Go plane's hand-rolled CORS.
async fn cors(req: Request, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        set_cors_headers(resp.headers_mut());
        return resp;
    }
    let mut resp = next.run(req).await;
    set_cors_headers(resp.headers_mut());
    resp
}

fn set_cors_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("authorization, content-type"),
    );
}
