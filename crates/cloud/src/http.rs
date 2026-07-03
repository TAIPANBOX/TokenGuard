//! HTTP surface for the control plane: `/healthz` + `/v1/ingest` (A2), the read
//! endpoints `/v1/runs`, `/v1/summary`, `/v1/alerts` + browser CORS (A3), the
//! admin-only mutations `kill` / `budget` with their poll endpoints
//! `/v1/kills`, `/v1/budgets` (A4), and an OpenAPI contract at `/openapi.json`
//! (A6) — the single source of truth the Swift and dashboard clients generate
//! from. See docs/14-mobile-companion.md.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::{Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::keys::Principal;
use crate::store::{Alert, CallRecord, RunAgg, SeriesBucket, Store, Summary};

/// The OpenAPI document for the control-plane API. Rendered at `/openapi.json`
/// and dumped by `tokenfuse-cloud --openapi`; downstream clients (Swift, the
/// Next.js dashboard) are generated from it.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "TokenFuse Cloud",
        description = "Fleet-wide control plane: per-org spend, kill-switch and central budgets."
    ),
    paths(ingest, runs, summary, alerts, series, kill, kills, set_budget, budgets),
    components(schemas(
        CallRecord,
        RunAgg,
        Summary,
        Alert,
        SeriesBucket,
        IngestBody,
        IngestResponse,
        BudgetBody,
        BudgetResponse,
        KillResponse,
        ErrorResponse,
    )),
    tags(
        (name = "telemetry", description = "Ingest of gateway call records"),
        (name = "reads", description = "Aggregated per-org views"),
        (name = "mutations", description = "Operator actions (admin only)"),
    )
)]
struct ApiDoc;

/// The generated OpenAPI document.
pub fn openapi_spec() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

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
        .route("/openapi.json", get(openapi_doc))
        .route("/v1/ingest", post(ingest))
        .route("/v1/runs", get(runs))
        .route("/v1/summary", get(summary))
        .route("/v1/alerts", get(alerts))
        .route("/v1/series", get(series))
        .route("/v1/stream", get(stream))
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

/// `GET /openapi.json` — the API contract. Not itself documented in the spec.
async fn openapi_doc() -> Json<utoipa::openapi::OpenApi> {
    Json(openapi_spec())
}

// ---- request / response bodies -------------------------------------------

#[derive(Deserialize, ToSchema)]
struct IngestBody {
    #[serde(default)]
    records: Vec<CallRecord>,
}

#[derive(Serialize, ToSchema)]
struct IngestResponse {
    accepted: usize,
}

#[derive(Deserialize, ToSchema)]
struct BudgetBody {
    budget_usd: f64,
}

#[derive(Serialize, ToSchema)]
struct BudgetResponse {
    run: String,
    budget_micros: i64,
}

#[derive(Serialize, ToSchema)]
struct KillResponse {
    killed: String,
}

#[derive(Serialize, ToSchema)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize, IntoParams)]
struct AlertQuery {
    /// Budget fraction (0..1) to flag at; defaults to the server's `alert_pct`.
    pct: Option<f64>,
}

// ---- handlers -------------------------------------------------------------

/// A gateway pushes a batch of settled calls for its org.
#[utoipa::path(
    post, path = "/v1/ingest",
    request_body = IngestBody,
    responses(
        (status = 200, description = "records accepted", body = IngestResponse),
        (status = 400, description = "malformed json", body = ErrorResponse),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "telemetry"
)]
async fn ingest(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    let parsed: IngestBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return bad_json(),
    };
    let accepted = parsed.records.len();
    st.store.ingest(&org, &parsed.records);
    (StatusCode::OK, Json(IngestResponse { accepted })).into_response()
}

/// The caller org's aggregated runs.
#[utoipa::path(
    get, path = "/v1/runs",
    responses(
        (status = 200, description = "aggregated runs", body = Vec<RunAgg>),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn runs(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.runs(&org))).into_response()
}

/// Org-wide totals.
#[utoipa::path(
    get, path = "/v1/summary",
    responses(
        (status = 200, description = "org totals", body = Summary),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn summary(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.summary(&org))).into_response()
}

/// Runs at or above the alert threshold of their central budget.
#[utoipa::path(
    get, path = "/v1/alerts",
    params(AlertQuery),
    responses(
        (status = 200, description = "runs near or over budget", body = Vec<Alert>),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "reads"
)]
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

#[derive(Deserialize, IntoParams)]
struct SeriesQuery {
    /// Scope to a single run; omit for the whole org.
    run: Option<String>,
    /// Time span back from now, e.g. `1h`, `24h`, `30m` (default `1h`).
    window: Option<String>,
    /// Bucket width, e.g. `60s`, `5m` (default `60s`).
    step: Option<String>,
}

/// Burn-rate buckets over a time window — feeds the chart and the Dynamic Island.
#[utoipa::path(
    get, path = "/v1/series",
    params(SeriesQuery),
    responses(
        (status = 200, description = "time buckets, oldest first", body = Vec<SeriesBucket>),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn series(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SeriesQuery>,
) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    let window = parse_duration_ms(q.window.as_deref()).unwrap_or(3_600_000);
    let step = parse_duration_ms(q.step.as_deref()).unwrap_or(60_000);
    let buckets = st
        .store
        .series(&org, q.run.as_deref(), window, step, now_millis());
    (StatusCode::OK, Json(buckets)).into_response()
}

/// `GET /v1/stream` — Server-Sent Events of live changes for the caller's org
/// (`run_update`, `kill`, `budget`), with a 25 s keep-alive. Not in the OpenAPI
/// document (SSE). Replaces client polling.
async fn stream(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    let events = BroadcastStream::new(st.store.subscribe()).filter_map(move |ev| match ev {
        Ok(e) if e.org() == org => Some(Ok::<Event, Infallible>(
            Event::default()
                .event(e.event_name())
                .json_data(&e)
                .unwrap_or_default(),
        )),
        _ => None,
    });
    Sse::new(events)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(25))
                .text("ping"),
        )
        .into_response()
}

/// Mark a run killed (admin only). Gateways poll `/v1/kills` and hard-stop it.
#[utoipa::path(
    post, path = "/v1/runs/{run}/kill",
    params(("run" = String, Path, description = "run id")),
    responses(
        (status = 200, description = "run killed", body = KillResponse),
        (status = 401, description = "unauthorized", body = ErrorResponse),
        (status = 403, description = "admin role required", body = ErrorResponse),
    ),
    tag = "mutations"
)]
async fn kill(State(st): State<AppState>, headers: HeaderMap, Path(run): Path<String>) -> Response {
    let org = match st.admin_org(&headers) {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    st.store.kill(&org, &run);
    (StatusCode::OK, Json(KillResponse { killed: run })).into_response()
}

/// Run ids this org has killed (gateways poll this).
#[utoipa::path(
    get, path = "/v1/kills",
    responses(
        (status = 200, description = "killed run ids", body = Vec<String>),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "mutations"
)]
async fn kills(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.kills(&org))).into_response()
}

/// Set a central budget for a run (admin only). Gateways poll `/v1/budgets`.
#[utoipa::path(
    post, path = "/v1/runs/{run}/budget",
    params(("run" = String, Path, description = "run id")),
    request_body = BudgetBody,
    responses(
        (status = 200, description = "budget set", body = BudgetResponse),
        (status = 400, description = "malformed json", body = ErrorResponse),
        (status = 401, description = "unauthorized", body = ErrorResponse),
        (status = 403, description = "admin role required", body = ErrorResponse),
    ),
    tag = "mutations"
)]
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
        Err(_) => return bad_json(),
    };
    let micros = (parsed.budget_usd * 1e6) as i64;
    st.store.set_budget(&org, &run, micros);
    (
        StatusCode::OK,
        Json(BudgetResponse {
            run,
            budget_micros: micros,
        }),
    )
        .into_response()
}

/// This org's run → budget-micros overrides (gateways poll this).
#[utoipa::path(
    get, path = "/v1/budgets",
    responses(
        (status = 200, description = "run → budget micros"),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "mutations"
)]
async fn budgets(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.budgets(&org))).into_response()
}

// ---- helpers --------------------------------------------------------------

/// Parse a duration like `1h`, `30m`, `60s`, `500ms`; a bare number is seconds.
fn parse_duration_ms(s: Option<&str>) -> Option<i64> {
    let s = s?.trim();
    if s.is_empty() {
        return None;
    }
    let (num, mult) = if let Some(v) = s.strip_suffix("ms") {
        (v, 1)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, 1000)
    } else if let Some(v) = s.strip_suffix('m') {
        (v, 60_000)
    } else if let Some(v) = s.strip_suffix('h') {
        (v, 3_600_000)
    } else {
        (s, 1000)
    };
    num.trim()
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
        .map(|n| n * mult)
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---- shared responses -----------------------------------------------------

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: "invalid api key".into(),
        }),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: "admin role required".into(),
        }),
    )
        .into_response()
}

fn bad_json() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: "bad json".into(),
        }),
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
