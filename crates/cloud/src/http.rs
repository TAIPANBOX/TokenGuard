//! HTTP surface for the control plane. This PR (A3) adds the read endpoints the
//! dashboard and mobile app consume (`/v1/runs`, `/v1/summary`, `/v1/alerts`)
//! plus browser CORS, on top of A2's `/healthz` + `/v1/ingest`. Mutations
//! (kill/budget) and the OpenAPI contract land in later PRs — see
//! docs/14-mobile-companion.md.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
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

    /// Resolve the bearer token to an org (any role), or `None` if the key is
    /// unknown or absent. Accepts the token with or without the `Bearer `
    /// prefix, matching the Go plane.
    fn org_for(&self, headers: &HeaderMap) -> Option<String> {
        let raw = headers.get("authorization")?.to_str().ok()?;
        let token = raw.strip_prefix("Bearer ").unwrap_or(raw).trim();
        if token.is_empty() {
            return None;
        }
        self.keys.get(token).map(|p| p.org.clone())
    }
}

/// Build the control-plane router.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/ingest", post(ingest))
        .route("/v1/runs", get(runs))
        .route("/v1/summary", get(summary))
        .route("/v1/alerts", get(alerts))
        .layer(middleware::from_fn(cors))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
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

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "invalid api key"})),
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
