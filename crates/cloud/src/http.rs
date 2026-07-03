//! HTTP surface for the control plane. This PR (A2) wires the skeleton:
//! `/healthz` and the telemetry ingest endpoint. Read endpoints, mutations,
//! durable persistence, CORS and the OpenAPI contract land in later PRs — see
//! docs/14-mobile-companion.md.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
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
}

impl AppState {
    pub fn new(store: Arc<Store>, keys: Arc<HashMap<String, Principal>>) -> Self {
        Self { store, keys }
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

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "invalid api key"})),
    )
        .into_response()
}
