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
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
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

use crate::devices::{self, Device};
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
    paths(
        ingest, runs, summary, alerts, series, kill, kills, set_budget, budgets,
        pair_new, pair, register_apns, register_activity,
    ),
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
        PairNewBody,
        PairNewResponse,
        PairRequest,
        PairResponse,
        ApnsBody,
        ActivityBody,
        OkResponse,
    )),
    tags(
        (name = "telemetry", description = "Ingest of gateway call records"),
        (name = "reads", description = "Aggregated per-org views"),
        (name = "mutations", description = "Operator actions (admin only)"),
        (name = "pairing", description = "Device pairing + Enclave-signed auth"),
        (name = "devices", description = "Per-device push registration (signed)"),
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

    /// Resolve the bearer token to an org-key principal (org keys only).
    fn principal_for(&self, headers: &HeaderMap) -> Option<&Principal> {
        self.keys.get(bearer(headers)?)
    }

    /// Resolve the bearer token to an org (any role) — an org key **or** a paired
    /// device token. Used by the read endpoints; `None` if unauthorized.
    fn org_for(&self, headers: &HeaderMap) -> Option<String> {
        let token = bearer(headers)?;
        if let Some(p) = self.keys.get(token) {
            return Some(p.org.clone());
        }
        self.store.device_by_token(token).map(|d| d.org)
    }

    /// Authorize an admin action by **org key only** (used for pairing, which is
    /// a dashboard/CLI action). `401` unknown key, `403` non-admin.
    fn admin_org_key(&self, headers: &HeaderMap) -> Result<String, AuthError> {
        match self.principal_for(headers) {
            None => Err(AuthError::Unauthorized),
            Some(p) if p.role != "admin" => Err(AuthError::Forbidden),
            Some(p) => Ok(p.org.clone()),
        }
    }

    /// Verify a paired device's ES256 signature over the canonical string
    /// (docs/14 §4.2): device known, `X-Fuse-Device` matches, `|now-ts| <= 120s`,
    /// signature valid, and nonce unseen (checked last, so only valid requests
    /// spend a nonce). Returns the device on success.
    fn verify_device_signature(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &HeaderMap,
    ) -> Result<Device, AuthError> {
        let token = bearer(headers).ok_or(AuthError::Unauthorized)?;
        let device = self
            .store
            .device_by_token(token)
            .ok_or(AuthError::Unauthorized)?;

        let dev_hdr = header_str(headers, "x-fuse-device").ok_or(AuthError::SignatureInvalid)?;
        if dev_hdr != device.device_id {
            return Err(AuthError::SignatureInvalid);
        }
        let ts = header_str(headers, "x-fuse-ts").ok_or(AuthError::SignatureInvalid)?;
        let nonce = header_str(headers, "x-fuse-nonce").ok_or(AuthError::SignatureInvalid)?;
        let sig = header_str(headers, "x-fuse-sig").ok_or(AuthError::SignatureInvalid)?;

        let ts_num: i64 = ts.parse().map_err(|_| AuthError::SignatureInvalid)?;
        if (now_unix() - ts_num).abs() > 120 {
            return Err(AuthError::SignatureInvalid);
        }

        let canonical = devices::canonical_string(method, path, body, ts, nonce);
        if !devices::verify_signature(&device.pubkey_b64, &canonical, sig) {
            return Err(AuthError::SignatureInvalid);
        }
        if !self.store.check_and_record_nonce(&device.device_id, nonce) {
            return Err(AuthError::SignatureInvalid);
        }
        Ok(device)
    }

    /// Authorize a mutation. Two accepted paths:
    /// 1. an **admin org key** (dashboard/CLI) — no signature; or
    /// 2. a **paired admin device** with a valid Enclave signature.
    fn authorize_mutation(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &HeaderMap,
    ) -> Result<String, AuthError> {
        let token = bearer(headers).ok_or(AuthError::Unauthorized)?;
        if let Some(p) = self.keys.get(token) {
            if p.role != "admin" {
                return Err(AuthError::Forbidden);
            }
            return Ok(p.org.clone());
        }
        let device = self.verify_device_signature(method, path, body, headers)?;
        if device.role != "admin" {
            return Err(AuthError::Forbidden);
        }
        Ok(device.org)
    }

    /// Authorize a device managing **its own** state (APNs token, activities):
    /// a valid Enclave signature from any paired device (no admin requirement).
    fn authorize_device(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &HeaderMap,
    ) -> Result<Device, AuthError> {
        self.verify_device_signature(method, path, body, headers)
    }
}

/// A mutation authorization failure, small so it doesn't bloat handler `Result`s.
enum AuthError {
    Unauthorized,
    Forbidden,
    SignatureInvalid,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::Unauthorized => unauthorized(),
            AuthError::Forbidden => forbidden(),
            AuthError::SignatureInvalid => error(StatusCode::FORBIDDEN, "signature_invalid"),
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
        .route("/v1/pair/new", post(pair_new))
        .route("/v1/pair", post(pair))
        .route("/v1/devices/{id}/apns", post(register_apns))
        .route("/v1/devices/{id}/activity", post(register_activity))
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

#[derive(Deserialize, ToSchema)]
struct PairNewBody {
    /// Role the paired device will have (`admin` | `viewer`); default `admin`.
    role: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct PairNewResponse {
    code: String,
    expires_unix: i64,
}

#[derive(Deserialize, ToSchema)]
struct PairRequest {
    code: String,
    /// Device public key, base64 SEC1/X9.63.
    pubkey_b64: String,
    #[serde(default)]
    platform: String,
    #[serde(default)]
    name: String,
}

#[derive(Serialize, ToSchema)]
struct PairResponse {
    device_id: String,
    org: String,
    role: String,
    device_token: String,
}

#[derive(Deserialize, ToSchema)]
struct ApnsBody {
    /// APNs device token (hex) for push delivery.
    token: String,
}

#[derive(Deserialize, ToSchema)]
struct ActivityBody {
    /// ActivityKit push-to-update token.
    activity_token: String,
    /// The run this Live Activity tracks.
    run_id: String,
}

#[derive(Serialize, ToSchema)]
struct OkResponse {
    ok: bool,
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
async fn kill(
    State(st): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(run): Path<String>,
) -> Response {
    let org = match st.authorize_mutation("POST", uri.path(), b"", &headers) {
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
    uri: Uri,
    Path(run): Path<String>,
    body: Bytes,
) -> Response {
    let org = match st.authorize_mutation("POST", uri.path(), &body, &headers) {
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

/// Issue a one-time pairing code (admin org key). The dashboard renders it as a
/// QR the app scans.
#[utoipa::path(
    post, path = "/v1/pair/new",
    request_body = PairNewBody,
    responses(
        (status = 200, description = "pairing code (valid 10 min)", body = PairNewResponse),
        (status = 401, description = "unauthorized", body = ErrorResponse),
        (status = 403, description = "admin role required", body = ErrorResponse),
    ),
    tag = "pairing"
)]
async fn pair_new(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let org = match st.admin_org_key(&headers) {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    // Role is optional; default admin, only admin/viewer allowed.
    let role = match serde_json::from_slice::<PairNewBody>(&body) {
        Ok(b) => b.role.unwrap_or_else(|| "admin".to_string()),
        Err(_) if body.is_empty() => "admin".to_string(),
        Err(_) => return bad_json(),
    };
    if role != "admin" && role != "viewer" {
        return error(StatusCode::BAD_REQUEST, "role must be admin or viewer");
    }
    let code = devices::pairing_code();
    let expires_unix = now_unix() + 600;
    st.store.create_pairing(&code, &org, &role, expires_unix);
    (StatusCode::OK, Json(PairNewResponse { code, expires_unix })).into_response()
}

/// Redeem a pairing code with a device public key. No bearer auth — the code is
/// the credential. Returns the device's identity and its read token.
#[utoipa::path(
    post, path = "/v1/pair",
    request_body = PairRequest,
    responses(
        (status = 200, description = "device registered", body = PairResponse),
        (status = 400, description = "invalid or expired code / bad json", body = ErrorResponse),
    ),
    tag = "pairing"
)]
async fn pair(State(st): State<AppState>, body: Bytes) -> Response {
    let req: PairRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return bad_json(),
    };
    let device_id = devices::random_hex(16);
    let device_token = devices::random_hex(32);
    match st.store.redeem_pairing(
        &req.code,
        now_unix(),
        device_id,
        device_token.clone(),
        req.pubkey_b64,
        req.name,
        req.platform,
    ) {
        Some(dev) => (
            StatusCode::OK,
            Json(PairResponse {
                device_id: dev.device_id,
                org: dev.org,
                role: dev.role,
                device_token,
            }),
        )
            .into_response(),
        None => error(StatusCode::BAD_REQUEST, "invalid or expired pairing code"),
    }
}

/// Register/refresh a device's APNs token (device-signed; `{id}` must be the
/// signing device).
#[utoipa::path(
    post, path = "/v1/devices/{id}/apns",
    params(("id" = String, Path, description = "device id")),
    request_body = ApnsBody,
    responses(
        (status = 200, description = "token registered", body = OkResponse),
        (status = 403, description = "signature invalid / not this device", body = ErrorResponse),
        (status = 404, description = "unknown device", body = ErrorResponse),
    ),
    tag = "devices"
)]
async fn register_apns(
    State(st): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let device = match st.authorize_device("POST", uri.path(), &body, &headers) {
        Ok(d) => d,
        Err(e) => return e.into_response(),
    };
    if device.device_id != id {
        return error(StatusCode::FORBIDDEN, "signature_invalid");
    }
    let req: ApnsBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return bad_json(),
    };
    if st.store.set_apns_token(&id, &req.token) {
        (StatusCode::OK, Json(OkResponse { ok: true })).into_response()
    } else {
        error(StatusCode::NOT_FOUND, "unknown device")
    }
}

/// Register a Live Activity push token for a run (device-signed).
#[utoipa::path(
    post, path = "/v1/devices/{id}/activity",
    params(("id" = String, Path, description = "device id")),
    request_body = ActivityBody,
    responses(
        (status = 200, description = "activity registered", body = OkResponse),
        (status = 403, description = "signature invalid / not this device", body = ErrorResponse),
    ),
    tag = "devices"
)]
async fn register_activity(
    State(st): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let device = match st.authorize_device("POST", uri.path(), &body, &headers) {
        Ok(d) => d,
        Err(e) => return e.into_response(),
    };
    if device.device_id != id {
        return error(StatusCode::FORBIDDEN, "signature_invalid");
    }
    let req: ActivityBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return bad_json(),
    };
    st.store
        .register_activity(&device.org, &req.run_id, &req.activity_token);
    (StatusCode::OK, Json(OkResponse { ok: true })).into_response()
}

// ---- helpers --------------------------------------------------------------

/// The bearer token from the `Authorization` header (with or without `Bearer `).
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get("authorization")?.to_str().ok()?;
    let token = raw.strip_prefix("Bearer ").unwrap_or(raw).trim();
    (!token.is_empty()).then_some(token)
}

/// A request header value as a `&str`, if present and valid UTF-8.
fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

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

/// A JSON error envelope `{ "error": … }` with the given status.
fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
        .into_response()
}

fn unauthorized() -> Response {
    error(StatusCode::UNAUTHORIZED, "invalid api key")
}

fn forbidden() -> Response {
    error(StatusCode::FORBIDDEN, "admin role required")
}

fn bad_json() -> Response {
    error(StatusCode::BAD_REQUEST, "bad json")
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
