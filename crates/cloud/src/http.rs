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
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokenfuse_core::audit::AuditEntry;
use tokenfuse_core::compliance::{
    compute_compliance_from_counts, ControlEvidence, Enforcement, CATALOG, DISCLAIMER,
};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::audit_sign::AuditManifest;
use crate::devices::{self, Device};
use crate::keys::Principal;
use crate::oidc::{self, OidcConfig};
use crate::replay::{read_run_events, ReplayEvent};
use crate::store::{
    AgentAgg, Alert, CallRecord, Incident, RunAgg, SavingsSummary, SeriesBucket, Store, Summary,
    UnitAgg,
};

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
        ingest, runs, agents, units, savings, summary, alerts, series, kill, kills, set_budget,
        budgets, set_unit_budget, unit_budgets, incidents, ack_incident, compliance,
        compliance_evidence, audit, audit_verify, audit_manifest, replay, pair_new, pair,
        register_apns, register_activity,
    ),
    components(schemas(
        CallRecord,
        RunAgg,
        AgentAgg,
        UnitAgg,
        SavingsSummary,
        Summary,
        Alert,
        SeriesBucket,
        Incident,
        ComplianceReportSchema,
        ControlEvidenceSchema,
        EvidencePackResponse,
        EvidenceControl,
        EvidenceStatus,
        AuditEntrySchema,
        AuditVerifyResponse,
        AuditManifest,
        ReplayResponse,
        ReplayEvent,
        IngestBody,
        IngestResponse,
        BudgetBody,
        BudgetResponse,
        UnitBudgetResponse,
        KillResponse,
        AckResponse,
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
    /// Optional, offline OIDC/JWT bearer config (WS4). `None` when unconfigured —
    /// in which case the auth chokepoints never consult it and behavior is
    /// byte-for-byte identical to a keys-only deployment. Parsed once at
    /// construction so no env/file I/O happens per request.
    pub oidc: Option<Arc<OidcConfig>>,
    /// Optional server P-256 key for signing audit manifests (P3 WS2). `None`
    /// when unconfigured — `/v1/audit/manifest` then reports not-configured
    /// (`404`); the rest of the audit trail is unaffected. Loaded once at
    /// construction from `TOKENFUSE_CLOUD_AUDIT_SIGNING_KEY`.
    pub audit_signing_key: Option<Arc<SigningKey>>,
    /// Optional path to the agent-event NDJSON export `GET /v1/replay/{run}`
    /// reads (wave 2). `None` when unconfigured: the endpoint still returns
    /// the store-derived incidents/audit for the run, just zero events. Read
    /// once at construction from `TOKENFUSE_CLOUD_REPLAY_EVENTS`.
    pub replay_events_path: Option<Arc<String>>,
}

impl AppState {
    pub fn new(store: Arc<Store>, keys: Arc<HashMap<String, Principal>>, alert_pct: f64) -> Self {
        Self {
            store,
            keys,
            alert_pct,
            oidc: None,
            audit_signing_key: None,
            replay_events_path: None,
        }
    }

    /// Attach an optional OIDC config (from [`OidcConfig::from_env`]). Kept off
    /// the `new` signature so every existing call site — and every existing test
    /// — is unchanged; a keys-only deployment simply never calls this.
    pub fn with_oidc(mut self, oidc: Option<OidcConfig>) -> Self {
        self.oidc = oidc.map(Arc::new);
        self
    }

    /// Attach an optional audit-manifest signing key (from
    /// [`crate::audit_sign::signing_key_from_env`]). Kept off `new` like
    /// [`Self::with_oidc`], so existing call sites and tests are unchanged; a
    /// deployment without a key simply never calls this and `/v1/audit/manifest`
    /// reports not-configured.
    pub fn with_audit_signing_key(mut self, key: Option<SigningKey>) -> Self {
        self.audit_signing_key = key.map(Arc::new);
        self
    }

    /// Attach an optional replay-events path (from `TOKENFUSE_CLOUD_REPLAY_EVENTS`).
    /// Kept off `new` like [`Self::with_oidc`], so existing call sites and
    /// tests are unchanged; a deployment without the env var simply never
    /// calls this and `/v1/replay/{run}` reports zero events.
    pub fn with_replay_events_path(mut self, path: Option<String>) -> Self {
        self.replay_events_path = path.filter(|p| !p.is_empty()).map(Arc::new);
        self
    }

    /// Try to resolve the bearer as an OIDC token — `None` if OIDC is
    /// unconfigured, there is no bearer, or the token fails validation.
    fn oidc_principal(&self, headers: &HeaderMap) -> Option<Principal> {
        let cfg = self.oidc.as_ref()?;
        oidc::verify_id_token(cfg, bearer(headers)?)
    }

    /// Resolve the bearer token to an org-key principal (org keys only).
    fn principal_for(&self, headers: &HeaderMap) -> Option<&Principal> {
        self.keys.get(bearer(headers)?)
    }

    /// Resolve the bearer token to an org — an org key, a paired device token,
    /// or (when configured) a valid OIDC token. Used by the read endpoints;
    /// `None` if unauthorized. Keys and devices take precedence; OIDC is only
    /// tried when neither matched, so keys-only behavior is unchanged.
    fn org_for(&self, headers: &HeaderMap) -> Option<String> {
        let token = bearer(headers)?;
        if let Some(p) = self.keys.get(token) {
            return Some(p.org.clone());
        }
        if let Some(d) = self.store.device_by_token(token) {
            return Some(d.org);
        }
        self.oidc_principal(headers).map(|p| p.org)
    }

    /// Authorize an admin action by **org key only** (used for pairing, which is
    /// a dashboard/CLI action). `401` unknown key, `403` non-admin. Returns the
    /// org.
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
    ///
    /// Returns the org and a stable, non-secret [`Mutator::actor`] id for the
    /// audit trail — captured here, where the principal is known exactly, so
    /// the wired mutation sites never re-parse the credential.
    fn authorize_mutation(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &HeaderMap,
    ) -> Result<Mutator, AuthError> {
        let token = bearer(headers).ok_or(AuthError::Unauthorized)?;
        if let Some(p) = self.keys.get(token) {
            if p.role != "admin" {
                return Err(AuthError::Forbidden);
            }
            return Ok(Mutator {
                org: p.org.clone(),
                actor: key_actor(token),
            });
        }
        // OIDC bearer (when configured). Only a *valid* token that maps to a
        // principal short-circuits here; an invalid/absent JWT falls through to
        // the device-signature path exactly as before. A verified but non-admin
        // token is `403` (matching a viewer org key), not a fall-through.
        if let Some(cfg) = self.oidc.as_ref() {
            if let Some(v) = oidc::verify(cfg, token) {
                if v.principal.role != "admin" {
                    return Err(AuthError::Forbidden);
                }
                return Ok(Mutator {
                    org: v.principal.org,
                    actor: v.actor,
                });
            }
        }
        let device = self.verify_device_signature(method, path, body, headers)?;
        if device.role != "admin" {
            return Err(AuthError::Forbidden);
        }
        Ok(Mutator {
            actor: format!("device:{}", device.device_id),
            org: device.org,
        })
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

/// The authenticated principal behind an authorized mutation: the org it acts
/// on, and a stable, non-secret `actor` id for the audit trail.
struct Mutator {
    org: String,
    /// `key:<fingerprint>` for an admin org key, or `device:<id>` for a paired
    /// admin device. Never the raw bearer secret.
    actor: String,
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
        .route("/v1/agents", get(agents))
        .route("/v1/units", get(units))
        .route("/v1/savings", get(savings))
        .route("/v1/summary", get(summary))
        .route("/v1/alerts", get(alerts))
        .route("/v1/series", get(series))
        .route("/v1/stream", get(stream))
        .route("/v1/runs/{run}/kill", post(kill))
        .route("/v1/kills", get(kills))
        .route("/v1/runs/{run}/budget", post(set_budget))
        .route("/v1/budgets", get(budgets))
        .route("/v1/units/{id}/budget", post(set_unit_budget))
        .route("/v1/unit-budgets", get(unit_budgets))
        .route("/v1/incidents", get(incidents))
        .route("/v1/incidents/{id}/ack", post(ack_incident))
        .route("/v1/findings", post(external_findings))
        .route("/v1/compliance", get(compliance))
        .route("/v1/compliance/evidence", get(compliance_evidence))
        .route("/v1/audit", get(audit))
        .route("/v1/audit/verify", get(audit_verify))
        .route("/v1/audit/manifest", get(audit_manifest))
        .route("/v1/replay/{run}", get(replay))
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

/// Response for `POST /v1/units/{id}/budget` - same shape as [`BudgetResponse`]
/// with `unit` in place of `run` (docs/20-identity-map.md section 4).
#[derive(Serialize, ToSchema)]
struct UnitBudgetResponse {
    unit: String,
    budget_micros: i64,
}

#[derive(Serialize, ToSchema)]
struct KillResponse {
    killed: String,
}

#[derive(Serialize, ToSchema)]
struct AckResponse {
    acknowledged: String,
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

/// Result of an audit-chain integrity check. `ok` is `true` for an intact (or
/// empty) chain; otherwise `break_index` is the 0-based position of the first
/// broken link.
#[derive(Serialize, ToSchema)]
struct AuditVerifyResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    break_index: Option<usize>,
}

/// OpenAPI documentation mirror of `tokenfuse_core::audit::AuditEntry` — the
/// `/v1/audit` handler returns the core type, which serializes identically. It
/// lives here (rather than deriving `ToSchema` in core) to keep `tokenfuse-core`
/// free of the web/OpenAPI `utoipa` dependency.
#[derive(ToSchema)]
#[allow(dead_code)]
struct AuditEntrySchema {
    seq: u64,
    ts_millis: i64,
    actor: String,
    action: String,
    subject: String,
    detail: String,
    prev_hash: String,
    entry_hash: String,
}

/// OpenAPI mirror of `tokenfuse_core::compliance::ControlEvidence` — one
/// control's realized evidence. The `/v1/compliance` handler returns the core
/// type, which serializes identically; the schema lives here (not deriving
/// `ToSchema` in core) to keep `tokenfuse-core` free of the `utoipa` dependency.
#[derive(ToSchema)]
#[allow(dead_code)]
struct ControlEvidenceSchema {
    control_id: String,
    title: String,
    /// Honesty classification, serialized lowercase (`enforced`/`partial`/
    /// `documented`).
    #[schema(value_type = String, example = "enforced")]
    enforcement: String,
    /// Watched wire `decision` -> times it fired.
    decision_counts: HashMap<String, u64>,
    /// Watched finding `kind` -> times it appeared.
    finding_counts: HashMap<String, u64>,
    /// Cloud incidents aggregating into this control.
    incident_count: u64,
    covered: bool,
    evidence_seen: bool,
}

/// OpenAPI mirror of `tokenfuse_core::compliance::ComplianceReport` — the full
/// evidence pack returned by `/v1/compliance`. Mirrors the core shape exactly
/// (the handler returns the core type). `framework_versions` is a list of
/// `[framework_id, human_name, version_or_retrieval_date]` triples.
#[derive(ToSchema)]
#[allow(dead_code)]
struct ComplianceReportSchema {
    /// Standing disclaimer — this is evidence, not a certification.
    generated_note: String,
    /// `[framework_id, human_name, version]` triples the mappings were cited
    /// against.
    framework_versions: Vec<Vec<String>>,
    /// Per-control realized evidence, in catalog order.
    controls: Vec<ControlEvidenceSchema>,
    decisions_total: u64,
    findings_total: u64,
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

/// The caller org's per-agent spend rollup, highest spend first. The
/// empty-string agent is the unattributed bucket.
#[utoipa::path(
    get, path = "/v1/agents",
    responses(
        (status = 200, description = "aggregated agents, highest spend first", body = Vec<AgentAgg>),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn agents(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.agents(&org))).into_response()
}

/// The caller org's per-unit spend rollup, highest month-to-date spend first
/// (all-time spend as the tie-break; docs/20-identity-map.md section 4). A
/// run with no resolved unit rolls up under the literal `"unassigned"`
/// bucket, never a blank one. Each row carries both all-time totals and the
/// `month`/`month_spent_microusd`/`month_calls` month-to-date columns - the
/// UTC-calendar-month window the `/v1/unit-budgets` caps are enforced
/// against (see `UnitAgg`).
#[utoipa::path(
    get, path = "/v1/units",
    responses(
        (status = 200, description = "aggregated units, highest month-to-date spend first; unmapped spend rolls up under \"unassigned\"; month_* columns cover the current UTC calendar month", body = Vec<UnitAgg>),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn units(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.units(&org))).into_response()
}

/// The caller org's FinOps savings: budget-protection blocked (avoided) spend,
/// semantic-cache savings, and model-router savings, plus their total.
#[utoipa::path(
    get, path = "/v1/savings",
    responses(
        (status = 200, description = "org FinOps savings totals", body = SavingsSummary),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn savings(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.savings(&org))).into_response()
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
    // Clamp to sane bounds before the store ever sees them — belt-and-braces
    // alongside `Store::series`'s own `MAX_SERIES_BUCKETS` cap, so a request
    // like `?window=2592000s&step=1ms` can't even ask for an absurd bucket
    // count in the first place.
    let window = parse_duration_ms(q.window.as_deref())
        .unwrap_or(3_600_000)
        .min(MAX_SERIES_WINDOW_MS);
    let step = parse_duration_ms(q.step.as_deref())
        .unwrap_or(60_000)
        .max(MIN_SERIES_STEP_MS);
    let buckets = st
        .store
        .series(&org, q.run.as_deref(), window, step, now_millis());
    (StatusCode::OK, Json(buckets)).into_response()
}

/// Floor on `/v1/series`'s `step` — a step below one second buys no
/// meaningful resolution for a burn-rate chart and is exactly the lever the
/// bucket-explosion DoS pulls (`step=1ms`).
const MIN_SERIES_STEP_MS: i64 = 1_000;

/// Ceiling on `/v1/series`'s `window` — 30 days comfortably covers any sane
/// burn-rate lookback; pairing this with the step floor keeps the requested
/// bucket count in the low thousands, well under `Store::MAX_SERIES_BUCKETS`.
const MAX_SERIES_WINDOW_MS: i64 = 30 * 24 * 3_600_000;

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
    let Mutator { org, actor } = match st.authorize_mutation("POST", uri.path(), b"", &headers) {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    // Mutation + audit entry under ONE store write-lock acquisition — see
    // `Store::kill_audited`'s doc for why the two-call form (mutate, then
    // `audit_append`) leaves a window where a crash/autosave can persist the
    // kill with no matching audit entry.
    st.store.kill_audited(&org, &run, &actor);
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
    let Mutator { org, actor } = match st.authorize_mutation("POST", uri.path(), &body, &headers) {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    let parsed: BudgetBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return bad_json(),
    };
    let micros = (parsed.budget_usd * 1e6) as i64;
    // Mutation + audit entry under ONE store write-lock acquisition — see
    // `Store::set_budget_audited`'s doc.
    st.store.set_budget_audited(&org, &run, micros, &actor);
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

/// Set a central monthly budget for a unit (admin only;
/// docs/20-identity-map.md section 4). Gateways poll `/v1/unit-budgets`.
#[utoipa::path(
    post, path = "/v1/units/{id}/budget",
    params(("id" = String, Path, description = "unit id")),
    request_body = BudgetBody,
    responses(
        (status = 200, description = "unit budget set", body = UnitBudgetResponse),
        (status = 400, description = "malformed json", body = ErrorResponse),
        (status = 401, description = "unauthorized", body = ErrorResponse),
        (status = 403, description = "admin role required", body = ErrorResponse),
    ),
    tag = "mutations"
)]
async fn set_unit_budget(
    State(st): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(unit): Path<String>,
    body: Bytes,
) -> Response {
    let Mutator { org, actor } = match st.authorize_mutation("POST", uri.path(), &body, &headers) {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    let parsed: BudgetBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return bad_json(),
    };
    let micros = (parsed.budget_usd * 1e6) as i64;
    // Mutation + audit entry under ONE store write-lock acquisition - see
    // `Store::set_unit_budget_audited`'s doc.
    st.store
        .set_unit_budget_audited(&org, &unit, micros, &actor);
    (
        StatusCode::OK,
        Json(UnitBudgetResponse {
            unit,
            budget_micros: micros,
        }),
    )
        .into_response()
}

/// This org's unit → budget-micros overrides (gateways poll this every 3s;
/// see `crates/gateway/src/cloudsink.rs::spawn_unit_budget_poller`). A
/// separate endpoint from `/v1/budgets` on purpose (docs/20-identity-map.md
/// section 4): that payload is a flat `run_id -> i64` map old gateways parse
/// verbatim, so it cannot grow a nested key without breaking them.
#[utoipa::path(
    get, path = "/v1/unit-budgets",
    responses(
        (status = 200, description = "unit → budget micros"),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "mutations"
)]
async fn unit_budgets(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.unit_budgets(&org))).into_response()
}

/// The caller org's open incidents, most-recently-seen first. Readable by any
/// role (viewer or admin), like the other read endpoints.
#[utoipa::path(
    get, path = "/v1/incidents",
    responses(
        (status = 200, description = "open incidents, newest first", body = Vec<Incident>),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn incidents(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.incidents(&org))).into_response()
}

/// One finding as another service in the stack reports it. The field names
/// are Idryx's generic webhook payload verbatim (`internal/sink/webhook.go`),
/// so that service needs no adapter and no change at all: it is pointed at
/// this path and keeps posting exactly what it already posts to a SIEM.
#[derive(Deserialize, ToSchema)]
struct ExternalFinding {
    /// The detector that fired, e.g. `agent_shadow_tool`, `data_exfiltration`.
    detector: String,
    /// What it fired about. An `agent://` identity is attributed as the agent,
    /// which is what puts the finding on that agent's row in the pocket app.
    identity: String,
    /// `info` | `low` | `medium` | `high` | `critical`. Anything else is
    /// rejected rather than guessed at: severity decides whether the phone
    /// treats this as something still running or a soft heads-up, so a typo
    /// must not silently become the safest-looking answer.
    severity: String,
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    summary: String,
}

#[derive(Serialize, ToSchema)]
struct ExternalFindingsResponse {
    accepted: usize,
}

/// `POST /v1/findings`: accept detections this plane did not make.
///
/// Admin-gated through the same `authorize_mutation` every other write uses,
/// and deliberately NOT ungated like `/v1/ingest`. Ingest submits evidence
/// that thresholds still have to agree with; this asserts an incident
/// outright, which is a different authority and must not be reachable with a
/// viewer key.
#[utoipa::path(
    post, path = "/v1/findings",
    request_body = Vec<ExternalFinding>,
    responses((status = 200, description = "Findings recorded", body = ExternalFindingsResponse)),
    tag = "incidents"
)]
async fn external_findings(
    State(st): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Query(params): Query<ExternalFindingParams>,
    body: axum::body::Bytes,
) -> Response {
    let Mutator { org, actor } = match st.authorize_mutation("POST", uri.path(), &body, &headers) {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    let findings: Vec<ExternalFinding> = match serde_json::from_slice(&body) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("bad findings payload: {e}") })),
            )
                .into_response()
        }
    };
    let source = sanitize_source(params.source.as_deref());
    let now = now_millis();
    let mut accepted = 0usize;
    for f in findings {
        let Some(severity) = parse_severity(&f.severity) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("unknown severity {:?}", f.severity)
                })),
            )
                .into_response();
        };
        // The detector's own stamp is accepted but deliberately not used. A
        // finding's clock belongs to whichever service reported it, and
        // trusting it would let a skewed or hostile reporter place an incident
        // in the past, ahead of the queue's ordering or outside a dedup
        // window. Arrival time is a fact this plane knows; `time` stays in the
        // payload only so a reporter needs no adapter to talk to this route.
        let _ = &f.time;
        let ts = now;
        st.store
            .record_external_finding(&org, &actor, finding_input(&source, &f, severity, ts));
        accepted += 1;
    }
    (StatusCode::OK, Json(ExternalFindingsResponse { accepted })).into_response()
}

/// Assemble the store's input from the wire shape, in one place, so the two
/// never drift apart silently.
fn finding_input<'a>(
    source: &'a str,
    f: &'a ExternalFinding,
    severity: tokenfuse_core::Severity,
    ts_millis: i64,
) -> crate::store::FindingInput<'a> {
    crate::store::FindingInput {
        source,
        detector: &f.detector,
        severity,
        subject: &f.identity,
        summary: &f.summary,
        ts_millis,
    }
}

#[derive(Deserialize)]
struct ExternalFindingParams {
    /// Who is reporting, e.g. `?source=idryx`.
    ///
    /// It lives in the URL rather than the body precisely so the reporting
    /// service needs no code change: an operator points Idryx's existing
    /// webhook sink at `/v1/findings?source=idryx` and that service keeps
    /// posting exactly what it already posts to a SIEM. It is a LABEL, not a
    /// credential: the credential is the bearer, and which credential actually
    /// filed each finding is written to the audit trail, where identity
    /// belongs. The label only has to be readable, because an operator reading
    /// "idryx" learns something an opaque key id would never tell them.
    source: Option<String>,
}

/// Keep the label short, lowercase and boring: it is rendered on a phone next
/// to a kill button, and it is attacker-influenced in the sense that anyone
/// with an admin credential picks it.
fn sanitize_source(raw: Option<&str>) -> String {
    let cleaned: String = raw
        .unwrap_or("external")
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(32)
        .collect();
    if cleaned.is_empty() {
        "external".to_string()
    } else {
        cleaned
    }
}

fn parse_severity(s: &str) -> Option<tokenfuse_core::Severity> {
    match s.trim().to_ascii_lowercase().as_str() {
        "info" => Some(tokenfuse_core::Severity::Info),
        "low" => Some(tokenfuse_core::Severity::Low),
        "medium" => Some(tokenfuse_core::Severity::Medium),
        "high" => Some(tokenfuse_core::Severity::High),
        "critical" => Some(tokenfuse_core::Severity::Critical),
        _ => None,
    }
}

/// Acknowledge an incident (admin only). Sets `acknowledged = true`.
#[utoipa::path(
    post, path = "/v1/incidents/{id}/ack",
    params(("id" = String, Path, description = "incident id")),
    responses(
        (status = 200, description = "incident acknowledged", body = AckResponse),
        (status = 401, description = "unauthorized", body = ErrorResponse),
        (status = 403, description = "admin role required", body = ErrorResponse),
        (status = 404, description = "unknown incident", body = ErrorResponse),
    ),
    tag = "mutations"
)]
async fn ack_incident(
    State(st): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
) -> Response {
    let Mutator { org, actor } = match st.authorize_mutation("POST", uri.path(), b"", &headers) {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    // Mutation + audit entry under ONE store write-lock acquisition — see
    // `Store::ack_incident_audited`'s doc. Preserves not-found → 404: no audit
    // entry is written when the incident id doesn't exist.
    if st.store.ack_incident_audited(&org, &id, &actor) {
        (StatusCode::OK, Json(AckResponse { acknowledged: id })).into_response()
    } else {
        error(StatusCode::NOT_FOUND, "unknown incident")
    }
}

/// The caller org's compliance evidence pack: the control catalog projected
/// against the org's live decision + incident evidence. Readable by any role
/// (like the other reads).
///
/// The cloud path has **incident** evidence but no **finding** evidence: MCP
/// scans aren't ingested to the control plane, so the findings map is empty
/// here. This is the exact mirror of the CLI path (`compute_compliance`), which
/// has scan findings but no incidents — both are honest partial views, and both
/// go through the same `compute_compliance_from_counts` kernel.
#[utoipa::path(
    get, path = "/v1/compliance",
    responses(
        (status = 200, description = "compliance evidence pack", body = ComplianceReportSchema),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn compliance(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    // Findings map is intentionally empty: scans aren't ingested to the plane
    // (see the fn doc). Incident evidence comes from the folded incident kinds.
    let report = tokenfuse_core::compliance::compute_compliance_from_counts(
        tokenfuse_core::compliance::CATALOG,
        &st.store.decision_counts(&org),
        &std::collections::BTreeMap::new(),
        &st.store.incident_kind_counts(&org),
    );
    (StatusCode::OK, Json(report)).into_response()
}

/// Honesty classification for one control in the regulator evidence pack
/// (`/v1/compliance/evidence`), decided from THIS org's live data, not a
/// static catalog claim: `Enforced` only when the org has produced concrete
/// evidence the control fired; `Partial` when the mechanism is caveated (see
/// `evidence_status`) or an integrity check itself failed; `Documented`
/// otherwise (implemented and described, but no evidence yet for this org).
/// Serialized as the bare variant name (`"Enforced"` / `"Partial"` /
/// `"Documented"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
enum EvidenceStatus {
    Enforced,
    Partial,
    Documented,
}

/// One control's entry in a regulator evidence-pack framework section: the
/// TokenFuse control plus the external clause it is cited against, honestly
/// graded, and the concrete signal the grade was decided from.
#[derive(Debug, Clone, Serialize, ToSchema)]
struct EvidenceControl {
    control: String,
    status: EvidenceStatus,
    evidence: String,
}

/// A regulator evidence pack: the same live decision/incident/audit data
/// behind `/v1/compliance`, additionally mapped to three external framework
/// sections and honestly graded per control (see `EvidenceStatus`). Read-only
/// and additive: this changes no stored state and does not affect
/// enforcement; it exists so an operator can hand a regulator a mapped,
/// evidence-backed view without the `/v1/compliance` contract itself moving.
#[derive(Debug, Clone, Serialize, ToSchema)]
struct EvidencePackResponse {
    /// Standing disclaimer, shared with `/v1/compliance`: evidence, not a
    /// certification.
    generated_note: &'static str,
    org: String,
    eu_ai_act: Vec<EvidenceControl>,
    /// US Federal Reserve SR 11-7 model-risk-management guidance.
    sr_11_7: Vec<EvidenceControl>,
    soc2: Vec<EvidenceControl>,
    /// Whether this org's audit chain verifies end-to-end right now (see
    /// `Store::audit_verify`).
    audit_chain_verified: bool,
    /// 0-based index of the first broken link, when `audit_chain_verified` is
    /// `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_break_index: Option<usize>,
    audit_entries: u64,
    decisions_total: u64,
    incidents_total: u64,
}

/// A regulator evidence pack: the org's live decision/incident/audit evidence
/// mapped to three external framework sections (EU AI Act, US SR 11-7
/// model-risk guidance, SOC 2) and honestly graded per control. A second view
/// over data `/v1/compliance` already exposes, never a new signal and never a
/// mutation; see `EvidenceStatus`'s doc for exactly how a grade is decided.
/// Readable by any role, like the other reads.
#[utoipa::path(
    get, path = "/v1/compliance/evidence",
    responses(
        (status = 200, description = "regulator evidence pack", body = EvidencePackResponse),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn compliance_evidence(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };

    let decision_counts = st.store.decision_counts(&org);
    let incident_kind_counts = st.store.incident_kind_counts(&org);
    // Same kernel `/v1/compliance` uses, so the two endpoints never drift on
    // what "this control observed evidence" means.
    let report = compute_compliance_from_counts(
        CATALOG,
        &decision_counts,
        &std::collections::BTreeMap::new(),
        &incident_kind_counts,
    );
    let evidence_by_id: HashMap<&str, &ControlEvidence> =
        report.controls.iter().map(|c| (c.control_id, c)).collect();

    let audit_entries = st.store.audit(&org);
    let audit_result = st.store.audit_verify(&org);
    let (audit_status, audit_evidence) = audit_chain_status(audit_entries.len(), audit_result);

    let mut eu_ai_act = catalog_section("EU-AI-ACT", &evidence_by_id);
    eu_ai_act.push(audit_control(
        "Art. 12 (Record-keeping)",
        audit_status,
        &audit_evidence,
    ));

    let mut soc2 = catalog_section("SOC2", &evidence_by_id);
    soc2.push(audit_control(
        "CC7.2 (System Monitoring)",
        audit_status,
        &audit_evidence,
    ));

    let sr_11_7 = vec![
        model_use_controls(&decision_counts),
        ongoing_monitoring(&incident_kind_counts),
        audit_control(
            "Governance, Policies, and Controls",
            audit_status,
            &audit_evidence,
        ),
    ];

    let (audit_chain_verified, audit_break_index) = match audit_result {
        Ok(()) => (true, None),
        Err(i) => (false, Some(i)),
    };

    let body = EvidencePackResponse {
        generated_note: DISCLAIMER,
        org,
        eu_ai_act,
        sr_11_7,
        soc2,
        audit_chain_verified,
        audit_break_index,
        audit_entries: audit_entries.len() as u64,
        decisions_total: decision_counts.values().sum(),
        incidents_total: incident_kind_counts.values().sum(),
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// Project `CATALOG`'s controls that cite `framework_id` into evidence-pack
/// entries. A nominally `Enforced` catalog control is honestly downgraded to
/// `Documented` when this org has produced no concrete evidence for it yet
/// (see `evidence_status`): the evidence pack cites what actually happened
/// for THIS org, not what the catalog nominally wires up.
///
/// `TF.AUDIT` is skipped here: its catalog entry predates this org's shipped
/// tamper-evident chain (the catalog text still says the hash chain "is not
/// yet implemented", which is stale now that `crates/core/src/audit.rs` and
/// `crates/cloud/src/audit_sign.rs` implement it). Rather than repeat that
/// stale claim, every section's audit-chain entry is computed straight from
/// the live chain instead (`audit_control`), which is a strictly stronger,
/// fresher signal than the static catalog text.
fn catalog_section(
    framework_id: &str,
    evidence_by_id: &HashMap<&str, &ControlEvidence>,
) -> Vec<EvidenceControl> {
    let mut out = Vec::new();
    for c in CATALOG {
        if c.control_id == "TF.AUDIT" {
            continue;
        }
        for fw in c.frameworks {
            if fw.0 != framework_id {
                continue;
            }
            let Some(ce) = evidence_by_id.get(c.control_id).copied() else {
                continue;
            };
            out.push(EvidenceControl {
                control: format!("{} ({}) - {}", c.control_id, c.title, fw.1),
                status: evidence_status(ce),
                evidence: control_evidence_text(ce),
            });
        }
    }
    out
}

/// Honest per-org status for one catalog control's realized evidence. A
/// `Partial`/`Documented` catalog classification is never upgraded (this pack
/// makes no claim the codebase itself doesn't make); an `Enforced`
/// classification is held down to `Documented` unless this org's live data
/// actually shows the control firing (`evidence_seen`): wired but silent does
/// not earn `Enforced` in a pack whose whole point is proving it ran.
fn evidence_status(ce: &ControlEvidence) -> EvidenceStatus {
    match ce.enforcement {
        Enforcement::Documented => EvidenceStatus::Documented,
        Enforcement::Partial => EvidenceStatus::Partial,
        Enforcement::Enforced if ce.evidence_seen => EvidenceStatus::Enforced,
        Enforcement::Enforced => EvidenceStatus::Documented,
    }
}

/// Render a control's watched decision/finding/incident counts as a short,
/// human-readable evidence string, e.g. `"budget_exceeded=3, incidents=1"`.
fn control_evidence_text(ce: &ControlEvidence) -> String {
    let mut bits: Vec<String> = ce
        .decision_counts
        .iter()
        .chain(ce.finding_counts.iter())
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    if ce.incident_count > 0 {
        bits.push(format!("incidents={}", ce.incident_count));
    }
    if bits.is_empty() {
        "no watched signal for this org yet".to_string()
    } else {
        bits.join(", ")
    }
}

/// Live status + evidence text for the tamper-evident audit chain, shared by
/// all three framework sections' audit-chain entry (only the external
/// citation differs per section, via `audit_control`'s `citation` argument).
/// `entries == 0` reads `Documented` (nothing recorded yet, so "verifies"
/// would be vacuous); a verified, non-empty chain reads `Enforced`; a BROKEN
/// chain reads `Partial`, never `Enforced` (the assurance failed) and never
/// silently `Documented` either (the detector did run, and did catch
/// something, which is itself evidence the control is live).
fn audit_chain_status(entries: usize, verify: Result<(), usize>) -> (EvidenceStatus, String) {
    match verify {
        Ok(()) if entries > 0 => (
            EvidenceStatus::Enforced,
            format!("audit chain verifies intact over {entries} entries"),
        ),
        Ok(()) => (
            EvidenceStatus::Documented,
            "audit chain configured; no mutations recorded yet".to_string(),
        ),
        Err(i) => (
            EvidenceStatus::Partial,
            format!(
                "audit chain verification FAILED at entry {i} of {entries}; integrity compromised"
            ),
        ),
    }
}

/// Build one framework section's audit-chain entry from a precomputed
/// `audit_chain_status` result, varying only the cited external clause.
fn audit_control(citation: &str, status: EvidenceStatus, evidence: &str) -> EvidenceControl {
    EvidenceControl {
        control: format!("TF.AUDIT (Tamper-evident audit trail) - {citation}"),
        status,
        evidence: evidence.to_string(),
    }
}

/// SR 11-7 "Model Development, Implementation, and Use": the runtime limits
/// that bound what a model/agent is allowed to spend or do (budget breaker,
/// loop breaker, operator kill-switch).
fn model_use_controls(
    decision_counts: &std::collections::BTreeMap<String, u64>,
) -> EvidenceControl {
    let watched = ["budget_exceeded", "loop_detected", "killed"];
    let bits: Vec<String> = watched
        .iter()
        .map(|k| format!("{k}={}", decision_counts.get(*k).copied().unwrap_or(0)))
        .collect();
    let seen = watched
        .iter()
        .any(|k| decision_counts.get(*k).copied().unwrap_or(0) > 0);
    EvidenceControl {
        control: "SR 11-7 Model Development, Implementation, and Use - runtime spend/behavior \
                  limits (budget breaker, loop breaker, kill-switch)"
            .to_string(),
        status: if seen {
            EvidenceStatus::Enforced
        } else {
            EvidenceStatus::Documented
        },
        evidence: bits.join(", "),
    }
}

/// SR 11-7 "Model Validation": ongoing performance/anomaly monitoring, from
/// the cloud's own incident detectors (budget exhaustion, sustained loops,
/// spend spikes, fanout explosions).
fn ongoing_monitoring(
    incident_kind_counts: &std::collections::BTreeMap<String, u64>,
) -> EvidenceControl {
    let seen: u64 = incident_kind_counts.values().sum();
    let bits: Vec<String> = incident_kind_counts
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    EvidenceControl {
        control: "SR 11-7 Model Validation - ongoing performance/anomaly monitoring (cloud \
                  incident detectors)"
            .to_string(),
        status: if seen > 0 {
            EvidenceStatus::Enforced
        } else {
            EvidenceStatus::Documented
        },
        evidence: if bits.is_empty() {
            "no incidents recorded for this org yet".to_string()
        } else {
            bits.join(", ")
        },
    }
}

/// The caller org's tamper-evident audit trail of control-plane mutations,
/// oldest first. Readable by any role (like the other reads).
#[utoipa::path(
    get, path = "/v1/audit",
    responses(
        (status = 200, description = "audit chain, oldest first", body = Vec<AuditEntrySchema>),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn audit(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    (StatusCode::OK, Json(st.store.audit(&org))).into_response()
}

/// Verify the caller org's audit chain end-to-end: `{ok:true}` when intact, else
/// `{ok:false, break_index:N}` at the first broken link.
#[utoipa::path(
    get, path = "/v1/audit/verify",
    responses(
        (status = 200, description = "chain integrity", body = AuditVerifyResponse),
        (status = 401, description = "unauthorized", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn audit_verify(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    let body = match st.store.audit_verify(&org) {
        Ok(()) => AuditVerifyResponse {
            ok: true,
            break_index: None,
        },
        Err(i) => AuditVerifyResponse {
            ok: false,
            break_index: Some(i),
        },
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// A cryptographically-signed manifest over the caller org's audit chain tip:
/// an ES256 signature (server P-256 key) an auditor can verify offline to prove
/// the log ended at this entry, unaltered. Readable by any role (like the other
/// audit reads). When no signing key is configured the server returns
/// `404 {"error":"audit manifest signing not configured"}` (never a `500`);
/// the rest of the audit trail is unaffected.
#[utoipa::path(
    get, path = "/v1/audit/manifest",
    responses(
        (status = 200, description = "signed manifest over the chain tip", body = AuditManifest),
        (status = 401, description = "unauthorized", body = ErrorResponse),
        (status = 404, description = "manifest signing not configured", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn audit_manifest(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    let Some(key) = st.audit_signing_key.as_ref() else {
        return error(
            StatusCode::NOT_FOUND,
            "audit manifest signing not configured",
        );
    };
    let manifest = st.store.audit_manifest(&org, key, now_millis());
    (StatusCode::OK, Json(manifest)).into_response()
}

/// Replay of one run: its ordered agent-event timeline (if
/// `TOKENFUSE_CLOUD_REPLAY_EVENTS` is configured), joined with the run's
/// incidents and any audit-chain entries that reference it. `RunAgg` is an
/// aggregate only, with no ordered per-call list, so the timeline itself
/// comes from the append-only agent-event NDJSON export (see
/// `crate::replay`), not the in-memory store. Read-only: no enforcement or
/// stored state changes. The run must belong to the caller's org or this
/// 404s (never leaks whether a run id exists for a different org).
#[utoipa::path(
    get, path = "/v1/replay/{run}",
    params(("run" = String, Path, description = "run id")),
    responses(
        (status = 200, description = "ordered replay of one run", body = ReplayResponse),
        (status = 401, description = "unauthorized", body = ErrorResponse),
        (status = 404, description = "unknown run for this org", body = ErrorResponse),
    ),
    tag = "reads"
)]
async fn replay(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(run): Path<String>,
) -> Response {
    let Some(org) = st.org_for(&headers) else {
        return unauthorized();
    };
    // Scope to the caller's own org BEFORE returning anything about `run`, so
    // a run id belonging to a different org 404s exactly like an unknown one.
    if !st.store.run_belongs_to_org(&org, &run) {
        return error(StatusCode::NOT_FOUND, "unknown run");
    }

    let (events, malformed_skipped) = match st.replay_events_path.as_deref() {
        Some(path) => read_run_events(path, &run),
        None => (Vec::new(), 0),
    };
    let event_count = events.len();

    let incidents: Vec<Incident> = st
        .store
        .incidents(&org)
        .into_iter()
        .filter(|i| i.run_id.as_deref() == Some(run.as_str()))
        .collect();

    // Every audited mutation records what it acted on as `subject` (a kill or
    // budget change's subject is the run id itself; see `Store::kill_audited`
    // / `Store::set_budget_audited`).
    let audit: Vec<AuditEntry> = st
        .store
        .audit(&org)
        .into_iter()
        .filter(|e| e.subject == run)
        .collect();

    (
        StatusCode::OK,
        Json(ReplayResponse {
            run_id: run,
            configured: st.replay_events_path.is_some(),
            events,
            event_count,
            malformed_skipped,
            incidents,
            audit,
        }),
    )
        .into_response()
}

/// Response body for `GET /v1/replay/{run}`.
#[derive(Serialize, ToSchema)]
struct ReplayResponse {
    run_id: String,
    /// Whether `TOKENFUSE_CLOUD_REPLAY_EVENTS` is configured on this server
    /// (independent of whether any events matched this run).
    configured: bool,
    /// This run's agent-events, ts-ascending.
    events: Vec<ReplayEvent>,
    event_count: usize,
    /// NDJSON lines in the configured file that failed to parse (skipped, not
    /// counted as this run's events).
    malformed_skipped: usize,
    /// This run's open incidents (see `Store::incidents`).
    incidents: Vec<Incident>,
    /// Audit-chain entries whose subject is this run (e.g. kills, budget
    /// changes), oldest first.
    #[schema(value_type = Vec<AuditEntrySchema>)]
    audit: Vec<AuditEntry>,
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
        Ok(v) => v,
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
    // A new device joining the org is a control-plane change. The device
    // self-redeemed (no bearer auth — the code was the credential), so the
    // actor is the device itself; the admin authorization happened earlier at
    // `pair/new`. Device registration + its `control.pair` audit entry are
    // folded into ONE store write-lock acquisition — see
    // `Store::redeem_pairing_audited`'s doc.
    match st.store.redeem_pairing_audited(
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

/// A stable, non-secret actor id for an API key: `key:` + the first 12 hex
/// chars of `sha256(token)`. The raw key is a bearer *secret*, so it must never
/// land in the audit trail; the fingerprint identifies *which* key acted
/// without leaking it (and is stable across restarts).
fn key_actor(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::from("key:");
    for b in digest.iter().take(6) {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
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
