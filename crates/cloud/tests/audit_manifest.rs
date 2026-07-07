//! HTTP-level tests for the signed audit manifest (P3 WS2 follow-up), mirroring
//! `tests/audit.rs`: with a signing key configured, `GET /v1/audit/manifest`
//! returns a manifest whose ES256 signature verifies (independently, with
//! `p256`) against the embedded public key over the canonical bytes; the tip
//! moves when the chain grows; an empty chain still signs a zero-tip manifest;
//! without a key the endpoint reports not-configured (`404`, not `500`); and it
//! is viewer-readable, auth-required, and gated as a paid feature.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine};
use http_body_util::BodyExt;
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use tower::ServiceExt;

use tokenfuse_cloud::{app, AppState, Plan, Principal, Store};

/// A deterministic P-256 signing key for tests (fixed scalar, no RNG), matching
/// the `devices.rs` test-key pattern.
fn test_key() -> SigningKey {
    SigningKey::from_slice(&[0x11u8; 32]).expect("valid scalar")
}

fn keys() -> HashMap<String, Principal> {
    let mut keys = HashMap::new();
    keys.insert(
        "devkey".into(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
            plan: Plan::Paid,
        },
    );
    keys.insert(
        "viewerkey".into(),
        Principal {
            org: "acme".into(),
            role: "viewer".into(),
            plan: Plan::Paid,
        },
    );
    // A separate org on the free plan, to prove the manifest is gated.
    keys.insert(
        "freekey".into(),
        Principal {
            org: "freeco".into(),
            role: "admin".into(),
            plan: Plan::Free,
        },
    );
    keys
}

/// State with the audit-manifest signing key configured.
fn state_with_key() -> AppState {
    AppState::new(Arc::new(Store::new()), Arc::new(keys()), 0.8)
        .with_audit_signing_key(Some(test_key()))
}

/// State with NO signing key (manifest signing disabled).
fn state_no_key() -> AppState {
    AppState::new(Arc::new(Store::new()), Arc::new(keys()), 0.8)
}

async fn send(
    state: &AppState,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(k) = key {
        req = req.header("authorization", format!("Bearer {k}"));
    }
    let req = req
        .body(
            body.map(|b| Body::from(b.to_owned()))
                .unwrap_or(Body::empty()),
        )
        .unwrap();
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

/// Verify a manifest JSON's ES256 signature against its embedded public key over
/// the canonical bytes — exactly as an offline auditor would, with `p256` and
/// the pure `tokenfuse_core::audit::manifest_signing_bytes`.
fn verify_manifest(m: &serde_json::Value) -> bool {
    let org = m["org"].as_str().unwrap();
    let tip_seq = m["tip_seq"].as_u64().unwrap();
    let tip_hash = m["tip_hash"].as_str().unwrap();
    let entry_count = m["entry_count"].as_u64().unwrap();
    let signed_at = m["signed_at_millis"].as_i64().unwrap();
    let pk = STANDARD
        .decode(m["public_key_b64"].as_str().unwrap())
        .unwrap();
    let sig = STANDARD
        .decode(m["signature_b64"].as_str().unwrap())
        .unwrap();
    let vk = VerifyingKey::from_sec1_bytes(&pk).expect("sec1 pubkey");
    let sig = Signature::from_slice(&sig).expect("sig");
    let bytes = tokenfuse_core::audit::manifest_signing_bytes(
        org,
        tip_seq,
        tip_hash,
        entry_count,
        signed_at,
    );
    vk.verify(&bytes, &sig).is_ok()
}

#[tokio::test]
async fn manifest_signature_verifies_and_matches_chain() {
    let state = state_with_key();

    // Two authenticated control-plane mutations → a two-entry chain.
    let (s, _) = send(&state, "POST", "/v1/runs/run-1/kill", Some("devkey"), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(
        &state,
        "POST",
        "/v1/runs/run-1/budget",
        Some("devkey"),
        Some(r#"{"budget_usd":2.5}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // A viewer of the org may read the manifest (like the other audit reads).
    let (status, m) = send(&state, "GET", "/v1/audit/manifest", Some("viewerkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(m["algorithm"], "ES256");
    assert_eq!(m["org"], "acme");
    assert_eq!(m["entry_count"], 2);
    assert_eq!(m["tip_seq"], 1);

    // The signature verifies against the embedded public key.
    assert!(verify_manifest(&m), "manifest signature must verify");

    // tip_hash / tip_seq / entry_count match the actual chain tip.
    let (_, chain) = send(&state, "GET", "/v1/audit", Some("viewerkey"), None).await;
    let entries = chain.as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(m["tip_hash"], entries[1]["entry_hash"]);
    assert_eq!(m["tip_seq"], entries[1]["seq"]);
}

#[tokio::test]
async fn manifest_tip_moves_after_a_new_mutation() {
    let state = state_with_key();

    // One mutation, then a manifest pinning that tip.
    let (s, _) = send(&state, "POST", "/v1/runs/r1/kill", Some("devkey"), None).await;
    assert_eq!(s, StatusCode::OK);
    let (_, a) = send(&state, "GET", "/v1/audit/manifest", Some("devkey"), None).await;
    assert_eq!(a["entry_count"], 1);
    assert!(verify_manifest(&a));

    // A further mutation moves the chain tip; the re-derived manifest's tip_hash
    // differs, so an auditor holding `a` sees the log has advanced past it.
    let (s, _) = send(
        &state,
        "POST",
        "/v1/runs/r1/budget",
        Some("devkey"),
        Some(r#"{"budget_usd":1.0}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, b) = send(&state, "GET", "/v1/audit/manifest", Some("devkey"), None).await;
    assert_eq!(b["entry_count"], 2);
    assert_ne!(a["tip_hash"], b["tip_hash"]);
    assert!(verify_manifest(&b));
}

#[tokio::test]
async fn empty_chain_signs_a_valid_zero_tip_manifest() {
    let state = state_with_key();

    // No mutations logged for acme yet.
    let (status, m) = send(&state, "GET", "/v1/audit/manifest", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(m["tip_seq"], 0);
    assert_eq!(m["entry_count"], 0);
    assert_eq!(m["tip_hash"], "");
    assert_eq!(m["algorithm"], "ES256");
    // Still a real, unforgeable signature over the "no entries" attestation.
    assert!(verify_manifest(&m));
}

#[tokio::test]
async fn not_configured_returns_404_not_500() {
    let state = state_no_key();

    let (status, v) = send(&state, "GET", "/v1/audit/manifest", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(v["error"], "audit manifest signing not configured");
}

#[tokio::test]
async fn manifest_requires_auth() {
    let state = state_with_key();

    let (no_key, _) = send(&state, "GET", "/v1/audit/manifest", None, None).await;
    assert_eq!(no_key, StatusCode::UNAUTHORIZED);
    let (wrong_key, _) = send(&state, "GET", "/v1/audit/manifest", Some("nope"), None).await;
    assert_eq!(wrong_key, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn manifest_is_gated_for_free_plan() {
    // Even with a signing key configured, a `:free` org is refused with 402.
    let state = state_with_key();

    let (status, v) = send(&state, "GET", "/v1/audit/manifest", Some("freekey"), None).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(v["error"]["type"], "plan_required");
    assert_eq!(v["error"]["feature"], "audit");
}
