//! End-to-end pairing + Enclave-signed-mutation tests (A8), covering the plan's
//! acceptance: happy path with a static P-256 key, replay rejection, stale
//! timestamp rejection, and a viewer device being unable to mutate. Reads and
//! org-key admin mutations must keep working alongside the signed path.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine};
use http_body_util::BodyExt;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use tower::ServiceExt;

use tokenfuse_cloud::devices::canonical_string;
use tokenfuse_cloud::{app, AppState, Principal, Store};

fn state() -> AppState {
    let mut keys = HashMap::new();
    keys.insert(
        "adm".into(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
        },
    );
    AppState::new(Arc::new(Store::new()), Arc::new(keys), 0.8)
}

fn keypair() -> (SigningKey, String) {
    let sk = SigningKey::from_slice(&[0x11u8; 32]).expect("valid scalar");
    let pubkey_b64 = STANDARD.encode(sk.verifying_key().to_encoded_point(false).as_bytes());
    (sk, pubkey_b64)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

/// Issue a pairing code (optionally a specific role) and redeem it with `pubkey`.
/// Returns (device_id, device_token).
async fn pair_device(state: &AppState, pubkey_b64: &str, role: Option<&str>) -> (String, String) {
    let new_body = match role {
        Some(r) => format!(r#"{{"role":"{r}"}}"#),
        None => "{}".to_string(),
    };
    let (st, v) = send(
        state,
        Request::post("/v1/pair/new")
            .header("authorization", "Bearer adm")
            .body(Body::from(new_body))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "pair/new failed: {v}");
    let code = v["code"].as_str().unwrap().to_string();

    let pair_body = format!(
        r#"{{"code":"{code}","pubkey_b64":"{pubkey_b64}","platform":"ios","name":"test iphone"}}"#
    );
    let (st, v) = send(
        state,
        Request::post("/v1/pair")
            .body(Body::from(pair_body))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "pair failed: {v}");
    (
        v["device_id"].as_str().unwrap().to_string(),
        v["device_token"].as_str().unwrap().to_string(),
    )
}

/// A signed POST kill request for `run` with explicit ts/nonce.
fn signed_kill(
    sk: &SigningKey,
    device_id: &str,
    token: &str,
    run: &str,
    ts: i64,
    nonce: &str,
) -> Request<Body> {
    let path = format!("/v1/runs/{run}/kill");
    let canonical = canonical_string("POST", &path, b"", &ts.to_string(), nonce);
    let sig: Signature = sk.sign(canonical.as_bytes());
    Request::post(&path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-fuse-device", device_id)
        .header("x-fuse-ts", ts.to_string())
        .header("x-fuse-nonce", nonce)
        .header("x-fuse-sig", STANDARD.encode(sig.to_bytes()))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn signed_mutation_happy_path_and_replay() {
    let state = state();
    let (sk, pubkey) = keypair();
    let (device_id, token) = pair_device(&state, &pubkey, None).await;

    // A device token authorizes reads.
    let (st, _) = send(
        &state,
        Request::get("/v1/runs")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // A correctly signed kill is accepted.
    let (st, v) = send(
        &state,
        signed_kill(&sk, &device_id, &token, "r1", now_unix(), "nonce-1"),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "signed kill rejected: {v}");
    assert_eq!(v["killed"], "r1");

    // Replaying the same nonce is rejected.
    let (st, _) = send(
        &state,
        signed_kill(&sk, &device_id, &token, "r1", now_unix(), "nonce-1"),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn stale_timestamp_is_rejected() {
    let state = state();
    let (sk, pubkey) = keypair();
    let (device_id, token) = pair_device(&state, &pubkey, None).await;
    let stale = now_unix() - 1000; // > 120s skew
    let (st, _) = send(
        &state,
        signed_kill(&sk, &device_id, &token, "r1", stale, "nonce-x"),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn wrong_key_signature_is_rejected() {
    let state = state();
    let (_sk, pubkey) = keypair();
    let (device_id, token) = pair_device(&state, &pubkey, None).await;
    // Sign with a different key than the one registered.
    let attacker = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
    let (st, _) = send(
        &state,
        signed_kill(&attacker, &device_id, &token, "r1", now_unix(), "nonce-y"),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn viewer_device_cannot_mutate() {
    let state = state();
    let (sk, pubkey) = keypair();
    let (device_id, token) = pair_device(&state, &pubkey, Some("viewer")).await;
    // Even a correctly signed request is forbidden for a viewer device.
    let (st, _) = send(
        &state,
        signed_kill(&sk, &device_id, &token, "r1", now_unix(), "nonce-z"),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // ...but it may still read.
    let (st, _) = send(
        &state,
        Request::get("/v1/summary")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn org_key_admin_still_mutates_without_a_signature() {
    let state = state();
    let (st, v) = send(
        &state,
        Request::post("/v1/runs/r9/kill")
            .header("authorization", "Bearer adm")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["killed"], "r9");
}

/// A signed POST to `path` with `body` from a paired device.
fn signed_post(
    sk: &SigningKey,
    device_id: &str,
    token: &str,
    path: &str,
    body: &str,
    ts: i64,
    nonce: &str,
) -> Request<Body> {
    let canonical = canonical_string("POST", path, body.as_bytes(), &ts.to_string(), nonce);
    let sig: Signature = sk.sign(canonical.as_bytes());
    Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-fuse-device", device_id)
        .header("x-fuse-ts", ts.to_string())
        .header("x-fuse-nonce", nonce)
        .header("x-fuse-sig", STANDARD.encode(sig.to_bytes()))
        .body(Body::from(body.to_owned()))
        .unwrap()
}

#[tokio::test]
async fn device_registers_its_apns_token() {
    let state = state();
    let (sk, pubkey) = keypair();
    let (device_id, token) = pair_device(&state, &pubkey, None).await;

    let body = r#"{"token":"apns-abc"}"#;
    let path = format!("/v1/devices/{device_id}/apns");
    let (st, v) = send(
        &state,
        signed_post(&sk, &device_id, &token, &path, body, now_unix(), "n-apns"),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "apns register failed: {v}");

    let devices = state.store.devices_for_org("acme");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].apns_token.as_deref(), Some("apns-abc"));
}

#[tokio::test]
async fn cannot_register_apns_for_a_different_device_id() {
    let state = state();
    let (sk, pubkey) = keypair();
    let (device_id, token) = pair_device(&state, &pubkey, None).await;

    // Sign for the wrong device id in the path; X-Fuse-Device is the real one.
    let body = r#"{"token":"apns-abc"}"#;
    let path = "/v1/devices/someone-else/apns";
    let (st, _) = send(
        &state,
        signed_post(&sk, &device_id, &token, path, body, now_unix(), "n-apns2"),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}
