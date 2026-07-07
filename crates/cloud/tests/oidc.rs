//! HTTP-level + unit tests for the offline OIDC/JWT bearer auth (WS4). A fixture
//! RSA key signs tokens in-test; a matching static JWKS is handed to an
//! `OidcConfig`. We prove: a valid token reads and (as admin) mutates with an
//! `oidc:*` audit actor; every malformed/forged/expired/wrong-claim token is
//! rejected `401`; and — crucially — API-key auth is unchanged when OIDC is off
//! and still takes precedence when it is on.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use tower::ServiceExt;

use tokenfuse_cloud::{app, verify_id_token, AppState, OidcConfig, Plan, Principal, Store};

const ISSUER: &str = "https://idp.example.com";
const AUDIENCE: &str = "tokenfuse-cloud";
const KID: &str = "test-key-1";

/// JWKS holding the public half of `KEY1_PEM` (kid `test-key-1`).
const JWKS: &str = r#"{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"test-key-1","n":"1AS-0OhDEXJLsz8X9gid8vzb-7nhyptCQSQ6MAvmJam2g4yv8gOiWuzrLhW9noAqqB1jhK-lzL2_ffkBQxaOJKKcTJKluq3pUjacFLrrqnfZA39Dl2FT8547gl05OBbRD2ZxaC-RJkFXJbVleKHd3r1Zs6vv9GEm42f3r5hay-0BhPblRjGXRqnYF9EMOA07ZamWnABihzn9Mb-Mht8sWty1vYvNP6Y7vMP6ftHnp4Jf3BrU-5lrrTHlMmfM5cIKp2GdtAGM1_gBJDGUU2F3BhBPFFZ6vPiq8HbS-cZvtR9JFpeZh_IOGdxcr32kH23mxum06ONsqywCFuR0AWOuJQ","e":"AQAB"}]}"#;

/// Fixture private key whose public half is in `JWKS`.
const KEY1_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDUBL7Q6EMRckuz
Pxf2CJ3y/Nv7ueHKm0JBJDowC+YlqbaDjK/yA6Ja7OsuFb2egCqoHWOEr6XMvb99
+QFDFo4kopxMkqW6relSNpwUuuuqd9kDf0OXYVPznjuCXTk4FtEPZnFoL5EmQVcl
tWV4od3evVmzq+/0YSbjZ/evmFrL7QGE9uVGMZdGqdgX0Qw4DTtlqZacAGKHOf0x
v4yG3yxa3LW9i80/pju8w/p+0eengl/cGtT7mWutMeUyZ8zlwgqnYZ20AYzX+AEk
MZRTYXcGEE8UVnq8+KrwdtL5xm+1H0kWl5mH8g4Z3FyvfaQfbebG6bTo42yrLAIW
5HQBY64lAgMBAAECggEADJldl3994M8IdZXlwB6h+DsTfYF9y/Lu/H0BIjLK0ekk
aevV1s1le/7BOQNcucsG/eeFLvDbKvAJrZw6+XghKUcqf5hlVdMY3uRU4Rx8faxS
jpUk+J11hjAcfDI7ALzGXqJpUdYly36thZWieokv7JkW+AjbIQwW6gOXIe2tU5nd
qc+k+Mh/AP9QuKCexFtlJ6jY6t5ZAX3upQLz9A1ay/1z5RXNzjnrgp6saFhlF5zc
Fb7bl92JrYavkp6gGvqNBCOVLwGVQnYXAAvrtMmNdpGeEvmBuysXJkgmMWG+pJo+
pcJytUaOHaQnwVnJd/spA6h12ZZ22TAv3hgqfMfmLwKBgQD8vulhV44XrKLayq/r
6pradndl7wSatASkRK56cK75HJXpQGbFAHQ5a96y5TRcW7sCCikL0TP6z9ViIMjd
wj47RAlEmgCuEWN+m6pduSIlm+vBtnBNLFK+IVDaIeMpasRJOQvEdiXAxcJYRdRD
pVx3xT4mAF60OOpehQKn+ftL2wKBgQDWv5c1e9Y5285HnfWeDXoq1PfYrUt1RiXb
rJNTCACebqxMmfSxNqKYapXfHXUW0Lp4PPZ2p7WAcHt/uqzKBnNHRh62E3ptYdH5
NOMgEzaXgvwd1+2w47bldJSag2yOzgcKg5VVPE97GWIzHbyEamHThnyfszh5O7pa
8s3f0XsN/wKBgGblbmwT0iRvQynh5LceHwcbvcZBBdXZvh4GXCY64/FFIv8AGhbP
9YE/Gj4otCV5ruvIqSdHd2r/2/aENGKb5uwH6eIE9IvpRmFQDI71hSJclSGbHaM9
jT4coCb+LtY4wkqxL8o+82XE3TdEzoLvunKEWaXs9qFWnov2iLtMOXOLAoGBAJWK
gzxuSOavhvzeJXzze6A5/4F2Y7Z9q71Gdqz6RJwPC5KoHvoMxrsGdekRtUi2/zLd
mO9VqBGRwp5Wmx5v0XTPgnFeLQHgfXxhdMwQNRLa1r/dbpqgZ+tu/FCAtmbXV5Xd
vW7Geb6KFZTs3ysCfa7z1vLKtcfObN4KeIykbmF3AoGASSKePOYmSXRxMjiZOQNX
7FOZpgoCGtaCxmJNKf1uLRLvVif5Z0pKTCjS83NcyOYSucb10FinC5m27x7YBKCX
dh3J9Q9K/JiBTKhW0Zwn7CD6I7RqUUONzJX3rPiv08z9VW1e8mPtfcrT3MVS3aCC
yyuNSwNVs/LTnw7nI9Ius8M=
-----END PRIVATE KEY-----";

/// A *different* fixture key, not in the JWKS — used to forge a bad signature.
const KEY2_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDB7+UeYCSIdRTX
igdYvzwXfNFn98/JJ3Wxhg77lopSqy1mNZU1bBC6ciDYMGaj32edhiudDFyUefwg
Y2WWYac3lcMWM/V65Bil5lYlnkQpRMJ+ViLGHfWTKSNMwRCDYLd5C1ibld/p88J0
SNH2KJJvY06uQrAH3uYkLk5d41Ge3dYVbHEAGRMUMvN+FAIBVo0LH9xWEBf9HiC1
C2R9HYBPMkq9QS3ZcKS1dPG2hs+tCRSRSIzb6p38LJBxXD8I3Z5Wsb7bpD0C3sfD
SkQhklR21JPfqlNTx3DFAL/lg2mKFcg7An59J0ZgUfUxID9tuZsxHe/wP66fu0qZ
KGHbQZGHAgMBAAECggEAFoqtPXIcXPYK5aCoCPM1Z199MZH2x2E8R1WXMTwGuOQn
oz0wKiT07s7sLWS20W5aq08Yi6kPq7xgB122RZv1JTtVkSOZ8V5I1SOoOLgkIQ3a
c3fMk+2QiTnbXgUEx9h6ium8M11gyN8p5309VljR6HuI/i1HK6sHYgY12qjc6FOZ
YGJx8LSZ5SVbTjpPB0wcJmGb8kyCNR0sUhtulQyYP1S4dj18yLUqWWX/sHs3pECe
STXRy0p8SWuUt4yEKNhuECaHN1HSiqeTiMdBQjIJDUSae8bmi1o4Mn9FoXwOVR65
VWWv12j1Yv3R+asSe5jaeiAWUdgbaXSlAJnFFwcwiQKBgQD9WR67R8Bn67YAuvJo
AiZl7gzE0WRgtWTl6kLjk39QUEW4emJoapUc6zstglD/uB8MUG6AV/Hm5Xt7gdVw
31zo0OXH6CYe1nsXaD22xK76NxVjGPE8sRobE+hugAMEHax+/Bz0HpDzx/DSnd+u
hkfos9SfOzD0w2jEIOgz1rOZ7wKBgQDD95M/ja5c1ELLFicwP9fNXekFm+C2tGl7
nDqxdVDH70xKYKXF8ofhkYTs1dQc977Hair1CZU4NZBk/+KhBBhp0hB6BduEEe/W
/dj7NVtJeBEQq0DZZTOKu51uJ8JwkzVdeRHCUlPSUdTtsfvrRGOp9DgCdMDZs3Re
ZvNqVP/56QKBgFTuFWFPEm9EE4V3JmA7qEevX9RzJaVN6f8xYy8LeTihUF4hmO/M
GyTQrsv4zdKMFMx6AjFASjXPZG/o/HaUSn852G4FoxHfcPBN37JviQEUijToXaas
8EV3jQnOHDS7BeKj/cjQnmM6+b6BckT9ewnFj1e57hV/lJV7Opx2M0s9AoGBALGo
gw+8zHRP4nXnEYQGfQgruRNiq6g3iuGLUxKKfr+jTBCp6d+47kMq/80OVYwldgmn
UGZxV5xrwwotiTHcWp2k2VcmdEoZUMwhulKTnrzOYvovp0zvGHkPebvhw773Vgv1
tInsxR0JHvaWwwIZMBll1Fk1q5gxvq/OuaKOiLnxAoGBAMy+Rd6hulP5eCfZTdkS
33ZP5ibk/F/BWYvFLYI18DMTf+xygKWQGKJZs/rxCkc01ijwb4RfsUXzdVuhT+Nq
RBUSaQlGEOWVVGIocS+91jOTyJF44iYGiGPPeS32waFnc0AnoEOE7fVBznOBxaEs
qphrtPKSBuqG4atcawP9cIFM
-----END PRIVATE KEY-----";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn cfg() -> OidcConfig {
    OidcConfig::new(ISSUER, AUDIENCE, JWKS, "org", "roles", "admin").expect("valid oidc config")
}

/// Sign `claims` with `key_pem` under `kid` (RS256).
fn sign(claims: &serde_json::Value, key_pem: &str, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(key_pem.as_bytes()).expect("encoding key");
    encode(&header, claims, &key).expect("sign token")
}

/// A well-formed, valid token with the given roles (empty ⇒ viewer).
fn token_with_roles(roles: serde_json::Value) -> String {
    sign(
        &serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-123",
            "exp": now() + 3600,
            "org": "acme",
            "roles": roles,
        }),
        KEY1_PEM,
        KID,
    )
}

/// App state with OIDC configured **and** one API key, to prove keys still work.
fn state_with_oidc() -> AppState {
    let store = Arc::new(Store::new());
    let mut keys = HashMap::new();
    keys.insert(
        "devkey".to_string(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
            plan: Plan::Paid,
        },
    );
    AppState::new(store, Arc::new(keys), 0.8).with_oidc(Some(cfg()))
}

/// App state with **no** OIDC — the keys-only baseline.
fn state_keys_only() -> AppState {
    let store = Arc::new(Store::new());
    let mut keys = HashMap::new();
    keys.insert(
        "devkey".to_string(),
        Principal {
            org: "acme".into(),
            role: "admin".into(),
            plan: Plan::Paid,
        },
    );
    AppState::new(store, Arc::new(keys), 0.8)
}

async fn send(
    state: &AppState,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
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

// ---- happy path -----------------------------------------------------------

#[test]
fn valid_token_maps_to_org_and_viewer_least_privilege() {
    // No roles claim → viewer (least privilege), org from the claim.
    let token = token_with_roles(serde_json::json!([]));
    let p = verify_id_token(&cfg(), &token).expect("token verifies");
    assert_eq!(p.org, "acme");
    assert_eq!(p.role, "viewer");
    assert_eq!(p.plan, Plan::Paid);

    // Admin role present → admin.
    let admin = token_with_roles(serde_json::json!(["admin"]));
    let p = verify_id_token(&cfg(), &admin).expect("admin token verifies");
    assert_eq!(p.role, "admin");
}

#[tokio::test]
async fn valid_viewer_token_authorizes_read_but_not_mutation() {
    let state = state_with_oidc();
    let token = token_with_roles(serde_json::json!([]));

    // Reads (200) — the token resolves to org `acme`.
    let (status, _) = send(&state, "GET", "/v1/runs", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);

    // ...but a viewer cannot mutate (403, proving the least-privilege role).
    let (status, _) = send(&state, "POST", "/v1/runs/r1/kill", Some(&token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_token_authorizes_kill_and_audit_actor_is_oidc() {
    let state = state_with_oidc();
    let token = token_with_roles(serde_json::json!(["admin"]));

    let (status, v) = send(&state, "POST", "/v1/runs/runaway/kill", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["killed"], "runaway");

    // The audit entry attributes the action to `oidc:<sub>`, never a secret.
    let (status, v) = send(&state, "GET", "/v1/audit", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let entries = v.as_array().expect("audit array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["action"], "control.kill");
    assert_eq!(entries[0]["actor"], "oidc:user-123");
}

// ---- rejection cases (each ⇒ 401 / unauthorized) --------------------------

async fn assert_rejected(name: &str, token: &str) {
    let state = state_with_oidc();
    let (status, _) = send(&state, "GET", "/v1/runs", Some(token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "read must reject: {name}");
    // And the config-level verify rejects it too.
    assert!(
        verify_id_token(&cfg(), token).is_none(),
        "verify must reject: {name}"
    );
}

#[tokio::test]
async fn rejects_expired_exp() {
    let token = sign(
        &serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": "u", "org": "acme",
            // An hour in the past — well beyond jsonwebtoken's default leeway.
            "roles": ["admin"], "exp": now() - 3600,
        }),
        KEY1_PEM,
        KID,
    );
    assert_rejected("expired", &token).await;
}

#[tokio::test]
async fn rejects_wrong_audience() {
    let token = sign(
        &serde_json::json!({
            "iss": ISSUER, "aud": "some-other-audience", "sub": "u", "org": "acme",
            "roles": ["admin"], "exp": now() + 3600,
        }),
        KEY1_PEM,
        KID,
    );
    assert_rejected("wrong_aud", &token).await;
}

#[tokio::test]
async fn rejects_wrong_issuer() {
    let token = sign(
        &serde_json::json!({
            "iss": "https://evil.example.com", "aud": AUDIENCE, "sub": "u", "org": "acme",
            "roles": ["admin"], "exp": now() + 3600,
        }),
        KEY1_PEM,
        KID,
    );
    assert_rejected("wrong_iss", &token).await;
}

#[tokio::test]
async fn rejects_bad_signature() {
    // Signed with KEY2 but claiming KEY1's kid → signature check fails.
    let token = sign(
        &serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": "u", "org": "acme",
            "roles": ["admin"], "exp": now() + 3600,
        }),
        KEY2_PEM,
        KID,
    );
    assert_rejected("bad_signature", &token).await;
}

#[tokio::test]
async fn rejects_missing_org_claim() {
    let token = sign(
        &serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": "u",
            "roles": ["admin"], "exp": now() + 3600,
        }),
        KEY1_PEM,
        KID,
    );
    assert_rejected("missing_org", &token).await;
}

#[tokio::test]
async fn rejects_unknown_kid() {
    let token = sign(
        &serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": "u", "org": "acme",
            "roles": ["admin"], "exp": now() + 3600,
        }),
        KEY1_PEM,
        "no-such-kid",
    );
    assert_rejected("unknown_kid", &token).await;
}

#[tokio::test]
async fn rejects_malformed_token() {
    assert_rejected("malformed", "not.a.valid.jwt").await;
    assert_rejected("garbage", "garbage").await;
}

// ---- regression: keys unchanged / take precedence -------------------------

#[tokio::test]
async fn api_key_auth_unchanged_when_oidc_unconfigured() {
    // This mirrors the existing mutations-test shape exactly: with no OIDC, an
    // admin API key reads and mutates, and an unknown key is 401.
    let state = state_keys_only();

    let (status, _) = send(&state, "GET", "/v1/runs", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, v) = send(&state, "POST", "/v1/runs/r1/kill", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["killed"], "r1");

    let (status, _) = send(&state, "POST", "/v1/runs/r1/kill", Some("nope"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A JWT is meaningless here (OIDC off) → 401, byte-identical to any bad key.
    let token = token_with_roles(serde_json::json!(["admin"]));
    let (status, _) = send(&state, "GET", "/v1/runs", Some(&token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_key_still_works_and_takes_precedence_with_oidc_configured() {
    let state = state_with_oidc();

    // The API key path is tried first and still authorizes a mutation; its audit
    // actor is the key fingerprint (`key:*`), not `oidc:*`.
    let (status, v) = send(&state, "POST", "/v1/runs/r2/kill", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["killed"], "r2");

    let (status, v) = send(&state, "GET", "/v1/audit", Some("devkey"), None).await;
    assert_eq!(status, StatusCode::OK);
    let actor = v[0]["actor"].as_str().unwrap();
    assert!(actor.starts_with("key:"), "actor was {actor}");
}
