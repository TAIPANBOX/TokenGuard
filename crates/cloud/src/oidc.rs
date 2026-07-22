//! Minimal, **offline** OIDC / JWT bearer authentication (WS4).
//!
//! This is a conservative, default-**off** alternative to the API keys in
//! [`crate::keys`]: an enterprise can hand the control plane a static JWKS from
//! its IdP and let users authenticate with an OIDC ID-token / JWT *alongside*
//! their keys. It is deliberately small:
//!
//! * **Offline only.** The JWKS is supplied statically (an env var holding the
//!   JWKS JSON, or a path to a file). There is **no** network fetch of the
//!   issuer's `.well-known` document or its keys — that, plus SAML, SCIM and
//!   session cookies, is explicitly out of scope for this PR.
//! * **Default off.** [`OidcConfig::from_env`] returns `None` unless the issuer,
//!   audience and JWKS are all configured. When it is `None`, the HTTP layer
//!   never calls into this module, so behavior is byte-for-byte identical to a
//!   keys-only deployment.
//! * **Keys win.** The HTTP chokepoint tries the API-key map *first*; a JWT is
//!   only consulted when no key matched and OIDC is configured.
//! * **Least privilege.** A verified token maps to a [`viewer`](Principal) by
//!   default and is only promoted to `admin` when the roles claim explicitly
//!   contains the configured admin role. No org claim → no access.
//!
//! ## What is validated (any failure ⇒ token rejected, `verify` returns `None`)
//!
//! 1. The token is a well-formed JWS with a `kid` header.
//! 2. The `kid` matches a key in the configured JWKS.
//! 3. The signature verifies against that key. The allowed algorithms are
//!    derived from the **JWK's key type** (RSA ⇒ RS256/384/512, EC ⇒
//!    ES256/384), never from the attacker-controlled token header — this closes
//!    the classic RS256→HS256 "alg confusion" downgrade.
//! 4. `exp` is present and not in the past.
//! 5. `iss` equals the configured issuer.
//! 6. `aud` equals the configured audience.
//! 7. The org claim is present and a non-empty string.

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;

use crate::keys::Principal;

/// Default claim name carrying the org identifier.
const DEFAULT_ORG_CLAIM: &str = "org";
/// Default claim name carrying the user's roles.
const DEFAULT_ROLES_CLAIM: &str = "roles";
/// Default role string that promotes a token to `admin`.
const DEFAULT_ADMIN_ROLE: &str = "admin";

/// Static, offline configuration for OIDC/JWT bearer validation. Built once at
/// startup (see [`OidcConfig::from_env`]) and held on the app state, so no env
/// or file I/O happens per request.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Expected `iss` claim — exact match required.
    issuer: String,
    /// Expected `aud` claim — exact match required.
    audience: String,
    /// The parsed, static JWKS. Keys are matched by `kid`.
    jwks: JwkSet,
    /// Claim carrying the org id (default `"org"`). Absent ⇒ reject.
    org_claim: String,
    /// Claim carrying the roles (default `"roles"`). May be an array of strings
    /// or a single space-separated string.
    roles_claim: String,
    /// Role that grants `admin` (default `"admin"`); anything else ⇒ `viewer`.
    admin_role: String,
}

impl OidcConfig {
    /// Build a config from explicit parts, parsing `jwks_json` as a JWKS
    /// document. Returns `None` if the JWKS is missing/empty or fails to parse —
    /// a misconfiguration fails **safe** (OIDC stays disabled; no token is ever
    /// accepted). Exposed (rather than only [`from_env`](Self::from_env)) so
    /// tests can construct a config around an in-test signing key.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_json: &str,
        org_claim: impl Into<String>,
        roles_claim: impl Into<String>,
        admin_role: impl Into<String>,
    ) -> Option<OidcConfig> {
        let issuer = issuer.into();
        let audience = audience.into();
        if issuer.is_empty() || audience.is_empty() {
            return None;
        }
        let jwks: JwkSet = serde_json::from_str(jwks_json).ok()?;
        if jwks.keys.is_empty() {
            return None;
        }
        Some(OidcConfig {
            issuer,
            audience,
            jwks,
            org_claim: non_empty(org_claim.into(), DEFAULT_ORG_CLAIM),
            roles_claim: non_empty(roles_claim.into(), DEFAULT_ROLES_CLAIM),
            admin_role: non_empty(admin_role.into(), DEFAULT_ADMIN_ROLE),
        })
    }

    /// Build a config from the environment, or `None` when OIDC is unconfigured.
    ///
    /// Required (all three must be present) — absent ⇒ OIDC **disabled**:
    /// * `TOKENFUSE_CLOUD_OIDC_ISSUER`
    /// * `TOKENFUSE_CLOUD_OIDC_AUDIENCE`
    /// * `TOKENFUSE_CLOUD_OIDC_JWKS` — either the JWKS JSON inline, or a path to
    ///   a file containing it (static; never fetched over the network).
    ///
    /// Optional overrides (sensible defaults):
    /// * `TOKENFUSE_CLOUD_OIDC_ORG_CLAIM` (default `org`)
    /// * `TOKENFUSE_CLOUD_OIDC_ROLES_CLAIM` (default `roles`)
    /// * `TOKENFUSE_CLOUD_OIDC_ADMIN_ROLE` (default `admin`)
    pub fn from_env() -> Option<OidcConfig> {
        let issuer = env_nonempty("TOKENFUSE_CLOUD_OIDC_ISSUER")?;
        let audience = env_nonempty("TOKENFUSE_CLOUD_OIDC_AUDIENCE")?;
        let jwks_raw = env_nonempty("TOKENFUSE_CLOUD_OIDC_JWKS")?;
        let jwks_json = load_jwks(&jwks_raw)?;
        OidcConfig::new(
            issuer,
            audience,
            &jwks_json,
            std::env::var("TOKENFUSE_CLOUD_OIDC_ORG_CLAIM").unwrap_or_default(),
            std::env::var("TOKENFUSE_CLOUD_OIDC_ROLES_CLAIM").unwrap_or_default(),
            std::env::var("TOKENFUSE_CLOUD_OIDC_ADMIN_ROLE").unwrap_or_default(),
        )
    }
}

/// A verified OIDC token: the mapped [`Principal`] plus a stable, non-secret
/// `actor` id (`oidc:<sub or org>`) for the audit trail.
pub struct Verified {
    pub principal: Principal,
    /// `oidc:<sub>` (or `oidc:<org>` when the token has no `sub`). Never the raw
    /// token — that is a bearer secret and must not reach the audit log.
    pub actor: String,
}

/// The subset of claims we read. `exp`, `aud` and `iss` are validated by
/// `jsonwebtoken` itself (from the raw token), so they need no field here; the
/// rest of the payload is captured in `extra` for the org/roles lookups.
#[derive(Deserialize)]
struct Claims {
    #[serde(default)]
    sub: String,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

impl Claims {
    /// A claim as a non-empty string, else `None`.
    fn string(&self, key: &str) -> Option<String> {
        match self.extra.get(key)? {
            serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    }

    /// Whether the roles claim contains `role`. Accepts either a JSON array of
    /// strings (`["admin","viewer"]`) or a single space-separated string
    /// (`"admin viewer"`), the two shapes IdPs commonly emit.
    fn has_role(&self, key: &str, role: &str) -> bool {
        match self.extra.get(key) {
            Some(serde_json::Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(role)),
            Some(serde_json::Value::String(s)) => s.split_whitespace().any(|r| r == role),
            _ => false,
        }
    }
}

/// Verify an OIDC ID-token / JWT and map it to a [`Principal`], or `None` on any
/// validation failure. See the module docs for the exact checks. The role is
/// `admin` **iff** the roles claim contains the configured admin role, else
/// `viewer` (least privilege).
pub fn verify_id_token(cfg: &OidcConfig, token: &str) -> Option<Principal> {
    verify(cfg, token).map(|v| v.principal)
}

/// Like [`verify_id_token`], but also returns the audit `actor` id. Used by the
/// mutation chokepoint so an OIDC-authenticated admin action is attributed to
/// `oidc:<sub>` rather than a raw credential.
pub fn verify(cfg: &OidcConfig, token: &str) -> Option<Verified> {
    // 1. Well-formed header with a key id.
    let header = decode_header(token).ok()?;
    let kid = header.kid?;

    // 2. Key id matches a configured JWKS key.
    let jwk = cfg.jwks.find(&kid)?;

    // 3. Allowed algorithms come from the *key type*, never the token header —
    //    this prevents an attacker from downgrading an RSA/EC key to HS256 and
    //    forging a signature ("alg confusion"). Symmetric / OKP keys are
    //    rejected outright.
    let algorithms: Vec<Algorithm> = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => {
            vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512]
        }
        AlgorithmParameters::EllipticCurve(_) => vec![Algorithm::ES256, Algorithm::ES384],
        _ => return None,
    };
    let key = DecodingKey::from_jwk(jwk).ok()?;

    // 4-6. Signature + exp + iss + aud, all enforced by `jsonwebtoken`.
    //
    // `Validation::set_issuer`/`set_audience` only check `iss`/`aud` *when the
    // claim is present* in the token — by default `jsonwebtoken` does not
    // require either claim to exist at all, so a token that simply omits
    // `iss`/`aud` would sail through unchecked (an audience-confusion /
    // privilege-escalation risk if an IdP reuses a signing key across
    // services). `set_required_spec_claims` closes that: a token missing
    // `exp`, `iss` or `aud` is rejected outright, regardless of signature
    // validity.
    let mut validation = Validation::new(algorithms[0]);
    validation.algorithms = algorithms;
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.set_issuer(&[&cfg.issuer]);
    validation.set_audience(&[&cfg.audience]);
    let data = decode::<Claims>(token, &key, &validation).ok()?;
    let claims = data.claims;

    // 7. Org claim is mandatory — no org, no access.
    let org = claims.string(&cfg.org_claim)?;

    // Least-privilege role default.
    let role = if claims.has_role(&cfg.roles_claim, &cfg.admin_role) {
        "admin"
    } else {
        "viewer"
    };

    // Stable, non-secret audit id: prefer `sub`, fall back to the org.
    let subject = if claims.sub.is_empty() {
        org.clone()
    } else {
        claims.sub.clone()
    };

    Some(Verified {
        principal: Principal {
            org,
            role: role.to_string(),
        },
        actor: format!("oidc:{subject}"),
    })
}

/// Read `TOKENFUSE_CLOUD_OIDC_JWKS`: if it looks like a JSON object, use it
/// verbatim; otherwise treat it as a file path and read the file. Returns `None`
/// if a path was given but could not be read.
fn load_jwks(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start();
    if trimmed.starts_with('{') {
        Some(raw.to_string())
    } else {
        std::fs::read_to_string(raw).ok()
    }
}

/// An env var's value if set and non-empty, else `None`.
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// `value` if non-empty, else `default`.
fn non_empty(value: String, default: &str) -> String {
    if value.is_empty() {
        default.to_string()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JWKS with a single RSA key, matching the fixture private key used by the
    /// integration tests.
    const JWKS: &str = r#"{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"test-key-1","n":"1AS-0OhDEXJLsz8X9gid8vzb-7nhyptCQSQ6MAvmJam2g4yv8gOiWuzrLhW9noAqqB1jhK-lzL2_ffkBQxaOJKKcTJKluq3pUjacFLrrqnfZA39Dl2FT8547gl05OBbRD2ZxaC-RJkFXJbVleKHd3r1Zs6vv9GEm42f3r5hay-0BhPblRjGXRqnYF9EMOA07ZamWnABihzn9Mb-Mht8sWty1vYvNP6Y7vMP6ftHnp4Jf3BrU-5lrrTHlMmfM5cIKp2GdtAGM1_gBJDGUU2F3BhBPFFZ6vPiq8HbS-cZvtR9JFpeZh_IOGdxcr32kH23mxum06ONsqywCFuR0AWOuJQ","e":"AQAB"}]}"#;

    #[test]
    fn from_env_is_none_when_unset() {
        // With none of the required vars set, OIDC must stay disabled so the
        // keys-only default behavior is preserved. (We clear the three required
        // vars to be robust against an ambient environment.)
        std::env::remove_var("TOKENFUSE_CLOUD_OIDC_ISSUER");
        std::env::remove_var("TOKENFUSE_CLOUD_OIDC_AUDIENCE");
        std::env::remove_var("TOKENFUSE_CLOUD_OIDC_JWKS");
        assert!(OidcConfig::from_env().is_none());
    }

    #[test]
    fn new_rejects_missing_issuer_or_audience() {
        assert!(OidcConfig::new("", "aud", JWKS, "", "", "").is_none());
        assert!(OidcConfig::new("iss", "", JWKS, "", "", "").is_none());
    }

    #[test]
    fn new_rejects_malformed_jwks() {
        assert!(OidcConfig::new("iss", "aud", "not json", "", "", "").is_none());
        assert!(OidcConfig::new("iss", "aud", r#"{"keys":[]}"#, "", "", "").is_none());
    }

    #[test]
    fn new_applies_claim_defaults() {
        let cfg = OidcConfig::new("iss", "aud", JWKS, "", "", "").expect("config");
        assert_eq!(cfg.org_claim, "org");
        assert_eq!(cfg.roles_claim, "roles");
        assert_eq!(cfg.admin_role, "admin");
    }

    #[test]
    fn claims_role_default_is_viewer_least_privilege() {
        // No roles claim at all → viewer.
        let claims = Claims {
            sub: "u1".into(),
            extra: HashMap::new(),
        };
        assert!(!claims.has_role("roles", "admin"));

        // Array form containing admin → admin.
        let mut extra = HashMap::new();
        extra.insert("roles".to_string(), serde_json::json!(["viewer", "admin"]));
        let claims = Claims {
            sub: "u1".into(),
            extra,
        };
        assert!(claims.has_role("roles", "admin"));

        // Space-separated string form.
        let mut extra = HashMap::new();
        extra.insert("roles".to_string(), serde_json::json!("viewer admin"));
        let claims = Claims {
            sub: "u1".into(),
            extra,
        };
        assert!(claims.has_role("roles", "admin"));
        assert!(!claims.has_role("roles", "superuser"));
    }

    #[test]
    fn org_claim_must_be_nonempty_string() {
        let mut extra = HashMap::new();
        extra.insert("org".to_string(), serde_json::json!(""));
        let claims = Claims {
            sub: "u1".into(),
            extra,
        };
        assert!(claims.string("org").is_none());

        let mut extra = HashMap::new();
        extra.insert("org".to_string(), serde_json::json!("acme"));
        let claims = Claims {
            sub: "u1".into(),
            extra,
        };
        assert_eq!(claims.string("org").as_deref(), Some("acme"));
    }
}
