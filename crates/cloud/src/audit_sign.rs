//! Signed audit manifest (P3 WS2 follow-up). The hash chain in
//! `tokenfuse_core::audit` is tamper-*evident*: any edit breaks it and
//! `verify_chain` pinpoints the break. This module adds tamper-*evidence with
//! external custody*: an ES256 signature (a server P-256 key) over an org's
//! chain tip, so an auditor can prove offline that "this org's audit log ended
//! at this entry, unaltered" without trusting the store to have kept the chain.
//!
//! The canonical bytes signed are built by the pure, crypto-free
//! `tokenfuse_core::audit::manifest_signing_bytes` (keeping core `p256`-free);
//! the signing key and the ES256 crypto live here, mirroring `apns.rs` (which
//! signs its provider JWT with the same `p256` ES256 primitives).

use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;
use serde::Serialize;
use utoipa::ToSchema;

use tokenfuse_core::audit::{self, AuditEntry};

/// Environment variable holding the server's P-256 audit-manifest signing key.
/// Absent (or unparseable) ⇒ manifest signing is disabled and the endpoint
/// reports not-configured; the rest of the audit trail is unaffected.
pub const AUDIT_SIGNING_KEY_ENV: &str = "TOKENFUSE_CLOUD_AUDIT_SIGNING_KEY";

/// A cryptographically-signed manifest over an org's audit chain tip. The
/// signature covers `tokenfuse_core::audit::manifest_signing_bytes(org,
/// tip_seq, tip_hash, entry_count, signed_at_millis)`; an auditor re-derives
/// those bytes from these fields and verifies `signature_b64` against
/// `public_key_b64` with any standard ES256 tool — no trust in the store
/// required.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuditManifest {
    /// The organization whose chain this manifest attests.
    pub org: String,
    /// The tip entry's `seq` (`0` for an empty chain).
    pub tip_seq: u64,
    /// The tip entry's `entry_hash` (`""` for an empty chain).
    pub tip_hash: String,
    /// Total entries in the chain at signing time (`0` for an empty chain).
    pub entry_count: u64,
    /// When the manifest was signed, epoch millis. Part of the signed bytes.
    pub signed_at_millis: i64,
    /// The signature algorithm — always `"ES256"` (ECDSA P-256 / SHA-256).
    pub algorithm: String,
    /// base64 (standard) of the raw 64-byte `r||s` (IEEE P1363) ES256 signature
    /// over the canonical bytes.
    pub signature_b64: String,
    /// base64 (standard) of the SEC1/X9.63 *uncompressed* public point, so an
    /// auditor can verify with any standard ECDSA tool.
    pub public_key_b64: String,
}

/// Load the audit-manifest signing key from [`AUDIT_SIGNING_KEY_ENV`], or
/// `None` when the var is unset/empty/unparseable (signing disabled). Accepts a
/// PKCS#8 or SEC1 **PEM**, or **base64** of a raw 32-byte scalar / PKCS#8 DER /
/// SEC1 DER — mirroring how `apns.rs` loads its ES256 provider key.
pub fn signing_key_from_env() -> Option<SigningKey> {
    let raw = std::env::var(AUDIT_SIGNING_KEY_ENV).ok()?;
    parse_signing_key(raw.trim())
}

/// Parse a P-256 signing key from PEM (PKCS#8 or SEC1) or base64 (raw 32-byte
/// scalar, PKCS#8 DER, or SEC1 DER). Returns `None` on any decode failure.
fn parse_signing_key(s: &str) -> Option<SigningKey> {
    if s.is_empty() {
        return None;
    }
    // PEM — the format `apns.rs` uses for its `.p8` provider key.
    if s.contains("-----BEGIN") {
        if let Ok(sk) = SecretKey::from_pkcs8_pem(s) {
            return Some(SigningKey::from(sk));
        }
        if let Ok(sk) = SecretKey::from_sec1_pem(s) {
            return Some(SigningKey::from(sk));
        }
        return None;
    }
    // Otherwise base64: a raw 32-byte scalar first (the compact form), then
    // PKCS#8 / SEC1 DER.
    let bytes = STANDARD.decode(s).ok()?;
    if bytes.len() == 32 {
        if let Ok(sk) = SigningKey::from_slice(&bytes) {
            return Some(sk);
        }
    }
    if let Ok(sk) = SecretKey::from_pkcs8_der(&bytes) {
        return Some(SigningKey::from(sk));
    }
    if let Ok(sk) = SecretKey::from_sec1_der(&bytes) {
        return Some(SigningKey::from(sk));
    }
    None
}

/// Build a signed manifest over `entries` (an org's chain, oldest first). The
/// tip is the last entry, or the zero-tip (`seq`/`entry_count` 0, empty
/// `tip_hash`) for an empty chain. Pure given the key: the manifest is derived
/// on demand from the persisted chain, so nothing new is persisted.
pub fn build_signed_manifest(
    org: &str,
    entries: &[AuditEntry],
    key: &SigningKey,
    now_ms: i64,
) -> AuditManifest {
    let (tip_seq, tip_hash, entry_count) = match entries.last() {
        Some(tip) => (tip.seq, tip.entry_hash.clone(), entries.len() as u64),
        None => (0, String::new(), 0),
    };
    let bytes = audit::manifest_signing_bytes(org, tip_seq, &tip_hash, entry_count, now_ms);
    let sig: Signature = key.sign(&bytes);
    let public_key_b64 = STANDARD.encode(key.verifying_key().to_encoded_point(false).as_bytes());
    AuditManifest {
        org: org.to_string(),
        tip_seq,
        tip_hash,
        entry_count,
        signed_at_millis: now_ms,
        algorithm: "ES256".to_string(),
        signature_b64: STANDARD.encode(sig.to_bytes()),
        public_key_b64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    /// A deterministic P-256 key for tests (fixed scalar, no RNG), matching the
    /// `devices.rs` test-key pattern.
    fn test_key() -> SigningKey {
        SigningKey::from_slice(&[0x11u8; 32]).expect("valid scalar")
    }

    /// Independently verify a manifest's ES256 signature against its embedded
    /// public key, exactly as an offline auditor would.
    fn manifest_verifies(m: &AuditManifest) -> bool {
        let pk = STANDARD.decode(&m.public_key_b64).expect("pubkey b64");
        let sig = STANDARD.decode(&m.signature_b64).expect("sig b64");
        let vk = VerifyingKey::from_sec1_bytes(&pk).expect("sec1 pubkey");
        let sig = Signature::from_slice(&sig).expect("sig");
        let bytes = audit::manifest_signing_bytes(
            &m.org,
            m.tip_seq,
            &m.tip_hash,
            m.entry_count,
            m.signed_at_millis,
        );
        vk.verify(&bytes, &sig).is_ok()
    }

    fn chain(n: usize) -> Vec<AuditEntry> {
        let mut out: Vec<AuditEntry> = Vec::new();
        for i in 0..n {
            out.push(audit::append(
                out.last(),
                1_000 + i as i64,
                format!("key:actor{i}"),
                "control.kill",
                format!("run-{i}"),
                "mode=hard",
            ));
        }
        out
    }

    #[test]
    fn manifest_signature_verifies_and_pins_the_tip() {
        let key = test_key();
        let c = chain(3);
        let m = build_signed_manifest("acme", &c, &key, 1_700_000_000_000);
        assert_eq!(m.algorithm, "ES256");
        assert_eq!(m.entry_count, 3);
        assert_eq!(m.tip_seq, 2);
        assert_eq!(m.tip_hash, c[2].entry_hash);
        assert!(
            manifest_verifies(&m),
            "signature must verify against pubkey"
        );
    }

    #[test]
    fn empty_chain_signs_a_valid_zero_tip_manifest() {
        let key = test_key();
        let m = build_signed_manifest("acme", &[], &key, 42);
        assert_eq!(m.tip_seq, 0);
        assert_eq!(m.entry_count, 0);
        assert_eq!(m.tip_hash, "");
        assert!(manifest_verifies(&m), "empty-chain manifest must verify");
    }

    #[test]
    fn tip_hash_moves_when_the_chain_grows() {
        let key = test_key();
        let a = build_signed_manifest("acme", &chain(1), &key, 1);
        let b = build_signed_manifest("acme", &chain(2), &key, 2);
        // A manifest pins its tip: after an append the tip_hash differs, so an
        // auditor holding `a` detects the chain has moved past it.
        assert_ne!(a.tip_hash, b.tip_hash);
        assert_eq!(a.entry_count, 1);
        assert_eq!(b.entry_count, 2);
    }

    #[test]
    fn a_tampered_signature_does_not_verify() {
        let key = test_key();
        let mut m = build_signed_manifest("acme", &chain(2), &key, 7);
        // Flip the pinned tip without re-signing: verification must fail.
        m.tip_hash = "deadbeef".to_string();
        assert!(!manifest_verifies(&m));
    }

    #[test]
    fn base64_raw_scalar_key_round_trips() {
        // The compact env form: base64 of a raw 32-byte scalar.
        let raw = [0x11u8; 32];
        let encoded = STANDARD.encode(raw);
        let key = parse_signing_key(&encoded).expect("parse raw scalar");
        // Signs the same as the direct scalar key.
        assert_eq!(
            key.verifying_key().to_encoded_point(false).as_bytes(),
            test_key()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
        );
    }

    #[test]
    fn garbage_key_material_is_none() {
        assert!(parse_signing_key("").is_none());
        assert!(parse_signing_key("not base64 !!!").is_none());
        assert!(parse_signing_key(
            "-----BEGIN EC PRIVATE KEY-----\nnope\n-----END EC PRIVATE KEY-----"
        )
        .is_none());
    }
}
