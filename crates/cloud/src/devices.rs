//! Device pairing + Secure-Enclave-signed mutations. The wire protocol is fixed
//! in docs/14-mobile-companion.md §4.1–4.2:
//!
//! - Pairing: an admin issues a one-time code; the app generates a P-256 key in
//!   the Secure Enclave and submits its public key with the code, receiving a
//!   `device_token` (Bearer, for reads) and being registered for signed writes.
//! - Signed mutations: each write carries `X-Fuse-{Device,TS,Nonce,Sig}`; the
//!   server verifies an **ES256** signature (ECDSA P-256 / SHA-256) over the
//!   canonical string below, against the device's stored public key.
//!
//! Signature encoding: base64 of the raw 64-byte `r||s` (IEEE P1363) form —
//! exactly Apple CryptoKit's `ECDSASignature.rawRepresentation`. Public key:
//! base64 of SEC1/X9.63 bytes (CryptoKit `x963Representation`).

use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A paired device authorized to read (via its token) and, if `role == admin`,
/// to sign mutations with its Enclave key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: String,
    pub org: String,
    pub role: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub platform: String,
    /// Public key, base64 SEC1/X9.63 (as received at pairing).
    pub pubkey_b64: String,
    /// APNs device token for push, if the device has registered one.
    #[serde(default)]
    pub apns_token: Option<String>,
}

/// A pending one-time pairing code (org/role are fixed by the issuing admin).
#[derive(Debug, Clone)]
pub struct Pairing {
    pub org: String,
    pub role: String,
    pub expires_unix: i64,
}

/// The exact string a client signs for a mutation (LF-joined, see §4.2):
/// `{METHOD}\n{PATH}\n{sha256(body) hex}\n{TS}\n{NONCE}`.
pub fn canonical_string(method: &str, path: &str, body: &[u8], ts: &str, nonce: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hex = hex_lower(&hasher.finalize());
    format!("{method}\n{path}\n{body_hex}\n{ts}\n{nonce}")
}

/// Verify an ES256 signature (base64 raw `r||s`) over `canonical` against a
/// SEC1 public key (base64). Any decode/parse failure verifies as `false`.
pub fn verify_signature(pubkey_b64: &str, canonical: &str, sig_b64: &str) -> bool {
    let Ok(pk_bytes) = STANDARD.decode(pubkey_b64) else {
        return false;
    };
    let Ok(sig_bytes) = STANDARD.decode(sig_b64) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&pk_bytes) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    vk.verify(canonical.as_bytes(), &sig).is_ok()
}

/// `n_bytes` of OS randomness as lowercase hex — used for device ids and tokens.
pub fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    getrandom::getrandom(&mut buf).expect("os rng");
    hex_lower(&buf)
}

/// An 8-character one-time pairing code from an unambiguous alphabet.
pub fn pairing_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).expect("os rng");
    buf.iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    /// A deterministic P-256 key for tests (fixed scalar, no RNG).
    fn test_key() -> (SigningKey, String) {
        let sk = SigningKey::from_slice(&[0x11u8; 32]).expect("valid scalar");
        let vk = sk.verifying_key();
        let pubkey_b64 = STANDARD.encode(vk.to_encoded_point(false).as_bytes());
        (sk, pubkey_b64)
    }

    #[test]
    fn canonical_is_stable_and_hashes_body() {
        let c = canonical_string("POST", "/v1/runs/r1/kill", b"", "100", "n1");
        // Empty-body sha256, lowercase hex.
        assert!(c.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert_eq!(c.lines().count(), 5);
        assert_eq!(c.lines().next().unwrap(), "POST");
    }

    #[test]
    fn valid_signature_verifies() {
        let (sk, pubkey) = test_key();
        let canonical = canonical_string("POST", "/v1/runs/r1/kill", b"", "100", "n1");
        let sig: Signature = sk.sign(canonical.as_bytes());
        let sig_b64 = STANDARD.encode(sig.to_bytes());
        assert!(verify_signature(&pubkey, &canonical, &sig_b64));
    }

    #[test]
    fn tampered_message_fails() {
        let (sk, pubkey) = test_key();
        let signed = canonical_string("POST", "/v1/runs/r1/kill", b"", "100", "n1");
        let sig: Signature = sk.sign(signed.as_bytes());
        let sig_b64 = STANDARD.encode(sig.to_bytes());
        // A different path must not verify with the same signature.
        let other = canonical_string("POST", "/v1/runs/r2/kill", b"", "100", "n1");
        assert!(!verify_signature(&pubkey, &other, &sig_b64));
    }

    #[test]
    fn garbage_inputs_do_not_panic() {
        assert!(!verify_signature("not-base64!!", "x", "y"));
        assert!(!verify_signature("", "x", ""));
    }
}
