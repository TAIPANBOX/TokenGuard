//! Client credentials for the gateway itself: who is allowed to send calls
//! through it, and which stable `key_id` their spend is attributed to.
//!
//! ## Why this exists
//!
//! Until now the gateway authenticated nobody. Every identity on a metered
//! call arrived as a request header the caller wrote: `x-fuse-run-id`,
//! `x-fuse-agent-id`, `x-fuse-parent-run-id`. That is fine for attribution a
//! cooperating fleet reports about itself, and it is documented as
//! attribution-only. It is NOT fine as the key of a budget: anything a caller
//! can choose, a caller can change, so a per-agent cap keyed on
//! `x-fuse-agent-id` is bypassed by sending a different one, and an agent id
//! that belongs to someone else can be burned on purpose.
//!
//! So a budget above the run keys on the credential the caller presented,
//! resolved here, server-side. This module is that resolution and nothing
//! more: it does not enforce a budget, it establishes the identity a later
//! slice can enforce one against.
//!
//! ## Off unless configured, then fail closed
//!
//! `TOKENFUSE_CLIENT_KEYS` unset means the gateway behaves exactly as it
//! always has: no credential is required and `key_id` is empty on every
//! record. Existing deployments are unaffected, which matters for a drop-in
//! proxy: requiring a credential by default would break every live install on
//! upgrade.
//!
//! Set, and the posture inverts: every metered call must present a known key
//! or get `401`, and calls carry the resolved `key_id`.
//!
//! The dangerous middle case is a spec that is set but yields nothing usable -
//! a typo, a stray quote, an empty interpolated variable. Treating that like
//! "unset" would silently leave the gateway open precisely when the operator
//! believed they had just closed it, so [`ClientKeys::from_spec`] returns an
//! error and startup refuses. The sibling `crates/cloud/src/keys.rs` reaches
//! the same conclusion from the other direction (it has no "off" state, so an
//! unusable spec there simply authenticates nobody); both refuse to guess.
//!
//! ## The credential header
//!
//! `x-fuse-key`, not `Authorization`. `Authorization` on an inbound call is
//! the caller's PROVIDER credential and is deliberately forwarded upstream
//! (`crate::provider::FORWARD_HEADERS`); reusing it would either send the
//! gateway's credential to Anthropic or steal the provider's. `x-fuse-*` is
//! not in that allowlist, so the gateway's own credential is never forwarded.

use std::collections::HashMap;

/// The header carrying a client's gateway credential.
pub const CLIENT_KEY_HEADER: &str = "x-fuse-key";

/// Resolved client credentials: secret -> stable `key_id`.
///
/// Lookup is a plain `HashMap` get, matching `crates/cloud/src/keys.rs`'s own
/// bearer resolution. That is a deliberate consistency choice with the sibling
/// plane rather than an oversight: moving to a constant-time comparison is a
/// posture change that belongs across both planes at once, not smuggled into
/// one crate where it would silently diverge.
#[derive(Debug, Clone, Default)]
pub struct ClientKeys {
    by_secret: HashMap<String, String>,
}

/// A `TOKENFUSE_CLIENT_KEYS` spec that was set but unusable. Startup refuses
/// rather than falling back to "no authentication", because that fallback
/// would leave the gateway open at exactly the moment an operator believed
/// they had closed it.
#[derive(Debug, PartialEq, Eq)]
pub struct EmptySpec;

impl std::fmt::Display for EmptySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "TOKENFUSE_CLIENT_KEYS is set but contains no usable `secret:key_id` entry \
             (expected e.g. `sk-live-abc:billing-agent,sk-live-def:research-agent`); \
             refusing to start rather than run with client authentication silently off",
        )
    }
}

impl std::error::Error for EmptySpec {}

impl ClientKeys {
    /// Parse `"secret:key_id,…"`.
    ///
    /// Entries missing either half are skipped, mirroring
    /// `cloud::keys::parse_keys`. A secret may contain `:` (many API-key
    /// formats do), so the split is on the LAST colon: everything before it is
    /// the secret, everything after is the `key_id`.
    ///
    /// A blank/whitespace-only spec is "not configured" and yields disabled
    /// keys. A non-blank spec that yields no entries is [`EmptySpec`].
    pub fn from_spec(spec: &str) -> Result<Self, EmptySpec> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Ok(Self::default());
        }
        let mut by_secret = HashMap::new();
        for entry in trimmed.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let Some((secret, key_id)) = entry.rsplit_once(':') else {
                continue;
            };
            let (secret, key_id) = (secret.trim(), key_id.trim());
            if secret.is_empty() || key_id.is_empty() {
                continue;
            }
            by_secret.insert(secret.to_string(), key_id.to_string());
        }
        if by_secret.is_empty() {
            return Err(EmptySpec);
        }
        Ok(Self { by_secret })
    }

    /// Whether client authentication is on at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.by_secret.is_empty()
    }

    /// How many distinct credentials are configured (startup logging).
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_secret.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_secret.is_empty()
    }

    /// The `key_id` a presented secret resolves to, or `None` if unknown.
    #[must_use]
    pub fn resolve(&self, secret: &str) -> Option<&str> {
        self.by_secret.get(secret).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_spec_leaves_authentication_off() {
        for spec in ["", "   ", "\n"] {
            let keys =
                ClientKeys::from_spec(spec).expect("blank is 'not configured', not an error");
            assert!(!keys.enabled(), "blank spec {spec:?} must not enable auth");
            assert_eq!(keys.resolve("anything"), None);
        }
    }

    #[test]
    fn a_set_but_unusable_spec_refuses_rather_than_failing_open() {
        // Each of these is a plausible operator mistake. None may be read as
        // "authentication off" - that is the whole point of the error.
        for spec in [
            "garbage",           // forgot the :key_id
            ":no-secret",        // empty secret
            "no-key-id:",        // empty key_id
            ",,,",               // an empty interpolated variable
            "  :  ",             // whitespace on both sides
            "${TOKENFUSE_KEYS}", // an unexpanded shell variable
        ] {
            assert_eq!(
                ClientKeys::from_spec(spec).err(),
                Some(EmptySpec),
                "spec {spec:?} must be rejected, never silently disable auth"
            );
        }
    }

    #[test]
    fn resolves_a_known_secret_and_rejects_an_unknown_one() {
        let keys = ClientKeys::from_spec("sk-live-abc:billing-agent,sk-live-def:research-agent")
            .expect("valid spec");
        assert!(keys.enabled());
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.resolve("sk-live-abc"), Some("billing-agent"));
        assert_eq!(keys.resolve("sk-live-def"), Some("research-agent"));
        assert_eq!(
            keys.resolve("sk-live-xyz"),
            None,
            "an unknown secret resolves to nothing"
        );
        assert_eq!(keys.resolve(""), None);
        assert_eq!(
            keys.resolve("billing-agent"),
            None,
            "the key_id is not itself a credential"
        );
    }

    #[test]
    fn a_secret_may_contain_colons() {
        // Real API keys often do (`sk-proj:abc:def`), so the split is on the
        // LAST colon, not the first.
        let keys = ClientKeys::from_spec("sk-proj:abc:def:billing-agent").expect("valid spec");
        assert_eq!(keys.resolve("sk-proj:abc:def"), Some("billing-agent"));
    }

    #[test]
    fn malformed_entries_are_skipped_beside_valid_ones() {
        // Matching cloud::keys::parse_keys: one bad entry does not discard the
        // rest. The spec is still usable, so this is not EmptySpec.
        let keys = ClientKeys::from_spec("garbage,sk-ok:agent-a,:also-bad,").expect("valid spec");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys.resolve("sk-ok"), Some("agent-a"));
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let keys = ClientKeys::from_spec(" sk-a : agent-a , sk-b : agent-b ").expect("valid spec");
        assert_eq!(keys.resolve("sk-a"), Some("agent-a"));
        assert_eq!(keys.resolve("sk-b"), Some("agent-b"));
    }
}
