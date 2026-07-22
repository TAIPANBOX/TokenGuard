//! API-key → principal mapping. A key spec is `key:org[:role]`, the role
//! defaulting to `admin` (`viewer` can read but not mutate). Ported from the Go
//! plane's `parseKeys`.
//!
//! **Fails closed by default.** An unset/empty/all-malformed spec yields an
//! *empty* map: every request then gets `401`, nobody authenticates. The
//! insecure `devkey → default/admin` convenience credential exists only for
//! local dev and is inserted **only** when the caller explicitly opts in (see
//! [`parse_keys`]'s `allow_devkey` parameter). It is never a silent default.
//! See `TOKENFUSE_CLOUD_ALLOW_DEVKEY` in `main.rs`.

use std::collections::HashMap;

/// Who a key belongs to: an organization and a role (`admin` | `viewer`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub org: String,
    pub role: String,
}

/// Parse `"key:org[:role],…"`. Entries missing a key or an org are skipped.
/// Segments are positional: the 3rd is the role (default `admin`).
///
/// With no valid entries, this **fails closed**: an empty map is returned, so
/// every request gets `401` (nobody authenticates) instead of silently
/// granting admin. Passing `allow_devkey = true` opts into the old
/// dev-convenience fallback instead: a single `devkey → default/admin` entry,
/// so a local/demo deployment is usable without minting a real key. Callers
/// must only ever set `allow_devkey` from an explicit operator opt-in (an env
/// var, a CLI flag), never as a silent default: an empty `TOKENFUSE_CLOUD_KEYS`
/// in production must not quietly authenticate anyone who sends
/// `Authorization: Bearer devkey` as an admin.
pub fn parse_keys(spec: &str, allow_devkey: bool) -> HashMap<String, Principal> {
    let mut keys = HashMap::new();
    for pair in spec.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let parts: Vec<&str> = pair.split(':').collect();
        if parts.len() < 2 || parts[0].trim().is_empty() || parts[1].trim().is_empty() {
            continue;
        }
        let role = parts
            .get(2)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("admin");
        keys.insert(
            parts[0].trim().to_string(),
            Principal {
                org: parts[1].trim().to_string(),
                role: role.to_string(),
            },
        );
    }
    if keys.is_empty() && allow_devkey {
        keys.insert(
            "devkey".to_string(),
            Principal {
                org: "default".into(),
                role: "admin".into(),
            },
        );
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_org_and_role() {
        let k = parse_keys("a:acme,b:globex:viewer", false);
        assert_eq!(
            k["a"],
            Principal {
                org: "acme".into(),
                role: "admin".into(),
            }
        );
        assert_eq!(
            k["b"],
            Principal {
                org: "globex".into(),
                role: "viewer".into(),
            }
        );
    }

    #[test]
    fn skips_malformed_entries() {
        let k = parse_keys("nokey, :noorg , good:org", false);
        assert_eq!(k.len(), 1);
        assert!(k.contains_key("good"));
    }

    // -- devkey fallback: fails closed unless explicitly opted in ----------

    #[test]
    fn empty_spec_fails_closed_without_opt_in() {
        // The security-critical case: an unset/empty TOKENFUSE_CLOUD_KEYS
        // must NOT silently grant a hardcoded admin credential. With
        // allow_devkey=false the map must be empty, so every request gets
        // 401 (nobody authenticates).
        let k = parse_keys("", false);
        assert!(
            k.is_empty(),
            "expected no keys when devkey is not explicitly allowed, got {k:?}"
        );
        assert!(!k.contains_key("devkey"));
    }

    #[test]
    fn all_malformed_spec_fails_closed_without_opt_in() {
        // Same fail-closed guarantee when every entry is malformed (missing
        // key or org) rather than the spec being literally empty.
        let k = parse_keys("nokey, :noorg ,   ", false);
        assert!(k.is_empty());
    }

    #[test]
    fn empty_spec_with_explicit_opt_in_yields_dev_key() {
        // Only when the caller explicitly opts in does the dev fallback
        // appear.
        let k = parse_keys("", true);
        assert_eq!(k.len(), 1);
        assert_eq!(k["devkey"].org, "default");
        assert_eq!(k["devkey"].role, "admin");
    }

    #[test]
    fn normal_spec_unaffected_by_allow_devkey_flag() {
        // A real, non-empty spec parses identically regardless of
        // allow_devkey: the flag must only ever affect the empty case, and
        // must never inject an extra "devkey" entry alongside real keys.
        let k = parse_keys("a:acme", true);
        assert_eq!(k.len(), 1);
        assert!(!k.contains_key("devkey"));
        assert_eq!(k["a"].org, "acme");
    }
}
