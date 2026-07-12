//! API-key → principal mapping. A key spec is `key:org[:role][:plan]`, the role
//! defaulting to `admin` (`viewer` can read but not mutate) and the plan
//! defaulting to `Paid` (full access). Ported from the Go plane's `parseKeys`,
//! extended with a plan tier for the P2 entitlements gate.
//!
//! **Fails closed by default.** An unset/empty/all-malformed spec yields an
//! *empty* map: every request then gets `401`, nobody authenticates. The
//! insecure `devkey → default/admin/paid` convenience credential exists only
//! for local dev and is inserted **only** when the caller explicitly opts in
//! (see [`parse_keys`]'s `allow_devkey` parameter). It is never a silent
//! default. See `TOKENFUSE_CLOUD_ALLOW_DEVKEY` in `main.rs`.

use std::collections::HashMap;

/// The plan tier a key's org is on.
///
/// The plan segment is **optional** and defaults to [`Plan::Paid`]: existing
/// keys (`key:org`, `key:org:role`) and the dev fallback keep full access, so
/// OSS self-hosters and every pre-entitlements deployment are unaffected.
/// `:free` is an *explicit* downgrade that turns the entitlement gate on for
/// that org (the hosted SaaS stamps free-tier orgs with `:free`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Plan {
    /// Free tier — the paid fleet surface is gated (`402 plan_required`).
    Free,
    /// Full paid access — the default when the plan segment is absent.
    #[default]
    Paid,
}

impl Plan {
    /// Parse a plan segment case-insensitively. `free` → [`Plan::Free`];
    /// `paid` → [`Plan::Paid`]; anything else (including a typo) → [`Plan::Paid`]
    /// — we fail *open* so a malformed segment never silently locks an org out.
    fn parse(seg: &str) -> Plan {
        if seg.eq_ignore_ascii_case("free") {
            Plan::Free
        } else {
            Plan::Paid
        }
    }
}

/// Who a key belongs to: an organization, a role (`admin` | `viewer`) and a
/// [`Plan`] tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub org: String,
    pub role: String,
    pub plan: Plan,
}

/// Parse `"key:org[:role][:plan],…"`. Entries missing a key or an org are
/// skipped. Segments are positional: the 3rd is the role (default `admin`) and
/// the **4th is the plan** (`free` | `paid`, default `paid`) — so 3-segment
/// `key:org:role` specs parse exactly as before and only gain a plan when a
/// 4th segment is present.
///
/// With no valid entries, this **fails closed**: an empty map is returned, so
/// every request gets `401` (nobody authenticates) instead of silently
/// granting admin. Passing `allow_devkey = true` opts into the old
/// dev-convenience fallback instead: a single `devkey → default/admin/paid`
/// entry, so a local/demo deployment is usable without minting a real key.
/// Callers must only ever set `allow_devkey` from an explicit operator opt-in
/// (an env var, a CLI flag), never as a silent default: an empty
/// `TOKENFUSE_CLOUD_KEYS` in production must not quietly authenticate anyone
/// who sends `Authorization: Bearer devkey` as an admin.
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
        let plan = parts
            .get(3)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(Plan::parse)
            .unwrap_or(Plan::Paid);
        keys.insert(
            parts[0].trim().to_string(),
            Principal {
                org: parts[1].trim().to_string(),
                role: role.to_string(),
                plan,
            },
        );
    }
    if keys.is_empty() && allow_devkey {
        keys.insert(
            "devkey".to_string(),
            Principal {
                org: "default".into(),
                role: "admin".into(),
                plan: Plan::Paid,
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
                plan: Plan::Paid,
            }
        );
        assert_eq!(
            k["b"],
            Principal {
                org: "globex".into(),
                role: "viewer".into(),
                plan: Plan::Paid,
            }
        );
    }

    #[test]
    fn plan_defaults_to_paid_when_absent() {
        let k = parse_keys("a:acme,b:globex:viewer", false);
        // No plan segment on either → full (paid) access, so existing
        // deployments are never gated.
        assert_eq!(k["a"].plan, Plan::Paid);
        assert_eq!(k["b"].plan, Plan::Paid);
    }

    #[test]
    fn explicit_free_downgrades_plan() {
        let k = parse_keys("a:acme:admin:free", false);
        assert_eq!(
            k["a"],
            Principal {
                org: "acme".into(),
                role: "admin".into(),
                plan: Plan::Free,
            }
        );
    }

    #[test]
    fn plan_segment_is_case_insensitive() {
        let k = parse_keys("a:acme:admin:FREE,b:globex:viewer:Paid", false);
        assert_eq!(k["a"].plan, Plan::Free);
        assert_eq!(k["b"].plan, Plan::Paid);
        assert_eq!(k["b"].role, "viewer");
    }

    #[test]
    fn unknown_plan_segment_fails_open_to_paid() {
        // A typo'd/unknown plan must never silently lock an org out.
        let k = parse_keys("a:acme:admin:bogus", false);
        assert_eq!(k["a"].plan, Plan::Paid);
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
        assert_eq!(k["devkey"].plan, Plan::Paid);
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
