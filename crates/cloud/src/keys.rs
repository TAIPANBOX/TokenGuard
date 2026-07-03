//! API-key → principal mapping. A key spec is `key:org[:role]`, the role
//! defaulting to `admin`; a `viewer` can read but not mutate. Ported from the
//! Go plane's `parseKeys`.

use std::collections::HashMap;

/// Who a key belongs to: an organization and a role (`admin` | `viewer`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub org: String,
    pub role: String,
}

/// Parse `"key:org[:role],…"`. Entries missing a key or an org are skipped.
/// With no valid entries, a single dev key `devkey → default/admin` is returned
/// so the plane is usable out of the box.
pub fn parse_keys(spec: &str) -> HashMap<String, Principal> {
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
    if keys.is_empty() {
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
        let k = parse_keys("a:acme,b:globex:viewer");
        assert_eq!(
            k["a"],
            Principal {
                org: "acme".into(),
                role: "admin".into()
            }
        );
        assert_eq!(
            k["b"],
            Principal {
                org: "globex".into(),
                role: "viewer".into()
            }
        );
    }

    #[test]
    fn empty_spec_yields_dev_key() {
        let k = parse_keys("");
        assert_eq!(k["devkey"].org, "default");
        assert_eq!(k["devkey"].role, "admin");
    }

    #[test]
    fn skips_malformed_entries() {
        let k = parse_keys("nokey, :noorg , good:org");
        assert_eq!(k.len(), 1);
        assert!(k.contains_key("good"));
    }
}
