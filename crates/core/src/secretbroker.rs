//! Credential brokering for MCP tool calls.
//!
//! Agents (and the LLM prompt) should never hold raw secrets. Instead a tool
//! call carries **handles** like `{{secret:github_token}}`, and the broker swaps
//! in the real value from a vault *at the boundary* — just before the request
//! leaves for the MCP server. The secret is therefore never in the model's
//! context, the trace, or the agent's memory.
//!
//! This module is the pure, dependency-light core (vault + substitution); the
//! network proxy that uses it lives in the gateway (`mcpbroker`).

use std::collections::HashMap;

use serde_json::Value;

/// A store of named secrets the broker can inject.
#[derive(Debug, Default, Clone)]
pub struct SecretVault {
    secrets: HashMap<String, String>,
}

impl SecretVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse `name1=value1,name2=value2`. Values must not contain `,` or `=`
    /// (fine for tokens); richer formats can build the vault directly.
    pub fn from_pairs(spec: &str) -> Self {
        let mut v = Self::new();
        for pair in spec.split(',').filter(|s| !s.trim().is_empty()) {
            if let Some((name, value)) = pair.split_once('=') {
                v.insert(name.trim(), value.trim());
            }
        }
        v
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.secrets.insert(name.into(), value.into());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.secrets.get(name).map(|s| s.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.secrets.len()
    }
}

/// Outcome of an injection pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Injection {
    /// How many handles were replaced with real secrets.
    pub replaced: usize,
    /// Handles whose secret was not in the vault (left as-is).
    pub missing: Vec<String>,
}

const OPEN: &str = "{{secret:";
const CLOSE: &str = "}}";

/// Replace every `{{secret:NAME}}` handle inside all string values of `v` with
/// the vault's secret. Unknown handles are left untouched and recorded in
/// [`Injection::missing`]. Recurses through objects and arrays.
pub fn inject_secrets(v: &mut Value, vault: &SecretVault) -> Injection {
    let mut inj = Injection::default();
    walk(v, vault, &mut inj);
    inj
}

fn walk(v: &mut Value, vault: &SecretVault, inj: &mut Injection) {
    match v {
        Value::String(s) => {
            if s.contains(OPEN) {
                *s = replace_handles(s, vault, inj);
            }
        }
        Value::Array(items) => {
            for it in items {
                walk(it, vault, inj);
            }
        }
        Value::Object(map) => {
            for (_, val) in map.iter_mut() {
                walk(val, vault, inj);
            }
        }
        _ => {}
    }
}

/// Replace all `{{secret:NAME}}` occurrences in a single string.
fn replace_handles(s: &str, vault: &SecretVault, inj: &mut Injection) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find(OPEN) {
        out.push_str(&rest[..start]);
        let after = &rest[start + OPEN.len()..];
        match after.find(CLOSE) {
            Some(end) => {
                let name = &after[..end];
                match vault.get(name) {
                    Some(secret) => {
                        out.push_str(secret);
                        inj.replaced += 1;
                    }
                    None => {
                        // Unknown secret: keep the handle verbatim so nothing
                        // silently becomes empty, and report it.
                        out.push_str(OPEN);
                        out.push_str(name);
                        out.push_str(CLOSE);
                        inj.missing.push(name.to_string());
                    }
                }
                rest = &after[end + CLOSE.len()..];
            }
            None => {
                // Unterminated handle — emit the rest unchanged.
                out.push_str(OPEN);
                out.push_str(after);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn injects_nested_handles() {
        let vault = SecretVault::from_pairs("github_token=ghp_REAL,api=KEY123");
        let mut v = json!({
            "name": "create_issue",
            "arguments": {
                "auth": "Bearer {{secret:github_token}}",
                "headers": ["x-api-key: {{secret:api}}"],
                "title": "hello"
            }
        });
        let inj = inject_secrets(&mut v, &vault);
        assert_eq!(inj.replaced, 2);
        assert!(inj.missing.is_empty());
        assert_eq!(v["arguments"]["auth"], "Bearer ghp_REAL");
        assert_eq!(v["arguments"]["headers"][0], "x-api-key: KEY123");
        assert_eq!(v["arguments"]["title"], "hello");
    }

    #[test]
    fn missing_handle_is_reported_and_kept() {
        let vault = SecretVault::from_pairs("a=1");
        let mut v = json!({ "x": "{{secret:nope}}" });
        let inj = inject_secrets(&mut v, &vault);
        assert_eq!(inj.replaced, 0);
        assert_eq!(inj.missing, vec!["nope".to_string()]);
        assert_eq!(v["x"], "{{secret:nope}}");
    }

    #[test]
    fn plain_values_untouched() {
        let vault = SecretVault::from_pairs("a=1");
        let mut v = json!({ "n": 42, "s": "no handles here", "b": true });
        let inj = inject_secrets(&mut v, &vault);
        assert_eq!(inj, Injection::default());
        assert_eq!(v["s"], "no handles here");
    }
}
