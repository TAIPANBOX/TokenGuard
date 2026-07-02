//! Agent-firewall configuration: how tools map to taint labels and capabilities,
//! and the rules that deny capabilities under taint.

use std::collections::HashMap;
use tokenfuse_core::taint::{FirewallMode, TaintRule};

#[derive(Debug, Clone, Default)]
pub struct FirewallConfig {
    pub mode: FirewallMode,
    /// tool name → taint label its output carries.
    pub sources: HashMap<String, String>,
    /// tool name → capability it exercises.
    pub capabilities: HashMap<String, String>,
    pub rules: Vec<TaintRule>,
}

impl FirewallConfig {
    /// Firewall off — no taint tracking, no blocks.
    pub fn disabled() -> Self {
        FirewallConfig::default()
    }

    /// A sensible starter policy: untrusted input (web/file/unknown) blocks
    /// exec/write/egress; a context that read secrets can't send data out.
    pub fn defaults(mode: FirewallMode) -> Self {
        let sources = HashMap::from([
            ("web_search".to_string(), "web".to_string()),
            ("fetch_url".to_string(), "web".to_string()),
            ("browse".to_string(), "web".to_string()),
            ("read_email".to_string(), "email".to_string()),
            ("read_upload".to_string(), "file".to_string()),
            ("read_file".to_string(), "file".to_string()),
            ("vault_read".to_string(), "secrets".to_string()),
            ("read_secret".to_string(), "secrets".to_string()),
        ]);
        let capabilities = HashMap::from([
            ("run_shell".to_string(), "exec".to_string()),
            ("exec".to_string(), "exec".to_string()),
            ("bash".to_string(), "exec".to_string()),
            ("write_file".to_string(), "write".to_string()),
            ("db_write".to_string(), "write".to_string()),
            ("deploy".to_string(), "write".to_string()),
            ("send_email".to_string(), "network_egress".to_string()),
            ("http_post".to_string(), "network_egress".to_string()),
            ("send_message".to_string(), "network_egress".to_string()),
        ]);
        let rules = vec![
            TaintRule {
                when_any: vec![
                    "web".into(),
                    "email".into(),
                    "file".into(),
                    "unclassified".into(),
                ],
                deny: vec!["exec".into(), "write".into(), "network_egress".into()],
            },
            TaintRule {
                when_any: vec!["secrets".into()],
                deny: vec!["network_egress".into()],
            },
        ];
        FirewallConfig {
            mode,
            sources,
            capabilities,
            rules,
        }
    }
}

/// Build from `TOKENFUSE_FIREWALL = off | shadow | enforce` (default off).
pub fn from_env() -> FirewallConfig {
    match std::env::var("TOKENFUSE_FIREWALL").as_deref() {
        Ok("enforce") => FirewallConfig::defaults(FirewallMode::Enforce),
        Ok("shadow") => FirewallConfig::defaults(FirewallMode::Shadow),
        _ => FirewallConfig::disabled(),
    }
}
