//! Taint tracking / agent firewall (Ring 3.1).
//!
//! Defends against prompt injection at the level of *actions*, not words: once a
//! run's context has touched an untrusted source (web, an uploaded file, an
//! unknown tool), high-privilege actions (exec, writing to prod, sending data
//! out) are denied. We do not try to detect "bad text" — we gate what a tainted
//! agent is allowed to *do*. See docs/07-taint-model.md.
//!
//! Pure logic here; the gateway maps tools → labels/capabilities, accumulates a
//! run's taint monotonically, and enforces the policy on the model's tool calls.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

/// The set of taint labels a run has accumulated (e.g. `web`, `file`, `secrets`).
pub type Labels = BTreeSet<String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FirewallMode {
    #[default]
    Off,
    /// Record would-blocks without blocking.
    Shadow,
    /// Block denied actions.
    Enforce,
}

/// A rule: if the context carries any `when_any` label and the action needs any
/// `deny` capability, the action is blocked.
#[derive(Debug, Clone)]
pub struct TaintRule {
    pub when_any: Vec<String>,
    pub deny: Vec<String>,
}

/// Extract tool-call names from a request (message history) or a response,
/// across Anthropic (`tool_use`) and OpenAI (`tool_calls`) shapes.
pub fn tool_names_in(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();

    // Anthropic response: top-level content array with tool_use blocks.
    push_tool_use_from_content(v.get("content"), &mut out);

    // Anthropic request: messages[].content[] tool_use; OpenAI messages[].tool_calls.
    if let Some(msgs) = v.get("messages").and_then(|m| m.as_array()) {
        for m in msgs {
            push_tool_use_from_content(m.get("content"), &mut out);
            push_openai_tool_calls(m.get("tool_calls"), &mut out);
        }
    }

    // OpenAI response: choices[].message.tool_calls.
    if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
        for ch in choices {
            push_openai_tool_calls(
                ch.get("message").and_then(|m| m.get("tool_calls")),
                &mut out,
            );
        }
    }

    out
}

fn push_tool_use_from_content(content: Option<&serde_json::Value>, out: &mut Vec<String>) {
    if let Some(blocks) = content.and_then(|c| c.as_array()) {
        for b in blocks {
            if b.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                if let Some(name) = b.get("name").and_then(|n| n.as_str()) {
                    out.push(name.to_string());
                }
            }
        }
    }
}

fn push_openai_tool_calls(calls: Option<&serde_json::Value>, out: &mut Vec<String>) {
    if let Some(arr) = calls.and_then(|c| c.as_array()) {
        for tc in arr {
            if let Some(name) = tc
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
            {
                out.push(name.to_string());
            }
        }
    }
}

/// Map tool names to the taint labels their output carries (unknown tools →
/// `unclassified`, which is treated as untrusted).
pub fn labels_for_tools(names: &[String], sources: &HashMap<String, String>) -> Labels {
    let mut labels = Labels::new();
    for n in names {
        match sources.get(n) {
            Some(label) => {
                labels.insert(label.clone());
            }
            None => {
                labels.insert("unclassified".to_string());
            }
        }
    }
    labels
}

/// Map tool names to the capabilities they exercise (tools with no mapped
/// capability are treated as harmless and omitted).
pub fn capabilities_for_tools(
    names: &[String],
    capabilities: &HashMap<String, String>,
) -> BTreeSet<String> {
    names
        .iter()
        .filter_map(|n| capabilities.get(n).cloned())
        .collect()
}

/// Evaluate the rules; return the reason for the first block, if any.
pub fn evaluate(
    labels: &Labels,
    requested: &BTreeSet<String>,
    rules: &[TaintRule],
) -> Option<String> {
    for rule in rules {
        let label_hit = rule.when_any.iter().any(|l| labels.contains(l));
        if !label_hit {
            continue;
        }
        let denied: Vec<&String> = rule
            .deny
            .iter()
            .filter(|c| requested.contains(*c))
            .collect();
        if !denied.is_empty() {
            return Some(format!(
                "tainted context [{}] denies capability [{}]",
                labels.iter().cloned().collect::<Vec<_>>().join(", "),
                denied
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sources() -> HashMap<String, String> {
        HashMap::from([
            ("web_search".to_string(), "web".to_string()),
            ("read_upload".to_string(), "file".to_string()),
            ("vault_read".to_string(), "secrets".to_string()),
        ])
    }
    fn caps() -> HashMap<String, String> {
        HashMap::from([
            ("run_shell".to_string(), "exec".to_string()),
            ("send_email".to_string(), "network_egress".to_string()),
        ])
    }
    fn rules() -> Vec<TaintRule> {
        vec![
            TaintRule {
                when_any: vec!["web".into(), "file".into(), "unclassified".into()],
                deny: vec!["exec".into(), "network_egress".into()],
            },
            TaintRule {
                when_any: vec!["secrets".into()],
                deny: vec!["network_egress".into()],
            },
        ]
    }

    #[test]
    fn extracts_tool_names_from_anthropic_response() {
        let resp = json!({"content":[{"type":"text","text":"hi"},{"type":"tool_use","name":"run_shell","input":{}}]});
        assert_eq!(tool_names_in(&resp), vec!["run_shell"]);
    }

    #[test]
    fn extracts_tool_names_from_openai_response() {
        let resp =
            json!({"choices":[{"message":{"tool_calls":[{"function":{"name":"send_email"}}]}}]});
        assert_eq!(tool_names_in(&resp), vec!["send_email"]);
    }

    #[test]
    fn unknown_tool_is_unclassified() {
        let l = labels_for_tools(&["mystery".to_string()], &sources());
        assert!(l.contains("unclassified"));
    }

    #[test]
    fn web_context_blocks_exec() {
        let labels = labels_for_tools(&["web_search".to_string()], &sources());
        let requested = capabilities_for_tools(&["run_shell".to_string()], &caps());
        assert!(evaluate(&labels, &requested, &rules()).is_some());
    }

    #[test]
    fn trusted_context_allows_exec() {
        let labels = Labels::new(); // nothing untrusted touched
        let requested = capabilities_for_tools(&["run_shell".to_string()], &caps());
        assert!(evaluate(&labels, &requested, &rules()).is_none());
    }

    #[test]
    fn secrets_context_blocks_only_egress_not_exec() {
        let labels = labels_for_tools(&["vault_read".to_string()], &sources());
        let exec = capabilities_for_tools(&["run_shell".to_string()], &caps());
        let egress = capabilities_for_tools(&["send_email".to_string()], &caps());
        // secrets rule denies egress but not exec
        assert!(evaluate(&labels, &exec, &rules()).is_none());
        assert!(evaluate(&labels, &egress, &rules()).is_some());
    }
}
