//! DLP — secret detection in prompts (Ring 3.2).
//!
//! Agents routinely slurp `.env` files, keys, and tokens into their context. We
//! sit on the LLM path — the one place a traditional DLP can't see — so we scan
//! the outgoing prompt for credentials and either flag, mask, or block them
//! before they reach the provider.
//!
//! Pattern-based (low false-positive), operating on the raw request text so
//! masking is a plain substring replacement that keeps the JSON valid.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DlpMode {
    #[default]
    Off,
    /// Detect and report, forward unchanged.
    Shadow,
    /// Replace secrets with `[REDACTED:kind]` before forwarding.
    Mask,
    /// Block the request if any secret is found.
    Block,
}

/// A detected secret: its kind and byte span in the scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: &'static str,
    pub start: usize,
    pub end: usize,
}

fn patterns() -> &'static [(&'static str, Regex)] {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        // Order matters: more specific patterns first so overlap dedup keeps them.
        vec![
            (
                "private_key",
                Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap(),
            ),
            (
                "anthropic_key",
                Regex::new(r"sk-ant-[A-Za-z0-9_\-]{20,}").unwrap(),
            ),
            ("openai_key", Regex::new(r"sk-[A-Za-z0-9_\-]{20,}").unwrap()),
            ("aws_access_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
            (
                "google_api_key",
                Regex::new(r"AIza[0-9A-Za-z_\-]{35}").unwrap(),
            ),
            (
                "github_token",
                Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").unwrap(),
            ),
            (
                "slack_token",
                Regex::new(r"xox[baprs]-[A-Za-z0-9\-]{10,}").unwrap(),
            ),
            (
                "jwt",
                Regex::new(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap(),
            ),
            (
                "bearer_token",
                Regex::new(r"Bearer\s+[A-Za-z0-9._\-]{20,}").unwrap(),
            ),
        ]
    })
}

/// Find all secrets in `text`, de-overlapped (leftmost, longest, most-specific).
pub fn scan(text: &str) -> Vec<Finding> {
    let mut found = Vec::new();
    for (kind, re) in patterns() {
        for m in re.find_iter(text) {
            found.push(Finding {
                kind,
                start: m.start(),
                end: m.end(),
            });
        }
    }
    // Leftmost first; for ties, longer first; stable so pattern order breaks
    // remaining ties (specific patterns are declared earlier).
    found.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

    let mut result: Vec<Finding> = Vec::new();
    let mut last_end = 0usize;
    for f in found {
        if f.start >= last_end {
            last_end = f.end;
            result.push(f);
        }
    }
    result
}

/// Replace each finding with `[REDACTED:kind]`, preserving the rest of the text.
pub fn redact(text: &str, findings: &[Finding]) -> String {
    let mut s = text.to_string();
    // Replace from the end so earlier byte offsets stay valid.
    let mut ordered: Vec<&Finding> = findings.iter().collect();
    ordered.sort_by_key(|f| std::cmp::Reverse(f.start));
    for f in ordered {
        if f.end <= s.len() && s.is_char_boundary(f.start) && s.is_char_boundary(f.end) {
            s.replace_range(f.start..f.end, &format!("[REDACTED:{}]", f.kind));
        }
    }
    s
}

/// A short human summary, e.g. "2 secret(s): anthropic_key, aws_access_key".
pub fn summary(findings: &[Finding]) -> String {
    let mut kinds: Vec<&str> = findings.iter().map(|f| f.kind).collect();
    kinds.sort_unstable();
    kinds.dedup();
    format!("{} secret(s): {}", findings.len(), kinds.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_key_shapes() {
        let text = "here is sk-ant-abc12345678901234567890 and AKIA1234567890ABCDEF end";
        let f = scan(text);
        let kinds: Vec<_> = f.iter().map(|x| x.kind).collect();
        assert!(kinds.contains(&"anthropic_key"));
        assert!(kinds.contains(&"aws_access_key"));
    }

    #[test]
    fn anthropic_wins_over_openai_for_sk_ant() {
        // sk-ant- also loosely matches the openai sk- pattern; dedup must keep
        // the more specific anthropic label.
        let f = scan("sk-ant-abcdefghij0123456789xyz");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "anthropic_key");
    }

    #[test]
    fn redaction_replaces_secret_and_keeps_surroundings() {
        let text = r#"{"content":"my key is AKIA1234567890ABCDEF ok"}"#;
        let f = scan(text);
        let out = redact(text, &f);
        assert!(!out.contains("AKIA1234567890ABCDEF"));
        assert!(out.contains("[REDACTED:aws_access_key]"));
        assert!(out.starts_with(r#"{"content":"my key is "#));
    }

    #[test]
    fn clean_text_has_no_findings() {
        assert!(scan("just a normal prompt about refunds").is_empty());
    }

    #[test]
    fn summary_counts_and_lists_kinds() {
        let f = scan("AKIA1234567890ABCDEF sk-ant-abcdefghij0123456789xyz");
        let s = summary(&f);
        assert!(s.starts_with("2 secret(s):"));
        assert!(s.contains("aws_access_key"));
        assert!(s.contains("anthropic_key"));
    }
}
