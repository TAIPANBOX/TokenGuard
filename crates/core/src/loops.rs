//! Runaway / loop detection.
//!
//! Two of the three signals are computed from a *single* request, because an
//! agent's request carries its own conversation history: the `messages` array
//! contains the tool calls it has already made. So we can spot "the same tool,
//! same arguments, N times" or an A→B→A→B ping-pong the moment a looping
//! conversation is proxied — no cross-request state required. The third signal,
//! context growth, needs the per-run history of input sizes and is fed from the
//! gateway's tracker.
//!
//! Detection is pure; the gateway decides what to do with a hit based on the
//! policy mode (shadow records, warn surfaces, enforce blocks).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

/// A count-within-a-window detector config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    pub window: usize,
    pub threshold: usize,
}

/// Context-growth detector config: `consecutive` steps each growing by at least
/// `factor` over the previous.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Growth {
    pub factor: f64,
    pub consecutive: usize,
}

/// Which anomaly detectors are enabled and with what thresholds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AnomalyConfig {
    #[serde(default)]
    pub identical_tool_call: Option<Window>,
    #[serde(default)]
    pub pingpong_pair: Option<Window>,
    #[serde(default)]
    pub context_growth: Option<Growth>,
}

impl AnomalyConfig {
    pub fn is_empty(&self) -> bool {
        self.identical_tool_call.is_none()
            && self.pingpong_pair.is_none()
            && self.context_growth.is_none()
    }
}

fn signature(name: &str, args: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut h);
    args.hash(&mut h);
    h.finish()
}

/// Extract tool-call signatures from a request body, in call order. Understands
/// both Anthropic (`content[].type == "tool_use"`) and OpenAI
/// (`tool_calls[].function`) message shapes.
pub fn tool_call_signatures(request: &serde_json::Value) -> Vec<u64> {
    let mut out = Vec::new();
    let Some(messages) = request.get("messages").and_then(|m| m.as_array()) else {
        return out;
    };
    for msg in messages {
        // Anthropic: assistant content blocks with type "tool_use".
        if let Some(content) = msg.get("content").and_then(|c| c.as_array()) {
            for block in content {
                if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                    let name = block.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let input = block
                        .get("input")
                        .map(|i| i.to_string())
                        .unwrap_or_default();
                    out.push(signature(name, &input));
                }
            }
        }
        // OpenAI: tool_calls array with function name + arguments.
        if let Some(calls) = msg.get("tool_calls").and_then(|c| c.as_array()) {
            for call in calls {
                let func = call.get("function");
                let name = func
                    .and_then(|f| f.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let args = func
                    .and_then(|f| f.get("arguments"))
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                out.push(signature(name, &args));
            }
        }
    }
    out
}

fn tail<T>(slice: &[T], n: usize) -> &[T] {
    &slice[slice.len().saturating_sub(n)..]
}

/// Same tool+args appears at least `threshold` times within the last `window`
/// tool calls.
pub fn detect_identical(sigs: &[u64], cfg: &Window) -> Option<String> {
    let window = tail(sigs, cfg.window);
    let mut counts: HashMap<u64, usize> = HashMap::new();
    for s in window {
        *counts.entry(*s).or_insert(0) += 1;
    }
    let max = counts.values().copied().max().unwrap_or(0);
    if max >= cfg.threshold && cfg.threshold > 0 {
        Some(format!(
            "identical tool call repeated {max}x within the last {} calls",
            cfg.window
        ))
    } else {
        None
    }
}

/// An A→B→A→B alternation between two distinct tools, at least `threshold`
/// overlapping cycles within the last `window` calls.
pub fn detect_pingpong(sigs: &[u64], cfg: &Window) -> Option<String> {
    let window = tail(sigs, cfg.window);
    let mut cycles = 0usize;
    for i in 0..window.len().saturating_sub(3) {
        if window[i] == window[i + 2]
            && window[i + 1] == window[i + 3]
            && window[i] != window[i + 1]
        {
            cycles += 1;
        }
    }
    if cycles >= cfg.threshold && cfg.threshold > 0 {
        Some(format!(
            "ping-pong tool alternation detected ({cycles} cycles) within the last {} calls",
            cfg.window
        ))
    } else {
        None
    }
}

/// Input size grew by at least `factor` for `consecutive` steps in a row — the
/// signature of a context that is ballooning toward a runaway.
pub fn detect_context_growth(input_sizes: &[u64], cfg: &Growth) -> Option<String> {
    if cfg.consecutive == 0 || input_sizes.len() <= cfg.consecutive {
        return None;
    }
    let mut run = 0usize;
    for pair in input_sizes.windows(2) {
        if pair[0] > 0 && (pair[1] as f64) >= (pair[0] as f64) * cfg.factor {
            run += 1;
            if run >= cfg.consecutive {
                return Some(format!(
                    "context grew ≥{:.1}x for {} consecutive steps",
                    cfg.factor, cfg.consecutive
                ));
            }
        } else {
            run = 0;
        }
    }
    None
}

/// Run all enabled detectors; return the first hit's reason.
pub fn detect(sigs: &[u64], input_sizes: &[u64], cfg: &AnomalyConfig) -> Option<String> {
    if let Some(w) = &cfg.identical_tool_call {
        if let Some(r) = detect_identical(sigs, w) {
            return Some(r);
        }
    }
    if let Some(w) = &cfg.pingpong_pair {
        if let Some(r) = detect_pingpong(sigs, w) {
            return Some(r);
        }
    }
    if let Some(g) = &cfg.context_growth {
        if let Some(r) = detect_context_growth(input_sizes, g) {
            return Some(r);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_anthropic_tool_use_signatures() {
        let req = json!({
            "messages": [
                {"role": "assistant", "content": [
                    {"type": "text", "text": "let me check"},
                    {"type": "tool_use", "name": "grep", "input": {"q": "foo"}}
                ]},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "name": "grep", "input": {"q": "foo"}}
                ]}
            ]
        });
        let sigs = tool_call_signatures(&req);
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0], sigs[1]); // same tool + same args
    }

    #[test]
    fn extracts_openai_tool_call_signatures() {
        let req = json!({
            "messages": [
                {"role": "assistant", "tool_calls": [
                    {"function": {"name": "search", "arguments": "{\"x\":1}"}}
                ]}
            ]
        });
        assert_eq!(tool_call_signatures(&req).len(), 1);
    }

    #[test]
    fn identical_fires_at_threshold() {
        let sigs = vec![1, 1, 1];
        let cfg = Window {
            window: 10,
            threshold: 3,
        };
        assert!(detect_identical(&sigs, &cfg).is_some());
        let cfg4 = Window {
            window: 10,
            threshold: 4,
        };
        assert!(detect_identical(&sigs, &cfg4).is_none());
    }

    #[test]
    fn identical_respects_window() {
        // Three 1s but they fall outside a window of 2.
        let sigs = vec![1, 1, 1, 2, 3];
        let cfg = Window {
            window: 2,
            threshold: 2,
        };
        assert!(detect_identical(&sigs, &cfg).is_none());
    }

    #[test]
    fn pingpong_detects_alternation() {
        let sigs = vec![1, 2, 1, 2];
        let cfg = Window {
            window: 8,
            threshold: 1,
        };
        assert!(detect_pingpong(&sigs, &cfg).is_some());
        // Not a ping-pong: same value repeated.
        assert!(detect_pingpong(&[1, 1, 1, 1], &cfg).is_none());
    }

    #[test]
    fn context_growth_fires_on_consecutive_growth() {
        let sizes = vec![1_000, 1_600, 2_600, 4_300];
        let cfg = Growth {
            factor: 1.5,
            consecutive: 3,
        };
        assert!(detect_context_growth(&sizes, &cfg).is_some());
    }

    #[test]
    fn context_growth_resets_on_a_flat_step() {
        let sizes = vec![1_000, 1_600, 1_600, 4_300];
        let cfg = Growth {
            factor: 1.5,
            consecutive: 3,
        };
        assert!(detect_context_growth(&sizes, &cfg).is_none());
    }

    #[test]
    fn detect_combines_all_and_returns_first_hit() {
        let cfg = AnomalyConfig {
            identical_tool_call: Some(Window {
                window: 10,
                threshold: 3,
            }),
            ..Default::default()
        };
        assert!(detect(&[7, 7, 7], &[], &cfg).is_some());
        assert!(detect(&[7, 8, 9], &[], &cfg).is_none());
    }
}
