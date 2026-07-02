//! Pre-flight cost estimation (ADR-6).
//!
//! Before forwarding, we need a cost estimate to reserve against the budget. We
//! don't have the provider's tokenizer, so we approximate — cheaply and
//! *conservatively* (a built-in margin), because under-estimating is what lets a
//! runaway slip through. The real cost is reconciled on settle, so the estimate
//! only needs to be a safe upper-ish bound, not exact.

use tokenfuse_core::{Microusd, PriceBook, Usage};

/// Conservative margin applied to the raw estimate (ADR-6: +15%).
const MARGIN: f64 = 1.15;

/// Rough characters-per-token ratio for English-ish text.
const CHARS_PER_TOKEN: u64 = 4;

/// Default assumed output tokens when the request does not cap `max_tokens`.
const DEFAULT_MAX_TOKENS: u64 = 1_024;

/// Estimate the cost of a call from the request body length and `max_tokens`.
/// `body_len` is the serialized request size in bytes; `max_tokens` is the
/// caller's output cap if present.
pub fn estimate_cost(
    prices: &PriceBook,
    model: &str,
    body_len: usize,
    max_tokens: Option<u64>,
) -> Option<Microusd> {
    let input_tokens = (body_len as u64) / CHARS_PER_TOKEN;
    let output_tokens = max_tokens.unwrap_or(DEFAULT_MAX_TOKENS);

    let usage = Usage {
        input_tokens,
        output_tokens,
        ..Default::default()
    };

    prices.cost(model, &usage).map(|raw| {
        // Apply the conservative margin.
        Microusd((raw.0 as f64 * MARGIN).ceil() as i64)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenfuse_core::ModelPrice;

    fn book() -> PriceBook {
        PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.0, 0.0))
    }

    #[test]
    fn estimate_includes_the_conservative_margin() {
        // 4000 bytes -> 1000 input tokens; max_tokens 1000 output.
        // raw = 1000/1e6*3 + 1000/1e6*15 = 0.003 + 0.015 = 0.018 USD
        // with +15% margin -> 0.0207 USD
        let est = estimate_cost(&book(), "m", 4000, Some(1000)).unwrap();
        assert_eq!(est, Microusd::from_usd(0.0207));
    }

    #[test]
    fn unknown_model_yields_no_estimate() {
        assert!(estimate_cost(&book(), "unknown", 4000, Some(100)).is_none());
    }

    #[test]
    fn missing_max_tokens_falls_back_to_default() {
        let est = estimate_cost(&book(), "m", 0, None).unwrap();
        assert!(est > Microusd::ZERO);
    }
}
