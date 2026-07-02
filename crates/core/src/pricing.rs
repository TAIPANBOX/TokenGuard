//! Token usage and per-model pricing.
//!
//! Prices are expressed as microdollars per 1,000,000 tokens ("per Mtok"),
//! matching how providers publish their rates. Cache read/write are priced
//! separately on purpose: with agent loops that reuse a cached prefix, folding
//! them into the input rate would skew the accounting by a large multiple.

use crate::money::Microusd;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Token counts for a single LLM call, as reported by the provider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
}

/// Per-model price, in microdollars per million tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelPrice {
    pub input_per_mtok: Microusd,
    pub output_per_mtok: Microusd,
    pub cache_read_per_mtok: Microusd,
    pub cache_write_per_mtok: Microusd,
}

impl ModelPrice {
    /// Build a price from USD-per-Mtok figures (the units providers publish).
    pub fn per_mtok_usd(input: f64, output: f64, cache_read: f64, cache_write: f64) -> Self {
        ModelPrice {
            input_per_mtok: Microusd::from_usd(input),
            output_per_mtok: Microusd::from_usd(output),
            cache_read_per_mtok: Microusd::from_usd(cache_read),
            cache_write_per_mtok: Microusd::from_usd(cache_write),
        }
    }

    /// Exact cost of a usage record. Uses i128 intermediates so a large token
    /// count times a per-Mtok price cannot overflow before the divide.
    pub fn cost(&self, usage: &Usage) -> Microusd {
        let part = |tokens: u64, price: Microusd| -> i64 {
            ((tokens as i128 * price.0 as i128) / 1_000_000) as i64
        };
        Microusd(
            part(usage.input_tokens, self.input_per_mtok)
                + part(usage.output_tokens, self.output_per_mtok)
                + part(usage.cache_read_tokens, self.cache_read_per_mtok)
                + part(usage.cache_write_tokens, self.cache_write_per_mtok),
        )
    }
}

/// A lookup of model name -> price, with an optional conservative fallback for
/// unknown models (ADR-8: unknown model -> price at the most expensive known
/// model, so we never under-charge a run we can't identify).
#[derive(Debug, Clone, Default)]
pub struct PriceBook {
    prices: HashMap<String, ModelPrice>,
    fallback: Option<ModelPrice>,
}

impl PriceBook {
    pub fn new() -> Self {
        PriceBook::default()
    }

    pub fn insert(&mut self, model: impl Into<String>, price: ModelPrice) {
        self.prices.insert(model.into(), price);
    }

    pub fn with(mut self, model: impl Into<String>, price: ModelPrice) -> Self {
        self.insert(model, price);
        self
    }

    /// Set the fallback used for models not present in the book.
    pub fn with_fallback(mut self, price: ModelPrice) -> Self {
        self.fallback = Some(price);
        self
    }

    /// Price for a model: exact match first, then fallback if configured.
    pub fn price(&self, model: &str) -> Option<ModelPrice> {
        self.prices.get(model).copied().or(self.fallback)
    }

    /// Whether the model was priced by an exact entry (vs. the fallback). The
    /// gateway flags fallback-priced calls so reports can surface them.
    pub fn is_known(&self, model: &str) -> bool {
        self.prices.contains_key(model)
    }

    pub fn cost(&self, model: &str, usage: &Usage) -> Option<Microusd> {
        self.price(model).map(|p| p.cost(usage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sonnet() -> ModelPrice {
        // Illustrative rates ($/Mtok): input 3, output 15, cache read 0.3, write 3.75.
        ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75)
    }

    #[test]
    fn cost_sums_all_four_token_kinds() {
        let price = sonnet();
        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_read_tokens: 1_000_000,
            cache_write_tokens: 1_000_000,
        };
        // 3 + 15 + 0.30 + 3.75 = 22.05 USD
        assert_eq!(price.cost(&usage), Microusd::from_usd(22.05));
    }

    #[test]
    fn cache_is_priced_separately_from_input() {
        let price = sonnet();
        let cached = Usage {
            cache_read_tokens: 1_000_000,
            ..Default::default()
        };
        let fresh = Usage {
            input_tokens: 1_000_000,
            ..Default::default()
        };
        // Cache read must be an order of magnitude cheaper than fresh input.
        assert!(price.cost(&cached) < price.cost(&fresh));
        assert_eq!(price.cost(&cached), Microusd::from_usd(0.30));
    }

    #[test]
    fn large_token_counts_do_not_overflow() {
        let price = ModelPrice::per_mtok_usd(15.0, 75.0, 0.0, 0.0);
        let usage = Usage {
            input_tokens: 5_000_000_000,
            ..Default::default()
        };
        // 5e9 tokens * $15/Mtok = $75,000
        assert_eq!(price.cost(&usage), Microusd::from_usd(75_000.0));
    }

    #[test]
    fn unknown_model_uses_fallback_when_set() {
        let book = PriceBook::new()
            .with("known", sonnet())
            .with_fallback(ModelPrice::per_mtok_usd(15.0, 75.0, 1.5, 18.75));
        assert!(book.is_known("known"));
        assert!(!book.is_known("mystery-model"));
        assert!(book.price("mystery-model").is_some());
    }

    #[test]
    fn unknown_model_without_fallback_is_none() {
        let book = PriceBook::new().with("known", sonnet());
        assert!(book.price("mystery-model").is_none());
    }
}
