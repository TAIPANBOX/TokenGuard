//! Default price book shipped with the gateway binary.
//!
//! Pulled out of `main.rs` so it's unit-testable: the goal is to catch a
//! units mistake (a 1e6 error turns a milli-dollar estimate into a
//! multi-thousand-dollar one) before it ships, and to pin which models
//! resolve via an exact price-book entry vs. the conservative fallback
//! (`x-fuse-price: exact` vs `fallback`, see `proxy.rs`).

use tokenfuse_core::{ModelPrice, PriceBook};

/// The price book used by `tokenfuse serve` when no external price feed is
/// wired in. Illustrative generic entries plus exact entries for the current
/// (2026-07) Anthropic and OpenAI model lineup, so common calls price exactly
/// instead of falling back to the conservative generic rate.
pub fn default_price_book() -> PriceBook {
    PriceBook::new()
        // --- Illustrative generic entries (pre-existing; kept for callers that
        // pass a bare family name rather than a real provider model string). ---
        .with(
            "claude-sonnet",
            ModelPrice::per_mtok_usd(3.0, 15.0, 0.30, 3.75),
        )
        .with(
            "claude-haiku",
            ModelPrice::per_mtok_usd(0.80, 4.0, 0.08, 1.0),
        )
        .with("gpt", ModelPrice::per_mtok_usd(2.5, 10.0, 0.25, 3.125))
        //
        // --- Anthropic, current lineup. Prices as of 2026-07, verify against
        // https://platform.claude.com/docs/en/about-claude/pricing before
        // relying on them for anything beyond reserve sizing (real cost is
        // reconciled on settle from actual usage — see estimate.rs). Cache
        // write/read follow Anthropic's published multiplier off the input
        // rate (5-minute TTL: write = 1.25x input, read = 0.1x input); the
        // 1-hour-TTL cache tier (2x write) and the >200K-context long-context
        // tier are not modeled here and would under-price those specific
        // calls — acceptable for a pre-call reserve estimate but flagged for
        // honesty (CLAUDE.md invariant 4). ---
        //
        // Claude Haiku 4.5: $1.00 / $5.00 per Mtok, cache write $1.25, cache
        // read $0.10. `claude-haiku-4-5` is Anthropic's "latest" alias for the
        // `-20251001` dated snapshot; both are entered so either resolves
        // exactly (the PriceBook has no alias-follows-alias mechanism, so
        // both are inserted directly rather than invented as an alias).
        .with(
            "claude-haiku-4-5",
            ModelPrice::per_mtok_usd(1.00, 5.00, 0.10, 1.25),
        )
        .with(
            "claude-haiku-4-5-20251001",
            ModelPrice::per_mtok_usd(1.00, 5.00, 0.10, 1.25),
        )
        // Claude Sonnet 4.5: $3.00 / $15.00 per Mtok (<=200K context), cache
        // write $3.75, cache read $0.30. Same $/Mtok as the generic
        // "claude-sonnet" entry above — Sonnet 4.5 kept Sonnet 4's pricing.
        .with(
            "claude-sonnet-4-5",
            ModelPrice::per_mtok_usd(3.00, 15.00, 0.30, 3.75),
        )
        .with(
            "claude-sonnet-4-5-20250929",
            ModelPrice::per_mtok_usd(3.00, 15.00, 0.30, 3.75),
        )
        // Claude Opus 4.5: $5.00 / $25.00 per Mtok, cache write $6.25, cache
        // read $0.50 (a 67% cut vs. Opus 4.1's $15/$75 — verify if this looks
        // stale, Opus pricing has moved before).
        .with(
            "claude-opus-4-5",
            ModelPrice::per_mtok_usd(5.00, 25.00, 0.50, 6.25),
        )
        .with(
            "claude-opus-4-5-20251101",
            ModelPrice::per_mtok_usd(5.00, 25.00, 0.50, 6.25),
        )
        //
        // --- OpenAI, current lineup. Prices as of 2026-07, verify against
        // https://developers.openai.com/api/docs/pricing. OpenAI's prompt
        // caching has no separate "cache write" fee (the first pass through
        // is billed as ordinary input) — cache_write_per_mtok is set equal to
        // input_per_mtok so writing to cache never appears artificially free
        // or artificially expensive if the caller ever tags tokens that way.
        // Cached-read discount is a flat 50% off input across these models. ---
        //
        // gpt-4o: $2.50 / $10.00 per Mtok, cached input $1.25.
        .with("gpt-4o", ModelPrice::per_mtok_usd(2.50, 10.00, 1.25, 2.50))
        // gpt-4o-mini: $0.15 / $0.60 per Mtok, cached input $0.075.
        .with(
            "gpt-4o-mini",
            ModelPrice::per_mtok_usd(0.15, 0.60, 0.075, 0.15),
        )
        // o1: $15.00 / $60.00 per Mtok, cached input $7.50.
        .with("o1", ModelPrice::per_mtok_usd(15.00, 60.00, 7.50, 15.00))
        //
        // --- Conservative fallback for anything not listed above (ADR-8):
        // priced at (a margin above) the most expensive known model, so an
        // unrecognized model never under-reserves. ---
        .with_fallback(ModelPrice::per_mtok_usd(15.0, 75.0, 1.5, 18.75))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenfuse_core::{Microusd, Usage};

    /// A 1000-input/500-output claude-haiku-4-5 call should land in the
    /// single-digit-to-low-tens-of-milli-dollars range. This is the guard
    /// against a units error: get the Microusd/per-Mtok conversion wrong by
    /// 1e6 and this would report either sub-micro-dollar or multi-dollar
    /// costs instead.
    #[test]
    fn haiku_4_5_sample_estimate_is_in_sane_milli_dollar_range() {
        let book = default_price_book();
        let usage = Usage {
            input_tokens: 1000,
            output_tokens: 500,
            ..Default::default()
        };
        let cost = book.cost("claude-haiku-4-5", &usage).unwrap();
        // input: 1000 * $1.00/1e6 = $0.001; output: 500 * $5.00/1e6 = $0.0025
        // total = $0.0035 = 3.5 milli-dollars.
        assert_eq!(cost, Microusd::from_usd(0.0035));
        // Sane-range guard, independent of the exact arithmetic above: not
        // sub-micro-dollar, not dollars.
        assert!(
            cost > Microusd::from_usd(0.0001) && cost < Microusd::from_usd(1.0),
            "cost {cost} is outside the sane milli-dollar range for a small haiku call"
        );
    }

    #[test]
    fn new_2026_models_resolve_by_exact_match_not_fallback() {
        let book = default_price_book();
        for model in [
            "claude-haiku-4-5",
            "claude-haiku-4-5-20251001",
            "claude-sonnet-4-5",
            "claude-sonnet-4-5-20250929",
            "claude-opus-4-5",
            "claude-opus-4-5-20251101",
            "gpt-4o",
            "gpt-4o-mini",
            "o1",
        ] {
            assert!(book.is_known(model), "{model} should be an exact entry");
        }
        // Still no exact entry for a genuinely unknown model — it must fall
        // back rather than silently gaining a made-up price.
        assert!(!book.is_known("some-future-model-nobody-has-priced-yet"));
        assert!(
            book.price("some-future-model-nobody-has-priced-yet")
                .is_some(),
            "unknown models must still resolve via the conservative fallback"
        );
    }

    #[test]
    fn opus_4_5_is_the_most_expensive_entry_the_fallback_stays_conservative() {
        // ADR-8: the fallback should remain at least as expensive as any
        // known model, so an unrecognized model is never under-reserved
        // relative to what we do know how to price.
        let book = default_price_book();
        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            ..Default::default()
        };
        let opus_cost = book.cost("claude-opus-4-5", &usage).unwrap();
        let fallback_cost = book.cost("truly-unknown-model", &usage).unwrap();
        assert!(fallback_cost >= opus_cost);
    }
}
