//! A guard that guarantees a streaming reservation is always settled — even if
//! the client disconnects mid-stream and the response future is dropped before
//! the normal end-of-stream settle runs.
//!
//! On normal completion the caller invokes [`SettleGuard::complete`], which
//! settles with the usage parsed from the stream. If the guard is dropped first
//! (client cancel, or an upstream error propagated via `?`), its `Drop` settles
//! with whatever usage was parsed so far, falling back to the reserved estimate
//! so the budget is never left over-reserved (a leaked reservation would wrongly
//! block later calls in the same run).

use crate::ledger_backend::LedgerBackend;
use crate::provider::UsageSlot;
use crate::sink::{now_millis, CallRecord, EventSink};
use std::sync::Arc;
use tokenfuse_core::{Microusd, PriceBook, Reservation};

pub struct SettleGuard {
    ledger: Arc<dyn LedgerBackend>,
    prices: Arc<PriceBook>,
    sink: Arc<dyn EventSink>,
    model: String,
    usage: UsageSlot,
    fallback: Microusd,
    reservation: Option<Reservation>,
    /// Request-scoped attribution carried into the settled `CallRecord`.
    agent_id: String,
}

impl SettleGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ledger: Arc<dyn LedgerBackend>,
        prices: Arc<PriceBook>,
        sink: Arc<dyn EventSink>,
        model: String,
        usage: UsageSlot,
        fallback: Microusd,
        reservation: Reservation,
        agent_id: String,
    ) -> Self {
        SettleGuard {
            ledger,
            prices,
            sink,
            model,
            usage,
            fallback,
            reservation: Some(reservation),
            agent_id,
        }
    }

    fn settle_now(&mut self) {
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        let parsed = self.usage.lock().unwrap().take();
        let actual = parsed
            .as_ref()
            .and_then(|u| self.prices.cost(&self.model, u))
            .unwrap_or(self.fallback);
        self.ledger.settle(&reservation, actual);

        let usage = parsed.unwrap_or_default();
        self.sink.record(CallRecord {
            ts_millis: now_millis(),
            run_id: reservation.run_id.clone(),
            model: self.model.clone(),
            decision: "allow".into(),
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cost_microusd: actual.0,
            step: reservation.step,
            agent_id: self.agent_id.clone(),
            // Streaming allows never serve from cache — no savings to record.
            saved_microusd: 0,
        });
    }

    /// Settle now with the parsed usage (normal end-of-stream). Consumes the
    /// guard so its `Drop` becomes a no-op.
    pub fn complete(mut self) {
        self.settle_now();
    }
}

impl Drop for SettleGuard {
    fn drop(&mut self) {
        // Only fires if `complete()` was not called (cancel / error path).
        self.settle_now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::UsageSlot;
    use std::sync::Mutex;
    use tokenfuse_core::{Ledger, ModelPrice, PriceBook, Usage};

    fn setup() -> (Arc<Ledger>, Arc<PriceBook>, UsageSlot, Reservation) {
        let ledger = Arc::new(Ledger::new());
        ledger.open_run("r", Microusd::from_usd(5.0), None);
        let reservation = ledger.reserve("r", Microusd::from_usd(1.0)).unwrap();
        let prices =
            Arc::new(PriceBook::new().with("m", ModelPrice::per_mtok_usd(3.0, 15.0, 0.0, 0.0)));
        let usage: UsageSlot = Arc::new(Mutex::new(None));
        (ledger, prices, usage, reservation)
    }

    #[test]
    fn complete_settles_with_parsed_usage() {
        let (ledger, prices, usage, reservation) = setup();
        *usage.lock().unwrap() = Some(Usage {
            input_tokens: 1_000_000,
            output_tokens: 0,
            ..Default::default()
        });
        let guard = SettleGuard::new(
            Arc::new(crate::ledger_backend::LocalLedger(ledger.clone())),
            prices,
            Arc::new(crate::sink::NullSink),
            "m".into(),
            usage,
            Microusd::from_usd(1.0),
            reservation,
            String::new(),
        );
        guard.complete();

        let snap = ledger.snapshot("r").unwrap();
        assert_eq!(snap.reserved, Microusd::ZERO); // released
        assert_eq!(snap.spent, Microusd::from_usd(3.0)); // 1M input @ $3/Mtok
    }

    #[test]
    fn drop_without_complete_settles_with_fallback() {
        let (ledger, prices, usage, reservation) = setup();
        // No usage parsed (cancel before any usage event).
        let fallback = Microusd::from_usd(1.0);
        {
            let _guard = SettleGuard::new(
                Arc::new(crate::ledger_backend::LocalLedger(ledger.clone())),
                prices,
                Arc::new(crate::sink::NullSink),
                "m".into(),
                usage,
                fallback,
                reservation,
                String::new(),
            );
            // dropped here without complete()
        }
        let snap = ledger.snapshot("r").unwrap();
        assert_eq!(snap.reserved, Microusd::ZERO); // reservation released, not leaked
        assert_eq!(snap.spent, fallback); // conservative fallback charge
    }
}
