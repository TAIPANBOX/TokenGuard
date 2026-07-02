//! Shared application state handed to every request handler.

use crate::provider::Provider;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokenfuse_core::{Ledger, Policy, PriceBook};

/// Per-run history of input sizes (tokens), used by the context-growth loop
/// detector. Bounded so a long-lived run cannot grow it without limit.
type History = Arc<Mutex<HashMap<String, Vec<u64>>>>;

/// Cloneable handle to the gateway's shared state (all fields are `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub ledger: Arc<Ledger>,
    pub prices: Arc<PriceBook>,
    pub policy: Arc<Policy>,
    pub provider: Arc<dyn Provider>,
    /// Identifier of the active policy, echoed in the 402 contract.
    pub policy_id: Arc<str>,
    history: History,
}

impl AppState {
    pub fn new(
        ledger: Arc<Ledger>,
        prices: Arc<PriceBook>,
        policy: Arc<Policy>,
        provider: Arc<dyn Provider>,
        policy_id: impl Into<Arc<str>>,
    ) -> Self {
        AppState {
            ledger,
            prices,
            policy,
            provider,
            policy_id: policy_id.into(),
            history: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record this step's input size for a run and return the recent history
    /// (oldest→newest), capped to the most recent `MAX` steps.
    pub fn record_input(&self, run_id: &str, input_tokens: u64) -> Vec<u64> {
        const MAX: usize = 128;
        let mut map = self.history.lock().unwrap();
        let entry = map.entry(run_id.to_string()).or_default();
        entry.push(input_tokens);
        if entry.len() > MAX {
            let excess = entry.len() - MAX;
            entry.drain(0..excess);
        }
        entry.clone()
    }
}
