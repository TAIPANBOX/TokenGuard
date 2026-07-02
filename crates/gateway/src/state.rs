//! Shared application state handed to every request handler.

use crate::provider::Provider;
use std::sync::Arc;
use tokenfuse_core::{Ledger, Policy, PriceBook};

/// Cloneable handle to the gateway's shared state (all fields are `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub ledger: Arc<Ledger>,
    pub prices: Arc<PriceBook>,
    pub policy: Arc<Policy>,
    pub provider: Arc<dyn Provider>,
    /// Identifier of the active policy, echoed in the 402 contract.
    pub policy_id: Arc<str>,
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
        }
    }
}
