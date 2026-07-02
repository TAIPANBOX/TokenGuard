//! Shared application state handed to every request handler.

use crate::provider::Provider;
use crate::sink::{EventSink, NullSink};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokenfuse_core::cache::{CacheConfig, HashEmbedder};
use tokenfuse_core::{Ledger, Policy, PriceBook, SemanticCache};

/// Per-run history of input sizes (tokens), used by the context-growth loop
/// detector. Bounded so a long-lived run cannot grow it without limit.
type History = Arc<Mutex<HashMap<String, Vec<u64>>>>;

/// Set of run ids an operator has killed (hard stop, any mode).
type Killed = Arc<Mutex<HashSet<String>>>;

/// Cloneable handle to the gateway's shared state (all fields are `Arc`).
#[derive(Clone)]
pub struct AppState {
    pub ledger: Arc<Ledger>,
    pub prices: Arc<PriceBook>,
    pub policy: Arc<Policy>,
    pub provider: Arc<dyn Provider>,
    /// Identifier of the active policy, echoed in the 402 contract.
    pub policy_id: Arc<str>,
    /// Where settled calls are recorded (Parquet, or a no-op by default).
    pub sink: Arc<dyn EventSink>,
    /// Semantic response cache (Off by default).
    pub cache: Arc<SemanticCache>,
    history: History,
    killed: Killed,
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
            sink: Arc::new(NullSink),
            cache: Arc::new(SemanticCache::new(
                Box::new(HashEmbedder::default()),
                CacheConfig::default(), // Off
            )),
            history: Arc::new(Mutex::new(HashMap::new())),
            killed: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Attach an event sink (e.g. the Parquet trace). Chainable.
    pub fn with_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.sink = sink;
        self
    }

    /// Attach a semantic cache. Chainable.
    pub fn with_cache(mut self, cache: Arc<SemanticCache>) -> Self {
        self.cache = cache;
        self
    }

    /// Mark a run as killed — subsequent calls are hard-blocked in any mode.
    pub fn kill(&self, run_id: &str) {
        self.killed.lock().unwrap().insert(run_id.to_string());
    }

    pub fn is_killed(&self, run_id: &str) -> bool {
        self.killed.lock().unwrap().contains(run_id)
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
