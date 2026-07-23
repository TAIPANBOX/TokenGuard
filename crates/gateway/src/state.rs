//! Shared application state handed to every request handler.

use crate::clientkeys::ClientKeys;
use crate::firewall::FirewallConfig;
use crate::identitymap::{IdentityMap, StrictMode};
use crate::ledger_backend::{LedgerBackend, LocalLedger};
use crate::provider::Provider;
use crate::router::Router;
use crate::sink::{EventSink, NullSink};
use crate::unitledger::UnitLedger;
use crate::wardryx::Wardryx;
use crate::wasmpolicy::WasmEval;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokenfuse_core::agent_event::Exporter as EventExporter;
use tokenfuse_core::cache::{CacheConfig, HashEmbedder};
use tokenfuse_core::taint::Labels;
use tokenfuse_core::{DlpMode, Ledger, Microusd, Policy, PriceBook, SemanticCache};

/// Per-run history of input sizes (tokens), used by the context-growth loop
/// detector. Bounded so a long-lived run cannot grow it without limit.
type History = Arc<Mutex<HashMap<String, Vec<u64>>>>;

/// Set of run ids an operator has killed (hard stop, any mode).
type Killed = Arc<Mutex<HashSet<String>>>;

/// Cloneable handle to the gateway's shared state (all fields are `Arc`).
#[derive(Clone)]
pub struct AppState {
    /// The budget ledger authority — in-process by default, or a raft-replicated
    /// backend under the `cluster` feature (see [`crate::ledger_backend`]).
    pub ledger: Arc<dyn LedgerBackend>,
    pub prices: Arc<PriceBook>,
    pub policy: Arc<Policy>,
    pub provider: Arc<dyn Provider>,
    /// Identifier of the active policy, echoed in the 402 contract.
    pub policy_id: Arc<str>,
    /// Where settled calls are recorded (Parquet, or a no-op by default).
    pub sink: Arc<dyn EventSink>,
    /// Semantic response cache (Off by default).
    pub cache: Arc<SemanticCache>,
    /// Agent-firewall config (Off by default).
    pub firewall: Arc<FirewallConfig>,
    /// Secret-scanning (DLP) mode (Off by default).
    pub dlp: DlpMode,
    /// Model router: picks the cheapest model that still meets a task's
    /// required quality tier (Off by default). See `crate::router`.
    pub router: Arc<Router>,
    /// Optional custom WASM policy.
    pub wasm: Option<Arc<dyn WasmEval>>,
    /// Wardryx enforcement hook (a PEP): enforces decisions made by the
    /// Wardryx policy service (a PDP). Off by default. See `crate::wardryx`.
    pub wardryx: Arc<Wardryx>,
    history: History,
    killed: Killed,
    /// Per-run accumulated taint labels.
    taint: Arc<Mutex<HashMap<String, Labels>>>,
    /// Per-run budgets pushed from the Cloud control plane (override the
    /// client-supplied budget). Empty unless cloud mode is on.
    cloud_budgets: Arc<Mutex<HashMap<String, Microusd>>>,
    /// Agent-event NDJSON exporter (agent-passport SPEC.md §6). Disabled
    /// (zero per-request cost) unless `TOKENFUSE_EVENTS_PATH` is set at
    /// startup — see `crate::events`.
    pub events: Arc<EventExporter>,
    /// Who may send calls through this gateway, and the stable `key_id` their
    /// spend is attributed to. Empty (authentication off, `key_id` empty)
    /// unless `TOKENFUSE_CLIENT_KEYS` is set at startup — see
    /// `crate::clientkeys`.
    pub client_keys: Arc<ClientKeys>,
    /// The declarative key<->agent<->unit identity map (docs/20). Disabled
    /// (every call resolves to no unit, no checks) unless
    /// `TOKENFUSE_IDENTITY_MAP` is set at startup - see `crate::identitymap`.
    pub identity: Arc<IdentityMap>,
    /// How a key<->agent mismatch is handled (`TOKENFUSE_IDENTITY_STRICT`):
    /// off = resolution only, warn = response header, enforce = 403. Governs
    /// ONLY the binding check; unit budgets follow `policy.mode` like every
    /// other budget.
    pub identity_strict: StrictMode,
    /// Per-unit monthly budget counters (docs/20). Uncapped units are not
    /// accounted; disabled entirely when the identity map is off.
    pub units: Arc<UnitLedger>,
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
            // Wrap the in-process ledger as the default backend. `with_ledger`
            // swaps in a raft-replicated backend for HA (cluster feature).
            ledger: Arc::new(LocalLedger(ledger)),
            prices,
            policy,
            provider,
            policy_id: policy_id.into(),
            sink: Arc::new(NullSink),
            cache: Arc::new(SemanticCache::new(
                Box::new(HashEmbedder::default()),
                CacheConfig::default(), // Off
            )),
            firewall: Arc::new(FirewallConfig::disabled()),
            dlp: DlpMode::Off,
            router: Arc::new(Router::disabled()),
            wasm: None,
            wardryx: Arc::new(Wardryx::disabled()),
            history: Arc::new(Mutex::new(HashMap::new())),
            killed: Arc::new(Mutex::new(HashSet::new())),
            taint: Arc::new(Mutex::new(HashMap::new())),
            cloud_budgets: Arc::new(Mutex::new(HashMap::new())),
            events: Arc::new(EventExporter::disabled()),
            client_keys: Arc::new(ClientKeys::default()),
            identity: Arc::new(IdentityMap::default()),
            identity_strict: StrictMode::Off,
            units: Arc::new(UnitLedger::default()),
        }
    }

    /// Require a client credential on metered calls, resolving it to a stable
    /// `key_id`. Chainable. Not set means authentication stays off, which is
    /// what every existing deployment gets on upgrade.
    pub fn with_client_keys(mut self, keys: Arc<ClientKeys>) -> Self {
        self.client_keys = keys;
        self
    }

    /// Wire the identity map, its strict mode, and the per-unit monthly
    /// ledger (docs/20). Chainable. Not set means identity stays off, which
    /// is what every existing deployment gets on upgrade.
    pub fn with_identity(
        mut self,
        map: Arc<IdentityMap>,
        strict: StrictMode,
        units: Arc<UnitLedger>,
    ) -> Self {
        self.identity = map;
        self.identity_strict = strict;
        self.units = units;
        self
    }

    /// Replace the Cloud-managed budget overrides (run id → µUSD). Called by the
    /// budget poller when cloud mode is on.
    pub fn set_cloud_budgets(&self, budgets: HashMap<String, Microusd>) {
        *self.cloud_budgets.lock().unwrap() = budgets;
    }

    /// The Cloud-managed budget for a run, if one has been set.
    pub fn cloud_budget(&self, run_id: &str) -> Option<Microusd> {
        self.cloud_budgets.lock().unwrap().get(run_id).copied()
    }

    /// Replace the ledger backend (e.g. a raft-replicated one). Chainable.
    pub fn with_ledger(mut self, ledger: Arc<dyn LedgerBackend>) -> Self {
        self.ledger = ledger;
        self
    }

    /// Set the DLP (secret-scanning) mode. Chainable.
    pub fn with_dlp(mut self, dlp: DlpMode) -> Self {
        self.dlp = dlp;
        self
    }

    /// Attach a custom WASM policy. Chainable.
    pub fn with_wasm(mut self, wasm: Arc<dyn WasmEval>) -> Self {
        self.wasm = Some(wasm);
        self
    }

    /// Attach an agent-firewall config. Chainable.
    pub fn with_firewall(mut self, firewall: Arc<FirewallConfig>) -> Self {
        self.firewall = firewall;
        self
    }

    /// Attach a model router. Chainable.
    pub fn with_router(mut self, router: Arc<Router>) -> Self {
        self.router = router;
        self
    }

    /// Attach the Wardryx enforcement hook. Chainable.
    pub fn with_wardryx(mut self, wardryx: Arc<Wardryx>) -> Self {
        self.wardryx = wardryx;
        self
    }

    /// Merge `new_labels` into a run's taint set and return the full current set.
    pub fn accumulate_taint(&self, run_id: &str, new_labels: Labels) -> Labels {
        let mut map = self.taint.lock().unwrap();
        let entry = map.entry(run_id.to_string()).or_default();
        entry.extend(new_labels);
        entry.clone()
    }

    /// Attach an event sink (e.g. the Parquet trace). Chainable.
    pub fn with_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.sink = sink;
        self
    }

    /// Attach the agent-event NDJSON exporter. Chainable.
    pub fn with_events(mut self, events: Arc<EventExporter>) -> Self {
        self.events = events;
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
