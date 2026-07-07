//! TokenFuse core domain: money, pricing, the reserve/settle ledger, and policy
//! evaluation. Pure logic with no I/O — the gateway and future packs build on
//! this. See `docs/02-architecture.md` for the design and ADRs.

pub mod backtest;
pub mod breaker;
pub mod cache;
pub mod dlp;
pub mod ledger;
pub mod loops;
pub mod mcp;
pub mod mcpexposure;
pub mod mcpreport;
pub mod money;
pub mod policy;
pub mod pricing;
pub mod savings;
pub mod secretbroker;
pub mod taint;

pub use backtest::{backtest, BacktestPolicy, BacktestReport};
pub use breaker::{BreakerReason, BreakerVerdict};
pub use cache::{CacheConfig, CacheMode, HashEmbedder, SemanticCache};
pub use dlp::DlpMode;
pub use ledger::{BudgetError, Ledger, Reservation, RunSnapshot};
pub use loops::{AnomalyConfig, Growth, Window};
pub use mcpreport::{Finding, ScanReport, Severity};
pub use money::Microusd;
pub use policy::{evaluate, Decision, Evaluation, Mode, Policy};
pub use pricing::{ModelPrice, PriceBook, Usage};
pub use savings::{compute_savings, SavingsReport};
pub use secretbroker::{inject_secrets, Injection, SecretVault};
pub use taint::{FirewallMode, Labels, TaintRule};
