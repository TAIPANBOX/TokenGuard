//! Tokenfuse core domain: money, pricing, the reserve/settle ledger, and policy
//! evaluation. Pure logic with no I/O — the gateway and future packs build on
//! this. See `docs/02-architecture.md` for the design and ADRs.

pub mod ledger;
pub mod loops;
pub mod money;
pub mod policy;
pub mod pricing;

pub use ledger::{BudgetError, Ledger, Reservation, RunSnapshot};
pub use loops::{AnomalyConfig, Growth, Window};
pub use money::Microusd;
pub use policy::{evaluate, Decision, Evaluation, Mode, Policy};
pub use pricing::{ModelPrice, PriceBook, Usage};
