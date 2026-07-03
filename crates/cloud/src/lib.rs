//! TokenFuse Cloud control plane — aggregates the call telemetry many gateways
//! push in into a single per-organization fleet view. The Rust successor to the
//! original Go control plane (see docs/02-architecture.md, ADR-7, and the full
//! plan in docs/14-mobile-companion.md).

pub mod devices;
pub mod http;
pub mod keys;
pub mod store;

pub use http::{app, openapi_spec, AppState};
pub use keys::{parse_keys, Principal};
pub use store::{CallRecord, Store};
