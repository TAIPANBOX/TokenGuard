//! TokenFuse Cloud control plane — aggregates the call telemetry many gateways
//! push in into a single per-organization fleet view. The Rust successor to the
//! original Go control plane (see docs/02-architecture.md, ADR-7, and the full
//! plan in docs/14-mobile-companion.md).

#[cfg(feature = "apns")]
pub mod apns;
pub mod audit_sign;
pub mod devices;
pub mod entitlements;
pub mod http;
pub mod keys;
pub mod oidc;
pub mod push;
pub mod store;

pub use audit_sign::{signing_key_from_env as audit_signing_key_from_env, AuditManifest};
pub use entitlements::{gate, Denied, Feature};
pub use http::{app, openapi_spec, AppState};
pub use keys::{parse_keys, Plan, Principal};
pub use oidc::{verify_id_token, OidcConfig};
pub use push::{NullSender, PushPipeline, PushSender};
pub use store::{CallRecord, Incident, IncidentConfig, Store};
