//! Plan entitlements — a pure, I/O-free gate mapping a [`Plan`] to the fleet
//! features it may use. This is the single decision point behind the P2
//! entitlements workstream: a lightweight flat-monthly plan gate on the paid
//! control-plane surface.
//!
//! [`Plan::Paid`] is allowed every feature; [`Plan::Free`] is denied the whole
//! paid surface (the caller turns a [`Denied`] into a `402 plan_required`).
//! Telemetry ingest is deliberately *not* modelled here — an org's gateways
//! must keep shipping data regardless of plan, so `/v1/ingest` never consults
//! this gate (fail-open for data collection; matches ADR-3). A Free org loses
//! fleet *visibility*, never data.
//!
//! ## Where Stripe plugs in later (not built here)
//!
//! Today a key's plan is parsed from `TOKENFUSE_CLOUD_KEYS` once at startup (see
//! [`crate::keys::parse_keys`]), so a plan change means a restart. The runtime
//! upgrade/downgrade path is a future durable `Store::set_plan(org, Plan)`
//! driven by a Stripe billing webhook — the `Store` already has save / load /
//! autosave, so persisting an org → plan map and having this gate read from it
//! is the natural next step. No billing code lives in this crate yet.

use crate::keys::Plan;

/// A gate-able capability on the paid control-plane surface. Features group the
/// endpoints that share a plan requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Aggregated per-org fleet reads: runs, summary, series, stream, alerts.
    FleetReads,
    /// Cross-fleet kill switch (`kill` + the gateway `kills` poll).
    CrossFleetKill,
    /// Central per-run budgets (`budget` + the gateway `budgets` poll).
    CentralBudgets,
    /// Per-agent spend rollups.
    Agents,
    /// FinOps savings totals.
    Savings,
    /// Fleet incidents (list + acknowledge).
    Incidents,
    /// Mobile device pairing + push registration (APNs / Live Activities).
    DevicePush,
}

impl Feature {
    /// A stable, wire-facing identifier for the feature, surfaced in the
    /// `402 plan_required` body so clients can key upgrade prompts off it.
    pub fn as_str(self) -> &'static str {
        match self {
            Feature::FleetReads => "fleet_reads",
            Feature::CrossFleetKill => "cross_fleet_kill",
            Feature::CentralBudgets => "central_budgets",
            Feature::Agents => "agents",
            Feature::Savings => "savings",
            Feature::Incidents => "incidents",
            Feature::DevicePush => "device_push",
        }
    }
}

/// The outcome of a denied [`gate`] check: the feature that was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// The wire-facing feature identifier (see [`Feature::as_str`]).
    pub feature: &'static str,
}

/// Decide whether `plan` may use `feature`. [`Plan::Paid`] passes everything;
/// [`Plan::Free`] is denied the whole paid surface. Pure — no I/O.
pub fn gate(plan: Plan, feature: Feature) -> Result<(), Denied> {
    match plan {
        Plan::Paid => Ok(()),
        Plan::Free => Err(Denied {
            feature: feature.as_str(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Feature; 7] = [
        Feature::FleetReads,
        Feature::CrossFleetKill,
        Feature::CentralBudgets,
        Feature::Agents,
        Feature::Savings,
        Feature::Incidents,
        Feature::DevicePush,
    ];

    #[test]
    fn paid_passes_every_feature() {
        for f in ALL {
            assert!(gate(Plan::Paid, f).is_ok(), "paid should allow {f:?}");
        }
    }

    #[test]
    fn free_denies_every_paid_feature() {
        for f in ALL {
            let denied = gate(Plan::Free, f).expect_err("free should deny {f:?}");
            assert_eq!(denied.feature, f.as_str());
        }
    }

    #[test]
    fn denied_feature_is_the_stable_wire_name() {
        assert_eq!(
            gate(Plan::Free, Feature::CrossFleetKill)
                .unwrap_err()
                .feature,
            "cross_fleet_kill"
        );
    }
}
