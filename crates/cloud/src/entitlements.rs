//! Plan entitlements — a pure, I/O-free gate mapping a [`Plan`] to the fleet
//! features it may use. This is the single decision point behind the P2
//! entitlements workstream: a lightweight flat-monthly plan gate on the paid
//! control-plane surface.
//!
//! [`Plan::Paid`] is allowed every feature. [`Plan::Free`] is OBSERVE-ONLY: it
//! passes [`Feature::FleetReads`] (the live fleet view — runs, summary, series,
//! stream, alerts) so a free org sees its own spend and can evaluate the
//! product, and is denied every ACTING or advanced surface (kill, central
//! budgets, agents, savings, incidents, device push, audit, compliance). The
//! caller turns a [`Denied`] into a `402 plan_required`.
//! Telemetry ingest is deliberately *not* modelled here — an org's gateways
//! must keep shipping data regardless of plan, so `/v1/ingest` never consults
//! this gate (fail-open for data collection; matches ADR-3). A Free org keeps
//! full fleet *visibility*; it loses only the *acting* surface, and data always
//! flows regardless of plan.
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
    /// Tamper-evident audit trail of control-plane mutations (read + verify).
    Audit,
    /// Compliance evidence pack (control catalog projected against the org's
    /// live decision + incident evidence).
    Compliance,
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
            Feature::Audit => "audit",
            Feature::Compliance => "compliance",
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
        // Free is observe-only: the live fleet view is included so a free org
        // can see its own spend and evaluate the product; every acting or
        // advanced surface stays paid.
        Plan::Free => match feature {
            Feature::FleetReads => Ok(()),
            _ => Err(Denied {
                feature: feature.as_str(),
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Feature; 9] = [
        Feature::FleetReads,
        Feature::CrossFleetKill,
        Feature::CentralBudgets,
        Feature::Agents,
        Feature::Savings,
        Feature::Incidents,
        Feature::DevicePush,
        Feature::Audit,
        Feature::Compliance,
    ];

    #[test]
    fn paid_passes_every_feature() {
        for f in ALL {
            assert!(gate(Plan::Paid, f).is_ok(), "paid should allow {f:?}");
        }
    }

    #[test]
    fn free_allows_observe_but_denies_acting() {
        // Free is observe-only: the live fleet view is allowed so a free org
        // can evaluate the product...
        assert!(
            gate(Plan::Free, Feature::FleetReads).is_ok(),
            "free should allow the observe surface (fleet reads)"
        );
        // ...but every other feature is the paid, acting/advanced surface.
        for f in ALL.into_iter().filter(|f| *f != Feature::FleetReads) {
            let denied = gate(Plan::Free, f).expect_err("free should deny the paid surface");
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
