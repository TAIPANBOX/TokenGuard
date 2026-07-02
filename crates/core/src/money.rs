//! Money is stored as integer microdollars to avoid floating-point drift in
//! accounting. 1 USD = 1_000_000 microUSD. All ledger math uses this type.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, Sub};

/// An amount of money in integer microdollars (1 USD = 1_000_000).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct Microusd(pub i64);

impl Microusd {
    pub const ZERO: Microusd = Microusd(0);

    /// Convert from a USD float (used only at config/report edges, never in the
    /// hot accounting path). Rounds to the nearest microdollar.
    pub fn from_usd(usd: f64) -> Self {
        Microusd((usd * 1_000_000.0).round() as i64)
    }

    /// Render as a USD float. For display/serialization at the edges only.
    pub fn as_usd(self) -> f64 {
        self.0 as f64 / 1_000_000.0
    }

    pub fn saturating_add(self, other: Microusd) -> Microusd {
        Microusd(self.0.saturating_add(other.0))
    }

    /// Subtract, clamping at zero (a settled reservation must never push a
    /// counter negative).
    pub fn saturating_sub(self, other: Microusd) -> Microusd {
        Microusd(self.0.saturating_sub(other.0).max(0))
    }
}

impl Add for Microusd {
    type Output = Microusd;
    fn add(self, rhs: Microusd) -> Microusd {
        Microusd(self.0 + rhs.0)
    }
}

impl Sub for Microusd {
    type Output = Microusd;
    fn sub(self, rhs: Microusd) -> Microusd {
        Microusd(self.0 - rhs.0)
    }
}

impl fmt::Display for Microusd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "${:.6}", self.as_usd())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usd_round_trips_through_microusd() {
        assert_eq!(Microusd::from_usd(5.0), Microusd(5_000_000));
        assert_eq!(Microusd::from_usd(0.000001), Microusd(1));
        assert_eq!(Microusd(2_500_000).as_usd(), 2.5);
    }

    #[test]
    fn from_usd_rounds_to_nearest_microdollar() {
        // 0.0000004 USD rounds down to 0, 0.0000006 rounds up to 1.
        assert_eq!(Microusd::from_usd(0.0000004), Microusd(0));
        assert_eq!(Microusd::from_usd(0.0000006), Microusd(1));
    }

    #[test]
    fn saturating_sub_never_goes_negative() {
        assert_eq!(Microusd(10).saturating_sub(Microusd(25)), Microusd::ZERO);
    }

    #[test]
    fn display_shows_six_decimals() {
        assert_eq!(Microusd(1_234_500).to_string(), "$1.234500");
    }
}
